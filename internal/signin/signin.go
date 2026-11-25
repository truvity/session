// Package signin is the sign-in handler: the paths under /_session/ (decision 0004), for one or more issuers (decision 0034). The
// sign-in page with one link for each issuer; login with authorisation code, PKCE, PAR and
// private_key_jwt (S3); the callback with the binding cookie, state, iss (RFC 9207) and ID token checks; logout as a POST with
// CSRF, then the issuer's end-session (S6); back-channel logout (OIDC Back-Channel Logout 1.0); whoami; jwks.
//
// It never logs a header value, a cookie, a token, a code or a body, and never shows the issuer's error text to the browser.
package signin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	tokenv1 "github.com/truvity/atoom/blocks/token/gen/atoom/token/v1alpha1"

	"github.com/truvity/session/core"
)

// Issuer is one issuer of the site and the site's client at it (decision 0034).
type Issuer struct {
	// ID names the issuer in the site: ?issuer=<id>, and the remembered choice.
	ID string
	// Label is what the sign-in page shows: "Sign in with <Label>".
	Label string
	// URL is the issuer identifier; its discovery document is read at the start.
	URL      string
	ClientID string
	Scopes   []string
}

// Options configure the handler.
type Options struct {
	Core *core.Core
	// Issuers are the site's issuers, one or more, in the order of the sign-in page.
	Issuers []Issuer
	// Signer signs the client assertion at every issuer: one key, the purpose client-assertion, published at /_session/jwks.
	Signer Signer
	// Identity is the signer of the identity header, whose public key /_session/jwks publishes too; nil publishes the client
	// key alone.
	Identity *Signer
	// Remember, when positive, keeps the issuer a person signed in with in a cookie for that long, and a sign-in that names no
	// issuer goes to it without the sign-in page. Zero remembers nothing.
	Remember time.Duration
	// HTTP is the client for the issuer's endpoints; nil is a client with a 10 s timeout.
	HTTP *http.Client
	// Log is the operational log; nil is slog.Default().
	Log *slog.Logger
}

// issuer is one issuer as the handler uses it: its discovery, its verifiers and the site's client at it.
type issuer struct {
	Issuer
	provider  *oidc.Provider
	idTokens  *oidc.IDTokenVerifier
	logouts   *oidc.IDTokenVerifier
	endpoints struct {
		PAR        string `json:"pushed_authorization_request_endpoint"`
		EndSession string `json:"end_session_endpoint"`
		Revocation string `json:"revocation_endpoint"`
		IssParam   bool   `json:"authorization_response_iss_parameter_supported"`
	}
}

// Handler serves the sign-in paths of one site.
type Handler struct {
	o       Options
	core    *core.Core
	origin  string // https://<site host>
	issuers []*issuer
	byID    map[string]*issuer
	byURL   map[string]*issuer
	page    *template.Template
	log     *slog.Logger
}

// New reads each issuer's discovery document and returns the handler. Every issuer must offer PAR (S3).
func New(ctx context.Context, o Options) (*Handler, error) {
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if len(o.Issuers) == 0 {
		return nil, errors.New("signin: at least one issuer")
	}
	h := &Handler{o: o, core: o.Core, origin: "https://" + o.Core.Rules().Host, byID: map[string]*issuer{}, byURL: map[string]*issuer{},
		page: signInPage, log: o.Log}
	for _, is := range o.Issuers {
		if is.ID == "" || h.byID[is.ID] != nil || h.byURL[is.URL] != nil {
			return nil, fmt.Errorf("signin: the issuer %q: an id and an issuer identifier, each once", is.ID)
		}
		p, err := oidc.NewProvider(oidc.ClientContext(ctx, o.HTTP), is.URL)
		if err != nil {
			return nil, fmt.Errorf("signin: discovery of the issuer %s: %w", is.ID, err)
		}
		e := &issuer{Issuer: is, provider: p}
		if err := p.Claims(&e.endpoints); err != nil {
			return nil, err
		}
		if e.endpoints.PAR == "" {
			return nil, fmt.Errorf("signin: the issuer %s offers no pushed authorization request endpoint (S3 needs PAR)", is.ID)
		}
		e.idTokens = p.VerifierContext(oidc.ClientContext(context.Background(), o.HTTP), &oidc.Config{ClientID: is.ClientID})
		e.logouts = p.VerifierContext(oidc.ClientContext(context.Background(), o.HTTP), &oidc.Config{ClientID: is.ClientID})
		h.issuers = append(h.issuers, e)
		h.byID[is.ID], h.byURL[is.URL] = e, e
	}
	return h, nil
}

// Register adds the paths to a mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+core.PathLogin, h.Login)
	mux.HandleFunc("GET "+core.PathSignIn, h.SignInPage)
	mux.HandleFunc("GET "+core.PathCallback, h.Callback)
	mux.HandleFunc("POST "+core.PathLogout, h.Logout)
	mux.HandleFunc("POST "+core.PathBackChannel, h.BackChannel)
	mux.HandleFunc("GET "+core.PathWhoami, h.Whoami)
	mux.HandleFunc("GET "+core.PathJWKS, h.JWKS)
}

func (h *Handler) redirectURL() string { return h.origin + core.PathCallback }

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fail answers the browser with a short page that names no internal detail, and logs the step and the reason word.
func (h *Handler) fail(w http.ResponseWriter, status int, step, reason string) {
	h.log.Info("sign-in path refused", "step", step, "reason", reason, "status", status)
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, http.StatusText(status)+": the sign-in could not be completed. Start again from the site.\n")
}

// safeReturnTo keeps a return address only when it is a path of this site (no open redirect), and never one of session's own.
func safeReturnTo(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n\t") ||
		strings.HasPrefix(s, core.Prefix) || len(s) > 2048 {
		return "/"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return s
}

func hashOf(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}

// postForm sends a form with the client's assertion to an endpoint of the issuer and decodes the JSON answer.
func (h *Handler) postForm(ctx context.Context, is *issuer, endpoint string, v url.Values, out any) (int, error) {
	status, body, err := h.post(ctx, is, endpoint, v)
	if err != nil {
		return status, err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return status, errors.New("an answer that is not JSON")
	}
	return status, nil
}

// post sends a form with the site's client assertion at the issuer to an endpoint of that issuer and returns the status and the
// body. The assertion's audience is that issuer's identifier, so an assertion made for one issuer is no good at another.
func (h *Handler) post(ctx context.Context, is *issuer, endpoint string, v url.Values) (int, []byte, error) {
	a, err := h.o.Signer.ClientAssertion(ctx, is.ClientID, is.URL, time.Now())
	if err != nil {
		return 0, nil, fmt.Errorf("client assertion: %w", err)
	}
	v.Set("client_id", is.ClientID)
	v.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	v.Set("client_assertion", a)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := h.o.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, body, err
}

// Login starts a sign-in at one issuer: ?issuer=<id>, or the only issuer of the site, or the remembered choice. Without one of
// them a site of several issuers sends the browser to the sign-in page. Then a transaction by state that names the issuer, PAR
// at that issuer with the client's assertion, and the browser goes to the issuer with only client_id and request_uri, and gets
// the binding cookie.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	is, ok := h.chosen(r)
	if !ok {
		h.fail(w, http.StatusBadRequest, "login", "issuer")
		return
	}
	if is == nil {
		noStore(w)
		http.Redirect(w, r, core.PathSignIn+"?"+url.Values{"return_to": {returnTo}}.Encode(), http.StatusFound)
		return
	}
	state, nonce, binding, verifier := core.NewID(), core.NewID(), core.NewID(), oauth2.GenerateVerifier()
	tx := &core.SignIn{Issuer: is.ID, Verifier: verifier, Nonce: nonce, ReturnTo: returnTo, BindingHash: hashOf(binding), Started: h.core.Now()}
	if err := h.core.PutSignIn(ctx, state, tx); err != nil {
		h.fail(w, http.StatusServiceUnavailable, "login", "store")
		return
	}
	params := url.Values{
		"response_type":         {"code"},
		"redirect_uri":          {h.redirectURL()},
		"scope":                 {strings.Join(is.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(verifier)},
		"code_challenge_method": {"S256"},
	}
	var par struct {
		RequestURI string `json:"request_uri"`
	}
	status, err := h.postForm(ctx, is, is.endpoints.PAR, params, &par)
	if err != nil || (status != http.StatusCreated && status != http.StatusOK) || par.RequestURI == "" {
		h.fail(w, http.StatusBadGateway, "par", fmt.Sprintf("status %d", status))
		return
	}
	q := url.Values{"client_id": {is.ClientID}, "request_uri": {par.RequestURI}}
	noStore(w)
	w.Header().Add("Set-Cookie", h.core.BindingCookie(binding))
	http.Redirect(w, r, is.provider.Endpoint().AuthURL+"?"+q.Encode(), http.StatusFound)
}

// chosen is the issuer of a sign-in: the one ?issuer= names (ok false when it names none of the site's), else the site's only
// issuer, else the remembered choice when the site remembers it. nil with ok true means the person has to pick.
func (h *Handler) chosen(r *http.Request) (*issuer, bool) {
	if id := r.URL.Query().Get("issuer"); id != "" {
		is := h.byID[id]
		return is, is != nil
	}
	if len(h.issuers) == 1 {
		return h.issuers[0], true
	}
	return h.remembered(r), true
}

// remembered is the issuer of the remembered-choice cookie, when the site remembers the choice and the cookie names one of its
// issuers; else nil.
func (h *Handler) remembered(r *http.Request) *issuer {
	if h.o.Remember <= 0 {
		return nil
	}
	if c, err := r.Cookie(h.core.ChoiceCookieName()); err == nil {
		return h.byID[c.Value]
	}
	return nil
}

// SignInPage is the sign-in page: one link for each issuer, "Sign in with <label>", each to the login path with its issuer and
// the return address. No script, no form, nothing from the issuers. ?issuer=<id> skips the page (CI and the remote runner use
// it), and a site of one issuer has no page: both go to the login path at once.
func (h *Handler) SignInPage(w http.ResponseWriter, r *http.Request) {
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	id := r.URL.Query().Get("issuer")
	if id != "" && h.byID[id] == nil {
		h.fail(w, http.StatusBadRequest, "signin", "issuer")
		return
	}
	if id == "" && len(h.issuers) == 1 {
		id = h.issuers[0].ID
	}
	if id != "" {
		noStore(w)
		http.Redirect(w, r, core.PathLogin+"?"+url.Values{"issuer": {id}, "return_to": {returnTo}}.Encode(), http.StatusFound)
		return
	}
	data := pageData{}
	for _, is := range h.issuers {
		data.Issuers = append(data.Issuers, pageIssuer{Label: is.Label,
			URL: core.PathLogin + "?" + url.Values{"issuer": {is.ID}, "return_to": {returnTo}}.Encode()})
	}
	var b strings.Builder
	if err := h.page.Execute(&b, data); err != nil {
		h.fail(w, http.StatusInternalServerError, "signin", "page")
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", pageCSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.WriteString(w, b.String())
}

type tokenAnswer struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
}

type idClaims struct {
	Nonce    string   `json:"nonce"`
	SID      string   `json:"sid"`
	AZP      string   `json:"azp"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	ACR      string   `json:"acr"`
	AuthTime int64    `json:"auth_time"`
}

// Callback ends a sign-in: it takes the transaction of the state once, checks the binding cookie and iss, redeems the code with
// the verifier and the client's assertion, checks the ID token, and makes a session under a new id.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	tx, err := h.core.TakeSignIn(ctx, q.Get("state"))
	if errors.Is(err, core.ErrNotFound) {
		h.fail(w, http.StatusBadRequest, "callback", "state")
		return
	}
	if err != nil {
		h.fail(w, http.StatusServiceUnavailable, "callback", "store")
		return
	}
	w.Header().Add("Set-Cookie", h.core.ClearBindingCookie())
	// The issuer is the one the person chose at login, kept in the transaction: never one the callback names (decision 0034).
	is := h.byID[tx.Issuer]
	if is == nil {
		h.core.Emit(ctx, core.Event{Kind: core.EventSignInFailed, Reason: "issuer"})
		h.fail(w, http.StatusBadRequest, "callback", "issuer")
		return
	}
	failed := func(status int, reason string) {
		h.core.Emit(ctx, core.Event{Kind: core.EventSignInFailed, Issuer: is.URL, Reason: reason})
		h.fail(w, status, "callback", reason)
	}
	bind := h.core.BindingValue(r.Header)
	if bind == "" || subtle.ConstantTimeCompare([]byte(hashOf(bind)), []byte(tx.BindingHash)) != 1 {
		failed(http.StatusBadRequest, "binding")
		return
	}
	// RFC 9207, the mix-up defence: the issuer that answered is the one the transaction was started with. An issuer that does
	// not send iss is held by the state alone, which names the issuer the code is redeemed at and the ID token verified against.
	if iss := q.Get("iss"); iss != is.URL && (iss != "" || is.endpoints.IssParam) {
		failed(http.StatusBadRequest, "iss")
		return
	}
	if q.Get("error") != "" {
		failed(http.StatusBadRequest, "issuer_error")
		return
	}
	if q.Get("code") == "" {
		failed(http.StatusBadRequest, "code")
		return
	}
	var tok tokenAnswer
	status, err := h.postForm(ctx, is, is.provider.Endpoint().TokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {q.Get("code")},
		"redirect_uri":  {h.redirectURL()},
		"code_verifier": {tx.Verifier},
	}, &tok)
	if err != nil || status != http.StatusOK || tok.IDToken == "" || tok.AccessToken == "" {
		failed(http.StatusBadGateway, "token")
		return
	}
	idt, err := is.idTokens.Verify(ctx, tok.IDToken) // signature, iss, aud, exp: of the chosen issuer
	if err != nil {
		failed(http.StatusBadRequest, "id_token")
		return
	}
	var cl idClaims
	if err := idt.Claims(&cl); err != nil {
		failed(http.StatusBadRequest, "id_token")
		return
	}
	if subtle.ConstantTimeCompare([]byte(cl.Nonce), []byte(tx.Nonce)) != 1 {
		failed(http.StatusBadRequest, "nonce")
		return
	}
	if (len(idt.Audience) > 1 || cl.AZP != "") && cl.AZP != is.ClientID {
		failed(http.StatusBadRequest, "azp")
		return
	}
	rec := &core.Record{
		Subject: idt.Subject, Issuer: idt.Issuer, SID: cl.SID,
		Claims:  core.Claims{Name: cl.Name, Email: cl.Email, Groups: cl.Groups, ACR: cl.ACR, AuthTime: cl.AuthTime},
		IDToken: tok.IDToken, AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken,
	}
	if tok.ExpiresIn > 0 {
		rec.AccessExpiry = time.Now().Unix() + tok.ExpiresIn
	}
	id, err := h.core.Create(ctx, rec, tx.Started)
	if errors.Is(err, core.ErrLoggedOut) {
		failed(http.StatusBadRequest, "logged_out")
		return
	}
	if err != nil {
		h.fail(w, http.StatusServiceUnavailable, "callback", "store")
		return
	}
	// A sign-in completes only after its event is accepted (decision 0008).
	if err := h.core.EmitAccepted(ctx, core.Event{Kind: core.EventSignIn, Subject: rec.Subject, Issuer: rec.Issuer}); err != nil {
		_ = h.core.Delete(ctx, id)
		h.fail(w, http.StatusServiceUnavailable, "callback", "audit")
		return
	}
	noStore(w)
	w.Header().Add("Set-Cookie", h.core.SessionCookie(id))
	if h.o.Remember > 0 && len(h.issuers) > 1 {
		w.Header().Add("Set-Cookie", h.core.ChoiceCookie(is.ID, h.o.Remember))
	}
	// The address was checked at login and kept server-side; it is checked again here.
	http.Redirect(w, r, safeReturnTo(tx.ReturnTo), http.StatusFound) //nolint:gosec // G710: a path of this site only (safeReturnTo)
}

// Logout is the person's own logout (S6, decision 0031): a POST with CSRF, which deletes the session, revokes its refresh
// token at the issuer (best effort), clears session's cookies and sends the browser to the issuer's end-session, also when
// there is no live session, so that "sign out" always ends the issuer's session. id_token_hint goes with it when the session
// is live (without it Keycloak asks the person to confirm, a finding of the reference stand). A request that asks for JSON
// (the browser helper's fetch, which cannot follow a cross-origin redirect) gets {"logout_url"} with 200; any other gets a
// 303 to the same address.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !h.core.CSRFOK(r.Method, r.Header) {
		h.core.Emit(ctx, core.Event{Kind: core.EventDenied, Route: core.PathLogout, Reason: "csrf"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf"})
		return
	}
	id, _ := h.core.SplitCookies(r.Header)
	var hint, refresh string
	// The end-session is the session's own issuer's (decision 0034). Without a live session it is the site's only issuer, or
	// the remembered choice; a site of several issuers that remembers nothing sends the browser back to the site.
	is, _ := h.chosen(&http.Request{URL: &url.URL{}, Header: r.Header})
	if id != "" {
		s, err := h.core.Load(ctx, id)
		switch {
		case err == nil:
			if err := h.core.Delete(ctx, id); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
				return
			}
			h.core.Emit(ctx, core.Event{Kind: core.EventLogout, Subject: s.Subject, Issuer: s.Issuer})
			if is = h.byURL[s.Issuer]; is != nil {
				hint, refresh = s.IDToken, s.RefreshToken
			}
		case errors.Is(err, core.ErrNotFound):
		default:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
			return
		}
	}
	if refresh != "" {
		h.revoke(ctx, is, refresh)
	}
	target := h.origin + "/"
	if is != nil && is.endpoints.EndSession != "" {
		q := url.Values{"client_id": {is.ClientID}, "post_logout_redirect_uri": {h.origin + "/"}}
		if hint != "" {
			q.Set("id_token_hint", hint)
		}
		target = is.endpoints.EndSession + "?" + q.Encode()
	}
	w.Header().Add("Set-Cookie", h.core.ClearSessionCookie())
	w.Header().Add("Set-Cookie", h.core.ClearBindingCookie())
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, map[string]string{"logout_url": target})
		return
	}
	noStore(w)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// revoke revokes a refresh token at the issuer's revocation endpoint (RFC 7009) with the client's assertion, best effort and
// bounded by the exchange timeout (decision 0031): only when the issuer names the endpoint; a failure is counted and logged,
// and the logout goes on, because the session is already deleted.
func (h *Handler) revoke(ctx context.Context, is *issuer, token string) {
	if is.endpoints.Revocation == "" {
		return
	}
	bound := h.core.Rules().ExchangeTimeout
	if bound <= 0 {
		bound = core.DefaultExchangeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	status, _, err := h.post(ctx, is, is.endpoints.Revocation, url.Values{"token": {token}, "token_type_hint": {"refresh_token"}})
	if err == nil && status == http.StatusOK {
		return
	}
	h.core.Metrics().CountRevocationFailed()
	if err != nil {
		h.log.Info("logout: the refresh token could not be revoked", "error", err.Error())
		return
	}
	h.log.Info("logout: the issuer refused to revoke the refresh token", "status", status)
}

const backChannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// BackChannel receives a logout token from the issuer (OIDC Back-Channel Logout 1.0, section 2.6) and ends the sessions of its
// sid, or of its subject when it has no sid, on every replica (decision 0010). A replayed jti is refused.
func (h *Handler) BackChannel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	var is *issuer
	refuse := func(reason string) {
		ev := core.Event{Kind: core.EventBackChannelLogout, Reason: reason}
		if is != nil {
			ev.Issuer = is.URL
		}
		h.core.Emit(ctx, ev)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
	}
	raw := r.PostForm.Get("logout_token")
	if raw == "" {
		refuse("no_token")
		return
	}
	if typ, ok := jwtType(raw); ok && typ != "" && typ != "logout+jwt" && typ != "JWT" {
		refuse("typ")
		return
	}
	// The token is verified by the issuer its iss names, among the site's only, with that issuer's keys and the site's client at
	// it as aud; its sid or subject then ends only that issuer's sessions, whose index entries are keyed by issuer (decision 0034).
	if is = h.byURL[unverifiedIssuer(raw)]; is == nil {
		refuse("issuer")
		return
	}
	tok, err := is.logouts.Verify(ctx, raw) // signature, iss, aud, exp
	if err != nil {
		refuse("token")
		return
	}
	var cl struct {
		Events map[string]json.RawMessage `json:"events"`
		SID    string                     `json:"sid"`
		Nonce  *string                    `json:"nonce"`
		JTI    string                     `json:"jti"`
		IAT    int64                      `json:"iat"`
	}
	if err := tok.Claims(&cl); err != nil {
		refuse("claims")
		return
	}
	ev, ok := cl.Events[backChannelEvent]
	if !ok || !json.Valid(ev) || !strings.HasPrefix(strings.TrimSpace(string(ev)), "{") || cl.Nonce != nil ||
		(cl.SID == "" && tok.Subject == "") || cl.JTI == "" || cl.IAT == 0 {
		refuse("claims")
		return
	}
	until := tok.Expiry
	if until.IsZero() || until.Before(h.core.Now()) {
		until = h.core.Now().Add(10 * time.Minute)
	}
	fresh, err := h.core.ClaimOnce(ctx, tok.Issuer+"\x00"+cl.JTI, until.Add(time.Minute))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	if !fresh {
		refuse("replay")
		return
	}
	if _, err := h.core.LogoutBy(ctx, tok.Issuer, cl.SID, tok.Subject); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	h.core.Emit(ctx, core.Event{Kind: core.EventBackChannelLogout, Subject: tok.Subject, Issuer: tok.Issuer})
	noStore(w)
	w.WriteHeader(http.StatusOK)
}

// unverifiedIssuer reads the iss of a compact JWS's payload without trusting it: it picks the issuer whose keys then verify it.
func unverifiedIssuer(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var cl struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(b, &cl) != nil {
		return ""
	}
	return cl.Iss
}

// jwtType reads the typ of a compact JWS header without trusting it.
func jwtType(raw string) (string, bool) {
	sig, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA})
	if err != nil || len(sig.Signatures) != 1 {
		return "", false
	}
	t, _ := sig.Signatures[0].Protected.ExtraHeaders["typ"].(string)
	return t, true
}

// Whoami answers the person's issuer id (idp, decision 0035), subject, name, groups and when the session ends. It reads the session itself, from the cookie:
// the paths of session are routed without a check.
func (h *Handler) Whoami(w http.ResponseWriter, r *http.Request) {
	id, _ := h.core.SplitCookies(r.Header)
	s, err := h.core.Load(r.Context(), id)
	if errors.Is(err, core.ErrNotFound) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "login_url": core.LoginURL("/")})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
		return
	}
	ends := s.Expires
	if idle := s.IdleExpires(h.core.Rules().Idle); idle.Before(ends) {
		ends = idle
	}
	groups := s.Claims.Groups
	if groups == nil {
		groups = []string{}
	}
	// idp is the site's id of the session's issuer (decision 0035): a person is idp and sub.
	idp := ""
	if is := h.byURL[s.Issuer]; is != nil {
		idp = is.ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"idp": idp, "sub": s.Subject, "name": s.Claims.Name, "email": s.Claims.Email,
		"groups": groups, "expires_at": ends.UTC().Format(time.RFC3339)})
}

// JWKS publishes the service's public keys, the token block's key set: the key of the client assertion, which the issuer
// reads, and the key of the identity header, which apps read. Each has its own kid; an app tells its key by the kid of the
// header it verifies.
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	purposes := []string{h.o.Signer.Purpose}
	if h.o.Identity != nil {
		purposes = append(purposes, h.o.Identity.Purpose)
	}
	res, err := h.o.Signer.Tokens.KeySet(r.Context(), connect.NewRequest(&tokenv1.KeySetRequest{Purposes: purposes}))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
		return
	}
	w.Header().Set("Cache-Control", "max-age=300")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(append(res.Msg.GetJwksJson(), '\n'))
}
