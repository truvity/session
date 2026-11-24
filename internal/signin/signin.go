// Package signin is the sign-in handler: the paths under /_session/ (decision 0004). Login with authorisation code, PKCE, PAR and
// private_key_jwt (S3); the callback with the binding cookie, state, iss (RFC 9207) and ID token checks; logout as a POST with
// CSRF, then the issuer's end-session (S6); back-channel logout (OIDC Back-Channel Logout 1.0); whoami; jwks.
//
// It never logs a header value, a cookie, a token, a code or a body, and never shows the issuer's error text to the browser.
package signin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/truvity/session/core"
)

// Options configure the handler.
type Options struct {
	Core     *core.Core
	Issuer   string
	ClientID string
	Scopes   []string
	Signer   Signer
	// Identity is the signer of the identity header, whose public key /_session/jwks publishes too; nil publishes the client
	// key alone.
	Identity *Signer
	// HTTP is the client for the issuer's endpoints; nil is a client with a 10 s timeout.
	HTTP *http.Client
	// Log is the operational log; nil is slog.Default().
	Log *slog.Logger
}

// Handler serves the sign-in paths of one site.
type Handler struct {
	o         Options
	core      *core.Core
	origin    string // https://<site host>
	provider  *oidc.Provider
	idTokens  *oidc.IDTokenVerifier
	logouts   *oidc.IDTokenVerifier
	endpoints struct {
		PAR        string `json:"pushed_authorization_request_endpoint"`
		EndSession string `json:"end_session_endpoint"`
		IssParam   bool   `json:"authorization_response_iss_parameter_supported"`
	}
	log *slog.Logger
}

// New reads the issuer's discovery document and returns the handler. The issuer must offer PAR (S3).
func New(ctx context.Context, o Options) (*Handler, error) {
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, o.HTTP), o.Issuer)
	if err != nil {
		return nil, fmt.Errorf("signin: discovery of the issuer: %w", err)
	}
	h := &Handler{o: o, core: o.Core, origin: "https://" + o.Core.Rules().Host, provider: p, log: o.Log}
	if err := p.Claims(&h.endpoints); err != nil {
		return nil, err
	}
	if h.endpoints.PAR == "" {
		return nil, errors.New("signin: the issuer offers no pushed authorization request endpoint (S3 needs PAR)")
	}
	h.idTokens = p.VerifierContext(oidc.ClientContext(context.Background(), o.HTTP), &oidc.Config{ClientID: o.ClientID})
	h.logouts = p.VerifierContext(oidc.ClientContext(context.Background(), o.HTTP), &oidc.Config{ClientID: o.ClientID})
	return h, nil
}

// Register adds the paths to a mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+core.PathLogin, h.Login)
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
func (h *Handler) postForm(ctx context.Context, endpoint string, v url.Values, out any) (int, error) {
	a, err := h.o.Signer.ClientAssertion(ctx, h.o.ClientID, h.o.Issuer, time.Now())
	if err != nil {
		return 0, fmt.Errorf("client assertion: %w", err)
	}
	v.Set("client_id", h.o.ClientID)
	v.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	v.Set("client_assertion", a)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := h.o.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return res.StatusCode, err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return res.StatusCode, errors.New("an answer that is not JSON")
	}
	return res.StatusCode, nil
}

// Login starts a sign-in: a transaction by state, PAR with the client's assertion, then the browser goes to the issuer with
// only client_id and request_uri, and gets the binding cookie.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	state, nonce, binding, verifier := core.NewID(), core.NewID(), core.NewID(), oauth2.GenerateVerifier()
	tx := &core.SignIn{Verifier: verifier, Nonce: nonce, ReturnTo: returnTo, BindingHash: hashOf(binding), Started: h.core.Now()}
	if err := h.core.PutSignIn(ctx, state, tx); err != nil {
		h.fail(w, http.StatusServiceUnavailable, "login", "store")
		return
	}
	params := url.Values{
		"response_type":         {"code"},
		"redirect_uri":          {h.redirectURL()},
		"scope":                 {strings.Join(h.o.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(verifier)},
		"code_challenge_method": {"S256"},
	}
	var par struct {
		RequestURI string `json:"request_uri"`
	}
	status, err := h.postForm(ctx, h.endpoints.PAR, params, &par)
	if err != nil || (status != http.StatusCreated && status != http.StatusOK) || par.RequestURI == "" {
		h.fail(w, http.StatusBadGateway, "par", fmt.Sprintf("status %d", status))
		return
	}
	q := url.Values{"client_id": {h.o.ClientID}, "request_uri": {par.RequestURI}}
	noStore(w)
	w.Header().Add("Set-Cookie", h.core.BindingCookie(binding))
	http.Redirect(w, r, h.provider.Endpoint().AuthURL+"?"+q.Encode(), http.StatusFound)
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
	failed := func(status int, reason string) {
		h.core.Emit(ctx, core.Event{Kind: core.EventSignInFailed, Issuer: h.o.Issuer, Reason: reason})
		h.fail(w, status, "callback", reason)
	}
	bind := h.core.BindingValue(r.Header)
	if bind == "" || subtle.ConstantTimeCompare([]byte(hashOf(bind)), []byte(tx.BindingHash)) != 1 {
		failed(http.StatusBadRequest, "binding")
		return
	}
	// RFC 9207: the issuer that answered is the one the transaction was started with.
	if iss := q.Get("iss"); iss != h.o.Issuer && (iss != "" || h.endpoints.IssParam) {
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
	status, err := h.postForm(ctx, h.provider.Endpoint().TokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {q.Get("code")},
		"redirect_uri":  {h.redirectURL()},
		"code_verifier": {tx.Verifier},
	}, &tok)
	if err != nil || status != http.StatusOK || tok.IDToken == "" || tok.AccessToken == "" {
		failed(http.StatusBadGateway, "token")
		return
	}
	idt, err := h.idTokens.Verify(ctx, tok.IDToken) // signature, iss, aud, exp
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
	if (len(idt.Audience) > 1 || cl.AZP != "") && cl.AZP != h.o.ClientID {
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
	// The address was checked at login and kept server-side; it is checked again here.
	http.Redirect(w, r, safeReturnTo(tx.ReturnTo), http.StatusFound) //nolint:gosec // G710: a path of this site only (safeReturnTo)
}

// Logout is the person's own logout (S6): a POST with CSRF, which deletes the session, clears the cookie and sends the browser
// to the issuer's end-session with id_token_hint (without it Keycloak asks the person to confirm, a finding of the reference
// stand). A request that asks for JSON (the browser helper's fetch, which cannot follow a cross-origin redirect) gets
// {"logout_url"} with 200; any other gets a 303 to the same address.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !h.core.CSRFOK(r.Method, r.Header) {
		h.core.Emit(ctx, core.Event{Kind: core.EventDenied, Route: core.PathLogout, Reason: "csrf"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf"})
		return
	}
	id, _ := h.core.SplitCookies(r.Header)
	target := h.origin + "/"
	if id != "" {
		s, err := h.core.Load(ctx, id)
		switch {
		case err == nil:
			if err := h.core.Delete(ctx, id); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
				return
			}
			h.core.Emit(ctx, core.Event{Kind: core.EventLogout, Subject: s.Subject, Issuer: s.Issuer})
			if h.endpoints.EndSession != "" {
				q := url.Values{"client_id": {h.o.ClientID}, "post_logout_redirect_uri": {h.origin + "/"}}
				if s.IDToken != "" {
					q.Set("id_token_hint", s.IDToken)
				}
				target = h.endpoints.EndSession + "?" + q.Encode()
			}
		case errors.Is(err, core.ErrNotFound):
		default:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
			return
		}
	}
	w.Header().Add("Set-Cookie", h.core.ClearSessionCookie())
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, map[string]string{"logout_url": target})
		return
	}
	noStore(w)
	http.Redirect(w, r, target, http.StatusSeeOther)
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
	refuse := func(reason string) {
		h.core.Emit(ctx, core.Event{Kind: core.EventBackChannelLogout, Issuer: h.o.Issuer, Reason: reason})
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
	tok, err := h.logouts.Verify(ctx, raw) // signature, iss, aud, exp
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

// jwtType reads the typ of a compact JWS header without trusting it.
func jwtType(raw string) (string, bool) {
	sig, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA})
	if err != nil || len(sig.Signatures) != 1 {
		return "", false
	}
	t, _ := sig.Signatures[0].Protected.ExtraHeaders["typ"].(string)
	return t, true
}

// Whoami answers the person's subject, name, groups and when the session ends. It reads the session itself, from the cookie:
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
	writeJSON(w, http.StatusOK, map[string]any{"sub": s.Subject, "name": s.Claims.Name, "email": s.Claims.Email,
		"groups": groups, "expires_at": ends.UTC().Format(time.RFC3339)})
}

// JWKS publishes the service's public keys: the key of the client assertion, which the issuer reads, and the key of the
// identity header, which apps read. Each has its own kid; an app tells its key by the kid of the header it verifies.
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	signers := []Signer{h.o.Signer}
	if h.o.Identity != nil {
		signers = append(signers, *h.o.Identity)
	}
	var set jose.JSONWebKeySet
	for _, s := range signers {
		k, err := s.JWK(r.Context())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
			return
		}
		set.Keys = append(set.Keys, k)
	}
	w.Header().Set("Cache-Control", "max-age=300")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}
