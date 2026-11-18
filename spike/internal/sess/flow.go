package sess

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// Flow is the sign-in handler: code + PKCE, PAR, private_key_jwt, ID token checks.
type Flow struct {
	Core        *Core
	Issuer      string
	ClientID    string
	RedirectURL string // https? no: the spike runs on http://127.0.0.1
	Key         *ecdsa.PrivateKey
	KeyID       string
	UsePAR      bool
	UseAssert   bool // private_key_jwt; else public client (not used by the realm)
	Provider    *oidc.Provider
	Verifier    *oidc.IDTokenVerifier
	LogoutVer   *oidc.IDTokenVerifier
	HTTP        *http.Client
	endpoints   struct {
		PAR      string `json:"pushed_authorization_request_endpoint"`
		IssParam bool   `json:"authorization_response_iss_parameter_supported"`
	}
	BindCookie string
}

func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	return x509.ParseECPrivateKey(blk.Bytes)
}

func NewFlow(ctx context.Context, core *Core, issuer, clientID, redirect string, key *ecdsa.PrivateKey) (*Flow, error) {
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	f := &Flow{Core: core, Issuer: issuer, ClientID: clientID, RedirectURL: redirect, Key: key, KeyID: "spike-1",
		UsePAR: true, UseAssert: true, Provider: p, HTTP: &http.Client{Timeout: 10 * time.Second},
		BindCookie: core.CookieName + "-tx"}
	if err := p.Claims(&f.endpoints); err != nil {
		return nil, err
	}
	f.Verifier = p.Verifier(&oidc.Config{ClientID: clientID})
	f.LogoutVer = p.Verifier(&oidc.Config{ClientID: clientID})
	return f, nil
}

func (f *Flow) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /_session/login", f.Login)
	mux.HandleFunc("GET /_session/callback", f.Callback)
	mux.HandleFunc("POST /_session/logout", f.Logout)
	mux.HandleFunc("POST /_session/backchannel-logout", f.BackChannel)
	mux.HandleFunc("GET /_session/whoami", f.Whoami)
}

func rnd() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// assertion builds a private_key_jwt client assertion for the token or PAR endpoint.
func (f *Flow) assertion() (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: f.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", f.KeyID))
	if err != nil {
		return "", err
	}
	now := time.Now()
	return jwt.Signed(sig).Claims(jwt.Claims{Issuer: f.ClientID, Subject: f.ClientID, Audience: jwt.Audience{f.Issuer},
		ID: rnd(), IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(60 * time.Second))}).Serialize()
}

func (f *Flow) clientAuth(v url.Values) error {
	v.Set("client_id", f.ClientID)
	a, err := f.assertion()
	if err != nil {
		return err
	}
	v.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	v.Set("client_assertion", a)
	return nil
}

func (f *Flow) Login(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	// open redirect: a relative path of the same site only
	if returnTo == "" || !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") || strings.Contains(returnTo, `\`) {
		returnTo = "/"
	}
	state, nonce, verifier, bind := rnd(), rnd(), oauth2.GenerateVerifier(), rnd()
	if err := f.Core.Store.PutTx(r.Context(), state, Tx{Verifier: verifier, Nonce: nonce, ReturnTo: returnTo, BindHash: hashOf(bind)}); err != nil {
		http.Error(w, "store", 503)
		return
	}
	params := url.Values{
		"response_type": {"code"}, "redirect_uri": {f.RedirectURL}, "scope": {"openid profile email"},
		"state": {state}, "nonce": {nonce},
		"code_challenge": {oauth2.S256ChallengeFromVerifier(verifier)}, "code_challenge_method": {"S256"},
	}
	var target string
	if f.UsePAR {
		if err := f.clientAuth(params); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		resp, err := f.HTTP.PostForm(f.endpoints.PAR, params)
		if err != nil {
			http.Error(w, "par: "+err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var pr struct {
			RequestURI string `json:"request_uri"`
			Error      string `json:"error"`
			Desc       string `json:"error_description"`
		}
		json.Unmarshal(body, &pr)
		if resp.StatusCode != 201 && resp.StatusCode != 200 || pr.RequestURI == "" {
			http.Error(w, fmt.Sprintf("par refused: %d %s", resp.StatusCode, body), 502)
			return
		}
		q := url.Values{"client_id": {f.ClientID}, "request_uri": {pr.RequestURI}}
		target = f.Provider.Endpoint().AuthURL + "?" + q.Encode()
	} else {
		params.Set("client_id", f.ClientID)
		target = f.Provider.Endpoint().AuthURL + "?" + params.Encode()
	}
	http.SetCookie(w, &http.Cookie{Name: f.BindCookie, Value: bind, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, target, http.StatusFound)
}

func (f *Flow) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, "issuer error: "+e, 400)
		return
	}
	tx, err := f.Core.Store.TakeTx(r.Context(), q.Get("state"))
	if err != nil {
		http.Error(w, "unknown state", 400)
		return
	}
	bc, err := r.Cookie(f.BindCookie)
	if err != nil || hashOf(bc.Value) != tx.BindHash {
		http.Error(w, "binding cookie mismatch", 400)
		return
	}
	// RFC 9207 iss parameter
	if f.endpoints.IssParam && q.Get("iss") != f.Issuer {
		http.Error(w, "iss mismatch", 400)
		return
	}
	v := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {f.RedirectURL}, "code_verifier": {tx.Verifier}}
	if err := f.clientAuth(v); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	resp, err := f.HTTP.PostForm(f.Provider.Endpoint().TokenURL, v)
	if err != nil {
		http.Error(w, "token: "+err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Error        string `json:"error"`
		Desc         string `json:"error_description"`
	}
	json.Unmarshal(body, &tr)
	if resp.StatusCode != 200 || tr.IDToken == "" {
		http.Error(w, fmt.Sprintf("token refused: %d %s", resp.StatusCode, body), 502)
		return
	}
	idt, err := f.Verifier.Verify(r.Context(), tr.IDToken)
	if err != nil {
		http.Error(w, "id token: "+err.Error(), 400)
		return
	}
	var cl struct {
		Nonce  string   `json:"nonce"`
		Sid    string   `json:"sid"`
		Azp    string   `json:"azp"`
		Email  string   `json:"email"`
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}
	idt.Claims(&cl)
	if cl.Nonce != tx.Nonce {
		http.Error(w, "nonce mismatch", 400)
		return
	}
	id := NewID() // new id at sign-in: no fixation
	rec := &Record{Sub: idt.Subject, Iss: idt.Issuer, Sid: cl.Sid, Email: cl.Email, Name: cl.Name, Groups: cl.Groups,
		IDToken: tr.IDToken, AccessToken: tr.AccessToken, RefreshToken: tr.RefreshToken, AccessExp: time.Now().Unix() + tr.ExpiresIn}
	// A logout that raced the sign-in: refuse a session older than a tombstone.
	if err := f.Core.Store.Create(r.Context(), id, rec); err != nil {
		http.Error(w, "store", 503)
		return
	}
	if f.Core.Tombstones {
		if _, err := f.Core.Store.Get(r.Context(), id, true); err != nil {
			http.Error(w, "signed out already", 400)
			return
		}
	}
	w.Header().Add("Set-Cookie", f.Core.ClearCookie(f.BindCookie))
	w.Header().Add("Set-Cookie", f.Core.SessionCookie(id))
	http.Redirect(w, r, tx.ReturnTo, http.StatusFound)
}

// Whoami is called through the proxy with the check in front, so the identity headers are set.
func (f *Flow) Whoami(w http.ResponseWriter, r *http.Request) {
	id, _ := f.Core.cookieID(r.Header)
	l, err := f.Core.Store.Get(r.Context(), id, f.Core.Tombstones)
	if err != nil {
		http.Error(w, `{"error":"login_required"}`, 401)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"sub": l.Rec.Sub, "name": l.Rec.Name, "groups": l.Rec.Groups, "expires": l.Expires})
}

func (f *Flow) csrfOK(r *http.Request) bool {
	if r.Header.Get("X-Requested-With") != "session" {
		return false
	}
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host != r.Host {
			return false
		}
	}
	return true
}

func (f *Flow) Logout(w http.ResponseWriter, r *http.Request) {
	if !f.csrfOK(r) {
		http.Error(w, "csrf", 403)
		return
	}
	id, _ := f.Core.cookieID(r.Header)
	loc := "/"
	if id != "" {
		if l, err := f.Core.Store.Get(r.Context(), id, false); err == nil {
			q := url.Values{"id_token_hint": {l.Rec.IDToken}, "client_id": {f.ClientID}, "post_logout_redirect_uri": {strings.TrimSuffix(f.RedirectURL, "/_session/callback") + "/"}}
			loc = f.Provider.Endpoint().AuthURL[:strings.LastIndex(f.Provider.Endpoint().AuthURL, "/auth")] + "/logout?" + q.Encode()
		}
		f.Core.Store.Delete(r.Context(), id)
	}
	w.Header().Add("Set-Cookie", f.Core.ClearCookie(f.Core.CookieName))
	http.Redirect(w, r, loc, http.StatusFound)
}

// BackChannel is OIDC Back-Channel Logout 1.0 (receiver side).
func (f *Flow) BackChannel(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	raw := r.PostForm.Get("logout_token")
	// Verify signature, iss, aud, exp with go-oidc; then the logout-specific claims.
	tok, err := f.LogoutVer.Verify(r.Context(), raw)
	if err != nil {
		http.Error(w, "logout token: "+err.Error(), 400)
		return
	}
	var cl struct {
		Events map[string]json.RawMessage `json:"events"`
		Sid    string                     `json:"sid"`
		Nonce  string                     `json:"nonce"`
		Jti    string                     `json:"jti"`
	}
	tok.Claims(&cl)
	if _, ok := cl.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok || cl.Nonce != "" || (cl.Sid == "" && tok.Subject == "") || cl.Jti == "" {
		http.Error(w, "not a logout token", 400)
		return
	}
	fresh, err := f.Core.Store.ClaimJTI(r.Context(), cl.Jti, tok.Expiry)
	if err != nil {
		http.Error(w, "store", 503)
		return
	}
	if !fresh {
		http.Error(w, "replay", 400)
		return
	}
	if f.Core.Tombstones {
		if err := f.Core.Store.PutTombstones(r.Context(), tok.Issuer, cl.Sid, tok.Subject); err != nil {
			http.Error(w, "store", 503)
			return
		}
	}
	nDel, err := f.Core.Store.DeleteByIndex(r.Context(), tok.Issuer, cl.Sid, tok.Subject)
	if err != nil {
		http.Error(w, "store", 503)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, "deleted %d\n", nDel)
}
