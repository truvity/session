package signin_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/sealer/sealertest"
	"github.com/truvity/session/internal/signin"
	"github.com/truvity/session/internal/storetest"
)

// issuersSite is a site of the issuers given, each a fake issuer (decision 0034): the first is corp, the second partner. The
// sign-in with Keycloak's form, and the mix-up refused there, are in the conformance suite.
type issuersSite struct {
	core    *core.Core
	handler *signin.Handler
	fakes   []*fakeIssuer
	audit   *events
}

var issuerIDs = []string{"corp", "partner"}

func newIssuersSite(t *testing.T, remember time.Duration, fakes ...*fakeIssuer) *issuersSite {
	t.Helper()
	mem := storetest.New(nil)
	items, stop := mem.Client()
	t.Cleanup(stop)
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0o700); err != nil { //nolint:gosec // G302: the key driver wants its state directory private
		t.Fatal(err)
	}
	keys, err := atoomx.OpenKeys(atoomx.KeyOptions{Purposes: signin.Purposes(), StateDir: keyDir, AliasPrefix: "session/docs"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Stop)
	blocks, err := sealertest.Tokens(t, keys, signin.TokenPurposes())
	if err != nil {
		t.Fatal(err)
	}
	signer, identity, err := signin.Signers(blocks.Tokens)
	if err != nil {
		t.Fatal(err)
	}
	var urls []core.SiteIssuer
	var issuers []signin.Issuer
	for i, f := range fakes {
		urls = append(urls, core.SiteIssuer{ID: issuerIDs[i], Identifier: f.srv.URL})
		issuers = append(issuers, signin.Issuer{ID: issuerIDs[i], Label: []string{"Example <Corp> & Co", "Example Partner"}[i],
			URL: f.srv.URL, ClientID: "session-" + issuerIDs[i], Scopes: []string{"openid", issuerIDs[i]}})
	}
	ev := &events{}
	c, err := core.New(core.Options{Items: items, Seal: blocks.Sealer, Audit: ev, Rules: core.Rules{Site: "docs", Host: "docs.example.test",
		Issuers: urls, Routes: []core.Route{{Prefix: "/", Mode: core.ModeSession}}}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := signin.New(context.Background(), signin.Options{Core: c, Issuers: issuers, Remember: remember, Signer: signer, Identity: &identity})
	if err != nil {
		t.Fatal(err)
	}
	return &issuersSite{core: c, handler: h, fakes: fakes, audit: ev}
}

func twoFakes(t *testing.T) []*fakeIssuer {
	return []*fakeIssuer{newFakeIssuer(t, true, http.StatusOK), newFakeIssuer(t, true, http.StatusOK)}
}

// get sends a GET through the handler's own paths, with the cookies given as NAME=VALUE.
func (s *issuersSite) get(path string, cookies ...string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	s.handler.Register(mux)
	r := httptest.NewRequest(http.MethodGet, "https://docs.example.test"+path, nil)
	for _, c := range cookies {
		r.Header.Add("Cookie", c)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// assertionAudience reads the aud of the client assertion of a request to the issuer, without verifying it.
func assertionAudience(t *testing.T, form url.Values) string {
	t.Helper()
	parts := strings.Split(form.Get("client_assertion"), ".")
	if len(parts) != 3 {
		t.Fatalf("client assertion %q", form.Get("client_assertion"))
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var cl struct {
		Aud string `json:"aud"`
	}
	if err := json.Unmarshal(b, &cl); err != nil {
		t.Fatal(err)
	}
	return cl.Aud
}

func TestTheSignInPageHasALinkForEachIssuerAndNoScript(t *testing.T) {
	s := newIssuersSite(t, 0, twoFakes(t)...)
	w := s.get(core.PathSignIn + "?return_to=%2Fapp%3Fx%3D1")
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	for _, want := range []string{
		`<a href="/_session/login?issuer=corp&amp;return_to=%2Fapp%3Fx%3D1">Sign in with Example &lt;Corp&gt; &amp; Co</a>`,
		`<a href="/_session/login?issuer=partner&amp;return_to=%2Fapp%3Fx%3D1">Sign in with Example Partner</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("no %s in\n%s", want, body)
		}
	}
	if strings.Contains(strings.ToLower(body), "<script") || strings.Contains(strings.ToLower(body), "<form") {
		t.Fatalf("a script or a form:\n%s", body)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
		t.Fatalf("CSP %q", csp)
	}
	// A return address that is not a path of the site becomes /.
	if w := s.get(core.PathSignIn + "?return_to=https%3A%2F%2Fevil.example.test%2F"); !strings.Contains(w.Body.String(), "return_to=%2F\"") {
		t.Fatalf("an open redirect:\n%s", w.Body.String())
	}
}

func TestIssuerSkipsTheSignInPageAndAnUnknownOneIsRefused(t *testing.T) {
	s := newIssuersSite(t, 0, twoFakes(t)...)
	w := s.get(core.PathSignIn + "?issuer=partner&return_to=%2Fapp")
	if w.Code != http.StatusFound || w.Header().Get("Location") != core.PathLogin+"?issuer=partner&return_to=%2Fapp" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
	for _, p := range []string{core.PathSignIn + "?issuer=nobody", core.PathLogin + "?issuer=nobody"} {
		if w := s.get(p); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
}

// A login that names no issuer, on a site of several, goes to the page with its return address; one that names an issuer runs
// PAR at that issuer only, as the site's client there, with an assertion for that issuer.
func TestTheLoginGoesToTheChosenIssuerOnly(t *testing.T) {
	s := newIssuersSite(t, 0, twoFakes(t)...)
	w := s.get(core.PathLogin + "?return_to=%2Fx")
	if w.Code != http.StatusFound || w.Header().Get("Location") != core.PathSignIn+"?return_to=%2Fx" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
	w = s.get(core.PathLogin + "?issuer=partner&return_to=%2Fx")
	partner := s.fakes[1]
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), partner.srv.URL+"/auth?") ||
		!strings.Contains(w.Header().Get("Location"), "client_id=session-partner") {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
	partner.mu.Lock()
	pars := append([]url.Values(nil), partner.pars...)
	partner.mu.Unlock()
	if len(pars) != 1 || pars[0].Get("client_id") != "session-partner" || pars[0].Get("scope") != "openid partner" ||
		assertionAudience(t, pars[0]) != partner.srv.URL {
		t.Fatalf("PAR at the partner: %v", pars)
	}
	if n := len(s.fakes[0].pars); n != 0 {
		t.Fatalf("PAR at the other issuer: %d", n)
	}
}

// The remembered choice (signin.remember_choice): set at the callback only on a site that remembers it, and then a login that
// names no issuer goes to the remembered one; a site that does not remember ignores the cookie, and so does one that names an
// issuer the site does not have.
func TestTheRememberedChoice(t *testing.T) {
	s := newIssuersSite(t, time.Hour, twoFakes(t)...)
	choice := s.core.ChoiceCookieName() + "=partner"
	if w := s.get(core.PathLogin+"?return_to=%2Fx", choice); w.Code != http.StatusFound ||
		!strings.HasPrefix(w.Header().Get("Location"), s.fakes[1].srv.URL+"/auth?") {
		t.Fatalf("remembered: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := s.get(core.PathLogin+"?return_to=%2Fx", s.core.ChoiceCookieName()+"=nobody"); w.Header().Get("Location") != core.PathSignIn+"?return_to=%2Fx" {
		t.Fatalf("an unknown remembered issuer: %s", w.Header().Get("Location"))
	}
	// The page itself always shows every issuer, so a person can pick another.
	if w := s.get(core.PathSignIn+"?return_to=%2Fx", choice); w.Code != http.StatusOK {
		t.Fatalf("the page with a remembered choice: %d", w.Code)
	}
	off := newIssuersSite(t, 0, twoFakes(t)...)
	if w := off.get(core.PathLogin+"?return_to=%2Fx", off.core.ChoiceCookieName()+"=partner"); w.Header().Get("Location") != core.PathSignIn+"?return_to=%2Fx" {
		t.Fatalf("a site that does not remember: %s", w.Header().Get("Location"))
	}
	// The cookie is session's own: the upstream never sees it.
	if _, rest := s.core.SplitCookies(http.Header{"Cookie": {choice + "; theme=dark"}}); rest != "theme=dark" {
		t.Fatalf("the upstream sees %q", rest)
	}
	if got := s.core.ChoiceCookie("partner", time.Hour); !strings.Contains(got, "Max-Age=3600") || !strings.Contains(got, "Secure") ||
		!strings.Contains(got, "HttpOnly") || !strings.HasPrefix(got, "__Host-docs-issuer=partner") {
		t.Fatalf("the cookie %s", got)
	}
}

func TestASiteOfOneIssuerHasNoPage(t *testing.T) {
	s := newIssuersSite(t, 0, newFakeIssuer(t, true, http.StatusOK))
	if w := s.get(core.PathSignIn + "?return_to=%2Fx"); w.Code != http.StatusFound || w.Header().Get("Location") != core.PathLogin+"?issuer=corp&return_to=%2Fx" {
		t.Fatalf("the page: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := s.get(core.PathLogin + "?return_to=%2Fx"); w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), s.fakes[0].srv.URL+"/auth?") {
		t.Fatalf("the login: %d %s", w.Code, w.Header().Get("Location"))
	}
}

// logout posts the logout with the CSRF headers and the cookies given, and returns the address the browser is sent to.
func (s *issuersSite) logout(t *testing.T, cookies ...string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://docs.example.test"+core.PathLogout, nil)
	r.Header.Set("Accept", "application/json")
	r.Header.Set(core.CSRFHeader, core.CSRFValue)
	r.Header.Set("Origin", "https://docs.example.test")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, c := range cookies {
		r.Header.Add("Cookie", c)
	}
	w := httptest.NewRecorder()
	s.handler.Logout(w, r)
	var out struct {
		LogoutURL string `json:"logout_url"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("logout: %d %s", w.Code, w.Body.String())
	}
	return out.LogoutURL
}

// The end-session and the revocation are the session's own issuer's. Without a live session, a site of several issuers goes
// to the remembered issuer when it remembers one, and back to the site otherwise.
func TestLogoutGoesThroughTheSessionsIssuer(t *testing.T) {
	s := newIssuersSite(t, time.Hour, twoFakes(t)...)
	corp, partner := s.fakes[0], s.fakes[1]
	id, err := s.core.Create(context.Background(), &core.Record{Subject: "bob", Issuer: partner.srv.URL, SID: "sid-1",
		IDToken: "id-token-1", AccessToken: "access-1", RefreshToken: "refresh-1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	target := s.logout(t, s.core.CookieName()+"="+id, s.core.ChoiceCookieName()+"=corp")
	u, err := url.Parse(target)
	if err != nil || !strings.HasPrefix(target, partner.srv.URL+"/logout?") || u.Query().Get("client_id") != "session-partner" ||
		u.Query().Get("id_token_hint") != "id-token-1" {
		t.Fatalf("logout url %q", target)
	}
	if rv := partner.revocations(); len(rv) != 1 || rv[0].Get("client_id") != "session-partner" || assertionAudience(t, rv[0]) != partner.srv.URL {
		t.Fatalf("revocations at the partner: %v", rv)
	}
	if rv := corp.revocations(); len(rv) != 0 {
		t.Fatalf("revocations at the other issuer: %v", rv)
	}
	if target := s.logout(t); target != "https://docs.example.test/" {
		t.Fatalf("no session, no remembered issuer: %q", target)
	}
	if target := s.logout(t, s.core.ChoiceCookieName()+"=corp"); !strings.HasPrefix(target, corp.srv.URL+"/logout?") ||
		strings.Contains(target, "id_token_hint") {
		t.Fatalf("no session, the remembered issuer: %q", target)
	}
}

// whoami names the session's issuer by its id in the site (decision 0035).
func TestWhoamiNamesTheIssuer(t *testing.T) {
	s := newIssuersSite(t, 0, twoFakes(t)...)
	id, err := s.core.Create(context.Background(), &core.Record{Subject: "bob", Issuer: s.fakes[1].srv.URL, SID: "sid-1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w := s.get(core.PathWhoami, s.core.CookieName()+"="+id)
	var who map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &who) != nil || who["idp"] != "partner" || who["sub"] != "bob" {
		t.Fatalf("whoami %d %s", w.Code, w.Body.String())
	}
}

// A session of an issuer the site no longer names is no session (the site file's issuers are the core's Rules.Issuers).
func TestASessionOfAnIssuerTheSiteDoesNotNameIsNoSession(t *testing.T) {
	s := newIssuersSite(t, 0, twoFakes(t)...)
	id, err := s.core.Create(context.Background(), &core.Record{Subject: "eve", Issuer: "https://gone.example.test", SID: "sid-1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.core.Load(context.Background(), id); err == nil {
		t.Fatal("a session of an issuer the site does not name was loaded")
	}
}

// A logout token is verified by the issuer its iss names, among the site's: a token of any other issuer is refused before any
// key is fetched, and audited without that issuer's name.
func TestABackChannelLogoutTokenOfAnotherIssuerIsRefused(t *testing.T) {
	s := newIssuersSite(t, 0, twoFakes(t)...)
	enc := base64.RawURLEncoding.EncodeToString
	tok := enc([]byte(`{"alg":"ES256","typ":"logout+jwt"}`)) + "." +
		enc([]byte(`{"iss":"https://other.example.test","aud":"session-corp","sub":"bob","jti":"j1","iat":1,`+
			`"events":{"http://schemas.openid.net/event/backchannel-logout":{}}}`)) + "." + enc(make([]byte, 64))
	r := httptest.NewRequest(http.MethodPost, "https://docs.example.test"+core.PathBackChannel,
		strings.NewReader(url.Values{"logout_token": {tok}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handler.BackChannel(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	s.audit.mu.Lock()
	defer s.audit.mu.Unlock()
	if len(s.audit.list) != 1 || s.audit.list[0].Reason != "issuer" || s.audit.list[0].Issuer != "" {
		t.Fatalf("events %+v", s.audit.list)
	}
}
