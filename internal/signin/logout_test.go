package signin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/sealer/sealertest"
	"github.com/truvity/session/internal/signin"
	"github.com/truvity/session/internal/storetest"
)

// fakeIssuer serves the discovery document and the revocation endpoint of an issuer, and records each revocation. It is enough
// for the logout path, which needs no sign-in (decision 0031); the sign-in itself is tested against Keycloak.
type fakeIssuer struct {
	srv        *httptest.Server
	revocation bool // the discovery document names a revocation endpoint
	status     int  // the revocation endpoint's answer
	mu         sync.Mutex
	revoked    []url.Values
	pars       []url.Values // the pushed authorization requests, for the tests of several issuers
	noPAR      bool         // the discovery document names no PAR endpoint, as sluis v1's (decision 0033)
}

func newFakeIssuer(t *testing.T, revocation bool, status int) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{revocation: revocation, status: status}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		d := map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "pushed_authorization_request_endpoint": f.srv.URL + "/par",
			"end_session_endpoint": f.srv.URL + "/logout", "id_token_signing_alg_values_supported": []string{"ES256"},
		}
		if f.noPAR {
			delete(d, "pushed_authorization_request_endpoint")
		}
		if f.revocation {
			d["revocation_endpoint"] = f.srv.URL + "/revoke"
		}
		_ = json.NewEncoder(w).Encode(d)
	})
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.revoked = append(f.revoked, r.PostForm)
		f.mu.Unlock()
		w.WriteHeader(f.status)
	})
	mux.HandleFunc("POST /par", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.pars = append(f.pars, r.PostForm)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"request_uri":"urn:example:par:1","expires_in":60}`))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) revocations() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.revoked...)
}

type logoutSite struct {
	core    *core.Core
	handler *signin.Handler
	issuer  *fakeIssuer
}

func newLogoutSite(t *testing.T, f *fakeIssuer) *logoutSite {
	t.Helper()
	c, h, err := newSignIn(t, f, false)
	if err != nil {
		t.Fatal(err)
	}
	return &logoutSite{core: c, handler: h, issuer: f}
}

// newSignIn is the sign-in handler of a site whose one issuer is f, signing in without PAR when withoutPAR is set.
func newSignIn(t *testing.T, f *fakeIssuer, withoutPAR bool) (*core.Core, *signin.Handler, error) {
	t.Helper()
	return newSignInAt(t, f.srv.URL, withoutPAR, newTestSigners(t))
}

// testSigners are a site's two signers on software keys in a private directory of the test.
type testSigners struct {
	client, identity signin.Signer
	sealer           core.Sealer
}

func newTestSigners(t *testing.T) testSigners {
	t.Helper()
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
	return testSigners{client: signer, identity: identity, sealer: blocks.Sealer}
}

// newSignInAt is the sign-in handler of the site docs.example.test whose one issuer is issuerURL, with the client session-docs.
func newSignInAt(t *testing.T, issuerURL string, withoutPAR bool, keys testSigners) (*core.Core, *signin.Handler, error) {
	t.Helper()
	mem := storetest.New(nil)
	items, stop := mem.Client()
	t.Cleanup(stop)
	c, err := core.New(core.Options{Items: items, Seal: keys.sealer, Rules: core.Rules{Site: "docs", Host: "docs.example.test",
		Routes: []core.Route{{Prefix: "/", Mode: core.ModeSession}}}})
	if err != nil {
		t.Fatal(err)
	}
	identity := keys.identity
	h, err := signin.New(context.Background(), signin.Options{Core: c,
		Issuers: []signin.Issuer{{ID: "corp", Label: "Example Corp", URL: issuerURL, ClientID: "session-docs", Scopes: []string{"openid"},
			WithoutPAR: withoutPAR}},
		Signer: keys.client, Identity: &identity})
	return c, h, err
}

// logout posts to the logout path with the CSRF headers, as the browser helper does, and returns the answer and its address.
func (s *logoutSite) logout(t *testing.T, id string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://docs.example.test"+core.PathLogout, nil)
	r.Header.Set("Accept", "application/json")
	r.Header.Set(core.CSRFHeader, core.CSRFValue)
	r.Header.Set("Origin", "https://docs.example.test")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if id != "" {
		r.Header.Set("Cookie", s.core.CookieName()+"="+id)
	}
	w := httptest.NewRecorder()
	s.handler.Logout(w, r)
	var out struct {
		LogoutURL string `json:"logout_url"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("logout: %d %s", w.Code, w.Body.String())
	}
	return w, out.LogoutURL
}

func (s *logoutSite) signIn(t *testing.T, refresh string) string {
	t.Helper()
	id, err := s.core.Create(context.Background(), &core.Record{Subject: "alice", Issuer: s.issuer.srv.URL, SID: "sid-1",
		IDToken: "id-token-1", AccessToken: "access-1", RefreshToken: refresh}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// clearsBoth checks that the answer clears both of session's cookies (decision 0031, L4).
func clearsBoth(t *testing.T, w *httptest.ResponseRecorder, c *core.Core) {
	t.Helper()
	got := strings.Join(w.Result().Header.Values("Set-Cookie"), "\n")
	for _, name := range []string{c.CookieName(), c.BindingCookieName()} {
		if !strings.Contains(got, name+"=;") || !strings.Contains(got, "Max-Age=0") {
			t.Fatalf("%s is not cleared: %s", name, got)
		}
	}
}

// L2 and L3 of decision 0031: a live session is deleted, its refresh token revoked with the client's assertion, and the
// browser sent to end-session with id_token_hint.
func TestLogoutRevokesTheRefreshTokenAndEndsTheIssuersSession(t *testing.T) {
	s := newLogoutSite(t, newFakeIssuer(t, true, http.StatusOK))
	id := s.signIn(t, "refresh-1")
	w, target := s.logout(t, id)
	if _, err := s.core.Load(context.Background(), id); err == nil {
		t.Fatal("the session survived the logout")
	}
	u, err := url.Parse(target)
	if err != nil || !strings.HasPrefix(target, s.issuer.srv.URL+"/logout?") || u.Query().Get("id_token_hint") != "id-token-1" ||
		u.Query().Get("client_id") != "session-docs" || u.Query().Get("post_logout_redirect_uri") != "https://docs.example.test/" {
		t.Fatalf("logout url %q", target)
	}
	rv := s.issuer.revocations()
	if len(rv) != 1 || rv[0].Get("token") != "refresh-1" || rv[0].Get("token_type_hint") != "refresh_token" ||
		rv[0].Get("client_id") != "session-docs" || rv[0].Get("client_assertion") == "" ||
		rv[0].Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("revocations %v", rv)
	}
	if s.core.Metrics().RevocationsFailed() != 0 {
		t.Fatal("a revocation counted as failed")
	}
	clearsBoth(t, w, s.core)
}

// L2: without a live session (no cookie, or a session already gone) the browser still goes to the issuer's end-session,
// without id_token_hint, and nothing is revoked.
func TestLogoutWithoutALiveSessionStillGoesToTheIssuer(t *testing.T) {
	s := newLogoutSite(t, newFakeIssuer(t, true, http.StatusOK))
	gone := s.signIn(t, "refresh-2")
	if err := s.core.Delete(context.Background(), gone); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", gone} {
		w, target := s.logout(t, id)
		u, err := url.Parse(target)
		if err != nil || !strings.HasPrefix(target, s.issuer.srv.URL+"/logout?") || u.Query().Has("id_token_hint") ||
			u.Query().Get("client_id") != "session-docs" {
			t.Fatalf("cookie %q: logout url %q", id, target)
		}
		clearsBoth(t, w, s.core)
	}
	if rv := s.issuer.revocations(); len(rv) != 0 {
		t.Fatalf("revoked without a session: %v", rv)
	}
}

// L3: a revocation the issuer refuses is counted and the logout goes on; an issuer without a revocation endpoint is not asked.
func TestARefusedRevocationIsCountedAndTheLogoutGoesOn(t *testing.T) {
	s := newLogoutSite(t, newFakeIssuer(t, true, http.StatusServiceUnavailable))
	id := s.signIn(t, "refresh-3")
	_, target := s.logout(t, id)
	if !strings.Contains(target, "id_token_hint=") {
		t.Fatalf("logout url %q", target)
	}
	if _, err := s.core.Load(context.Background(), id); err == nil {
		t.Fatal("the session survived the logout")
	}
	if n := s.core.Metrics().RevocationsFailed(); n != 1 {
		t.Fatalf("failed revocations: %d", n)
	}
	var b strings.Builder
	_ = s.core.Metrics().WritePrometheus(&b, "docs")
	if !strings.Contains(b.String(), `session_logout_revocation_failed_total{site="docs"} 1`) {
		t.Fatalf("metrics: %s", b.String())
	}

	none := newLogoutSite(t, newFakeIssuer(t, false, http.StatusOK))
	none.logout(t, none.signIn(t, "refresh-4"))
	if rv := none.issuer.revocations(); len(rv) != 0 || none.core.Metrics().RevocationsFailed() != 0 {
		t.Fatalf("an issuer without a revocation endpoint was asked: %v", rv)
	}
}
