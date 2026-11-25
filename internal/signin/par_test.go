package signin_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/truvity/session/core"
)

// client.par: unavailable (decision 0033): at an issuer with no PAR endpoint the authorization request goes on the browser's
// URL, with the same state, nonce and PKCE challenge, and nothing is pushed.
func TestASignInWithoutPARPutsTheRequestOnTheURL(t *testing.T) {
	f := newFakeIssuer(t, false, http.StatusOK)
	f.noPAR = true
	c, h, err := newSignIn(t, f, true)
	if err != nil {
		t.Fatalf("an issuer without PAR and client.par unavailable: %v", err)
	}

	w := httptest.NewRecorder()
	h.Login(w, httptest.NewRequest(http.MethodGet, "https://docs.example.test"+core.PathLogin+"?return_to=/app", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}

	to, err := url.Parse(w.Header().Get("Location"))
	if err != nil || to.Scheme+"://"+to.Host+to.Path != f.srv.URL+"/auth" {
		t.Fatalf("login went to %q, want the issuer's authorization endpoint", w.Header().Get("Location"))
	}

	q := to.Query()
	for name, want := range map[string]string{
		"response_type": "code", "client_id": "session-docs", "redirect_uri": "https://docs.example.test" + core.PathCallback,
		"scope": "openid", "code_challenge_method": "S256",
	} {
		if got := q.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	for _, name := range []string{"state", "nonce", "code_challenge"} {
		if q.Get(name) == "" {
			t.Errorf("%s is missing from the authorization request", name)
		}
	}

	if q.Has("request_uri") || q.Has("client_assertion") || q.Has("code_verifier") {
		t.Errorf("the URL carries %v: no request_uri, no assertion and never the verifier", q)
	}

	if len(f.pars) != 0 {
		t.Errorf("%d pushed authorization requests, want none", len(f.pars))
	}

	if !strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), "\n"), c.BindingCookieName()) {
		t.Errorf("no binding cookie in %v", w.Header().Values("Set-Cookie"))
	}

	// The transaction is kept by state, as with PAR, so the callback finds it once.
	if _, err := c.TakeSignIn(t.Context(), q.Get("state")); err != nil {
		t.Errorf("the transaction of the state: %v", err)
	}
}

// The setting never turns PAR off where the issuer has it, and an issuer without PAR still needs the setting.
func TestClientPARMustMatchTheIssuersDiscovery(t *testing.T) {
	withPAR := newFakeIssuer(t, false, http.StatusOK)
	if _, _, err := newSignIn(t, withPAR, true); err == nil || !strings.Contains(err.Error(), "offers a pushed authorization request endpoint") {
		t.Errorf("client.par unavailable at an issuer with PAR: %v, want refused", err)
	}

	without := newFakeIssuer(t, false, http.StatusOK)
	without.noPAR = true
	if _, _, err := newSignIn(t, without, false); err == nil || !strings.Contains(err.Error(), "client.par: unavailable") {
		t.Errorf("an issuer without PAR and client.par required: %v, want refused naming the setting", err)
	}
}
