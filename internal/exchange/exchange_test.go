package exchange_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/exchange"
)

type asserter struct{ audience string }

func (a *asserter) ClientAssertion(_ context.Context, clientID, audience string, _ time.Time) (string, error) {
	a.audience = audience
	return "assertion-of-" + clientID, nil
}

// endpoint is a token endpoint that records the last form and answers with status and body.
type endpoint struct {
	form   url.Values
	status int
	body   string
}

func (e *endpoint) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			iss := "http://" + r.Host
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "token_endpoint": iss + "/token",
				"authorization_endpoint": iss + "/auth", "jwks_uri": iss + "/jwks"})
			return
		}
		_ = r.ParseForm()
		e.form = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(e.status)
		_, _ = w.Write([]byte(e.body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newClient(t *testing.T, e *endpoint) (*exchange.Client, *asserter, string) {
	t.Helper()
	srv := e.start(t)
	a := &asserter{}
	c, err := exchange.New(context.Background(), exchange.Options{Issuer: srv.URL, ClientID: "session-docs", Asserter: a})
	if err != nil {
		t.Fatal(err)
	}
	return c, a, srv.URL
}

// The request is the one sluis's exchange serves: RFC 8693 with the access token as subject, an access token requested, the
// audience, and no scope or resource; the client authenticates with its assertion, whose audience is the issuer.
func TestTheExchangeRequest(t *testing.T) {
	e := &endpoint{status: 200, body: `{"access_token":"at-billing","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":300}`}
	c, a, iss := newClient(t, e)
	tok, err := c.Exchange(context.Background(), "subject-at", "billing")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at-billing" || tok.ExpiresIn != 5*time.Minute {
		t.Fatalf("token %+v", tok)
	}
	want := map[string]string{
		"grant_type": exchange.GrantTokenExchange, "subject_token": "subject-at", "subject_token_type": exchange.TokenTypeAccess,
		"requested_token_type": exchange.TokenTypeAccess, "audience": "billing", "client_id": "session-docs",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": "assertion-of-session-docs",
	}
	for k, v := range want {
		if e.form.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, e.form.Get(k), v)
		}
	}
	for _, k := range []string{"scope", "resource", "actor_token", "client_secret"} {
		if e.form.Has(k) {
			t.Errorf("the request carries %s", k)
		}
	}
	if len(e.form) != len(want) || a.audience != iss {
		t.Fatalf("form %v, assertion audience %q", e.form, a.audience)
	}
}

func TestTheRefreshRequest(t *testing.T) {
	e := &endpoint{status: 200, body: `{"access_token":"at-2","token_type":"bearer","expires_in":60,"refresh_token":"rt-2","id_token":"idt-2"}`}
	c, _, _ := newClient(t, e)
	r, err := c.Refresh(context.Background(), "rt-1")
	if err != nil {
		t.Fatal(err)
	}
	if r.AccessToken != "at-2" || r.ExpiresIn != time.Minute || r.RefreshToken != "rt-2" || r.IDToken != "idt-2" {
		t.Fatalf("refreshed %+v", r)
	}
	if e.form.Get("grant_type") != "refresh_token" || e.form.Get("refresh_token") != "rt-1" || e.form.Get("client_assertion") == "" {
		t.Fatalf("form %v", e.form)
	}
}

// An OAuth error answer is a refusal with its code and nothing of its description; anything else that is not a good answer
// is an outage.
func TestAnswers(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		refused string // the code of a refusal; empty: an outage
	}{
		{"invalid_target", 400, `{"error":"invalid_target","error_description":"A token for the requested audience cannot be issued."}`, "invalid_target"},
		{"invalid_client", 401, `{"error":"invalid_client"}`, "invalid_client"},
		{"a 4xx without a code", 400, `{}`, ""},
		{"a code that is not one", 400, `{"error":"bad \"code\""}`, ""},
		{"a 500", 500, `{"error":"server_error"}`, ""},
		{"a 503 page", 503, `<html>down</html>`, ""},
		{"not JSON", 200, `<html>ok</html>`, ""},
		{"no token", 200, `{"token_type":"Bearer"}`, ""},
		{"not a bearer token", 200, `{"access_token":"x","token_type":"DPoP"}`, ""},
		{"not an access token", 200, `{"access_token":"x","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:id_token"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := newClient(t, &endpoint{status: tc.status, body: tc.body})
			_, err := c.Exchange(context.Background(), "s", "billing")
			var refused *core.RefusedError
			switch {
			case err == nil:
				t.Fatal("accepted")
			case tc.refused != "":
				if !errors.As(err, &refused) || refused.Code != tc.refused {
					t.Fatalf("error %v, want the refusal %s", err, tc.refused)
				}
			case errors.As(err, &refused):
				t.Fatalf("a refusal %q, want an outage", refused.Code)
			}
		})
	}
}

func TestAnIssuerThatIsNotThereIsAnOutage(t *testing.T) {
	c, err := exchange.New(context.Background(), exchange.Options{ //nolint:gosec // G101: a test address, no credential
		Issuer: "http://127.0.0.1:1", TokenURL: "http://127.0.0.1:1/token", ClientID: "c", Asserter: &asserter{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Exchange(context.Background(), "s", "a")
	var refused *core.RefusedError
	if err == nil || errors.As(err, &refused) {
		t.Fatalf("error %v", err)
	}
}
