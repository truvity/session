package site_test

import (
	"strings"
	"testing"
	"time"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/site"
)

const good = `
site: docs
host: docs.example.test
issuers:
  - id: corp
    label: Example Corp
    issuer: https://issuer.example.test/realms/docs
    client:
      id: session-docs
      auth: private_key_jwt
    scopes: [openid, profile, email]
session:
  idle: 20m
  max: 4h
policy:
  bundle: policy-bundle
  verify_key:
    kid: publisher-1
    public_key: |
      -----BEGIN PUBLIC KEY-----
      MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEKwsvu/lKOYwP0gNG9wTasVXZHfp1bEWk
      oSq/SzJQbWqYGN9urpU1EFl6ypRKdcc8olyuacxsRDML4ZGtDcLA2gcsTUXZGfvL
      hkPfEOilNuWdXkXOQrrZsO/Retc6BTZk
      -----END PUBLIC KEY-----
routes:
  - match: { prefix: /assets/ }
    mode: public
  - name: api
    match: { prefix: /api/ }
    mode: session
    unauthenticated: "401"
  - match: { prefix: / }
    mode: session
`

func TestAGoodSiteFile(t *testing.T) {
	f, err := site.Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if r.Site != "docs" || r.Idle != 20*time.Minute || r.Max != 4*time.Hour || len(r.Routes) != 3 ||
		r.Routes[1].Unauthenticated != core.Unauthenticated401 || r.Routes[1].Name != "api" || f.Policy.Bundle != "policy-bundle" ||
		len(r.Issuers) != 1 || r.Issuers[0] != "https://issuer.example.test/realms/docs" || f.Remember() != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestBadSiteFiles(t *testing.T) {
	cases := map[string]string{
		"unknown key":            strings.Replace(good, "session:", "extra: 1\nsession:", 1),
		"duplicate key":          strings.Replace(good, "site: docs", "site: docs\nsite: other", 1),
		"two documents":          good + "\n---\nsite: other\n",
		"plain issuer":           strings.Replace(good, "https://issuer", "http://issuer", 1),
		"client secret":          strings.Replace(good, "private_key_jwt", "client_secret_basic", 1),
		"no openid":              strings.Replace(good, "[openid, profile, email]", "[profile]", 1),
		"no issuers":             good[:strings.Index(good, "issuers:")] + good[strings.Index(good, "session:"):],
		"the old issuer key":     strings.Replace(good, "issuers:", "issuer: https://issuer.example.test/realms/docs\nissuers:", 1),
		"the old scopes key":     strings.Replace(good, "issuers:", "scopes: [openid]\nissuers:", 1),
		"no issuer id":           strings.Replace(good, "id: corp", "id: \"\"", 1),
		"a bad issuer id":        strings.Replace(good, "id: corp", "id: Corp_1", 1),
		"no label":               strings.Replace(good, "label: Example Corp", "label: \" \"", 1),
		"an id twice":            strings.Replace(good, "session:", second("corp", "https://other.example.test")+"session:", 1),
		"an issuer twice":        strings.Replace(good, "session:", second("partner", "https://issuer.example.test/realms/docs")+"session:", 1),
		"a bad remember":         strings.Replace(good, "session:", "signin:\n  remember_choice: forever\nsession:", 1),
		"bad duration":           strings.Replace(good, "idle: 20m", "idle: soon", 1),
		"idle above max":         strings.Replace(good, "idle: 20m", "idle: 5h", 1),
		"exchange, no audience":  strings.Replace(good, "mode: public", "mode: exchange", 1),
		"session with audience":  strings.Replace(good, "mode: public", "mode: session\n    audience: https://api.example.test", 1),
		"error page is the site": strings.Replace(good, "routes:", "error_page: site\nroutes:", 1),
		"bad site name":          strings.Replace(good, "site: docs", "site: Docs_1", 1),
		"own prefix":             strings.Replace(good, "prefix: /assets/", "prefix: /_session/x", 1),
		"empty bundle":           strings.Replace(good, "bundle: policy-bundle", "bundle: \"\"", 1),
		"no kid":                 strings.Replace(good, "kid: publisher-1", "kid: \"\"", 1),
		"no verify key":          good[:strings.Index(good, "  verify_key:")] + good[strings.Index(good, "routes:"):],
		"a broken verify key":    strings.Replace(good, "MHYw", "MHYx", 1),
	}
	for name, text := range cases {
		if _, err := site.Parse([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// second is a second entry of issuers.
func second(id, issuer string) string {
	return "  - id: " + id + "\n    label: Example Partner\n    issuer: " + issuer +
		"\n    client:\n      id: session-docs\n      auth: private_key_jwt\n    scopes: [openid]\n"
}

func TestSeveralIssuersAndTheRememberedChoice(t *testing.T) {
	text := strings.Replace(good, "session:", second("partner", "https://partner.example.test/realms/staff")+
		"signin:\n  remember_choice: 720h\nsession:", 1)
	f, err := site.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Issuers) != 2 || f.Issuers[1].ID != "partner" || f.Issuers[1].Label != "Example Partner" || f.Remember() != 720*time.Hour ||
		len(r.Issuers) != 2 || r.Issuers[1] != "https://partner.example.test/realms/staff" {
		t.Fatalf("%+v %+v", f.Issuers, r.Issuers)
	}
}

func TestALoopbackIssuerOnPlainHTTPIsAccepted(t *testing.T) {
	if _, err := site.Parse([]byte(strings.Replace(good, "https://issuer.example.test", "http://127.0.0.1:8080", 1))); err != nil {
		t.Fatal(err)
	}
}

// client.par (decision 0033): required by default, unavailable for an issuer without PAR, nothing else.
func TestClientPAR(t *testing.T) {
	for value, without := range map[string]bool{"": false, "required": false, "unavailable": true} {
		text := good
		if value != "" {
			text = strings.Replace(good, "      auth: private_key_jwt\n", "      auth: private_key_jwt\n      par: "+value+"\n", 1)
		}
		f, err := site.Parse([]byte(text))
		if err != nil {
			t.Fatalf("par %q: %v", value, err)
		}
		if got := f.Issuers[0].Client.WithoutPAR(); got != without {
			t.Errorf("par %q: WithoutPAR = %v, want %v", value, got, without)
		}
	}
	bad := strings.Replace(good, "      auth: private_key_jwt\n", "      auth: private_key_jwt\n      par: optional\n", 1)
	if _, err := site.Parse([]byte(bad)); err == nil || !strings.Contains(err.Error(), "client.par") {
		t.Errorf("par optional: %v, want refused", err)
	}
}
