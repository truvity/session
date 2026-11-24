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
		r.Routes[1].Unauthenticated != core.Unauthenticated401 || r.Routes[1].Name != "api" || f.Policy.Bundle != "policy-bundle" {
		t.Fatalf("%+v", r)
	}
}

func TestBadSiteFiles(t *testing.T) {
	cases := map[string]string{
		"unknown key":            strings.Replace(good, "scopes:", "extra: 1\nscopes:", 1),
		"duplicate key":          strings.Replace(good, "site: docs", "site: docs\nsite: other", 1),
		"two documents":          good + "\n---\nsite: other\n",
		"plain issuer":           strings.Replace(good, "https://issuer", "http://issuer", 1),
		"client secret":          strings.Replace(good, "private_key_jwt", "client_secret_basic", 1),
		"no openid":              strings.Replace(good, "[openid, profile, email]", "[profile]", 1),
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

func TestALoopbackIssuerOnPlainHTTPIsAccepted(t *testing.T) {
	if _, err := site.Parse([]byte(strings.Replace(good, "https://issuer.example.test", "http://127.0.0.1:8080", 1))); err != nil {
		t.Fatal(err)
	}
}
