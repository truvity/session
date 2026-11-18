// genrealm writes a throwaway client key and a Keycloak realm import for the spike.
// Usage: genrealm <outdir>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/go-jose/go-jose/v4"
)

func main() {
	out := os.Args[1]
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	der, err := x509.MarshalECPrivateKey(key)
	must(err)
	must(os.WriteFile(filepath.Join(out, "client-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600))

	jwk := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "spike-1", Algorithm: "ES256", Use: "sig"}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	must(err)

	realm := map[string]any{
		"realm":   "spike",
		"enabled": true,
		"users": []map[string]any{{
			"username": "alice", "enabled": true, "emailVerified": true,
			"firstName": "Alice", "lastName": "Tester",
			"credentials": []map[string]any{{"type": "password", "value": "alice", "temporary": false}},
		}},
		"clients": []map[string]any{{
			"clientId":                  "session-spike",
			"enabled":                   true,
			"publicClient":              false,
			"clientAuthenticatorType":   "client-jwt",
			"standardFlowEnabled":       true,
			"directAccessGrantsEnabled": false,
			"redirectUris":              []string{"http://127.0.0.1:18081/_session/callback", "http://127.0.0.1:18082/_session/callback", "http://127.0.0.1:18090/_session/callback"},
			"attributes": map[string]string{
				"use.jwks.string":                       "true",
				"jwks.string":                           string(jwks),
				"token.endpoint.auth.signing.alg":       "ES256",
				"pkce.code.challenge.method":            "S256",
				"require.pushed.authorization.requests": "true",
				"backchannel.logout.url":                "http://127.0.0.1:18090/_session/backchannel-logout",
				"backchannel.logout.session.required":   "true",
				"post.logout.redirect.uris":             "http://127.0.0.1:18081/*##http://127.0.0.1:18082/*##http://127.0.0.1:18090/*",
			},
		}},
	}
	b, err := json.MarshalIndent(realm, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(out, "realm.json"), b, 0o644))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
