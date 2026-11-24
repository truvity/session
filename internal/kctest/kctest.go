// Package kctest drives a test Keycloak for the integration tests: a realm made through the admin API, a person, and a browser
// that signs in through Keycloak's login form. The Keycloak runs in a container that `just test-keycloak` starts, pinned by
// digest, and removes at the end; the tests find it through SESSION_TEST_KEYCLOAK (its base URL) and
// SESSION_TEST_KEYCLOAK_ADMIN_PASSWORD. Without them the tests that need it are skipped.
package kctest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/truvity/session/core"
)

// Keycloak is a running test Keycloak.
type Keycloak struct {
	Base     string
	password string
	http     *http.Client
}

// Need returns the test Keycloak, or skips the test.
func Need(t *testing.T) *Keycloak {
	t.Helper()
	base := os.Getenv("SESSION_TEST_KEYCLOAK")
	if base == "" {
		t.Skip("no test Keycloak: run `just test-keycloak` (SESSION_TEST_KEYCLOAK is not set)")
	}
	return &Keycloak{Base: strings.TrimSuffix(base, "/"), password: os.Getenv("SESSION_TEST_KEYCLOAK_ADMIN_PASSWORD"),
		http: &http.Client{Timeout: 30 * time.Second}}
}

func (k *Keycloak) adminToken(ctx context.Context) (string, error) {
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {k.password}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, k.Base+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := k.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("admin token: status %d", res.StatusCode)
	}
	return tok.AccessToken, nil
}

// Admin calls the admin API with a fresh admin token and returns the status and the body.
func (k *Keycloak) Admin(ctx context.Context, method, path string, body any) (int, []byte, error) {
	tok, err := k.adminToken(ctx)
	if err != nil {
		return 0, nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, k.Base+"/admin"+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	res, err := k.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	return res.StatusCode, b, err
}

// Person is a person of a test realm.
type Person struct {
	Username, Password, Email string
	Groups                    []string
}

// RealmSpec is what a test realm needs.
type RealmSpec struct {
	Realm          string
	ClientID       string
	RedirectURI    string // the callback
	PostLogoutURI  string
	BackChannelURL string // empty: no back-channel logout
	JWKS           string // the client's public keys, as a JWKS document
	People         []Person
	// Audiences are API clients that the client may exchange its access token for (Keycloak's standard token exchange): each
	// is made as a client with no flow of its own, and the client's access tokens carry it and the client itself in aud.
	Audiences []string
}

// Realm makes a realm with one confidential client that authenticates with private_key_jwt (ES256, the key given inline as
// a JWKS), must use PAR and PKCE S256, and has a groups claim; and the people. It removes the realm at the end of the test.
// It returns the issuer.
func (k *Keycloak) Realm(t *testing.T, s RealmSpec) string {
	t.Helper()
	ctx := context.Background()
	groups := map[string]bool{}
	var users []map[string]any
	for _, p := range s.People {
		var gs []string
		for _, g := range p.Groups {
			groups[g] = true
			gs = append(gs, "/"+g)
		}
		users = append(users, map[string]any{
			"username": p.Username, "email": p.Email, "emailVerified": true, "enabled": true,
			"firstName": "Test", "lastName": p.Username,
			"credentials": []map[string]any{{"type": "password", "value": p.Password, "temporary": false}},
			"groups":      gs,
		})
	}
	var groupList []map[string]any
	for g := range groups {
		groupList = append(groupList, map[string]any{"name": g})
	}
	attrs := map[string]string{
		"use.jwks.string":                          "true",
		"use.jwks.url":                             "false",
		"jwks.string":                              s.JWKS,
		"token.endpoint.auth.signing.alg":          "ES256",
		"pkce.code.challenge.method":               "S256",
		"require.pushed.authorization.requests":    "true",
		"post.logout.redirect.uris":                s.PostLogoutURI,
		"backchannel.logout.session.required":      "true",
		"backchannel.logout.revoke.offline.tokens": "false",
	}
	if s.BackChannelURL != "" {
		attrs["backchannel.logout.url"] = s.BackChannelURL
	}
	mappers := []map[string]any{{
		"name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
		"config": map[string]string{"claim.name": "groups", "full.path": "false", "id.token.claim": "true",
			"access.token.claim": "true", "userinfo.token.claim": "true"},
	}}
	clients := []map[string]any{}
	if len(s.Audiences) > 0 {
		// Keycloak's standard token exchange (V2): the requesting client is in the subject token's aud, and a requested
		// audience is one the client's tokens may carry.
		attrs["standard.token.exchange.enabled"] = "true"
		for _, aud := range append([]string{s.ClientID}, s.Audiences...) {
			mappers = append(mappers, map[string]any{
				"name": "audience " + aud, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
				"config": map[string]string{"included.client.audience": aud, "access.token.claim": "true", "id.token.claim": "false"},
			})
		}
		for _, aud := range s.Audiences {
			clients = append(clients, map[string]any{"clientId": aud, "protocol": "openid-connect", "enabled": true,
				"publicClient": false, "standardFlowEnabled": false, "directAccessGrantsEnabled": false})
		}
	}
	clients = append([]map[string]any{{
		"clientId": s.ClientID, "protocol": "openid-connect", "enabled": true, "publicClient": false,
		"clientAuthenticatorType": "client-jwt", "standardFlowEnabled": true, "directAccessGrantsEnabled": false,
		"redirectUris": []string{s.RedirectURI}, "webOrigins": []string{}, "frontchannelLogout": false,
		"attributes": attrs, "protocolMappers": mappers,
	}}, clients...)
	realm := map[string]any{"realm": s.Realm, "enabled": true, "users": users, "groups": groupList, "clients": clients}
	status, body, err := k.Admin(ctx, http.MethodPost, "/realms", realm)
	if err != nil || status != http.StatusCreated {
		t.Fatalf("make realm %s: status %d %v %s", s.Realm, status, err, body)
	}
	t.Cleanup(func() { _, _, _ = k.Admin(context.Background(), http.MethodDelete, "/realms/"+s.Realm, nil) })
	return k.Base + "/realms/" + s.Realm
}

// UserID returns the id of a person of a realm.
func (k *Keycloak) UserID(t *testing.T, realm, username string) string {
	t.Helper()
	status, body, err := k.Admin(context.Background(), http.MethodGet, "/realms/"+realm+"/users?exact=true&username="+url.QueryEscape(username), nil)
	var users []struct {
		ID string `json:"id"`
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(body, &users) != nil || len(users) != 1 {
		t.Fatalf("user %s: status %d %v", username, status, err)
	}
	return users[0].ID
}

// LogoutUser ends a person's sessions at Keycloak, which then sends the back-channel logout tokens.
func (k *Keycloak) LogoutUser(t *testing.T, realm, username string) {
	t.Helper()
	status, body, err := k.Admin(context.Background(), http.MethodPost, "/realms/"+realm+"/users/"+k.UserID(t, realm, username)+"/logout", nil)
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("logout %s: status %d %v %s", username, status, err, body)
	}
}

var formAction = regexp.MustCompile(`<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"`)

// ErrNoLoginForm means Keycloak answered with something other than its login form.
var ErrNoLoginForm = errors.New("kctest: no login form")

// SignIn plays the person at the login form: res is the answer to the request that reached Keycloak's authorization endpoint
// (the browser followed the sign-in redirect there). It posts the username and the password and returns Keycloak's answer,
// which the client follows as far as its CheckRedirect lets it.
func SignIn(browser *http.Client, res *http.Response, p Person) (*http.Response, error) {
	b, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		return nil, err
	}
	m := formAction.FindSubmatch(b)
	if m == nil {
		return nil, fmt.Errorf("%w (status %d at %s)", ErrNoLoginForm, res.StatusCode, res.Request.URL.Path)
	}
	action := html.UnescapeString(string(m[1]))
	return browser.PostForm(action, url.Values{"username": {p.Username}, "password": {p.Password}, "credentialId": {""}})
}

// Password returns a random password for a test person.
func Password() string { return core.NewID() }
