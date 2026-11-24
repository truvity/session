package signin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/atoom/key/awskms"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/exchange"
	"github.com/truvity/session/internal/kctest"
	"github.com/truvity/session/internal/kmstest"
	"github.com/truvity/session/internal/sealer/sealertest"
	"github.com/truvity/session/internal/signin"
	"github.com/truvity/session/internal/storetest"
)

// stand is one site behind session, against the test Keycloak: the sign-in paths on TLS (the browser's address, so the
// __Host- cookie travels), the same paths on plain HTTP on the loopback for Keycloak's back-channel calls, a realm and a person.
type stand struct {
	kc       *kctest.Keycloak
	realm    string
	issuer   string
	core     *core.Core
	handler  *signin.Handler
	site     *httptest.Server
	back     *httptest.Server
	person   kctest.Person
	mu       sync.Mutex
	captured []string // logout tokens the issuer sent, kept by the test only
	audit    *events
	ahead    atomic.Int64 // how far the core's clock runs ahead of the wall clock, in nanoseconds
}

// standConfig is what a test may change in its stand: the API audiences of the realm, the route table, and the key drivers
// (both purposes on the in-process KMS double when kms is set, else in key files).
type standConfig struct {
	audiences []string
	routes    []core.Route
	kms       *kmstest.KMS
}

type events struct {
	mu   sync.Mutex
	list []core.Event
	fail bool
}

func (e *events) Emit(_ context.Context, ev core.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail {
		return io.ErrClosedPipe
	}
	e.list = append(e.list, ev)
	return nil
}

func (e *events) kinds() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, ev := range e.list {
		out = append(out, string(ev.Kind)+":"+ev.Reason)
	}
	return out
}

var realmSeq = struct {
	sync.Mutex
	n int
}{}

func newStand(t *testing.T, opts ...func(*standConfig)) *stand {
	t.Helper()
	cfg := standConfig{routes: []core.Route{{Prefix: "/", Mode: core.ModeSession}}}
	for _, o := range opts {
		o(&cfg)
	}
	kc := kctest.Need(t)
	ctx := context.Background()
	st := &stand{kc: kc, audit: &events{}}
	mux := http.NewServeMux()
	var h http.Handler = mux
	// The test keeps the logout tokens Keycloak sends, to replay one; session itself never logs or keeps them.
	capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == core.PathBackChannel {
			b, _ := io.ReadAll(r.Body)
			if v, err := url.ParseQuery(string(b)); err == nil {
				st.mu.Lock()
				st.captured = append(st.captured, v.Get("logout_token"))
				st.mu.Unlock()
			}
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		h.ServeHTTP(w, r)
	})
	st.site = httptest.NewTLSServer(mux)
	t.Cleanup(st.site.Close)
	st.back = httptest.NewServer(capture)
	t.Cleanup(st.back.Close)
	host := strings.TrimPrefix(st.site.URL, "https://")

	mem := storetest.New(nil)
	items, stopItems := mem.Client()
	t.Cleanup(stopItems)
	sealer := sealertest.New(t)
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0o700); err != nil { //nolint:gosec // G302: a directory needs its x bit // the key driver wants its state directory private
		t.Fatal(err)
	}
	var keyFlags []string
	if cfg.kms != nil {
		keyFlags = []string{"client-assertion=awskms", "identity-header=awskms:" + cfg.kms.AddKey("")}
		cfg.kms.AddKey("alias/session/docs/client-assertion")
	}
	choices, err := atoomx.ParseKeyChoices(keyFlags, signin.Purposes())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := atoomx.OpenKeys(atoomx.KeyOptions{Purposes: signin.Purposes(), Choices: choices, StateDir: keyDir, Environment: "development",
		AliasPrefix: "session/docs", KMS: func() (awskms.API, error) { return cfg.kms, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Stop)
	signer, identity, err := signin.Signers(ctx, keys)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := signer.JWK(ctx)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})

	realmSeq.Lock()
	realmSeq.n++
	st.realm = "session-test-" + strings.ToLower(core.NewID()[:8])
	realmSeq.Unlock()
	st.person = kctest.Person{Username: "alice", Password: kctest.Password(), Email: "alice@example.test", Groups: []string{"admins"}}
	st.issuer = kc.Realm(t, kctest.RealmSpec{
		Realm: st.realm, ClientID: "session-docs",
		RedirectURI: st.site.URL + core.PathCallback, PostLogoutURI: st.site.URL + "/",
		BackChannelURL: st.back.URL + core.PathBackChannel, JWKS: string(jwks),
		People: []kctest.Person{st.person}, Audiences: cfg.audiences,
	})
	issuer, err := exchange.New(ctx, exchange.Options{Issuer: st.issuer, ClientID: "session-docs", Asserter: signer})
	if err != nil {
		t.Fatal(err)
	}
	c, err := core.New(core.Options{Items: items, Seal: sealer, Audit: st.audit, Issuer: issuer, Identity: identity,
		Now:   func() time.Time { return time.Now().Add(time.Duration(st.ahead.Load())) },
		Rules: core.Rules{Site: "docs", Host: host, Routes: cfg.routes}})
	if err != nil {
		t.Fatal(err)
	}
	st.core = c
	st.handler, err = signin.New(ctx, signin.Options{Core: c, Issuer: st.issuer, ClientID: "session-docs",
		Scopes: []string{"openid", "profile", "email"}, Signer: signer, Identity: &identity})
	if err != nil {
		t.Fatal(err)
	}
	st.handler.Register(mux)
	return st
}

// browser is a client with a cookie jar that trusts the site's test certificate. The site is on TLS, so the jar sends the
// Secure __Host- cookie (a jar does not send it over plain HTTP, decision 0011).
func (st *stand) browser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Transport: st.site.Client().Transport, Timeout: 30 * time.Second}
}

func (st *stand) sessionCookie(b *http.Client) string {
	u, _ := url.Parse(st.site.URL)
	for _, c := range b.Jar.Cookies(u) {
		if c.Name == st.core.CookieName() {
			return c.Value
		}
	}
	return ""
}

// signIn runs the whole browser flow: the site's sign-in path, PAR, Keycloak's form, the callback, the return.
func (st *stand) signIn(t *testing.T, b *http.Client, returnTo string) *http.Response {
	t.Helper()
	res, err := b.Get(st.site.URL + core.LoginURL(returnTo))
	if err != nil {
		t.Fatal(err)
	}
	res, err = kctest.SignIn(b, res, st.person)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res
}

func TestSignInWithPARAndPrivateKeyJWTAgainstKeycloak(t *testing.T) {
	st := newStand(t)
	b := st.browser(t)
	res := st.signIn(t, b, "/app/page?x=1")
	if res.Request.URL.String() != st.site.URL+"/app/page?x=1" {
		t.Fatalf("landed at %s", res.Request.URL)
	}
	id := st.sessionCookie(b)
	if id == "" {
		t.Fatal("no session cookie")
	}
	// The cookie is S1's: __Host-, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain. The jar does not keep the attributes,
	// so the Set-Cookie line is checked in TestTheCallbackSetsTheS1Cookie.
	s, err := st.core.Load(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if s.Issuer != st.issuer || s.SID == "" || s.Claims.Email != "alice@example.test" || len(s.Claims.Groups) != 1 || s.Claims.Groups[0] != "admins" ||
		s.IDToken == "" || s.AccessToken == "" || s.RefreshToken == "" {
		t.Fatalf("session %+v", s.Claims)
	}
	d := st.core.Check(context.Background(), core.Request{Method: "GET", Path: "/app", Header: http.Header{"Cookie": {st.core.CookieName() + "=" + id}}})
	if d.Outcome != core.Allow || d.Subject != s.Subject {
		t.Fatalf("check: %+v", d)
	}
	// whoami
	res, err = b.Get(st.site.URL + core.PathWhoami)
	if err != nil {
		t.Fatal(err)
	}
	var who map[string]any
	_ = json.NewDecoder(res.Body).Decode(&who)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || who["sub"] != s.Subject || who["email"] != "alice@example.test" || who["expires_at"] == "" {
		t.Fatalf("whoami %d %v", res.StatusCode, who)
	}
	if k := st.audit.kinds(); len(k) != 1 || k[0] != "sign-in:" {
		t.Fatalf("events %v", k)
	}
}

// stopAt makes the browser stop following redirects at the site's callback, so a test can tamper with it.
func stopAtCallback(b *http.Client) {
	b.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Path == core.PathCallback {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

func (st *stand) toCallback(t *testing.T, b *http.Client) *url.URL {
	t.Helper()
	stopAtCallback(b)
	res, err := b.Get(st.site.URL + core.LoginURL("/app"))
	if err != nil {
		t.Fatal(err)
	}
	// With a Keycloak session already (single sign-on) Keycloak answers at once, without its form.
	if res.StatusCode != http.StatusFound {
		res, err = kctest.SignIn(b, res, st.person)
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = res.Body.Close()
	loc, err := res.Location()
	if err != nil || loc.Path != core.PathCallback {
		t.Fatalf("not at the callback: %d %v", res.StatusCode, err)
	}
	b.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return loc
}

func get(t *testing.T, b *http.Client, u string) *http.Response {
	t.Helper()
	res, err := b.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res
}

func TestTheCallbackSetsTheS1Cookie(t *testing.T) {
	st := newStand(t)
	b := st.browser(t)
	loc := st.toCallback(t, b)
	res := get(t, b, loc.String())
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/app" {
		t.Fatalf("callback %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	var line string
	for _, l := range res.Header.Values("Set-Cookie") {
		if strings.HasPrefix(l, st.core.CookieName()+"=") {
			line = l
		}
	}
	for _, want := range []string{"Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(line, want) {
			t.Fatalf("Set-Cookie %q lacks %s", line, want)
		}
	}
	if strings.Contains(strings.ToLower(line), "domain=") {
		t.Fatalf("Set-Cookie %q has a Domain", line)
	}
}

// Login CSRF and code injection: the callback needs the binding cookie of the browser that started the sign-in, the issuer's
// iss, and a state that is used once.
func TestTheCallbackRefusesAnotherBrowserATamperedIssAndAReplay(t *testing.T) {
	st := newStand(t)
	victim := st.browser(t)
	loc := st.toCallback(t, victim)
	// Another browser with the same callback address has no binding cookie.
	other := st.browser(t)
	other.CheckRedirect = victim.CheckRedirect
	if res := get(t, other, loc.String()); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("another browser: %d", res.StatusCode)
	}
	// The state is used: the right browser cannot use it after that.
	if res := get(t, victim, loc.String()); res.StatusCode != http.StatusBadRequest || st.sessionCookie(victim) != "" {
		t.Fatalf("replay: %d", res.StatusCode)
	}
	// A tampered iss.
	loc = st.toCallback(t, victim)
	q := loc.Query()
	q.Set("iss", "https://evil.example.test/realms/x")
	loc.RawQuery = q.Encode()
	if res := get(t, victim, loc.String()); res.StatusCode != http.StatusBadRequest || st.sessionCookie(victim) != "" {
		t.Fatalf("iss: %d", res.StatusCode)
	}
	// An unknown state.
	if res := get(t, victim, st.site.URL+core.PathCallback+"?state="+core.NewID()+"&code=x"); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown state: %d", res.StatusCode)
	}
}

func TestReturnToIsAPathOfTheSite(t *testing.T) {
	st := newStand(t)
	for _, rt := range []string{"https://evil.example.test/", "//evil.example.test/x", `/\evil.example.test`, "/_session/logout", "javascript:alert(1)"} {
		b := st.browser(t)
		res := st.signIn(t, b, rt)
		if res.Request.URL.String() != st.site.URL+"/" {
			t.Fatalf("return_to %q landed at %s", rt, res.Request.URL)
		}
	}
}

func csrfPost(t *testing.T, b *http.Client, u, origin string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, u, nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", origin)
	req.Header.Set("Accept", "application/json")
	res, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// S6: logout is a POST with CSRF; it ends the session and sends the browser to Keycloak's end-session with id_token_hint, which
// Keycloak takes without asking the person and sends back to the site.
func TestLogout(t *testing.T) {
	st := newStand(t)
	b := st.browser(t)
	st.signIn(t, b, "/")
	id := st.sessionCookie(b)
	// Without the CSRF headers: refused, the session stays.
	res, err := b.Post(st.site.URL+core.PathLogout, "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without CSRF: %d", res.StatusCode)
	}
	if _, err := st.core.Load(context.Background(), id); err != nil {
		t.Fatal("a refused logout ended the session")
	}
	res = csrfPost(t, b, st.site.URL+core.PathLogout, st.site.URL)
	var out struct {
		LogoutURL string `json:"logout_url"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(out.LogoutURL, st.issuer+"/protocol/openid-connect/logout?") || !strings.Contains(out.LogoutURL, "id_token_hint=") {
		t.Fatalf("logout %d %q", res.StatusCode, out.LogoutURL)
	}
	if _, err := st.core.Load(context.Background(), id); err == nil {
		t.Fatal("the session survived the logout")
	}
	if st.sessionCookie(b) != "" {
		t.Fatal("the cookie was not cleared")
	}
	res = get(t, b, out.LogoutURL)
	if res.Request.URL.String() != st.site.URL+"/" {
		t.Fatalf("end-session landed at %s (status %d)", res.Request.URL, res.StatusCode)
	}
	// Keycloak's own session is gone: a new sign-in shows the login form again.
	res, err = b.Get(st.site.URL + core.LoginURL("/"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kctest.SignIn(b, res, st.person); err != nil {
		t.Fatalf("no login form after the logout: %v", err)
	}
}

// Back-channel logout: Keycloak ends the person's session and posts a logout token; the session is gone at once, and a replayed
// token is refused.
func TestBackChannelLogoutFromKeycloak(t *testing.T) {
	st := newStand(t)
	b := st.browser(t)
	st.signIn(t, b, "/")
	id := st.sessionCookie(b)
	st.kc.LogoutUser(t, st.realm, st.person.Username)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := st.core.Load(context.Background(), id); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the session survived the back-channel logout")
		}
		time.Sleep(100 * time.Millisecond)
	}
	st.mu.Lock()
	tokens := append([]string(nil), st.captured...)
	st.mu.Unlock()
	if len(tokens) == 0 {
		t.Fatal("no logout token arrived")
	}
	res, err := http.PostForm(st.back.URL+core.PathBackChannel, url.Values{"logout_token": {tokens[0]}})
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a replayed logout token: %d", res.StatusCode)
	}
	// Not a logout token at all: an ID token of the same issuer is refused.
	st.signIn(t, b, "/")
	s, err := st.core.Load(context.Background(), st.sessionCookie(b))
	if err != nil {
		t.Fatal(err)
	}
	res, err = http.PostForm(st.back.URL+core.PathBackChannel, url.Values{"logout_token": {s.IDToken}})
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("an ID token as a logout token: %d", res.StatusCode)
	}
	if _, err := st.core.Load(context.Background(), st.sessionCookie(b)); err != nil {
		t.Fatal("an ID token ended a session")
	}
}

// A sign-in completes only after its event is accepted (decision 0008).
func TestASignInWithoutAuditIsRefused(t *testing.T) {
	st := newStand(t)
	st.audit.fail = true
	b := st.browser(t)
	res := st.signIn(t, b, "/")
	if res.StatusCode != http.StatusServiceUnavailable || st.sessionCookie(b) != "" {
		t.Fatalf("status %d", res.StatusCode)
	}
}

// The JWKS publishes the client key and the identity header's key, each with its own kid.
func TestJWKSPublishesTheClientKeyAndTheIdentityKey(t *testing.T) {
	st := newStand(t)
	set := st.jwks(t)
	if len(set.Keys) != 2 || set.Keys[0].KeyID == set.Keys[1].KeyID {
		t.Fatalf("jwks %+v", set)
	}
	for _, k := range set.Keys {
		if k.Algorithm != "ES256" || !k.IsPublic() || k.KeyID == "" || k.Use != "sig" {
			t.Fatalf("key %+v", k)
		}
	}
}

func (st *stand) jwks(t *testing.T) jose.JSONWebKeySet {
	t.Helper()
	res, err := http.Get(st.back.URL + core.PathJWKS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	return set
}

func exchangeRoutes(c *standConfig) {
	c.audiences = []string{"billing"}
	c.routes = []core.Route{
		{Name: "billing", Prefix: "/api/billing/", Mode: core.ModeExchange, Audience: "billing"},
		{Name: "nowhere", Prefix: "/api/nowhere/", Mode: core.ModeExchange, Audience: "no-such-client"},
		{Name: "legacy", Prefix: "/legacy/", Mode: core.ModeIdentityHeader, Audience: "legacy-app"},
		{Prefix: "/", Mode: core.ModeSession},
	}
}

func (st *stand) check(t *testing.T, id, path string) core.Decision {
	t.Helper()
	return st.core.Check(context.Background(), core.Request{Method: "GET", Host: strings.TrimPrefix(st.site.URL, "https://"), Path: path,
		Header: http.Header{"Cookie": {st.core.CookieName() + "=" + id}, "Accept": {"application/json"}}})
}

// The exchange against Keycloak's standard token exchange: the check gets a token whose audience is the route's API, signed
// by the realm; an audience the realm does not have is refused with a 403 and the session stays; once the sign-in token is
// old, it is refreshed first and the exchange takes the new one.
func TestExchangeAndRefreshAgainstKeycloak(t *testing.T) {
	st := newStand(t, exchangeRoutes)
	b := st.browser(t)
	st.signIn(t, b, "/")
	id := st.sessionCookie(b)
	ctx := context.Background()

	d := st.check(t, id, "/api/billing/x")
	tok, ok := strings.CutPrefix(d.Set["authorization"], "Bearer ")
	if d.Outcome != core.Allow || !ok {
		t.Fatalf("exchange: %+v %s", d, d.Body)
	}
	p, err := oidc.NewProvider(ctx, st.issuer)
	if err != nil {
		t.Fatal(err)
	}
	at, err := p.VerifierContext(ctx, &oidc.Config{ClientID: "billing"}).Verify(ctx, tok)
	if err != nil {
		t.Fatalf("the exchanged token: %v", err)
	}
	s, err := st.core.Load(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if at.Subject != s.Subject || tok == s.AccessToken {
		t.Fatalf("subject %q, the sign-in token itself %v", at.Subject, tok == s.AccessToken)
	}
	if again := st.check(t, id, "/api/billing/y"); again.Set["authorization"] != d.Set["authorization"] {
		t.Fatal("the second check did not take the cached token")
	}

	d = st.check(t, id, "/api/nowhere/x")
	if d.Status != http.StatusForbidden || d.Reason != "exchange_refused" {
		t.Fatalf("unknown audience: %d %q %s", d.Status, d.Reason, d.Body)
	}
	if _, err := st.core.Load(ctx, id); err != nil {
		t.Fatal("a refused exchange ended the session")
	}

	// Keycloak's access tokens live five minutes: six minutes on, the sign-in token is old and the cached token has ended.
	st.ahead.Store(int64(6 * time.Minute))
	d = st.check(t, id, "/api/billing/z")
	if d.Outcome != core.Allow || d.Set["authorization"] == "" {
		t.Fatalf("after the refresh: %+v %s", d, d.Body)
	}
	fresh, err := st.core.Load(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.AccessToken == s.AccessToken || fresh.AccessExpiry <= s.AccessExpiry {
		t.Fatal("the sign-in token was not refreshed")
	}
	kinds := st.audit.kinds()
	if !slices.Contains(kinds, "token-exchange:") || !slices.Contains(kinds, "token-exchange:invalid_client") && !slices.Contains(kinds, "token-exchange:invalid_request") && !slices.Contains(kinds, "token-exchange:invalid_target") {
		t.Fatalf("events %v", kinds)
	}
}

// The identity header is a JWS of typ session-identity+jwt that verifies with a key of /_session/jwks, with the person's
// claims and a life of a minute.
func TestTheIdentityHeaderVerifiesWithTheJWKS(t *testing.T) {
	st := newStand(t, exchangeRoutes)
	b := st.browser(t)
	st.signIn(t, b, "/")
	d := st.check(t, st.sessionCookie(b), "/legacy/x")
	h := d.Set[core.IdentityHeader]
	if d.Outcome != core.Allow || h == "" {
		t.Fatalf("decision %+v", d)
	}
	sig, err := jose.ParseSignedCompact(h, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	hdr := sig.Signatures[0].Protected
	if hdr.ExtraHeaders["typ"] != core.IdentityType {
		t.Fatalf("typ %v", hdr.ExtraHeaders["typ"])
	}
	set := st.jwks(t)
	keys := set.Key(hdr.KeyID)
	if len(keys) != 1 {
		t.Fatalf("the kid %q is not in the JWKS", hdr.KeyID)
	}
	payload, err := sig.Verify(keys[0])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Iss, Aud, Sub, Email string
		Groups               []string
		Iat, Exp             int64
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	if c.Iss != st.core.Origin() || c.Aud != "legacy-app" || c.Sub == "" || c.Email != st.person.Email ||
		!slices.Equal(c.Groups, []string{"admins"}) || c.Exp-c.Iat != 60 {
		t.Fatalf("claims %+v", c)
	}
}

// Both keys on AWS KMS (atoom's key/awskms over the in-process KMS double; no AWS is called): Keycloak takes the client
// assertion signed in KMS, whose kid is the key ARN and the fingerprint, for PAR, the code and the token exchange; the identity
// header verifies with the JWKS; the JWKS publishes the two KMS keys.
func TestKeysOnAWSKMSAgainstKeycloak(t *testing.T) {
	fake := kmstest.New()
	st := newStand(t, exchangeRoutes, func(c *standConfig) { c.kms = fake })
	set := st.jwks(t)
	if len(set.Keys) != 2 {
		t.Fatalf("jwks %+v", set)
	}
	for _, k := range set.Keys {
		if !strings.HasPrefix(k.KeyID, "arn:aws:kms:") || k.Algorithm != "ES256" {
			t.Fatalf("key %+v", k)
		}
	}
	b := st.browser(t)
	signs := fake.Signs.Load()
	st.signIn(t, b, "/")
	id := st.sessionCookie(b)
	if id == "" {
		t.Fatal("no session")
	}
	if fake.Signs.Load() == signs {
		t.Fatal("the client assertion was not signed in KMS")
	}
	d := st.check(t, id, "/api/billing/x")
	if d.Outcome != core.Allow || !strings.HasPrefix(d.Set["authorization"], "Bearer ") {
		t.Fatalf("exchange: %+v %s", d, d.Body)
	}
	d = st.check(t, id, "/legacy/x")
	sig, err := jose.ParseSignedCompact(d.Set[core.IdentityHeader], []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	keys := set.Key(sig.Signatures[0].Protected.KeyID)
	if len(keys) != 1 {
		t.Fatalf("the kid %q is not in the JWKS", sig.Signatures[0].Protected.KeyID)
	}
	if _, err := sig.Verify(keys[0]); err != nil {
		t.Fatal(err)
	}
}
