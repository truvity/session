package nginx_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/nginx"
	"github.com/truvity/session/internal/sealer/sealertest"
	"github.com/truvity/session/internal/storetest"
)

type site struct {
	core *core.Core
	mem  *storetest.Store
}

func newSite(t *testing.T) *site {
	t.Helper()
	mem := storetest.New(nil)
	items, stop := mem.Client()
	t.Cleanup(stop)
	sealer := sealertest.New(t)
	c, err := core.New(core.Options{Items: items, Seal: sealer, Issuer: issuer{}, Identity: signer{}, Rules: core.Rules{
		Site: "docs", Host: "docs.example.test", StoreTimeout: 300 * time.Millisecond,
		Routes: []core.Route{
			{Prefix: "/assets/", Mode: core.ModePublic},
			{Prefix: "/api/billing/", Mode: core.ModeExchange, Audience: "billing"},
			{Prefix: "/api/refused/", Mode: core.ModeExchange, Audience: "refused"},
			{Prefix: "/legacy/", Mode: core.ModeIdentityHeader},
			{Prefix: "/", Mode: core.ModeSession},
		}}})
	if err != nil {
		t.Fatal(err)
	}
	return &site{core: c, mem: mem}
}

// issuer and signer stand in for the issuer's token endpoint and the key port: the adapter only carries what the core decides.
// The issuer refuses the exchange for the audience "refused", and every refresh.
type issuer struct{}

func (issuer) Exchange(_ context.Context, _, audience string) (core.Token, error) {
	if audience == "refused" {
		return core.Token{}, &core.RefusedError{Code: "access_denied"}
	}
	return core.Token{AccessToken: "token-for-" + audience, ExpiresIn: time.Minute}, nil
}

func (issuer) Refresh(context.Context, string) (core.Refreshed, error) {
	return core.Refreshed{}, &core.RefusedError{Code: "invalid_grant"}
}

type signer struct{}

func (signer) Sign(_ context.Context, claims map[string]any) (string, error) {
	return "signed-identity-of-" + fmt.Sprint(claims["sub"]), nil
}

func (s *site) signIn(t *testing.T, r *core.Record) string {
	t.Helper()
	if r == nil {
		r = &core.Record{Subject: "alice", Issuer: "https://issuer.example.test", SID: "sid-1"}
	}
	id, err := s.core.Create(context.Background(), r, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// expired is a session whose sign-in token has ended and that has no refresh token: its next exchange ends it.
func expired() *core.Record {
	return &core.Record{Subject: "bob", Issuer: "https://issuer.example.test", SID: "sid-2", AccessToken: "old",
		AccessExpiry: time.Now().Add(-time.Minute).Unix()}
}

func TestHandler(t *testing.T) {
	s := newSite(t)
	srv := httptest.NewServer(&nginx.Handler{Core: s.core, ErrorPage: []byte("<p>refused</p>")})
	defer srv.Close()
	id := s.signIn(t, nil)
	ck := s.core.CookieName() + "=" + id
	do := func(path string, h ...string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Host = "docs.example.test"
		for i := 0; i+1 < len(h); i += 2 {
			req.Header.Add(h[i], h[i+1])
		}
		res, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}
	check := func(method, uri string, h ...string) *http.Response {
		return do(nginx.PathCheck, append([]string{nginx.HeaderURI, uri, nginx.HeaderMethod, method}, h...)...)
	}

	res := check("GET", "/app", "Cookie", "a=1; "+ck)
	if res.StatusCode != http.StatusOK || res.Header.Get("Cookie") != "a=1" || res.Header.Get("Authorization") != "" {
		t.Fatalf("allow: %d %v", res.StatusCode, res.Header)
	}
	res = check("GET", "/api/billing/x", "Cookie", ck)
	if res.Header.Get("Authorization") != "Bearer token-for-billing" || res.Header.Get("Cookie") != "" {
		t.Fatalf("exchange: %v", res.Header)
	}
	res = check("GET", "/legacy/x", "Cookie", ck)
	if res.Header.Get(core.IdentityHeader) != "signed-identity-of-alice" {
		t.Fatalf("identity header: %v", res.Header)
	}
	// The method is X-Original-Method's, not the subrequest's: a POST without the CSRF header is refused.
	res = check("POST", "/app", "Cookie", ck)
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get(nginx.HeaderStatus) != "403" ||
		res.Header.Get(nginx.HeaderAction) != nginx.ActionDeny || res.Header.Get(nginx.HeaderBody) != `{"error":"csrf"}` {
		t.Fatalf("csrf: %d %v", res.StatusCode, res.Header)
	}
	res = check("GET", "/app?x=1", "Sec-Fetch-Mode", "navigate", "Accept", "text/html")
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get(nginx.HeaderAction) != nginx.ActionRedirect ||
		res.Header.Get(nginx.HeaderStatus) != "302" || res.Header.Get(nginx.HeaderLocation) != "/_session/login?return_to=%2Fapp%3Fx%3D1" {
		t.Fatalf("redirect: %d %v", res.StatusCode, res.Header)
	}
	res = check("GET", "/api/x")
	if res.Header.Get(nginx.HeaderStatus) != "401" || !strings.Contains(res.Header.Get(nginx.HeaderBody), `"login_required"`) ||
		res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("401: %v", res.Header)
	}
	res = check("GET", "/api/refused/x", "Cookie", ck, "Sec-Fetch-Mode", "navigate", "Accept", "text/html")
	if res.Header.Get(nginx.HeaderAction) != nginx.ActionPage || res.Header.Get(nginx.HeaderStatus) != "403" {
		t.Fatalf("page: %v", res.Header)
	}
	res = do(nginx.PathErrorPage)
	if res.StatusCode != http.StatusForbidden || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("error page: %d %v", res.StatusCode, res.Header)
	}
	// A session that ends at its exchange: the cookie is cleared on the refusal.
	res = check("GET", "/api/billing/x", "Cookie", s.core.CookieName()+"="+s.signIn(t, expired()))
	if res.Header.Get(nginx.HeaderStatus) != "401" || !strings.Contains(res.Header.Get("Set-Cookie"), s.core.CookieName()+"=;") {
		t.Fatalf("session ended: %v", res.Header)
	}
	// Without the headers nginx sets, the check refuses rather than check the subrequest's own path.
	if res := do(nginx.PathCheck, "Cookie", ck); res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("no X-Original-URI: %d", res.StatusCode)
	}
	if res := do("/elsewhere"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("other path: %d", res.StatusCode)
	}
	s.mem.Down.Store(true)
	res = check("GET", "/app", "Cookie", ck)
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get(nginx.HeaderStatus) != "503" {
		t.Fatalf("503: %d %v", res.StatusCode, res.Header)
	}
}

// ---- nginx in a container ----

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func serveOn(t *testing.T, h http.Handler) (int, *http.Server) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().(*net.TCPAddr).Port, srv
}

// seen is what the site behind nginx received: the path and the headers. The test site echoes them; session never does.
type seen struct {
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
}

type proxy struct {
	url   string
	site  *site
	check *http.Server
}

// placeholder is a ${NAME} of the example; nginx's own $variables are left alone.
var placeholder = regexp.MustCompile(`\$\{([A-Z_]+)\}`)

// startNginx runs examples/nginx/nginx.conf in nginx, with the check, the sign-in stub and the site of this test behind it.
func startNginx(t *testing.T) *proxy {
	t.Helper()
	image := os.Getenv("SESSION_TEST_NGINX_IMAGE")
	if image == "" {
		t.Skip("no nginx: run `just test-nginx` (SESSION_TEST_NGINX_IMAGE is not set)")
	}
	s := newSite(t)
	p := &proxy{site: s}
	checkPort, checkSrv := serveOn(t, &nginx.Handler{Core: s.core, ErrorPage: s.core.Rules().ErrorPage})
	p.check = checkSrv
	signinStub, _ := serveOn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "sign-in path "+r.URL.Path) //nolint:gosec // G705: a test stub, text/plain
	}))
	sitePort, _ := serveOn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/fails" {
			http.Error(w, "the site failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(seen{Path: r.URL.RequestURI(), Headers: r.Header})
	}))

	ports := map[string]int{"NGINX_PORT": freePort(t), "SESSION_CHECK_PORT": checkPort, "SESSION_SIGNIN_PORT": signinStub, "SITE_PORT": sitePort}
	tmpl, err := os.ReadFile("../../examples/nginx/nginx.conf")
	if err != nil {
		t.Fatal(err)
	}
	cfg := placeholder.ReplaceAllStringFunc(string(tmpl), func(m string) string {
		v, ok := ports[placeholder.FindStringSubmatch(m)[1]]
		if !ok {
			t.Fatalf("the example names %s, which the test does not fill", m)
		}
		return fmt.Sprint(v)
	})
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: nginx's own user reads the file
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(cfg), 0o644); err != nil { //nolint:gosec // G306: as above
		t.Fatal(err)
	}
	name := fmt.Sprintf("session-test-nginx-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "--network", "host", //nolint:gosec // G204: the test's own image and file
		"-v", dir+":/etc/session-test:ro", "--entrypoint", "nginx", image, "-g", "daemon off;", "-c", "/etc/session-test/nginx.conf").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v %s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", "--tail", "30", name).CombinedOutput() //nolint:gosec // G204: as above
			t.Logf("nginx logs:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run() //nolint:gosec // G204: as above
	})
	p.url = fmt.Sprintf("http://127.0.0.1:%d", ports["NGINX_PORT"])
	deadline := time.Now().Add(60 * time.Second)
	for {
		res, err := http.Get(p.url + "/_session/ready")
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "30", name).CombinedOutput() //nolint:gosec // G204: as above
			t.Fatalf("nginx did not become ready:\n%s", logs)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return p
}

var noRedirect = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// call sends a request with its path as given: Go's client does not clean dot segments or merge slashes, so they reach nginx.
func call(t *testing.T, method, base, path string, h ...string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "docs.example.test"
	for i := 0; i+1 < len(h); i += 2 {
		req.Header.Add(h[i], h[i+1])
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res, b
}

func siteSaw(t *testing.T, b []byte) seen {
	t.Helper()
	var s seen
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("not the site's answer: %q", b)
	}
	return s
}

// The behaviour of decisions 0011 and 0018 through a real nginx: the same answers as on Envoy, the same stripping, fail closed.
func TestThroughNginx(t *testing.T) {
	p := startNginx(t)
	base := p.url
	id := p.site.signIn(t, nil)
	ck := p.site.core.CookieName() + "=" + id

	// A valid session: the site sees the request, without Authorization, the identity headers or session's cookie.
	res, b := call(t, "GET", base, "/app/x?q=1", "Cookie", "theme=dark; "+ck, "Authorization", "Bearer forged",
		"X-Session-Identity", "forged", "X-Session-Token", "forged")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("allow: %d %s", res.StatusCode, b)
	}
	got := siteSaw(t, b)
	for _, h := range []string{"Authorization", "X-Session-Identity", "X-Session-Token", "X-Session-Action", "X-Original-Uri"} {
		if v, ok := got.Headers[h]; ok {
			t.Fatalf("the site got %s %q", h, v)
		}
	}
	if c := got.Headers["Cookie"]; len(c) != 1 || c[0] != "theme=dark" {
		t.Fatalf("the site got Cookie %q", c)
	}
	if got.Path != "/app/x?q=1" {
		t.Fatalf("the site got the path %q", got.Path)
	}
	// The check sees the request's path, not the subrequest's: a public route passes without a session.
	res, b = call(t, "GET", base, "/assets/app.js")
	if res.StatusCode != http.StatusOK || siteSaw(t, b).Path != "/assets/app.js" {
		t.Fatalf("public route: %d %s", res.StatusCode, b)
	}
	// An exchange route: the site gets the token of its audience, once, never the browser's Authorization; and no identity
	// header. An identity-header route: the signed identity, and no Authorization.
	_, b = call(t, "GET", base, "/api/billing/x", "Cookie", ck, "Authorization", "Bearer forged", "X-Session-Identity", "forged")
	got = siteSaw(t, b)
	if a := got.Headers["Authorization"]; len(a) != 1 || a[0] != "Bearer token-for-billing" {
		t.Fatalf("the exchange route's site got Authorization %q", a)
	}
	if v, ok := got.Headers["X-Session-Identity"]; ok {
		t.Fatalf("the exchange route's site got X-Session-Identity %q", v)
	}
	_, b = call(t, "GET", base, "/legacy/x", "Cookie", ck, "Authorization", "Bearer forged", "X-Session-Identity", "forged")
	got = siteSaw(t, b)
	if v := got.Headers["X-Session-Identity"]; len(v) != 1 || v[0] != "signed-identity-of-alice" {
		t.Fatalf("the identity route's site got X-Session-Identity %q", v)
	}
	if v, ok := got.Headers["Authorization"]; ok {
		t.Fatalf("the identity route's site got Authorization %q", v)
	}
	// Only the session cookie: the site gets no Cookie header at all.
	_, b = call(t, "GET", base, "/app/x", "Cookie", ck)
	if c, ok := siteSaw(t, b).Headers["Cookie"]; ok {
		t.Fatalf("the site got Cookie %q", c)
	}
	// No session: a navigation is redirected, a fetch gets the JSON 401; neither is cached.
	res, _ = call(t, "GET", base, "/app/x?q=1", "Sec-Fetch-Mode", "navigate", "Accept", "text/html")
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/_session/login?return_to=%2Fapp%2Fx%3Fq%3D1" ||
		res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("redirect: %d %v", res.StatusCode, res.Header)
	}
	res, b = call(t, "GET", base, "/api/x", "Accept", "application/json")
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get("Content-Type") != "application/json" ||
		string(b) != `{"error":"login_required","login_url":"/_session/login?return_to=%2Fapi%2Fx"}` {
		t.Fatalf("401: %d %q %s", res.StatusCode, res.Header.Get("Content-Type"), b)
	}
	// CSRF: the method and the custom header reach the check, and the header's absence is refused.
	res, b = call(t, "POST", base, "/api/x", "Cookie", ck, "X-Requested-With", "XMLHttpRequest", "Origin", "https://docs.example.test")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST with CSRF headers: %d %s", res.StatusCode, b)
	}
	res, b = call(t, "POST", base, "/api/x", "Cookie", ck, "Origin", "https://docs.example.test")
	if res.StatusCode != http.StatusForbidden || string(b) != `{"error":"csrf"}` {
		t.Fatalf("POST without the CSRF header: %d %s", res.StatusCode, b)
	}
	// A refused exchange: the site's error page to a navigation, JSON to a fetch; both 403.
	res, b = call(t, "GET", base, "/api/refused/x", "Cookie", ck, "Sec-Fetch-Mode", "navigate", "Accept", "text/html")
	if res.StatusCode != http.StatusForbidden || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(string(b), "Access refused") {
		t.Fatalf("refused exchange, navigation: %d %v %s", res.StatusCode, res.Header, b)
	}
	res, b = call(t, "GET", base, "/api/refused/x", "Cookie", ck)
	if res.StatusCode != http.StatusForbidden || string(b) != `{"error":"exchange_refused"}` {
		t.Fatalf("refused exchange, fetch: %d %s", res.StatusCode, b)
	}
	// A session that ends at its exchange: the browser gets the 401 and the cleared cookie.
	res, _ = call(t, "GET", base, "/api/billing/x", "Cookie", p.site.core.CookieName()+"="+p.site.signIn(t, expired()))
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("Set-Cookie"), p.site.core.CookieName()+"=;") {
		t.Fatalf("session ended: %d %v", res.StatusCode, res.Header)
	}
	// The sign-in prefix is routed to session without a check.
	res, b = call(t, "GET", base, "/_session/login?return_to=%2F", "Sec-Fetch-Mode", "navigate", "Accept", "text/html")
	if res.StatusCode != http.StatusOK || string(b) != "sign-in path /_session/login" {
		t.Fatalf("sign-in path: %d %s", res.StatusCode, b)
	}
	// The internal locations cannot be reached from outside.
	for _, path := range []string{"/_session_check", "/_session_error_page"} {
		res, b = call(t, "GET", base, path, "Cookie", ck)
		if res.StatusCode == http.StatusOK || strings.Contains(string(b), "Access refused") {
			t.Fatalf("%s from outside: %d %s", path, res.StatusCode, b)
		}
	}
	// The site's own 500 is not taken for an unreachable check.
	res, b = call(t, "GET", base, "/app/fails", "Cookie", ck)
	if res.StatusCode != http.StatusInternalServerError || !strings.Contains(string(b), "the site failed") {
		t.Fatalf("the site's 500: %d %s", res.StatusCode, b)
	}
	// Path confusion: nginx passes the site the URI as the browser sent it, so a path the site could read differently from
	// the $uri the check gets is refused, with or without a session. Merged slashes are checked as the merged path.
	for _, path := range []string{"/assets/../app/x", "/app/../assets/x", "/assets/%2e%2e/app/x", "/assets/%2E%2E/app/x",
		"/assets%2F..%2Fapp/x", "/assets/.%2e/app/x", "/./app/x", "/app/x/..", "/assets/%5c../app/x"} {
		res, b = call(t, "GET", base, path, "Cookie", ck)
		if res.StatusCode != http.StatusBadRequest || string(b) != `{"error":"bad_path"}` {
			t.Fatalf("%s: %d %s", path, res.StatusCode, b)
		}
	}
	res, _ = call(t, "GET", base, "//app//x")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("merged slashes, private: %d", res.StatusCode)
	}
	res, _ = call(t, "GET", base, "//assets//app.js")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("merged slashes, public: %d", res.StatusCode)
	}
	// Fail closed: a store that is down is a 503 (decision 0018: not nginx's 500).
	p.site.mem.Down.Store(true)
	res, b = call(t, "GET", base, "/app/x", "Cookie", ck)
	if res.StatusCode != http.StatusServiceUnavailable || string(b) != `{"error":"unavailable"}` {
		t.Fatalf("store down: %d %s", res.StatusCode, b)
	}
	p.site.mem.Down.Store(false)
	// A check that cannot be reached is a 503 too, never an allow; the site's own 500 passes as it is.
	_ = p.check.Close()
	res, b = call(t, "GET", base, "/app/x", "Cookie", ck)
	if res.StatusCode != http.StatusServiceUnavailable || string(b) != `{"error":"unavailable"}` {
		t.Fatalf("check unreachable: %d %s", res.StatusCode, b)
	}
	res, _ = call(t, "GET", base, "/assets/app.js")
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("check unreachable, public route: %d", res.StatusCode)
	}
}
