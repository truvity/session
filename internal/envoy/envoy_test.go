package envoy_test

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
	"slices"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/envoy"
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
			{Prefix: "/legacy/", Mode: core.ModeIdentityHeader},
			{Prefix: "/", Mode: core.ModeSession},
		}}})
	if err != nil {
		t.Fatal(err)
	}
	return &site{core: c, mem: mem}
}

// issuer and signer stand in for the issuer's token endpoint and the key port: the adapters only carry what the core decides.
type issuer struct{}

func (issuer) Exchange(_ context.Context, _, audience string) (core.Token, error) {
	return core.Token{AccessToken: "token-for-" + audience, ExpiresIn: time.Minute}, nil
}

func (issuer) Refresh(context.Context, string) (core.Refreshed, error) {
	return core.Refreshed{}, &core.RefusedError{Code: "invalid_grant"}
}

type signer struct{}

func (signer) Sign(_ context.Context, claims map[string]any) (string, error) {
	return "signed-identity-of-" + fmt.Sprint(claims["sub"]), nil
}

func (s *site) signIn(t *testing.T) string {
	t.Helper()
	id, err := s.core.Create(context.Background(), &core.Record{Subject: "alice", Issuer: "https://issuer.example.test", SID: "sid-1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func checkRequest(method, path string, h map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
		Http: &authv3.AttributeContext_HttpRequest{Method: method, Path: path, Host: "docs.example.test", Headers: h}}}}
}

func headerValue(hs []*corev3.HeaderValueOption, k string) (string, bool) {
	for _, h := range hs {
		if h.GetHeader().GetKey() == k {
			return h.GetHeader().GetValue(), true
		}
	}
	return "", false
}

func TestGRPCAdapter(t *testing.T) {
	s := newSite(t)
	g := &envoy.GRPC{Core: s.core}
	ctx := context.Background()
	id := s.signIn(t)

	res, _ := g.Check(ctx, checkRequest("GET", "/app", map[string]string{"cookie": "a=1; " + s.core.CookieName() + "=" + id, ":path": "/ignored"}))
	ok := res.GetOkResponse()
	if res.GetStatus().GetCode() != int32(codes.OK) || ok == nil {
		t.Fatalf("allow: %v", res)
	}
	if v, _ := headerValue(ok.GetHeaders(), "cookie"); v != "a=1" {
		t.Fatalf("cookie %q", v)
	}
	if !slices.Contains(ok.GetHeadersToRemove(), "authorization") {
		t.Fatalf("remove %v", ok.GetHeadersToRemove())
	}

	res, _ = g.Check(ctx, checkRequest("GET", "/app?x=1", map[string]string{"sec-fetch-mode": "navigate", "accept": "text/html"}))
	den := res.GetDeniedResponse()
	if res.GetStatus().GetCode() != int32(codes.PermissionDenied) || den.GetStatus().GetCode() != 302 {
		t.Fatalf("redirect: %v", res)
	}
	if v, _ := headerValue(den.GetHeaders(), "location"); v != "/_session/login?return_to=%2Fapp%3Fx%3D1" {
		t.Fatalf("location %q", v)
	}

	res, _ = g.Check(ctx, checkRequest("GET", "/api/x", nil))
	den = res.GetDeniedResponse()
	if v, _ := headerValue(den.GetHeaders(), "content-type"); den.GetStatus().GetCode() != 401 || v != "application/json" || !strings.Contains(den.GetBody(), "login_required") {
		t.Fatalf("401: %v", res)
	}

	// An exchange route: the token is set over a browser-sent Authorization and is not also removed.
	res, _ = g.Check(ctx, checkRequest("GET", "/api/billing/x", map[string]string{"cookie": s.core.CookieName() + "=" + id, "authorization": "Bearer forged"}))
	ok = res.GetOkResponse()
	if v, _ := headerValue(ok.GetHeaders(), "authorization"); v != "Bearer token-for-billing" || slices.Contains(ok.GetHeadersToRemove(), "authorization") {
		t.Fatalf("exchange: %v", res)
	}

	s.mem.Down.Store(true)
	res, _ = g.Check(ctx, checkRequest("GET", "/app", map[string]string{"cookie": s.core.CookieName() + "=" + id}))
	if res.GetStatus().GetCode() != int32(codes.Unavailable) || res.GetDeniedResponse().GetStatus().GetCode() != 503 {
		t.Fatalf("503: %v", res)
	}
}

func TestHTTPAdapter(t *testing.T) {
	s := newSite(t)
	srv := httptest.NewServer(&envoy.HTTP{Core: s.core, Prefix: "/check"})
	defer srv.Close()
	id := s.signIn(t)
	do := func(method, path string, h ...string) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+"/check"+path, nil)
		for i := 0; i+1 < len(h); i += 2 {
			req.Header.Add(h[i], h[i+1])
		}
		res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}
	res := do("GET", "/app", "Cookie", s.core.CookieName()+"="+id)
	if res.StatusCode != http.StatusOK || !strings.Contains(res.Header.Get(envoy.HeadersToRemove), "cookie") || !strings.Contains(res.Header.Get(envoy.HeadersToRemove), "authorization") {
		t.Fatalf("allow: %d %v", res.StatusCode, res.Header)
	}
	res = do("GET", "/app", "Cookie", "a=1; "+s.core.CookieName()+"="+id)
	if res.Header.Get("Cookie") != "a=1" || strings.Contains(res.Header.Get(envoy.HeadersToRemove), "cookie") {
		t.Fatalf("allow with a cookie: %v", res.Header)
	}
	res = do("GET", "/legacy/x", "Cookie", s.core.CookieName()+"="+id)
	if res.Header.Get(core.IdentityHeader) != "signed-identity-of-alice" || strings.Contains(res.Header.Get(envoy.HeadersToRemove), core.IdentityHeader) {
		t.Fatalf("identity header: %v", res.Header)
	}
	res = do("GET", "/app", "Sec-Fetch-Mode", "navigate", "Accept", "text/html")
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/_session/login?return_to=%2Fapp" {
		t.Fatalf("redirect: %d %v", res.StatusCode, res.Header)
	}
	if res := do("GET", "/elsewhere-than-check"); res.StatusCode != http.StatusOK && res.StatusCode != http.StatusFound && res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", res.StatusCode)
	}
}

// ---- Envoy in a container ----

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func serveOn(t *testing.T, h http.Handler) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().(*net.TCPAddr).Port
}

// seen is what the site behind Envoy received: the path and the headers. The test site echoes them; session never does.
type seen struct {
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
}

type proxy struct {
	grpcURL, httpURL string
	site             *site
	grpcSrv          *grpc.Server
}

// startEnvoy runs examples/envoy/envoy.yaml in Envoy, with the check, the sign-in stub and the site of this test behind it.
func startEnvoy(t *testing.T) *proxy {
	t.Helper()
	image := os.Getenv("SESSION_TEST_ENVOY_IMAGE")
	if image == "" {
		t.Skip("no Envoy: run `just test-envoy` (SESSION_TEST_ENVOY_IMAGE is not set)")
	}
	s := newSite(t)
	p := &proxy{site: s}

	gl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.grpcSrv = grpc.NewServer()
	authv3.RegisterAuthorizationServer(p.grpcSrv, &envoy.GRPC{Core: s.core})
	go func() { _ = p.grpcSrv.Serve(gl) }()
	t.Cleanup(p.grpcSrv.Stop)

	httpCheck := serveOn(t, &envoy.HTTP{Core: s.core, Prefix: "/check"})
	signinStub := serveOn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "sign-in path "+r.URL.Path) //nolint:gosec // G705: a test stub, text/plain
	}))
	sitePort := serveOn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(seen{Path: r.URL.RequestURI(), Headers: r.Header})
	}))

	ports := map[string]int{"ADMIN_PORT": freePort(t), "GRPC_MODE_PORT": freePort(t), "HTTP_MODE_PORT": freePort(t),
		"SESSION_GRPC_PORT": gl.Addr().(*net.TCPAddr).Port, "SESSION_HTTP_PORT": httpCheck, "SESSION_SIGNIN_PORT": signinStub, "SITE_PORT": sitePort}
	tmpl, err := os.ReadFile("../../examples/envoy/envoy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := os.Expand(string(tmpl), func(k string) string { return fmt.Sprint(ports[k]) })
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: Envoy's own user reads the file
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "envoy.yaml"), []byte(cfg), 0o644); err != nil { //nolint:gosec // G306: as above
		t.Fatal(err)
	}
	name := fmt.Sprintf("session-test-envoy-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "--network", "host", //nolint:gosec // G204: the test's own image and file
		"-v", dir+":/etc/session-test:ro", image, "-c", "/etc/session-test/envoy.yaml", "--base-id", fmt.Sprint(ports["ADMIN_PORT"])).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v %s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", "--tail", "30", name).CombinedOutput() //nolint:gosec // G204: as above
			t.Logf("envoy logs:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run() //nolint:gosec // G204: as above
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		res, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/ready", ports["ADMIN_PORT"]))
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Envoy did not become ready")
		}
		time.Sleep(200 * time.Millisecond)
	}
	p.grpcURL = fmt.Sprintf("http://127.0.0.1:%d", ports["GRPC_MODE_PORT"])
	p.httpURL = fmt.Sprintf("http://127.0.0.1:%d", ports["HTTP_MODE_PORT"])
	return p
}

var noRedirect = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func call(t *testing.T, method, url string, h ...string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
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

// The behaviour of decision 0011 through a real Envoy, in both modes: the same answers, the same stripping, fail closed.
func TestThroughEnvoy(t *testing.T) {
	p := startEnvoy(t)
	id := p.site.signIn(t)
	ck := p.site.core.CookieName() + "=" + id
	for mode, base := range map[string]string{"grpc": p.grpcURL, "http": p.httpURL} {
		t.Run(mode, func(t *testing.T) {
			// A valid session: the site sees the request, without Authorization, the identity headers or session's cookie.
			res, b := call(t, "GET", base+"/app/x?q=1", "Cookie", "theme=dark; "+ck, "Authorization", "Bearer forged",
				"X-Session-Identity", "forged", "X-Session-Token", "forged")
			if res.StatusCode != http.StatusOK {
				t.Fatalf("allow: %d %s", res.StatusCode, b)
			}
			got := siteSaw(t, b)
			for _, h := range []string{"Authorization", "X-Session-Identity", "X-Session-Token"} {
				if v, ok := got.Headers[h]; ok {
					t.Fatalf("the site got %s (%d values)", h, len(v))
				}
			}
			if c := got.Headers["Cookie"]; len(c) != 1 || c[0] != "theme=dark" {
				t.Fatalf("the site got Cookie %q", c)
			}
			// An exchange route: the site gets the token of its audience, once, never the browser's Authorization; and no
			// identity header. An identity-header route: the signed identity, and no Authorization.
			_, b = call(t, "GET", base+"/api/billing/x", "Cookie", ck, "Authorization", "Bearer forged", "X-Session-Identity", "forged")
			got = siteSaw(t, b)
			if a := got.Headers["Authorization"]; len(a) != 1 || a[0] != "Bearer token-for-billing" {
				t.Fatalf("the exchange route's site got Authorization %q", a)
			}
			if v, ok := got.Headers["X-Session-Identity"]; ok {
				t.Fatalf("the exchange route's site got X-Session-Identity %q", v)
			}
			_, b = call(t, "GET", base+"/legacy/x", "Cookie", ck, "Authorization", "Bearer forged", "X-Session-Identity", "forged")
			got = siteSaw(t, b)
			if v := got.Headers["X-Session-Identity"]; len(v) != 1 || v[0] != "signed-identity-of-alice" {
				t.Fatalf("the identity route's site got X-Session-Identity %q", v)
			}
			if v, ok := got.Headers["Authorization"]; ok {
				t.Fatalf("the identity route's site got Authorization %q", v)
			}
			// Only the session cookie: the site gets no Cookie header at all.
			_, b = call(t, "GET", base+"/app/x", "Cookie", ck)
			if c, ok := siteSaw(t, b).Headers["Cookie"]; ok {
				t.Fatalf("the site got Cookie %q", c)
			}
			// No session: a navigation is redirected, a fetch gets the JSON 401.
			res, _ = call(t, "GET", base+"/app/x?q=1", "Sec-Fetch-Mode", "navigate", "Accept", "text/html")
			if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/_session/login?return_to=%2Fapp%2Fx%3Fq%3D1" {
				t.Fatalf("redirect: %d %q", res.StatusCode, res.Header.Get("Location"))
			}
			res, b = call(t, "GET", base+"/api/x", "Accept", "application/json")
			if res.StatusCode != http.StatusUnauthorized || res.Header.Get("Content-Type") != "application/json" || !strings.Contains(string(b), `"login_required"`) {
				t.Fatalf("401: %d %q %s", res.StatusCode, res.Header.Get("Content-Type"), b)
			}
			// CSRF: the custom header reaches the check (allowed_headers), and its absence is refused.
			res, _ = call(t, "POST", base+"/api/x", "Cookie", ck, "X-Requested-With", "XMLHttpRequest", "Origin", "https://docs.example.test")
			if res.StatusCode != http.StatusOK {
				t.Fatalf("POST with CSRF headers: %d", res.StatusCode)
			}
			res, _ = call(t, "POST", base+"/api/x", "Cookie", ck, "Origin", "https://docs.example.test")
			if res.StatusCode != http.StatusForbidden {
				t.Fatalf("POST without the CSRF header: %d", res.StatusCode)
			}
			// The sign-in prefix is routed to session without a check.
			res, b = call(t, "GET", base+"/_session/login?return_to=/", "Sec-Fetch-Mode", "navigate", "Accept", "text/html")
			if res.StatusCode != http.StatusOK || string(b) != "sign-in path /_session/login" {
				t.Fatalf("sign-in path: %d %s", res.StatusCode, b)
			}
			// Path confusion: the check sees the path the router uses. A dot segment under a public prefix is normalised
			// to the private path and needs a session; an encoded slash is refused by Envoy.
			res, _ = call(t, "GET", base+"/assets/../app/x")
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("dot segment: %d", res.StatusCode)
			}
			res, _ = call(t, "GET", base+"/assets/%2e%2e/app/x")
			if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusBadRequest { // normalised by Envoy, or refused by the check
				t.Fatalf("encoded dot segment: %d", res.StatusCode)
			}
			res, b = call(t, "GET", base+"//assets//app.js")
			if res.StatusCode != http.StatusOK || siteSaw(t, b).Path != "/assets/app.js" {
				t.Fatalf("merged slashes: %d %s", res.StatusCode, b)
			}
			res, _ = call(t, "GET", base+"/assets%2F..%2Fapp/x")
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("encoded slash: %d", res.StatusCode)
			}
		})
	}
	// Fail closed: a store that is down is a 503 in both modes (the body is lost in HTTP mode, decision 0011).
	p.site.mem.Down.Store(true)
	for mode, base := range map[string]string{"grpc": p.grpcURL, "http": p.httpURL} {
		res, _ := call(t, "GET", base+"/app/x", "Cookie", ck)
		if res.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s, store down: %d", mode, res.StatusCode)
		}
	}
	p.site.mem.Down.Store(false)
	// A check that cannot be reached is Envoy's status_on_error, 503, never an allow.
	p.grpcSrv.Stop()
	res, _ := call(t, "GET", p.grpcURL+"/app/x", "Cookie", ck)
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("check unreachable: %d", res.StatusCode)
	}
}
