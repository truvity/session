package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc"

	"github.com/truvity/atoom/key/awskms"

	"github.com/truvity/session/conformance/echo"
	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/audit"
	"github.com/truvity/session/internal/envoy"
	"github.com/truvity/session/internal/exchange"
	"github.com/truvity/session/internal/kctest"
	"github.com/truvity/session/internal/nginx"
	"github.com/truvity/session/internal/policy/policytest"
	"github.com/truvity/session/internal/sealer/sealertest"
	"github.com/truvity/session/internal/signin"
	"github.com/truvity/session/internal/storetest"
)

// siteName is the host name the browser uses for the site. The browser maps it to the loopback (--host-resolver-rules), so the
// site's cookies are apart from Keycloak's, which the browser reaches at 127.0.0.1.
const siteName = "docs.example.test"

// The routes of the suite: one of each mode, and an exchange the issuer refuses.
var routes = []core.Route{
	{Name: "assets", Prefix: "/assets/", Mode: core.ModePublic},
	{Name: "billing", Prefix: "/api/billing/", Mode: core.ModeExchange, Audience: "billing"},
	{Name: "nowhere", Prefix: "/api/nowhere/", Mode: core.ModeExchange, Audience: "no-such-client"},
	{Name: "legacy", Prefix: "/legacy/", Mode: core.ModeIdentityHeader, Audience: "legacy-app"},
	{Prefix: "/", Mode: core.ModeSession},
}

// stand is one site behind one host proxy, against the test Keycloak, for one host of the suite:
//
//	browser -> TLS front (https://docs.example.test:PORT) -> host proxy (plain HTTP, the example config as it is)
//	             -> session's check (gRPC, HTTP or nginx), session's sign-in paths, and the site
//
// The TLS front is a test fixture, the TLS a load balancer or the proxy's own listener ends in an install: the __Host- cookie is
// Secure, and the CSRF rule wants the Origin https://<host>. It passes every request on as it came, Host included. Keycloak
// sends its back-channel logout to the proxy's plain port, through the sign-in prefix, as an issuer inside the network would.
type stand struct {
	kc     *kctest.Keycloak
	realm  string // the first issuer's: realm, issuer identifier and person
	issuer string
	person kctest.Person
	// issuers are the site's issuers, the first one first: one, or two on the stand of several issuers (decision 0034).
	issuers []standIssuer
	core    *core.Core
	mem     *storetest.Store
	ahead   atomic.Int64 // how far the core's clock runs ahead of the wall clock, in nanoseconds
	origin  string       // https://docs.example.test:PORT, the browser's address of the site
	host    string       // docs.example.test:PORT
	proxy   string       // http://127.0.0.1:PORT, the host proxy's plain listener
	ports   map[string]int
	audit   *records // the security-audit records, written by the emitter of truvity/audit through the driver of JSON lines
}

// records is the writer of the driver of JSON lines: what the stand's emitter delivered, one record a line.
type records struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (r *records) Write(p []byte) (int, error) { r.mu.Lock(); defer r.mu.Unlock(); return r.b.Write(p) }

// check says that every record is JSON and names no one in clear, and that the scenarios wrote every action they reach.
func (r *records) check(t *testing.T, p kctest.Person) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	checkRecords(t, r.b.String(), []string{p.Username, p.Email}, []string{audit.ActionSignIn, audit.ActionDenied,
		audit.ActionTokenExchange, audit.ActionLogout, audit.ActionBackChannelLogout, audit.ActionRefresh})
}

// checkRecords says that every line of text is a record, that none names any of names in clear, and that the records hold
// every one of actions.
func checkRecords(t *testing.T, text string, names, actions []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		var rec struct {
			Metadata struct {
				EventCode string `json:"event_code"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("not a record: %q", line)
		}
		for _, n := range names {
			if n != "" && strings.Contains(line, n) {
				t.Fatalf("a record names the person: %s", line)
			}
		}
		seen[rec.Metadata.EventCode] = true
	}
	for _, a := range actions {
		if !seen[a] {
			t.Errorf("no record of %s; seen %v", a, seen)
		}
	}
}

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

// standIssuer is one issuer of the stand: a realm of the test Keycloak, its id and label in the site, and its person.
type standIssuer struct {
	id, label     string
	realm, issuer string
	person        kctest.Person
}

// standConfig is what a stand may have besides the suite's: a second issuer, with the routes and the policy that tell the
// issuers apart (decision 0034).
type standConfig struct {
	partner bool
}

// The routes of the stand of two issuers: the suite's, and a route for the people of each issuer only, which the policy keeps.
var twoIssuerRoutes = append([]core.Route{
	{Name: "corp-only", Prefix: "/corp/", Mode: core.ModeSession},
	{Name: "partner-only", Prefix: "/partner/", Mode: core.ModeSession},
}, routes...)

// issuerPolicy keeps each issuer's route to that issuer's people, and lets everyone else through: a policy by principal.issuer.
func issuerPolicy(corp, partner string) string {
	return fmt.Sprintf(`permit(principal, action, resource) unless {
  (resource == Route::"corp-only" && principal.issuer != %q) ||
  (resource == Route::"partner-only" && principal.issuer != %q)
};`, corp, partner)
}

// seen is what the site behind the proxy received. The test site (package echo) echoes it; session never does.
type seen = echo.Seen

// newStand makes the session service of one host: a realm whose redirect, post-logout and back-channel addresses are this
// stand's, the check on all three listeners, the sign-in paths and the site. The proxy is started by the host.
func newStand(t *testing.T, kc *kctest.Keycloak, cfgs ...standConfig) *stand {
	t.Helper()
	var cfg standConfig
	if len(cfgs) == 1 {
		cfg = cfgs[0]
	}
	ctx := context.Background()
	st := &stand{kc: kc}
	proxyPort := freePort(t)
	st.proxy = fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
	target := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", proxyPort)}
	front := httptest.NewUnstartedServer(&httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(target)
		r.Out.Host = r.In.Host
	}})
	front.StartTLS()
	t.Cleanup(front.Close)
	st.host = fmt.Sprintf("%s:%d", siteName, front.Listener.Addr().(*net.TCPAddr).Port)
	st.origin = "https://" + st.host

	mem := storetest.New(nil)
	items, stopItems := mem.Client()
	t.Cleanup(stopItems)
	st.mem = mem
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0o700); err != nil { //nolint:gosec // G302: the key driver wants its state directory private
		t.Fatal(err)
	}
	choices, err := atoomx.ParseKeyChoices(nil, signin.Purposes())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := atoomx.OpenKeys(atoomx.KeyOptions{Purposes: signin.Purposes(), Choices: choices, StateDir: keyDir,
		KMS: func() (awskms.API, error) { return nil, fmt.Errorf("the conformance suite runs without AWS") }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Stop)
	blocks, err := sealertest.Tokens(t, keys, signin.TokenPurposes())
	if err != nil {
		t.Fatal(err)
	}
	sealer := blocks.Sealer
	signer, identity, err := signin.Signers(blocks.Tokens)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := signer.JWK(ctx)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})

	st.issuers = []standIssuer{{id: "corp", label: "Example Corp",
		person: kctest.Person{Username: "alice", Password: kctest.Password(), Email: "alice@example.test", Groups: []string{"admins"}}}}
	if cfg.partner {
		st.issuers = append(st.issuers, standIssuer{id: "partner", label: "Example Partner",
			person: kctest.Person{Username: "bob", Password: kctest.Password(), Email: "bob@partner.example.test", Groups: []string{"staff"}}})
	}
	// Each issuer is a realm of its own, with the same client id and the same client key: the site has one key for every issuer.
	exchanges := map[string]core.Issuer{}
	var issuerURLs []string
	var signIns []signin.Issuer
	for i := range st.issuers {
		is := &st.issuers[i]
		is.realm = "session-conformance-" + is.id + "-" + strings.ToLower(core.NewID()[:8])
		is.issuer = kc.Realm(t, kctest.RealmSpec{
			Realm: is.realm, ClientID: "session-docs",
			RedirectURI: st.origin + core.PathCallback, PostLogoutURI: st.origin + "/",
			BackChannelURL: st.proxy + core.PathBackChannel, JWKS: string(jwks),
			People: []kctest.Person{is.person}, Audiences: []string{"billing"},
		})
		ex, err := exchange.New(ctx, exchange.Options{Issuer: is.issuer, ClientID: "session-docs", Asserter: signer})
		if err != nil {
			t.Fatal(err)
		}
		exchanges[is.issuer] = ex
		issuerURLs = append(issuerURLs, is.issuer)
		signIns = append(signIns, signin.Issuer{ID: is.id, Label: is.label, URL: is.issuer, ClientID: "session-docs",
			Scopes: []string{"openid", "profile", "email"}})
	}
	st.realm, st.issuer, st.person = st.issuers[0].realm, st.issuers[0].issuer, st.issuers[0].person
	standRoutes := routes
	var pol core.Policy
	if cfg.partner {
		standRoutes = twoIssuerRoutes
		pol = policytest.Engine(t, map[string]string{"by-issuer": issuerPolicy(st.issuers[0].issuer, st.issuers[1].issuer)})
	}
	st.audit = &records{}
	tr, stopAudit := audit.NewLines(st.audit).Mount()
	t.Cleanup(stopAudit)
	auditor, err := audit.New(audit.Options{Transport: tr, Pseudonyms: sealer, Release: "0.0.0-test", Scope: "development"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := core.New(core.Options{Items: items, Seal: sealer, Issuers: exchanges, Identity: identity, Audit: auditor, Policy: pol,
		Now: func() time.Time { return time.Now().Add(time.Duration(st.ahead.Load())) },
		Rules: core.Rules{Site: "docs", Host: st.host, Routes: standRoutes, Issuers: issuerURLs,
			StoreTimeout: 500 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	st.core = c
	h, err := signin.New(ctx, signin.Options{Core: c, Issuers: signIns, Signer: signer, Identity: &identity})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)

	gl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, &envoy.GRPC{Core: c})
	go func() { _ = gs.Serve(gl) }()
	t.Cleanup(gs.Stop)

	st.ports = map[string]int{
		"PROXY_PORT":          proxyPort,
		"SESSION_GRPC_PORT":   gl.Addr().(*net.TCPAddr).Port,
		"SESSION_HTTP_PORT":   serveOn(t, &envoy.HTTP{Core: c, Prefix: "/check"}),
		"SESSION_CHECK_PORT":  serveOn(t, &nginx.Handler{Core: c, ErrorPage: c.Rules().ErrorPage}),
		"SESSION_SIGNIN_PORT": serveOn(t, mux),
		"SITE_PORT":           serveOn(t, echo.Handler()),
	}
	return st
}

// target is the stand as the scenarios see it, through the host h: Keycloak's password form, and the bad paths sent to the
// proxy's plain listener.
func (st *stand) target(h host) *target {
	return &target{
		origin: st.origin, issuer: st.issuer, cookieName: st.core.CookieName(), email: st.person.Email, ctx: context.Background(),
		signIn:       func(t *testing.T, b *tab) { b.signIn(t, st.issuer, st.person) },
		leftToSignIn: func(t *testing.T, b *tab) bool { return b.atLoginForm(t, st.issuer) },
		raw:          func(method, path string) (answer, error) { return raw(st.proxy, method, path, st.host) },
		paths:        h.paths, st: st, h: h,
	}
}

// placeholder is a ${NAME} of an example; nginx's own $variables are left alone.
var placeholder = regexp.MustCompile(`\$\{([A-Z_]+)\}`)

// runProxy runs an example configuration in its image, on the host network, with the stand's addresses filled in, and waits
// until a public route answers through it. The container is removed at the end of the test.
func (st *stand) runProxy(t *testing.T, image, example, mountAs string, ports map[string]int, dockerOpts, proxyArgs []string) {
	t.Helper()
	tmpl, err := os.ReadFile(filepath.Join("..", "examples", example)) //nolint:gosec // G304: an example of this repository
	if err != nil {
		t.Fatal(err)
	}
	cfg := placeholder.ReplaceAllStringFunc(string(tmpl), func(m string) string {
		name := placeholder.FindStringSubmatch(m)[1]
		v, ok := ports[name]
		if !ok {
			v, ok = st.ports[name]
		}
		if !ok {
			t.Fatalf("the example names %s, which the suite does not fill", m)
		}
		return fmt.Sprint(v)
	})
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the proxy's own user reads the file
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, mountAs), []byte(cfg), 0o644); err != nil { //nolint:gosec // G306: as above
		t.Fatal(err)
	}
	name := fmt.Sprintf("session-conformance-%d", time.Now().UnixNano())
	run := append([]string{"run", "-d", "--rm", "--name", name, "--network", "host", "-v", dir + ":/etc/session-test:ro"}, dockerOpts...)
	run = append(append(run, image), proxyArgs...)
	out, err := exec.Command("docker", run...).CombinedOutput() //nolint:gosec // G204: the suite's own image and file
	if err != nil {
		t.Fatalf("docker run: %v %s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", "--tail", "40", name).CombinedOutput() //nolint:gosec // G204: as above
			t.Logf("%s logs:\n%s", example, logs)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run() //nolint:gosec // G204: as above
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		res, err := raw(st.proxy, http.MethodGet, "/assets/ready", st.host)
		if err == nil && res.status == http.StatusOK {
			return
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "40", name).CombinedOutput() //nolint:gosec // G204: as above
			t.Fatalf("%s did not become ready: %v\n%s", example, err, logs)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// answer is a plain HTTP answer.
type answer struct {
	status int
	header http.Header
	body   string
}

var noRedirect = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// raw sends a request outside the browser, with its path exactly as given: Go's client does not clean dot segments, merge
// slashes or decode an escape, and a browser does all three before it sends, so the bad paths cannot come from the browser.
func raw(base, method, path, host string, h ...string) (answer, error) {
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		return answer{}, err
	}
	req.Host = host
	for i := 0; i+1 < len(h); i += 2 {
		req.Header.Add(h[i], h[i+1])
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		return answer{}, err
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return answer{status: res.StatusCode, header: res.Header, body: string(b)}, nil
}

// withoutBackChannel takes the back-channel logout address off the realm's client, so a logout at Keycloak reaches session
// only at the next refresh.
func (st *stand) withoutBackChannel(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	status, body, err := st.kc.Admin(ctx, http.MethodGet, "/realms/"+st.realm+"/clients?clientId=session-docs", nil)
	var clients []map[string]any
	if err != nil || status != http.StatusOK || json.Unmarshal(body, &clients) != nil || len(clients) != 1 {
		t.Fatalf("the client: %d %v", status, err)
	}
	c := clients[0]
	attrs, _ := c["attributes"].(map[string]any)
	attrs["backchannel.logout.url"] = ""
	status, body, err = st.kc.Admin(ctx, http.MethodPut, "/realms/"+st.realm+"/clients/"+fmt.Sprint(c["id"]), c)
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("update the client: %d %v %s", status, err, body)
	}
}
