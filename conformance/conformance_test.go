package conformance_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/kctest"
)

// host is one host of the suite: how to run its example in front of a stand, and the answers in which it differs from the
// others by design.
type host struct {
	name  string
	start func(t *testing.T, st *stand)
	// unavailable is the body of the 503 of a store outage. Envoy's HTTP mode loses the check's body of a 5xx (decision 0011).
	unavailable string
	// paths are the bad paths, sent without a session outside the browser, and the answer each must get: Envoy normalises
	// dot segments and checks the normalised path, and refuses an encoded slash; nginx refuses every path the site could read
	// differently from the $uri the check gets (decision 0018).
	paths []badPath
}

type badPath struct {
	path   string
	status int
	body   string // the exact body of a refusal
	site   string // for a 200: the path the site must get
}

const (
	loginRequiredBody = `{"error":"login_required","login_url":"/_session/login?return_to=%2Fapp%2Fx"}`
	badPathBody       = `{"error":"bad_path"}`
	unavailableBody   = `{"error":"unavailable"}`
)

// envoyPaths are the bad paths through the Envoy example: normalize_path, merge_slashes and
// path_with_escaped_slashes_action REJECT_REQUEST (decision 0011). The check sees the path the router uses.
var envoyPaths = []badPath{
	{path: "/assets/../app/x", status: http.StatusUnauthorized, body: loginRequiredBody}, // normalised to /app/x, which needs a session
	{path: "/./app/x", status: http.StatusUnauthorized, body: loginRequiredBody},
	{path: "/assets/%2e%2e/app/x", status: http.StatusUnauthorized, body: loginRequiredBody}, // an encoded dot is a dot to Envoy
	{path: "/assets/%2E%2E/app/x", status: http.StatusUnauthorized, body: loginRequiredBody},
	// Envoy refuses an encoded slash or backslash itself (path_with_escaped_slashes_action), with its own empty 400.
	{path: "/assets%2F..%2Fapp/x", status: http.StatusBadRequest},
	{path: "/assets/%5c../app/x", status: http.StatusBadRequest},
	{path: "//assets//app.js", status: http.StatusOK, site: "/assets/app.js"},
}

// nginxPaths are the bad paths through the nginx example: refused with 400 before any check, because nginx passes the site the
// URI as the browser sent it (decision 0018). Merged slashes pass, and the site gets the URI as sent.
var nginxPaths = []badPath{
	{path: "/assets/../app/x", status: http.StatusBadRequest, body: badPathBody},
	{path: "/./app/x", status: http.StatusBadRequest, body: badPathBody},
	{path: "/assets/%2e%2e/app/x", status: http.StatusBadRequest, body: badPathBody},
	{path: "/assets/%2E%2E/app/x", status: http.StatusBadRequest, body: badPathBody},
	{path: "/assets%2F..%2Fapp/x", status: http.StatusBadRequest, body: badPathBody},
	{path: "/assets/%5c../app/x", status: http.StatusBadRequest, body: badPathBody},
	{path: "//assets//app.js", status: http.StatusOK, site: "//assets//app.js"},
}

func envoyHost(name, listener string, unavailable string) host {
	return host{name: name, unavailable: unavailable, paths: envoyPaths, start: func(t *testing.T, st *stand) {
		image := os.Getenv("SESSION_TEST_ENVOY_IMAGE")
		if image == "" {
			t.Skip("no Envoy: run `just test-conformance` (SESSION_TEST_ENVOY_IMAGE is not set)")
		}
		admin := freePort(t)
		ports := map[string]int{"ADMIN_PORT": admin, "GRPC_MODE_PORT": freePort(t), "HTTP_MODE_PORT": freePort(t)}
		ports[listener] = st.ports["PROXY_PORT"]
		st.runProxy(t, image, "envoy/envoy.yaml", "envoy.yaml", ports, nil,
			[]string{"-c", "/etc/session-test/envoy.yaml", "--base-id", fmt.Sprint(admin), "-l", "warning"})
	}}
}

var hosts = []host{
	envoyHost("envoy-grpc", "GRPC_MODE_PORT", unavailableBody),
	envoyHost("envoy-http", "HTTP_MODE_PORT", ""),
	{name: "nginx", unavailable: unavailableBody, paths: nginxPaths, start: func(t *testing.T, st *stand) {
		image := os.Getenv("SESSION_TEST_NGINX_IMAGE")
		if image == "" {
			t.Skip("no nginx: run `just test-conformance` (SESSION_TEST_NGINX_IMAGE is not set)")
		}
		st.runProxy(t, image, "nginx/nginx.conf", "nginx.conf", map[string]int{"NGINX_PORT": st.ports["PROXY_PORT"]},
			[]string{"--entrypoint", "nginx"}, []string{"-g", "daemon off;", "-c", "/etc/session-test/nginx.conf"})
	}},
}

// TestConformance runs the scenarios through each host in turn, in one browser. Each host gets its own realm, session service,
// proxy container and browser profile; one proxy container runs at a time.
func TestConformance(t *testing.T) {
	kc := kctest.Need(t)
	browser := startBrowser(t, localBrowserArgs()...)
	for _, h := range hosts {
		t.Run(h.name, func(t *testing.T) {
			st := newStand(t, kc)
			h.start(t, st)
			runScenarios(t, st.target(h), newTab(browser, t, st.origin), runLocal)
			st.audit.check(t, st.person)
		})
	}
}

func decodeSeen(t *testing.T, s string) seen {
	t.Helper()
	var v seen
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("not the site's answer: %q", s)
	}
	return v
}

// csrf are the headers the browser helper adds to a state-changing fetch (S5); the browser adds Origin and Sec-Fetch-Site.
var csrf = map[string]string{core.CSRFHeader: core.CSRFValue, "Accept": "application/json"}

// target is the site the scenarios run against: the local stand of one host (TestConformance), or a deployed site
// (TestRemote, decision 0029). What only the local stand can do is in st, which is nil for a deployed site.
type target struct {
	origin, issuer string
	cookieName     string
	// email is the e-mail address whoami must name; empty accepts any.
	email string
	// signIn plays the person from the navigation that left the site to sign in until the browser is back at the site.
	signIn func(t *testing.T, b *tab)
	// leftToSignIn says whether the last navigation went to the issuer's sign-in.
	leftToSignIn func(t *testing.T, b *tab) bool
	// raw sends a request outside the browser, with its path as given and the site's Host.
	raw func(method, path string) (answer, error)
	// paths are the bad paths and the answers of the site's host.
	paths []badPath
	// ctx carries the HTTP client the suite reaches the issuer with (oidc.ClientContext).
	ctx context.Context
	// idle and max are the lifetimes of the site file, for the scenarios that wait them out in real time.
	idle, max time.Duration
	st        *stand
	h         host

	subject string // the person's subject at the issuer, from whoami
}

// where says where a scenario can run.
type where int

const (
	// anywhere: on the local stand and against a deployed site.
	anywhere where = iota
	// localOnly: the scenario needs what only the local stand has (the store double, the movable clock, the issuer's admin API).
	localOnly
	// remoteOnly: the scenario waits out the short lifetimes of the remote site file in real time; the local stand keeps the
	// defaults, and the local suite is the one of decision 0020.
	remoteOnly
)

// run is which runner is asking.
type runner int

const (
	runLocal runner = iota
	runRemote
)

func (w where) runsOn(r runner) bool {
	return w == anywhere || (w == localOnly && r == runLocal) || (w == remoteOnly && r == runRemote)
}

// scenario is one step of the suite. why says, for a scenario that does not run anywhere, what the other runner lacks.
type scenario struct {
	name  string
	where where
	why   string
	run   func(t *testing.T, x *target, b *tab)
}

// runScenarios runs the suite's steps in order. A step that fails stops the run, because the later steps build on the session
// of the earlier ones; a step the runner cannot run is skipped with its reason.
func runScenarios(t *testing.T, x *target, b *tab, r runner) {
	for _, s := range scenarios {
		ok := t.Run(s.name, func(t *testing.T) {
			if !s.where.runsOn(r) {
				t.Skip(s.why)
			}
			s.run(t, x, b)
		})
		if !ok {
			t.FailNow()
		}
	}
}

// scenarios is the suite: the same steps, in order, on every host and, where they can, against a deployed site.
var scenarios = []scenario{
	{name: "no session: a public route passes, an API call gets the JSON 401", where: anywhere, run: func(t *testing.T, x *target, b *tab) {
		if s := b.open(t, x.origin+"/assets/app.js"); s != http.StatusOK || decodeSeen(t, b.text(t)).Path != "/assets/app.js" {
			t.Fatalf("public route: %d %s", s, b.text(t))
		}
		r := b.fetch(t, "GET", "/app/x", nil)
		if r.Status != http.StatusUnauthorized || r.Type != "application/json" || r.Body != loginRequiredBody {
			t.Fatalf("401: %+v", r)
		}
	}},

	{name: "sign-in: a navigation is sent to Keycloak, and the callback brings it back with the S1 cookie", where: anywhere, run: func(t *testing.T, x *target, b *tab) {
		b.open(t, x.origin+"/app/page?x=1")
		if !x.leftToSignIn(t, b) {
			t.Fatalf("not sent to Keycloak's sign-in: %s", b.location(t))
		}
		x.signIn(t, b)
		if loc := b.location(t); loc != x.origin+"/app/page?x=1" {
			t.Fatalf("landed at %s", loc)
		}
		got := decodeSeen(t, b.text(t))
		if got.Path != "/app/page?x=1" || got.Method != http.MethodGet {
			t.Fatalf("the site got %+v", got)
		}
		if c, ok := got.Headers["Cookie"]; ok {
			t.Fatalf("the site got session's cookie: %q", c)
		}
		host := strings.TrimPrefix(x.origin, "https://")
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		c := b.cookie(t, x.cookieName)
		if c == nil || !c.Secure || !c.HTTPOnly || c.SameSite != network.CookieSameSiteLax || c.Path != "/" || c.Domain != host || !c.Session {
			t.Fatalf("the session cookie (S1): %+v", c)
		}
	}},

	{name: "protected route: the site gets the request without session's cookie or the browser's owned headers (S8)", where: anywhere, run: func(t *testing.T, _ *target, b *tab) {
		run(t, b, chromedp.Evaluate[chromedp.Void](`document.cookie = "theme=dark; path=/; secure"`))
		r := b.fetch(t, "GET", "/app/x?q=1", map[string]string{"Authorization": "Bearer forged", "X-Session-Identity": "forged",
			"X-Session-Token": "forged"})
		if r.Status != http.StatusOK {
			t.Fatalf("allow: %+v", r)
		}
		got := decodeSeen(t, r.Body)
		for _, name := range []string{"Authorization", "X-Session-Identity", "X-Session-Token"} {
			if v, ok := got.Headers[name]; ok {
				t.Fatalf("the site got %s %q", name, v)
			}
		}
		if c := got.Headers["Cookie"]; len(c) != 1 || c[0] != "theme=dark" {
			t.Fatalf("the site got Cookie %q", c)
		}
		if got.Path != "/app/x?q=1" {
			t.Fatalf("the site got the path %q", got.Path)
		}
	}},

	{name: "sign-in prefix: /_session/ reaches session without a check", where: anywhere, run: func(t *testing.T, x *target, b *tab) {
		r := b.fetch(t, "GET", core.PathWhoami, nil)
		var who struct {
			Sub, Email string
		}
		if r.Status != http.StatusOK || json.Unmarshal([]byte(r.Body), &who) != nil || who.Sub == "" ||
			(x.email != "" && who.Email != x.email) {
			t.Fatalf("whoami: %+v", r)
		}
		x.subject = who.Sub
	}},

	{name: "CSRF: a POST with the header passes, without it is refused (S5)", where: anywhere, run: func(t *testing.T, _ *target, b *tab) {
		r := b.fetch(t, "POST", "/app/x", csrf)
		if r.Status != http.StatusOK || decodeSeen(t, r.Body).Method != http.MethodPost {
			t.Fatalf("POST with the CSRF header: %+v", r)
		}
		r = b.fetch(t, "POST", "/app/x", map[string]string{"Accept": "application/json"})
		if r.Status != http.StatusForbidden || r.Body != `{"error":"csrf"}` {
			t.Fatalf("POST without the CSRF header: %+v", r)
		}
	}},

	{name: "exchange and identity header: the site gets a token of its audience, or the signed identity", where: anywhere, run: func(t *testing.T, x *target, b *tab) {
		ctx := x.ctx
		r := b.fetch(t, "GET", "/api/billing/x", map[string]string{"Authorization": "Bearer forged"})
		got := decodeSeen(t, r.Body)
		a := got.Headers["Authorization"]
		if r.Status != http.StatusOK || len(a) != 1 || !strings.HasPrefix(a[0], "Bearer ") {
			t.Fatalf("exchange route: %d %q", r.Status, a)
		}
		p, err := oidc.NewProvider(ctx, x.issuer)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := p.VerifierContext(ctx, &oidc.Config{ClientID: "billing"}).Verify(ctx, strings.TrimPrefix(a[0], "Bearer "))
		if err != nil || tok.Subject != x.subject {
			t.Fatalf("the exchanged token: %v", err)
		}

		r = b.fetch(t, "GET", "/legacy/x", map[string]string{"X-Session-Identity": "forged"})
		got = decodeSeen(t, r.Body)
		id := got.Headers["X-Session-Identity"]
		if r.Status != http.StatusOK || len(id) != 1 {
			t.Fatalf("identity route: %d %q", r.Status, id)
		}
		if _, ok := got.Headers["Authorization"]; ok {
			t.Fatal("the identity route's site got Authorization")
		}
		jr := b.fetch(t, "GET", core.PathJWKS, nil)
		var set jose.JSONWebKeySet
		if jr.Status != http.StatusOK || json.Unmarshal([]byte(jr.Body), &set) != nil {
			t.Fatalf("jwks: %+v", jr)
		}
		sig, err := jose.ParseSignedCompact(id[0], []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatal(err)
		}
		keys := set.Key(sig.Signatures[0].Protected.KeyID)
		if len(keys) != 1 || sig.Signatures[0].Protected.ExtraHeaders["typ"] != core.IdentityType {
			t.Fatalf("identity header: kid %q", sig.Signatures[0].Protected.KeyID)
		}
		payload, err := sig.Verify(keys[0])
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Iss, Aud, Sub string
		}
		if json.Unmarshal(payload, &claims) != nil || claims.Iss != x.origin || claims.Aud != "legacy-app" || claims.Sub != x.subject {
			t.Fatalf("identity claims: %s", payload)
		}

		// A refused exchange: JSON to a fetch, the site's error page to a navigation; both 403, and the session stays.
		r = b.fetch(t, "GET", "/api/nowhere/x", nil)
		if r.Status != http.StatusForbidden || r.Body != `{"error":"exchange_refused"}` {
			t.Fatalf("refused exchange, fetch: %+v", r)
		}
		if s := b.open(t, x.origin+"/api/nowhere/x"); s != http.StatusForbidden || !strings.Contains(b.text(t), "Access refused") {
			t.Fatalf("refused exchange, navigation: %d %q", s, b.text(t))
		}
		if r := b.fetch(t, "GET", "/app/x", nil); r.Status != http.StatusOK {
			t.Fatalf("after the refusal: %+v", r)
		}
	}},

	{name: "store outage: 503, never an allow", where: localOnly,
		why: "local only: a deployed site's store cannot be taken down from the test", run: func(t *testing.T, x *target, b *tab) {
			x.st.mem.Down.Store(true)
			r := b.fetch(t, "GET", "/app/x", nil)
			x.st.mem.Down.Store(false)
			if r.Status != http.StatusServiceUnavailable || r.Body != x.h.unavailable {
				t.Fatalf("store down: %+v, want the body %q", r, x.h.unavailable)
			}
			if r := b.fetch(t, "GET", "/app/x", nil); r.Status != http.StatusOK {
				t.Fatalf("store back: %+v", r)
			}
		}},

	{name: "bad paths: dot segments, encoded dots, slashes and backslashes, merged slashes", where: anywhere, run: func(t *testing.T, x *target, _ *tab) {
		for _, p := range x.paths {
			a, err := x.raw(http.MethodGet, p.path)
			if err != nil {
				t.Fatal(err)
			}
			if a.status != p.status || p.status != http.StatusOK && a.body != p.body {
				t.Errorf("%s: %d %q, want %d %q", p.path, a.status, a.body, p.status, p.body)
				continue
			}
			if p.site != "" && decodeSeen(t, a.body).Path != p.site {
				t.Errorf("%s: the site got %q, want %q", p.path, decodeSeen(t, a.body).Path, p.site)
			}
		}
	}},

	{name: "logout: a POST with CSRF ends the session and sends the browser to Keycloak's end-session (S6)", where: anywhere, run: func(t *testing.T, x *target, b *tab) {
		r := b.fetch(t, "POST", core.PathLogout, map[string]string{"Accept": "application/json"})
		if r.Status != http.StatusForbidden || b.cookie(t, x.cookieName) == nil {
			t.Fatalf("logout without the CSRF header: %+v", r)
		}
		if r := b.fetch(t, "GET", "/app/x", nil); r.Status != http.StatusOK {
			t.Fatalf("a refused logout ended the session: %+v", r)
		}
		r = b.fetch(t, "POST", core.PathLogout, csrf)
		var out struct {
			LogoutURL string `json:"logout_url"`
		}
		if r.Status != http.StatusOK || json.Unmarshal([]byte(r.Body), &out) != nil ||
			!strings.HasPrefix(out.LogoutURL, x.issuer+"/protocol/openid-connect/logout?") || !strings.Contains(out.LogoutURL, "id_token_hint=") {
			t.Fatalf("logout: %+v", r)
		}
		if c := b.cookie(t, x.cookieName); c != nil {
			t.Fatalf("the cookie was not cleared: %+v", c)
		}
		if r := b.fetch(t, "GET", "/app/x", nil); r.Status != http.StatusUnauthorized {
			t.Fatalf("after the logout: %+v", r)
		}
		// Keycloak ends its own session without asking (id_token_hint) and sends the browser back to the site, which sends it to
		// sign in: Keycloak's sign-in shows, because Keycloak's session is gone too.
		b.open(t, out.LogoutURL)
		b.waitFor(t, "Keycloak's sign-in after the logout", func() bool { return x.leftToSignIn(t, b) })
		x.signIn(t, b)
		if loc := b.location(t); loc != x.origin+"/" {
			t.Fatalf("after the new sign-in: %s", loc)
		}
	}},

	{name: "back-channel logout: Keycloak's logout ends the session at once, through the host's sign-in prefix", where: localOnly,
		why: "local only: ending the person's Keycloak session from outside the browser takes the realm's admin API", run: func(t *testing.T, x *target, b *tab) {
			if r := b.fetch(t, "GET", "/app/x", nil); r.Status != http.StatusOK {
				t.Fatalf("before: %+v", r)
			}
			x.st.kc.LogoutUser(t, x.st.realm, x.st.person.Username)
			b.waitFor(t, "the 401 after the back-channel logout", func() bool {
				return b.fetch(t, "GET", "/app/x", nil).Status == http.StatusUnauthorized
			})
		}},

	{name: "refresh refused: a session Keycloak ended unseen ends at its next exchange, and the check clears the cookie", where: localOnly,
		why: "local only: it needs the realm's admin API and a clock six minutes ahead (Keycloak's access tokens live five)", run: func(t *testing.T, x *target, b *tab) {
			st := x.st
			b.open(t, x.origin+"/app/again")
			x.signIn(t, b)
			if b.cookie(t, x.cookieName) == nil {
				t.Fatal("no session cookie")
			}
			st.withoutBackChannel(t)
			st.kc.LogoutUser(t, st.realm, st.person.Username)
			// Keycloak's access tokens live five minutes: six minutes on, the sign-in token is old and is refreshed first.
			st.ahead.Store(int64(6 * time.Minute))
			defer st.ahead.Store(0)
			r := b.fetch(t, "GET", "/api/billing/x", nil)
			if r.Status != http.StatusUnauthorized || !strings.Contains(r.Body, `"login_required"`) {
				t.Fatalf("after the refused refresh: %+v", r)
			}
			// The only Set-Cookie of a check's answer today; on nginx the only one that can pass (decision 0018).
			if c := b.cookie(t, x.cookieName); c != nil {
				t.Fatalf("the check did not clear the cookie: %+v", c)
			}
		}},

	{name: "idle lifetime: a session unused for longer than session.idle ends", where: remoteOnly,
		why: "remote only: it waits out session.idle of the remote site file in real time", run: func(t *testing.T, x *target, b *tab) {
			if r := b.fetch(t, "GET", "/app/x", nil); r.Status != http.StatusOK {
				t.Fatalf("before: %+v", r)
			}
			time.Sleep(x.idle + 15*time.Second)
			if r := b.fetch(t, "GET", "/app/x", nil); r.Status != http.StatusUnauthorized || !strings.Contains(r.Body, `"login_required"`) {
				t.Fatalf("after %s idle: %+v", x.idle, r)
			}
		}},

	{name: "absolute lifetime: a session in use ends at session.max", where: remoteOnly,
		why: "remote only: it waits out session.max of the remote site file in real time", run: func(t *testing.T, x *target, b *tab) {
			b.open(t, x.origin+"/app/max")
			if x.leftToSignIn(t, b) {
				x.signIn(t, b)
			}
			signedIn := time.Now()
			if r := b.fetch(t, "GET", "/app/x", nil); r.Status != http.StatusOK {
				t.Fatalf("after the sign-in: %+v", r)
			}
			// A request every 20 seconds keeps the session from going idle; it must pass until shortly before max and fail
			// shortly after it.
			for {
				time.Sleep(20 * time.Second)
				r := b.fetch(t, "GET", "/app/x", nil)
				age := time.Since(signedIn)
				switch {
				case r.Status == http.StatusOK && age > x.max+30*time.Second:
					t.Fatalf("still signed in %s after the sign-in; session.max is %s", age.Round(time.Second), x.max)
				case r.Status == http.StatusOK:
				case r.Status == http.StatusUnauthorized && age < x.max-10*time.Second:
					t.Fatalf("ended %s after the sign-in, before session.max %s: %+v", age.Round(time.Second), x.max, r)
				case r.Status == http.StatusUnauthorized:
					return
				default:
					t.Fatalf("at %s: %+v", age.Round(time.Second), r)
				}
			}
		}},
}
