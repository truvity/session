package core_test

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/policy"
)

func body(t *testing.T, d core.Decision) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(d.Body, &m); err != nil {
		t.Fatalf("body %q: %v", d.Body, err)
	}
	return m
}

// S4 and decision 0004: a navigation without a session is redirected, anything else gets a JSON 401 with a login URL; a route
// may force either.
func TestNoSessionRedirectsANavigationAndAnswers401Otherwise(t *testing.T) {
	e := newEnv(t, "storetest")
	ctx := context.Background()
	cases := []struct {
		name     string
		r        core.Request
		outcome  core.Outcome
		status   int
		location string
	}{
		{"navigation", nav("/app/x?a=1"), core.Redirect, 302, "/_session/login?return_to=%2Fapp%2Fx%3Fa%3D1"},
		{"fetch", req("GET", "/api/x", "Accept", "application/json"), core.Deny, 401, ""},
		{"navigation without Sec-Fetch-Mode", req("GET", "/app/x", "Accept", "text/html"), core.Deny, 401, ""},
		{"navigation without text/html", req("GET", "/app/x", "Sec-Fetch-Mode", "navigate", "Accept", "*/*"), core.Deny, 401, ""},
		{"HEAD navigation", req("HEAD", "/app/x", "Sec-Fetch-Mode", "navigate", "Accept", "text/html"), core.Deny, 401, ""},
		{"route forces 401", nav("/api/strict/x"), core.Deny, 401, ""},
		{"route forces redirect", req("POST", "/go/x"), core.Redirect, 302, "/_session/login?return_to=%2Fgo%2Fx"},
		{"unknown cookie id", nav("/app/x", "Cookie", e.core.CookieName()+"="+core.NewID()), core.Redirect, 302, "/_session/login?return_to=%2Fapp%2Fx"},
		{"malformed cookie id", req("GET", "/api/x", "Cookie", e.core.CookieName()+"=short"), core.Deny, 401, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.core.Check(ctx, tc.r)
			if d.Outcome != tc.outcome || d.Status != tc.status || d.Reason != "login_required" {
				t.Fatalf("got outcome %v status %d reason %q", d.Outcome, d.Status, d.Reason)
			}
			if tc.outcome == core.Redirect && d.Location != tc.location {
				t.Fatalf("location %q, want %q", d.Location, tc.location)
			}
			if tc.outcome == core.Deny {
				b := body(t, d)
				if b["error"] != "login_required" || !strings.HasPrefix(b["login_url"], "/_session/login?return_to=") || d.ContentType != "application/json" {
					t.Fatalf("body %v content type %q", b, d.ContentType)
				}
			}
		})
	}
	if got := e.mem.Gets.Load(); got != 1 {
		t.Fatalf("the store was read %d times; only the well-formed unknown id costs a read", got)
	}
}

// The check of a valid session is exactly one linearizable read, and the allow answer strips what the browser must not send
// upstream (S8): Authorization and the identity headers are removed, and Cookie loses session's own cookies.
func TestAValidSessionIsOneLinearizableReadAndStripsOwnedHeaders(t *testing.T) {
	for _, backend := range stores() {
		t.Run(backend, func(t *testing.T) {
			e := newEnv(t, backend)
			id := e.signIn(t, "alice", "sid-1")
			var gets0, lin0, tx0 int64
			if e.mem != nil {
				gets0, lin0, tx0 = e.mem.Gets.Load(), e.mem.LinearGets.Load(), e.mem.Transacts.Load()
			}
			d := e.core.Check(context.Background(), nav("/app/x",
				"Cookie", "theme=dark; "+e.cookie(id)+"; "+e.core.BindingCookieName()+"="+core.NewID(),
				"Cookie", "lang=nl",
				"Authorization", "Bearer forged", "X-Session-Identity", "forged"))
			if d.Outcome != core.Allow || d.Subject != "alice" {
				t.Fatalf("got %+v", d)
			}
			if d.Set["cookie"] != "theme=dark; lang=nl" {
				t.Fatalf("cookie %q", d.Set["cookie"])
			}
			for _, h := range core.OwnedHeaders {
				if !slices.Contains(d.Remove, h) {
					t.Fatalf("%s is not removed: %v", h, d.Remove)
				}
				if _, set := d.Set[h]; set {
					t.Fatalf("%s is set in a session-mode answer", h)
				}
			}
			if e.mem != nil {
				if g, l, x := e.mem.Gets.Load()-gets0, e.mem.LinearGets.Load()-lin0, e.mem.Transacts.Load()-tx0; g != 1 || l != 1 || x != 0 {
					t.Fatalf("the check made %d gets (%d linearizable) and %d transactions; want 1, 1, 0", g, l, x)
				}
			}
		})
	}
}

func TestOnlySessionCookieRemovesTheCookieHeader(t *testing.T) {
	e := newEnv(t, "storetest")
	id := e.signIn(t, "alice", "sid-1")
	d := e.core.Check(context.Background(), req("GET", "/api/x", "Cookie", e.cookie(id)))
	if d.Outcome != core.Allow || !slices.Contains(d.Remove, "cookie") || d.Set["cookie"] != "" {
		t.Fatalf("got %+v", d)
	}
}

func TestPublicRoutesAndTheSignInPrefixPassWithoutAStoreRead(t *testing.T) {
	e := newEnv(t, "storetest")
	for _, p := range []string{"/assets/app.js", "/_session/login?return_to=/", "/_session/callback?code=x"} {
		d := e.core.Check(context.Background(), req("GET", p, "Authorization", "Bearer forged", "Cookie", "a=b"))
		if d.Outcome != core.Allow || !slices.Contains(d.Remove, "authorization") || d.Set["cookie"] != "a=b" {
			t.Fatalf("%s: got %+v", p, d)
		}
	}
	if e.mem.Gets.Load() != 0 {
		t.Fatal("a public route read the store")
	}
}

func TestNoRouteAndUnnormalisedPathsAreRefused(t *testing.T) {
	e := newEnv(t, "storetest")
	if d := e.core.Check(context.Background(), req("GET", "/elsewhere")); d.Status != 404 || d.Reason != "no_route" {
		t.Fatalf("got %+v", d)
	}
	// The check matches on the path the proxy routes on; a path the proxy should have normalised is refused, never guessed
	// (the nginx hole of the first spike: /assets/../private/x).
	for _, p := range []string{"/assets/../app/x", "/assets/./x", "/assets//x", "/assets/%2e%2e/app", "/assets/%2E%2e/app",
		"/assets/x%2fy", `/assets\x`, "/assets/..", "assets/x", "/assets/%00"} {
		d := e.core.Check(context.Background(), req("GET", p))
		if d.Outcome != core.Deny || d.Status != 400 || d.Reason != "bad_path" {
			t.Fatalf("%s: got %+v", p, d)
		}
	}
}

// S5: a state-changing request needs the CSRF header and a same-origin Origin or Sec-Fetch-Site.
func TestCSRF(t *testing.T) {
	e := newEnv(t, "storetest")
	id := e.signIn(t, "alice", "sid-1")
	ck := e.cookie(id)
	const own = "https://docs.example.test"
	cases := []struct {
		name string
		r    core.Request
		ok   bool
	}{
		{"GET needs nothing", req("GET", "/api/x", "Cookie", ck), true},
		{"POST with header and Origin", req("POST", "/api/x", "Cookie", ck, "X-Requested-With", "XMLHttpRequest", "Origin", own), true},
		{"POST with header, Origin and same-origin", req("POST", "/api/x", "Cookie", ck, "X-Requested-With", "XMLHttpRequest", "Origin", own, "Sec-Fetch-Site", "same-origin"), true},
		{"POST with header and same-origin, no Origin", req("POST", "/api/x", "Cookie", ck, "X-Requested-With", "XMLHttpRequest", "Sec-Fetch-Site", "same-origin"), true},
		{"POST without the header", req("POST", "/api/x", "Cookie", ck, "Origin", own, "Sec-Fetch-Site", "same-origin"), false},
		{"POST with another header value", req("POST", "/api/x", "Cookie", ck, "X-Requested-With", "fetch", "Origin", own), false},
		{"POST from another origin", req("POST", "/api/x", "Cookie", ck, "X-Requested-With", "XMLHttpRequest", "Origin", "https://evil.example.test"), false},
		{"POST from a sibling site", req("POST", "/api/x", "Cookie", ck, "X-Requested-With", "XMLHttpRequest", "Origin", own, "Sec-Fetch-Site", "same-site"), false},
		{"POST over plain http origin", req("POST", "/api/x", "Cookie", ck, "X-Requested-With", "XMLHttpRequest", "Origin", "http://docs.example.test"), false},
		{"POST with neither Origin nor Sec-Fetch-Site", req("POST", "/api/x", "Cookie", ck, "X-Requested-With", "XMLHttpRequest"), false},
		{"DELETE cross-site", req("DELETE", "/api/x", "Cookie", ck, "X-Requested-With", "XMLHttpRequest", "Sec-Fetch-Site", "cross-site"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.core.Check(context.Background(), tc.r)
			if tc.ok != (d.Outcome == core.Allow) {
				t.Fatalf("got %+v", d)
			}
			if !tc.ok && (d.Status != 403 || d.Reason != "csrf") {
				t.Fatalf("got %+v", d)
			}
		})
	}
	// A POST without a session is a sign-in question first, not a CSRF one.
	if d := e.core.Check(context.Background(), req("POST", "/api/x")); d.Status != 401 {
		t.Fatalf("got %+v", d)
	}
	n := 0
	for _, ev := range e.audit.Events() {
		if ev.Kind == core.EventDenied && ev.Reason == "csrf" {
			n++
		}
	}
	if n != 7 {
		t.Fatalf("%d csrf denials audited, want 7", n)
	}
}

// Fail closed: a store that is down or slow is answered with 503, within the check's own store timeout.
func TestStoreFailureIs503(t *testing.T) {
	e := newEnv(t, "storetest", func(o *core.Options) { o.Rules.StoreTimeout = 150 * time.Millisecond })
	id := e.signIn(t, "alice", "sid-1")
	e.mem.Down.Store(true)
	d := e.core.Check(context.Background(), nav("/app", "Cookie", e.cookie(id)))
	if d.Outcome != core.Unavailable || d.Status != 503 || d.Reason != "store" {
		t.Fatalf("down: got %+v", d)
	}
	e.mem.Down.Store(false)
	e.mem.Delay.Store(int64(3 * time.Second))
	start := time.Now()
	d = e.core.Check(context.Background(), nav("/app", "Cookie", e.cookie(id)))
	if took := time.Since(start); d.Status != 503 || took > time.Second {
		t.Fatalf("slow: got %+v after %v", d, took)
	}
	if e.core.Metrics().Checks("unavailable/store") != 2 {
		t.Fatal("the unavailable answers are not counted")
	}
}

func TestIdleAndAbsoluteExpiry(t *testing.T) {
	for _, backend := range stores() {
		t.Run(backend, func(t *testing.T) {
			e := newEnv(t, backend, func(o *core.Options) { o.Rules.Idle = 10 * time.Minute; o.Rules.Max = 30 * time.Minute })
			id := e.signIn(t, "alice", "sid-1")
			check := func() core.Decision {
				return e.core.Check(context.Background(), req("GET", "/api/x", "Cookie", e.cookie(id)))
			}
			// Used every 9 minutes the session lives on, its idle time refreshed, until its absolute end.
			for i := 0; i < 3; i++ {
				e.clock.Add(9 * time.Minute)
				if d := check(); d.Outcome != core.Allow {
					t.Fatalf("round %d: got %+v", i, d)
				}
			}
			e.clock.Add(4 * time.Minute) // 31 minutes after creation
			if d := check(); d.Reason != "login_required" {
				t.Fatalf("past max: got %+v", d)
			}
			id = e.signIn(t, "alice", "sid-2")
			e.clock.Add(10*time.Minute + time.Second)
			if d := check(); d.Reason != "login_required" {
				t.Fatalf("past idle: got %+v", d)
			}
		})
	}
}

// The idle time is refreshed at most once per TouchEvery: one conditional write, not one per check.
func TestIdleRefreshAtMostOncePerMinute(t *testing.T) {
	e := newEnv(t, "storetest")
	id := e.signIn(t, "alice", "sid-1")
	check := func() { e.core.Check(context.Background(), req("GET", "/api/x", "Cookie", e.cookie(id))) }
	tx0 := e.mem.Transacts.Load()
	for i := 0; i < 5; i++ {
		e.clock.Add(10 * time.Second)
		check()
	}
	if n := e.mem.Transacts.Load() - tx0; n != 0 {
		t.Fatalf("%d writes in the first 50 s", n)
	}
	e.clock.Add(15 * time.Second)
	check()
	check()
	if n := e.mem.Transacts.Load() - tx0; n != 1 {
		t.Fatalf("%d writes after a minute, want 1", n)
	}
	s, err := e.core.Load(context.Background(), id)
	if err != nil || !s.LastSeen.Equal(e.clock.Now().Truncate(time.Second)) {
		t.Fatalf("last seen %v, err %v", s.LastSeen, err)
	}
}

func cedarEngine(t *testing.T, text string) *policy.Engine {
	t.Helper()
	eng, err := policy.Start(context.Background(), policy.Static{Name: "test", Policies: []byte(text)})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

// Cedar decides who may reach a route (decision 0007), from the session the check already read; a denial is a 403 and a
// security-audit event with the digest of the policy set.
func TestPolicyDecidesWhoMayReachARoute(t *testing.T) {
	eng := cedarEngine(t, `
permit (principal, action, resource) unless { resource == Route::"admin" };
permit (principal in Group::"admins", action, resource == Route::"admin");
`)
	e := newEnv(t, "storetest", func(o *core.Options) { o.Policy = eng })
	alice := e.signIn(t, "alice", "sid-a", "admins")
	bob := e.signIn(t, "bob", "sid-b", "staff")
	ctx := context.Background()
	if d := e.core.Check(ctx, req("GET", "/admin/x", "Cookie", e.cookie(alice))); d.Outcome != core.Allow {
		t.Fatalf("alice: %+v", d)
	}
	d := e.core.Check(ctx, req("GET", "/admin/x", "Cookie", e.cookie(bob)))
	if d.Status != http.StatusForbidden || d.Reason != "forbidden" {
		t.Fatalf("bob: %+v", d)
	}
	if d := e.core.Check(ctx, req("GET", "/api/x", "Cookie", e.cookie(bob))); d.Outcome != core.Allow {
		t.Fatalf("bob elsewhere: %+v", d)
	}
	evs := e.audit.Events()
	if len(evs) != 1 || evs[0].Kind != core.EventDenied || evs[0].Subject != "bob" || evs[0].Route != "admin" ||
		evs[0].PolicyDigest != eng.Digest() || !strings.HasPrefix(evs[0].PolicyDigest, "sha256:") || evs[0].Site != "docs" {
		t.Fatalf("events %+v", evs)
	}
}

// A check never waits on audit: when the Auditor refuses, the check is answered and the drop is counted.
func TestAuditOutageDoesNotStopChecks(t *testing.T) {
	e := newEnv(t, "storetest")
	e.audit.fail = true
	id := e.signIn(t, "alice", "sid-1")
	d := e.core.Check(context.Background(), req("POST", "/api/x", "Cookie", e.cookie(id)))
	if d.Reason != "csrf" || e.core.Metrics().AuditDropped() != 1 {
		t.Fatalf("got %+v, dropped %d", d, e.core.Metrics().AuditDropped())
	}
}

// Allowed requests are metrics, never events (decision 0008).
func TestAllowsAreCountedNotAudited(t *testing.T) {
	e := newEnv(t, "storetest")
	id := e.signIn(t, "alice", "sid-1")
	for i := 0; i < 3; i++ {
		e.core.Check(context.Background(), req("GET", "/api/x", "Cookie", e.cookie(id)))
	}
	if e.core.Metrics().Checks("allow") != 3 || len(e.audit.Events()) != 0 {
		t.Fatalf("allow %d, events %d", e.core.Metrics().Checks("allow"), len(e.audit.Events()))
	}
	var sb strings.Builder
	if err := e.core.Metrics().WritePrometheus(&sb, "docs"); err != nil || !strings.Contains(sb.String(), `session_checks_total{site="docs",outcome="allow",reason=""} 3`) {
		t.Fatalf("metrics %q, %v", sb.String(), err)
	}
}

func TestRulesAreValidated(t *testing.T) {
	bad := []core.Rules{
		{Site: "Docs", Host: "h", Routes: []core.Route{{Prefix: "/", Mode: core.ModeSession}}},
		{Site: "docs", Host: "", Routes: []core.Route{{Prefix: "/", Mode: core.ModeSession}}},
		{Site: "docs", Host: "h"},
		{Site: "docs", Host: "h", Routes: []core.Route{{Prefix: "/", Exact: "/", Mode: core.ModeSession}}},
		{Site: "docs", Host: "h", Routes: []core.Route{{Prefix: "/_session/x", Mode: core.ModePublic}}},
		{Site: "docs", Host: "h", Routes: []core.Route{{Prefix: "/", Mode: core.ModeExchange, Audience: "a"}}},
		{Site: "docs", Host: "h", Routes: []core.Route{{Prefix: "/", Mode: "other"}}},
		{Site: "docs", Host: "h", Routes: []core.Route{{Prefix: "/", Mode: core.ModePublic, Unauthenticated: core.Unauthenticated401}}},
		{Site: "docs", Host: "h", Idle: time.Hour, Max: time.Minute, Routes: []core.Route{{Prefix: "/", Mode: core.ModeSession}}},
		{Site: "docs", Host: "h", Routes: []core.Route{{Prefix: "/a", Mode: core.ModeSession}, {Name: "/a", Prefix: "/b", Mode: core.ModeSession}}},
	}
	for i, r := range bad {
		if err := r.WithDefaults().Validate(); err == nil {
			t.Fatalf("rules %d accepted", i)
		}
	}
}
