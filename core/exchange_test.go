package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	storev1 "github.com/truvity/atoom/store/gen/atoom/store/v1alpha1"

	"github.com/truvity/session/core"
)

// fakeIssuer is the issuer's token endpoint as the check sees it.
type fakeIssuer struct {
	mu        sync.Mutex
	exchanges atomic.Int64
	refreshes atomic.Int64
	subjects  []string // the subject tokens of the exchanges, in order
	delay     time.Duration
	expiresIn time.Duration
	refuse    string // an OAuth error code for every exchange
	refuseRef string // an OAuth error code for every refresh
	down      bool
	n         atomic.Int64
}

func (f *fakeIssuer) Exchange(ctx context.Context, subject, audience string) (core.Token, error) {
	f.exchanges.Add(1)
	f.mu.Lock()
	f.subjects = append(f.subjects, subject)
	delay, down, refuse, exp := f.delay, f.down, f.refuse, f.expiresIn
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return core.Token{}, ctx.Err()
		}
	}
	switch {
	case down:
		return core.Token{}, errors.New("connection refused")
	case refuse != "":
		return core.Token{}, &core.RefusedError{Code: refuse}
	}
	return core.Token{AccessToken: "tok-" + audience + "-" + subject + "-" + strconv.FormatInt(f.n.Add(1), 10), ExpiresIn: exp}, nil
}

func (f *fakeIssuer) Refresh(_ context.Context, rt string) (core.Refreshed, error) {
	f.refreshes.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuseRef != "" {
		return core.Refreshed{}, &core.RefusedError{Code: f.refuseRef}
	}
	if f.down {
		return core.Refreshed{}, errors.New("connection refused")
	}
	return core.Refreshed{Token: core.Token{AccessToken: "fresh-access", ExpiresIn: 5 * time.Minute}, RefreshToken: rt + "-rotated"}, nil
}

func (f *fakeIssuer) subjectList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.subjects...)
}

// fakeSigner "signs" the claims as their JSON, so the test can read them.
type fakeSigner struct {
	signs atomic.Int64
	fail  atomic.Bool
}

func (s *fakeSigner) Sign(_ context.Context, claims map[string]any) (string, error) {
	s.signs.Add(1)
	if s.fail.Load() {
		return "", errors.New("key driver down")
	}
	b, err := json.Marshal(claims)
	return string(b), err
}

func exchangeRules() core.Rules {
	return core.Rules{
		Site: "docs", Host: "docs.example.test",
		Routes: []core.Route{
			{Name: "billing", Prefix: "/api/billing/", Mode: core.ModeExchange, Audience: "billing"},
			{Name: "legacy", Prefix: "/api/legacy/", Mode: core.ModeIdentityHeader, Audience: "legacy-app"},
			{Name: "hr", Prefix: "/hr/", Mode: core.ModeIdentityHeader},
			{Prefix: "/", Mode: core.ModeSession},
		},
	}
}

func withExchange(iss *fakeIssuer, sig *fakeSigner) option {
	return func(o *core.Options) {
		o.Rules = exchangeRules()
		o.Issuers = map[string]core.Issuer{"https://issuer.example.test": iss}
		o.Identity = sig
	}
}

// signInWith makes a session whose sign-in token ends at accessExp (zero: the issuer said nothing) and has the refresh token.
func (e *env) signInWith(t *testing.T, accessExp time.Time, refresh string) string {
	t.Helper()
	r := &core.Record{Subject: "alice", Issuer: "https://issuer.example.test", SID: "sid-1",
		Claims:  core.Claims{Name: "Alice", Email: "alice@example.test", Groups: []string{"billing-readers"}},
		IDToken: "id-token", AccessToken: "access-token", RefreshToken: refresh}
	if !accessExp.IsZero() {
		r.AccessExpiry = accessExp.Unix()
	}
	id, err := e.core.Create(context.Background(), r, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func bearer(t *testing.T, d core.Decision) string {
	t.Helper()
	if d.Outcome != core.Allow {
		t.Fatalf("outcome %v status %d reason %q", d.Outcome, d.Status, d.Reason)
	}
	v, ok := strings.CutPrefix(d.Set["authorization"], "Bearer ")
	if !ok || v == "" {
		t.Fatalf("no bearer token: %v", d.Set)
	}
	return v
}

// An exchange route carries a token of its audience in Authorization, set over a browser-sent one and never also removed; the
// other owned headers are removed. The next check takes the token from the cache.
func TestAnExchangeRouteCarriesATokenOfItsAudience(t *testing.T) {
	for _, backend := range stores() {
		t.Run(backend, func(t *testing.T) {
			iss := &fakeIssuer{expiresIn: 5 * time.Minute}
			e := newEnv(t, backend, withExchange(iss, &fakeSigner{}))
			id := e.signInWith(t, time.Time{}, "")
			ctx := context.Background()
			d := e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id), "Authorization", "Bearer forged"))
			tok := bearer(t, d)
			if !strings.HasPrefix(tok, "tok-billing-access-token-") {
				t.Fatalf("token %q", tok)
			}
			if slices.Contains(d.Remove, "authorization") || !slices.Contains(d.Remove, "x-session-token") || !slices.Contains(d.Remove, core.IdentityHeader) {
				t.Fatalf("remove %v", d.Remove)
			}
			again := bearer(t, e.core.Check(ctx, req("GET", "/api/billing/y", "Cookie", e.cookie(id))))
			if again != tok || iss.exchanges.Load() != 1 {
				t.Fatalf("second check: %q after %d exchanges", again, iss.exchanges.Load())
			}
			// A session route next to it carries no token.
			if d := e.core.Check(ctx, req("GET", "/app", "Cookie", e.cookie(id))); d.Outcome != core.Allow || d.Set["authorization"] != "" {
				t.Fatalf("session route: %+v", d)
			}
			ev := e.audit.Events()
			if len(ev) != 1 || ev[0].Kind != core.EventExchange || ev[0].Audience != "billing" || ev[0].Reason != "" || ev[0].Subject != "alice" {
				t.Fatalf("events %+v", ev)
			}
		})
	}
}

// A cached token is used until its end minus the skew, then exchanged again. A token that lives no longer than the skew is not
// cached.
func TestACachedTokenEndsBeforeTheToken(t *testing.T) {
	iss := &fakeIssuer{expiresIn: 2 * time.Minute}
	e := newEnv(t, "storetest", withExchange(iss, &fakeSigner{}))
	id := e.signInWith(t, time.Time{}, "")
	ctx := context.Background()
	check := func() string {
		return bearer(t, e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id))))
	}
	first := check()
	e.clock.Add(89 * time.Second)
	if check() != first || iss.exchanges.Load() != 1 {
		t.Fatal("the token was exchanged again before its end minus the skew")
	}
	e.clock.Add(2 * time.Second)
	if check() == first || iss.exchanges.Load() != 2 {
		t.Fatal("the token was used past its end minus the skew")
	}
	iss.mu.Lock()
	iss.expiresIn = 20 * time.Second
	iss.mu.Unlock()
	e.clock.Add(2 * time.Minute)
	check()
	check()
	if iss.exchanges.Load() != 4 {
		t.Fatalf("a token shorter than the skew was cached: %d exchanges", iss.exchanges.Load())
	}
}

// Parallel checks of one session and audience make one exchange: the others wait for the lock holder's token.
func TestParallelChecksMakeOneExchange(t *testing.T) {
	for _, backend := range stores() {
		t.Run(backend, func(t *testing.T) {
			iss := &fakeIssuer{expiresIn: 5 * time.Minute, delay: 300 * time.Millisecond}
			e := newEnv(t, backend, withExchange(iss, &fakeSigner{}))
			id := e.signInWith(t, time.Time{}, "")
			var wg sync.WaitGroup
			toks := make([]string, 12)
			for i := range toks {
				wg.Go(func() {
					d := e.core.Check(context.Background(), req("GET", "/api/billing/x", "Cookie", e.cookie(id)))
					toks[i] = d.Set["authorization"]
				})
			}
			wg.Wait()
			for _, tk := range toks {
				if tk == "" || tk != toks[0] {
					t.Fatalf("tokens %q", toks)
				}
			}
			if n := iss.exchanges.Load(); n != 1 {
				t.Fatalf("%d exchanges", n)
			}
		})
	}
}

// A refused exchange is a 403 for the route: the site's error page to a navigation, JSON to anything else. The session
// stays, and the refusal is an audit event with the issuer's error code.
func TestARefusedExchangeIs403AndTheSessionStays(t *testing.T) {
	iss := &fakeIssuer{refuse: "invalid_target"}
	e := newEnv(t, "storetest", func(o *core.Options) {
		withExchange(iss, &fakeSigner{})(o)
		o.Rules.ErrorPage = []byte("<p>no billing for you</p>")
	})
	id := e.signInWith(t, time.Time{}, "")
	ctx := context.Background()
	d := e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id), "Accept", "application/json"))
	if d.Outcome != core.Deny || d.Status != http.StatusForbidden || d.ContentType != "application/json" || body(t, d)["error"] != "exchange_refused" {
		t.Fatalf("fetch: %+v", d)
	}
	d = e.core.Check(ctx, nav("/api/billing/x", "Cookie", e.cookie(id)))
	if d.Status != http.StatusForbidden || !strings.HasPrefix(d.ContentType, "text/html") || string(d.Body) != "<p>no billing for you</p>" {
		t.Fatalf("navigation: %d %q %q", d.Status, d.ContentType, d.Body)
	}
	if _, err := e.core.Load(ctx, id); err != nil {
		t.Fatalf("the session did not stay: %v", err)
	}
	if d := e.core.Check(ctx, req("GET", "/app", "Cookie", e.cookie(id))); d.Outcome != core.Allow {
		t.Fatalf("the other routes: %+v", d)
	}
	ev := e.audit.Events()
	if len(ev) != 2 || ev[0].Kind != core.EventExchange || ev[0].Reason != "invalid_target" {
		t.Fatalf("events %+v", ev)
	}
}

// An issuer that does not answer, or answers past the exchange timeout, is a 503: fail closed, never an allow without the
// token, and the session stays.
func TestAnIssuerOutageIs503(t *testing.T) {
	iss := &fakeIssuer{down: true}
	e := newEnv(t, "storetest", func(o *core.Options) {
		withExchange(iss, &fakeSigner{})(o)
		o.Rules.ExchangeTimeout = 200 * time.Millisecond
	})
	id := e.signInWith(t, time.Time{}, "")
	ctx := context.Background()
	d := e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id)))
	if d.Outcome != core.Unavailable || d.Status != 503 || d.Reason != "exchange" {
		t.Fatalf("down: %+v", d)
	}
	iss.mu.Lock()
	iss.down, iss.delay = false, time.Second
	iss.mu.Unlock()
	start := time.Now()
	d = e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id)))
	if d.Outcome != core.Unavailable || time.Since(start) > 800*time.Millisecond {
		t.Fatalf("slow: %+v after %v", d, time.Since(start))
	}
	if _, err := e.core.Load(ctx, id); err != nil {
		t.Fatal("an outage ended the session")
	}
	// The store down is a 503 too.
	e.mem.Down.Store(true)
	if d := e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id))); d.Outcome != core.Unavailable {
		t.Fatalf("store down: %+v", d)
	}
}

// An old sign-in token is refreshed before the exchange, under the same lock: the exchange gets the new token, and the
// session keeps the rotated refresh token.
func TestAnOldSignInTokenIsRefreshedFirst(t *testing.T) {
	for _, backend := range stores() {
		t.Run(backend, func(t *testing.T) {
			iss := &fakeIssuer{expiresIn: 5 * time.Minute}
			e := newEnv(t, backend, withExchange(iss, &fakeSigner{}))
			id := e.signInWith(t, e.clock.Now().Add(10*time.Second), "refresh-1")
			ctx := context.Background()
			tok := bearer(t, e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id))))
			if iss.refreshes.Load() != 1 || !strings.HasPrefix(tok, "tok-billing-fresh-access-") || iss.subjectList()[0] != "fresh-access" {
				t.Fatalf("token %q after %d refreshes", tok, iss.refreshes.Load())
			}
			s, err := e.core.Load(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if s.AccessToken != "fresh-access" || s.RefreshToken != "refresh-1-rotated" || s.AccessExpiry != e.clock.Now().Add(5*time.Minute).Unix() {
				t.Fatalf("record %+v", s.Record)
			}
			// A fresh token is not refreshed again.
			if d := e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id))); d.Outcome != core.Allow || iss.refreshes.Load() != 1 {
				t.Fatalf("refreshed again: %d", iss.refreshes.Load())
			}
			// The write of the rotated tokens resent the index entries (decision 0031): a back-channel logout still finds it.
			if n, err := e.core.LogoutBy(ctx, "https://issuer.example.test", "sid-1", ""); err != nil || n != 1 {
				t.Fatalf("logout after the refresh: %d, %v", n, err)
			}
			if _, err := e.core.Load(ctx, id); !errors.Is(err, core.ErrNotFound) {
				t.Fatalf("the session survived: %v", err)
			}
		})
	}
}

// A refresh that the issuer refuses with invalid_grant, or a session without a refresh token, ends the session: the check
// answers as without a session and clears the cookie. Any other refusal or an outage is a 503, and the session stays.
func TestAFailedRefreshEndsTheSession(t *testing.T) {
	ctx := context.Background()
	t.Run("invalid_grant", func(t *testing.T) {
		iss := &fakeIssuer{expiresIn: 5 * time.Minute, refuseRef: "invalid_grant"}
		e := newEnv(t, "storetest", withExchange(iss, &fakeSigner{}))
		id := e.signInWith(t, e.clock.Now(), "refresh-1")
		d := e.core.Check(ctx, nav("/api/billing/x", "Cookie", e.cookie(id)))
		if d.Outcome != core.Redirect || d.Reason != "login_required" || len(d.SetCookies) != 1 || !strings.Contains(d.SetCookies[0], "Max-Age=0") {
			t.Fatalf("decision %+v", d)
		}
		if _, err := e.core.Load(ctx, id); !errors.Is(err, core.ErrNotFound) {
			t.Fatalf("the session stayed: %v", err)
		}
		if iss.exchanges.Load() != 0 {
			t.Fatal("exchanged with an old token")
		}
		ev := e.audit.Events()
		if len(ev) != 1 || ev[0].Kind != core.EventRefreshFailed || ev[0].Reason != "invalid_grant" {
			t.Fatalf("events %+v", ev)
		}
	})
	t.Run("no refresh token", func(t *testing.T) {
		e := newEnv(t, "storetest", withExchange(&fakeIssuer{}, &fakeSigner{}))
		id := e.signInWith(t, e.clock.Now(), "")
		if d := e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id))); d.Status != http.StatusUnauthorized {
			t.Fatalf("decision %+v", d)
		}
		if _, err := e.core.Load(ctx, id); !errors.Is(err, core.ErrNotFound) {
			t.Fatal("the session stayed")
		}
	})
	t.Run("invalid_client", func(t *testing.T) {
		e := newEnv(t, "storetest", withExchange(&fakeIssuer{refuseRef: "invalid_client"}, &fakeSigner{}))
		id := e.signInWith(t, e.clock.Now(), "refresh-1")
		if d := e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id))); d.Outcome != core.Unavailable {
			t.Fatalf("decision %+v", d)
		}
		if _, err := e.core.Load(ctx, id); err != nil {
			t.Fatal("a fault of the installation ended the session")
		}
	})
	t.Run("outage", func(t *testing.T) {
		e := newEnv(t, "storetest", withExchange(&fakeIssuer{down: true}, &fakeSigner{}))
		id := e.signInWith(t, e.clock.Now(), "refresh-1")
		if d := e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id))); d.Outcome != core.Unavailable {
			t.Fatalf("decision %+v", d)
		}
		if _, err := e.core.Load(ctx, id); err != nil {
			t.Fatal("an outage ended the session")
		}
	})
}

// The cached tokens are deleted with the session: at the person's logout and at a back-channel logout.
func TestCachedTokensAreDeletedWithTheSession(t *testing.T) {
	for _, backend := range stores() {
		t.Run(backend, func(t *testing.T) {
			iss := &fakeIssuer{expiresIn: 5 * time.Minute}
			e := newEnv(t, backend, withExchange(iss, &fakeSigner{}))
			ctx := context.Background()
			under := func(id string) int {
				prefix := string(sessionKeyOf(t, e, id)) + "/"
				n := 0
				for _, k := range e.storeKeys(t) {
					if strings.HasPrefix(k, prefix) {
						n++
					}
				}
				return n
			}
			a := e.signInWith(t, time.Time{}, "")
			bearer(t, e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(a))))
			if under(a) != 1 {
				t.Fatalf("%d items under the session, want the cached token", under(a))
			}
			if err := e.core.Delete(ctx, a); err != nil {
				t.Fatal(err)
			}
			if under(a) != 0 {
				t.Fatal("the cached token outlived the logout")
			}
			b := e.signInWith(t, time.Time{}, "")
			bearer(t, e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(b))))
			if _, err := e.core.LogoutBy(ctx, "https://issuer.example.test", "sid-1", "alice"); err != nil {
				t.Fatal(err)
			}
			if under(b) != 0 {
				t.Fatal("the cached token outlived the back-channel logout")
			}
		})
	}
}

// identity reads the fake signer's "header" back into claims.
func identity(t *testing.T, d core.Decision) map[string]any {
	t.Helper()
	if d.Outcome != core.Allow {
		t.Fatalf("outcome %v status %d reason %q", d.Outcome, d.Status, d.Reason)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(d.Set[core.IdentityHeader]), &m); err != nil {
		t.Fatalf("identity header %q: %v", d.Set[core.IdentityHeader], err)
	}
	return m
}

// An identity-header route carries the signed identity: iss the site's origin, aud the route's audience or the origin, the
// person's subject, name, email and groups, and a life of a minute. A header is reused for half its life.
func TestAnIdentityHeaderRouteCarriesTheSignedIdentity(t *testing.T) {
	sig := &fakeSigner{}
	e := newEnv(t, "storetest", withExchange(&fakeIssuer{}, sig))
	id := e.signInWith(t, time.Time{}, "")
	ctx := context.Background()
	d := e.core.Check(ctx, req("GET", "/api/legacy/x", "Cookie", e.cookie(id), "X-Session-Identity", "forged"))
	c := identity(t, d)
	now := e.clock.Now().Unix()
	if c["iss"] != "https://docs.example.test" || c["aud"] != "legacy-app" || c["sub"] != "alice" || c["name"] != "Alice" ||
		c["email"] != "alice@example.test" || c["iat"] != float64(now) || c["exp"] != float64(now+60) {
		t.Fatalf("claims %v", c)
	}
	if g, _ := c["groups"].([]any); len(g) != 1 || g[0] != "billing-readers" {
		t.Fatalf("groups %v", c["groups"])
	}
	if slices.Contains(d.Remove, core.IdentityHeader) || !slices.Contains(d.Remove, "authorization") {
		t.Fatalf("remove %v", d.Remove)
	}
	if c := identity(t, e.core.Check(ctx, req("GET", "/hr/x", "Cookie", e.cookie(id)))); c["aud"] != "https://docs.example.test" {
		t.Fatalf("default aud %v", c["aud"])
	}
	if sig.signs.Load() != 2 {
		t.Fatalf("%d signatures", sig.signs.Load())
	}
	e.clock.Add(29 * time.Second)
	identity(t, e.core.Check(ctx, req("GET", "/api/legacy/y", "Cookie", e.cookie(id))))
	if sig.signs.Load() != 2 {
		t.Fatal("a header was signed again within half its life")
	}
	e.clock.Add(2 * time.Second)
	if c := identity(t, e.core.Check(ctx, req("GET", "/api/legacy/y", "Cookie", e.cookie(id)))); c["iat"] != float64(now+31) || sig.signs.Load() != 3 {
		t.Fatalf("not signed again after half its life: %v", c)
	}
	// After a logout the cached header is never served: the check reads the session first.
	if err := e.core.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if d := e.core.Check(ctx, req("GET", "/api/legacy/y", "Cookie", e.cookie(id))); d.Outcome == core.Allow {
		t.Fatal("an identity header after the logout")
	}
	// A key driver that fails is a 503.
	id = e.signInWith(t, time.Time{}, "")
	sig.fail.Store(true)
	if d := e.core.Check(ctx, req("GET", "/api/legacy/x", "Cookie", e.cookie(id))); d.Outcome != core.Unavailable || d.Reason != "identity" {
		t.Fatalf("signer down: %+v", d)
	}
}

// The block refuses to start with a route whose dependency is missing.
func TestTheModesNeedTheirDependencies(t *testing.T) {
	e := newEnv(t, "storetest")
	for name, o := range map[string]core.Options{
		"exchange without issuer": {Rules: exchangeRules(), Items: e.items, Seal: e.seal, Identity: &fakeSigner{}},
		"identity-header without signer": {Rules: exchangeRules(), Items: e.items, Seal: e.seal,
			Issuers: map[string]core.Issuer{"https://issuer.example.test": &fakeIssuer{}}},
	} {
		if _, err := core.New(o); err == nil {
			t.Errorf("%s: started", name)
		}
	}
}

// storeKeys lists the keys of the live session items and the items under them, on either backend.
func (e *env) storeKeys(t *testing.T) []string {
	t.Helper()
	var keys []string
	var token []byte
	for {
		res, err := e.items.Query(context.Background(), connect.NewRequest(&storev1.QueryRequest{Prefix: []byte("s/"), PageToken: token, Linearizable: true}))
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range res.Msg.GetItems() {
			keys = append(keys, string(it.GetKey()))
		}
		if token = res.Msg.GetNextPageToken(); len(token) == 0 {
			return keys
		}
	}
}

// A site of several issuers (decision 0034): a session's exchange and refresh go to its own issuer, never to another; the block
// refuses to start when an issuer of the rules has no client.
func TestTheExchangeGoesToTheSessionsIssuer(t *testing.T) {
	corp, partner := &fakeIssuer{expiresIn: 5 * time.Minute}, &fakeIssuer{expiresIn: 5 * time.Minute}
	const corpURL, partnerURL = "https://issuer.example.test", "https://partner.example.test"
	e := newEnv(t, "storetest", func(o *core.Options) {
		o.Rules = exchangeRules()
		o.Rules.Issuers = []string{corpURL, partnerURL}
		o.Issuers = map[string]core.Issuer{corpURL: corp, partnerURL: partner}
		o.Identity = &fakeSigner{}
	})
	ctx := context.Background()
	id, err := e.core.Create(ctx, &core.Record{Subject: "bob", Issuer: partnerURL, SID: "sid-2", AccessToken: "partner-access",
		RefreshToken: "partner-refresh", AccessExpiry: e.clock.Now().Add(10 * time.Second).Unix()}, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	bearer(t, e.core.Check(ctx, req("GET", "/api/billing/x", "Cookie", e.cookie(id))))
	if corp.exchanges.Load() != 0 || corp.refreshes.Load() != 0 || partner.exchanges.Load() != 1 || partner.refreshes.Load() != 1 {
		t.Fatalf("corp %d/%d, partner %d/%d", corp.exchanges.Load(), corp.refreshes.Load(), partner.exchanges.Load(), partner.refreshes.Load())
	}
	missing := exchangeRules()
	missing.Issuers = []string{corpURL, partnerURL}
	if _, err := core.New(core.Options{Rules: missing, Items: e.items, Seal: e.seal, Identity: &fakeSigner{},
		Issuers: map[string]core.Issuer{corpURL: corp}}); err == nil {
		t.Fatal("started without the partner's client")
	}
}
