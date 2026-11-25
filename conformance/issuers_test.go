package conformance_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/kctest"
)

// TestConformanceTwoIssuers runs the scenarios of a site of two issuers (decision 0034): two realms of the test Keycloak, each
// an issuer of the site with its own person, the sign-in page, ?issuer=, a sign-in through each, a mix-up refused, a policy by
// issuer, the exchange at the session's issuer, and logout and back-channel logout through the right issuer. The sign-in paths
// are the same on every host, so they run through one host, Envoy over gRPC; the suite of one issuer runs through every host.
func TestConformanceTwoIssuers(t *testing.T) {
	kc := kctest.Need(t)
	browser := startBrowser(t, localBrowserArgs()...)
	st := newStand(t, kc, standConfig{partner: true})
	hosts[0].start(t, st)
	x := &twoIssuers{st: st, corp: st.issuers[0], partner: st.issuers[1],
		a: newTab(browser, t, st.origin), b: newTab(browser, t, st.origin)}
	for _, s := range twoIssuerScenarios {
		if !t.Run(s.name, func(t *testing.T) { s.run(t, x) }) {
			t.FailNow()
		}
	}
	st.audit.mu.Lock()
	text := st.audit.b.String()
	st.audit.mu.Unlock()
	checkRecords(t, text, []string{st.issuers[0].person.Email, st.issuers[1].person.Email}, nil)
	for _, is := range st.issuers {
		if !strings.Contains(text, `"issuer":"`+is.issuer+`"`) {
			t.Errorf("no audit record names the issuer %s", is.id)
		}
	}
}

// twoIssuers is the stand of two issuers as its scenarios see it: tab a is the person of the first issuer, tab b the person of
// the second, each a browser profile of its own.
type twoIssuers struct {
	st            *stand
	corp, partner standIssuer
	a, b          *tab
}

type twoIssuerScenario struct {
	name string
	run  func(t *testing.T, x *twoIssuers)
}

// whoamiEmail is the e-mail address whoami names in the tab, or "" without a session.
func whoamiEmail(t *testing.T, b *tab) string {
	t.Helper()
	r := b.fetch(t, "GET", core.PathWhoami, nil)
	if r.Status != http.StatusOK {
		return ""
	}
	var who struct{ Email string }
	_ = json.Unmarshal([]byte(r.Body), &who)
	return who.Email
}

// exchangedBy says that the tab's exchange route gets a token of the audience billing that the issuer signed, and no other.
func exchangedBy(t *testing.T, b *tab, is, other standIssuer) {
	t.Helper()
	r := b.fetch(t, "GET", "/api/billing/x", nil)
	a := decodeSeen(t, r.Body).Headers["Authorization"]
	if r.Status != http.StatusOK || len(a) != 1 || !strings.HasPrefix(a[0], "Bearer ") {
		t.Fatalf("exchange route: %d %q", r.Status, a)
	}
	ctx := context.Background()
	verify := func(issuer string) error {
		p, err := oidc.NewProvider(ctx, issuer)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.VerifierContext(ctx, &oidc.Config{ClientID: "billing"}).Verify(ctx, strings.TrimPrefix(a[0], "Bearer "))
		return err
	}
	if err := verify(is.issuer); err != nil {
		t.Fatalf("the token is not %s's: %v", is.id, err)
	}
	if verify(other.issuer) == nil {
		t.Fatalf("the token verifies at %s too", other.id)
	}
}

// logoutURL posts the logout with the CSRF headers and returns the address the browser is sent to.
func logoutURL(t *testing.T, b *tab) string {
	t.Helper()
	r := b.fetch(t, "POST", core.PathLogout, csrf)
	var out struct {
		LogoutURL string `json:"logout_url"`
	}
	if r.Status != http.StatusOK || json.Unmarshal([]byte(r.Body), &out) != nil {
		t.Fatalf("logout: %+v", r)
	}
	return out.LogoutURL
}

// toCallback starts a sign-in at the issuer outside the browser, through the host's plain listener, plays the person at the
// issuer's form, and stops at the site's callback: it returns the callback's address and the binding cookie of the sign-in.
func (x *twoIssuers) toCallback(t *testing.T, is standIssuer, returnTo string) (*url.URL, string) {
	t.Helper()
	st := x.st
	login, err := raw(st.proxy, http.MethodGet, core.PathLogin+"?"+url.Values{"issuer": {is.id}, "return_to": {returnTo}}.Encode(), st.host)
	if err != nil || login.status != http.StatusFound {
		t.Fatalf("login: %v %+v", err, login)
	}
	var binding string
	for _, c := range (&http.Response{Header: login.header}).Cookies() {
		if c.Name == st.core.BindingCookieName() {
			binding = c.Name + "=" + c.Value
		}
	}
	at := login.header.Get("Location")
	if binding == "" || !strings.HasPrefix(at, is.issuer+"/") {
		t.Fatalf("login: sent to %q, binding %q", at, binding)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Path == core.PathCallback {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	res, err := client.Get(at)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusFound {
		if res, err = kctest.SignIn(client, res, is.person); err != nil {
			t.Fatal(err)
		}
	}
	_ = res.Body.Close()
	cb, err := res.Location()
	if err != nil || cb.Path != core.PathCallback {
		t.Fatalf("not at the callback: %d %v", res.StatusCode, err)
	}
	return cb, binding
}

var twoIssuerScenarios = []twoIssuerScenario{
	{name: "the sign-in page: a navigation without a session lands on one link for each issuer, with no script", run: func(t *testing.T, x *twoIssuers) {
		if s := x.a.open(t, x.st.origin+"/app/x?y=1"); s != http.StatusOK {
			t.Fatalf("the page: %d", s)
		}
		if loc := x.a.location(t); loc != x.st.origin+core.PathSignIn+"?return_to=%2Fapp%2Fx%3Fy%3D1" {
			t.Fatalf("landed at %s", loc)
		}
		text := x.a.text(t)
		for _, is := range x.st.issuers {
			if !strings.Contains(text, "Sign in with "+is.label) {
				t.Fatalf("no link for %s: %q", is.id, text)
			}
		}
		hrefs := run(t, x.a, chromedp.Evaluate[[]string](`[...document.querySelectorAll("a")].map(a => a.getAttribute("href"))`))
		want := []string{
			core.PathLogin + "?issuer=corp&return_to=%2Fapp%2Fx%3Fy%3D1",
			core.PathLogin + "?issuer=partner&return_to=%2Fapp%2Fx%3Fy%3D1",
		}
		if strings.Join(hrefs, " ") != strings.Join(want, " ") {
			t.Fatalf("links %q, want %q", hrefs, want)
		}
		if n := run(t, x.a, chromedp.Evaluate[int](`document.scripts.length + document.forms.length`)); n != 0 {
			t.Fatalf("the page has %d scripts and forms", n)
		}
		page, err := raw(x.st.proxy, http.MethodGet, core.PathSignIn+"?return_to=%2F", x.st.host)
		if err != nil {
			t.Fatal(err)
		}
		if csp := page.header.Get("Content-Security-Policy"); page.status != http.StatusOK || !strings.Contains(csp, "default-src 'none'") ||
			strings.Contains(csp, "script-src") || page.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("the page's headers: %d %v", page.status, page.header)
		}
	}},

	{name: "sign-in through the first issuer: its link leads to its realm and back", run: func(t *testing.T, x *twoIssuers) {
		run(t, x.a, chromedp.Click(chromedp.CSS(`a[href*="issuer=corp"]`)))
		x.a.signIn(t, x.corp.issuer, x.corp.person)
		if loc := x.a.location(t); loc != x.st.origin+"/app/x?y=1" {
			t.Fatalf("landed at %s", loc)
		}
		if e := whoamiEmail(t, x.a); e != x.corp.person.Email {
			t.Fatalf("whoami: %q", e)
		}
	}},

	{name: "?issuer= skips the page: sign-in through the second issuer", run: func(t *testing.T, x *twoIssuers) {
		x.b.open(t, x.st.origin+core.PathSignIn+"?issuer=partner&return_to=%2Fapp%2Fy")
		if !x.b.atLoginForm(t, x.partner.issuer) {
			t.Fatalf("not at the second issuer's form: %s", x.b.location(t))
		}
		x.b.signIn(t, x.partner.issuer, x.partner.person)
		if loc := x.b.location(t); loc != x.st.origin+"/app/y" {
			t.Fatalf("landed at %s", loc)
		}
		if e := whoamiEmail(t, x.b); e != x.partner.person.Email {
			t.Fatalf("whoami: %q", e)
		}
		if s := x.b.open(t, x.st.origin+core.PathSignIn+"?issuer=nobody&return_to=%2F"); s != http.StatusBadRequest {
			t.Fatalf("an unknown issuer: %d", s)
		}
	}},

	{name: "policy by issuer: each issuer's route lets only its own people through", run: func(t *testing.T, x *twoIssuers) {
		for _, c := range []struct {
			b      *tab
			path   string
			status int
		}{{x.a, "/corp/x", http.StatusOK}, {x.a, "/partner/x", http.StatusForbidden}, {x.b, "/partner/x", http.StatusOK},
			{x.b, "/corp/x", http.StatusForbidden}, {x.a, "/app/x", http.StatusOK}, {x.b, "/app/x", http.StatusOK}} {
			if r := c.b.fetch(t, "GET", c.path, nil); r.Status != c.status {
				t.Errorf("%s: %+v, want %d", c.path, r, c.status)
			}
		}
	}},

	{name: "the exchange goes to the session's issuer", run: func(t *testing.T, x *twoIssuers) {
		exchangedBy(t, x.a, x.corp, x.partner)
		exchangedBy(t, x.b, x.partner, x.corp)
	}},

	{name: "mix-up: a callback that names another issuer than the one chosen is refused", run: func(t *testing.T, x *twoIssuers) {
		st := x.st
		cb, binding := x.toCallback(t, x.corp, "/mix")
		q := cb.Query()
		if q.Get("iss") != x.corp.issuer {
			t.Fatalf("Keycloak sent iss %q", q.Get("iss"))
		}
		q.Set("iss", x.partner.issuer)
		r, err := raw(st.proxy, http.MethodGet, cb.Path+"?"+q.Encode(), st.host, "Cookie", binding)
		if err != nil || r.status != http.StatusBadRequest {
			t.Fatalf("the mixed-up callback: %v %+v", err, r)
		}
		for _, c := range r.header.Values("Set-Cookie") {
			if strings.HasPrefix(c, st.core.CookieName()+"=") {
				t.Fatalf("the mixed-up callback set a session: %s", c)
			}
		}
		// The same sign-in, untampered, completes: the refusal was the iss.
		cb, binding = x.toCallback(t, x.corp, "/mix")
		r, err = raw(st.proxy, http.MethodGet, cb.Path+"?"+cb.RawQuery, st.host, "Cookie", binding)
		if err != nil || r.status != http.StatusFound || r.header.Get("Location") != "/mix" {
			t.Fatalf("the callback: %v %+v", err, r)
		}
	}},

	{name: "logout through the session's issuer, and without a live session back to the site", run: func(t *testing.T, x *twoIssuers) {
		u := logoutURL(t, x.a)
		if !strings.HasPrefix(u, x.corp.issuer+"/protocol/openid-connect/logout?") || !strings.Contains(u, "id_token_hint=") {
			t.Fatalf("logout: %s", u)
		}
		x.a.open(t, u)
		x.a.waitFor(t, "the sign-in page after the logout", func() bool {
			return strings.HasPrefix(x.a.location(t), x.st.origin+core.PathSignIn+"?")
		})
		if r := x.b.fetch(t, "GET", "/app/x", nil); r.Status != http.StatusOK {
			t.Fatalf("the other issuer's session after the logout: %+v", r)
		}
		// The sign-in page allows no fetch (its CSP): the tab goes back to a page of the site first, as the site's own scripts run there.
		x.a.open(t, x.st.origin+"/assets/app.js")
		// Without a live session, a site of two issuers that remembers no choice cannot tell whose end-session it is.
		if u := logoutURL(t, x.a); u != x.st.origin+"/" {
			t.Fatalf("logout without a live session: %s", u)
		}
		// The first issuer's session is gone too: its form shows again.
		x.a.open(t, x.st.origin+core.PathSignIn+"?issuer=corp&return_to=%2Fapp%2Fz")
		x.a.signIn(t, x.corp.issuer, x.corp.person)
	}},

	{name: "back-channel logout: one issuer's logout ends only its own sessions", run: func(t *testing.T, x *twoIssuers) {
		x.st.kc.LogoutUser(t, x.partner.realm, x.partner.person.Username)
		x.b.waitFor(t, "the 401 after the back-channel logout", func() bool {
			return x.b.fetch(t, "GET", "/app/x", nil).Status == http.StatusUnauthorized
		})
		if r := x.a.fetch(t, "GET", "/app/x", nil); r.Status != http.StatusOK {
			t.Fatalf("the first issuer's session after the second's logout: %+v", r)
		}
		u := logoutURL(t, x.b)
		if u != x.st.origin+"/" {
			t.Fatalf("logout after the back-channel logout: %s", u)
		}
		if u := logoutURL(t, x.a); !strings.HasPrefix(u, x.corp.issuer+"/protocol/openid-connect/logout?") {
			t.Fatalf("logout: %s", u)
		}
	}},
}
