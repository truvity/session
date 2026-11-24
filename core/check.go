package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Request is what an adapter hands the check: the method, the host, the path with its query as the proxy routes it, and the
// headers. Never a body.
type Request struct {
	Method string
	Host   string
	Path   string
	Header http.Header
}

// Outcome is the kind of a decision.
type Outcome int

// The outcomes. An adapter turns each into its proxy's protocol.
const (
	Allow       Outcome = iota // the request passes, with the headers of the decision
	Redirect                   // a 302 to Location (a navigation without a session)
	Deny                       // a 4xx with a JSON body
	Unavailable                // the store or a dependency failed: 503, never allow
)

// OwnedHeaders are the headers the check owns on the upstream request (S8). A browser-sent value never passes: the allow answer removes them, or
// sets them. Cookie is rewritten without session's own cookies.
var OwnedHeaders = []string{"authorization", "x-session-token", "x-session-identity"}

// Decision is the check's answer.
type Decision struct {
	Outcome     Outcome
	Status      int
	Reason      string // a short machine word: login_required, csrf, forbidden, no_route, bad_path, store, policy, exchange_refused, exchange, identity
	Location    string
	ContentType string
	Body        []byte
	// Set are the upstream request headers to set, overwriting a browser-sent value (lower-case names).
	Set map[string]string
	// Remove are the upstream request headers to remove (lower-case names).
	Remove []string
	// SetCookies are Set-Cookie values for the response to the browser.
	SetCookies []string
	// Subject is the session's subject on an allow, for the adapter's own log line; it is never a header of the answer.
	Subject string
}

// The CSRF rule (S5): a state-changing request carries this header with exactly this value, which a cross-site form cannot
// send, and its Origin and Sec-Fetch-Site say it came from the site's own pages.
const (
	CSRFHeader = "X-Requested-With"
	CSRFValue  = "XMLHttpRequest"
)

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// CSRFOK applies S5 to a request: a safe method passes; any other needs the CSRF header with its value, a Sec-Fetch-Site that is
// same-origin when present, and an Origin that is the site's own, or no Origin with Sec-Fetch-Site same-origin.
func (c *Core) CSRFOK(method string, h http.Header) bool {
	if safeMethod(method) {
		return true
	}
	if h.Get(CSRFHeader) != CSRFValue {
		return false
	}
	sfs := h.Get("Sec-Fetch-Site")
	if sfs != "" && sfs != "same-origin" {
		return false
	}
	if o := h.Get("Origin"); o != "" {
		return o == "https://"+c.rules.Host
	}
	return sfs == "same-origin"
}

// IsNavigation says whether a request is a top-level navigation (decision 0004): GET, Sec-Fetch-Mode navigate, Accept with
// text/html.
func IsNavigation(r Request) bool {
	return r.Method == http.MethodGet && r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
}

// cleanPath refuses a path that the proxy should have normalised: the check must match on the path the proxy routes on
// (decision 0011), so a path with dot segments, empty segments, encoded dots, slashes or backslashes is refused, not guessed.
func cleanPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.Contains(p, `\`) {
		return false
	}
	lower := strings.ToLower(p)
	for _, bad := range []string{"%2e", "%2f", "%5c", "%00"} {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// LoginURL is the sign-in address with the page to return to.
func LoginURL(returnTo string) string { return PathLogin + "?return_to=" + url.QueryEscape(returnTo) }

func jsonBody(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func (c *Core) deny(status int, reason string, body any) Decision {
	return Decision{Outcome: Deny, Status: status, Reason: reason, ContentType: "application/json", Body: jsonBody(body)}
}

func unavailable(reason string) Decision {
	return Decision{Outcome: Unavailable, Status: http.StatusServiceUnavailable, Reason: reason,
		ContentType: "application/json", Body: jsonBody(map[string]string{"error": "unavailable"})}
}

// defaultErrorPage is the page a navigation gets when the issuer refuses the exchange of its route and the site file names
// no page of its own.
const defaultErrorPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Access refused</title></head>
<body><h1>Access refused</h1><p>You are signed in, but this part of the site is not available to you.</p></body></html>
`

// exchangeRefused is the answer when the issuer refuses the exchange for a route (decision 0005): the site's error page to a
// navigation, a JSON 403 to anything else. The session stays.
func (c *Core) exchangeRefused(r Request) Decision {
	if IsNavigation(r) {
		return Decision{Outcome: Deny, Status: http.StatusForbidden, Reason: "exchange_refused",
			ContentType: "text/html; charset=utf-8", Body: c.rules.ErrorPage}
	}
	return c.deny(http.StatusForbidden, "exchange_refused", map[string]string{"error": "exchange_refused"})
}

// Check is the whole decision for one request. It fails closed: a store failure is 503, never allow.
func (c *Core) Check(ctx context.Context, r Request) Decision {
	d := c.check(ctx, r)
	label := map[Outcome]string{Allow: "allow", Redirect: "deny", Deny: "deny", Unavailable: "unavailable"}[d.Outcome]
	if d.Reason != "" {
		label += "/" + d.Reason
	}
	c.metrics.count(label)
	return d
}

func (c *Core) check(ctx context.Context, r Request) Decision {
	path, _, _ := strings.Cut(r.Path, "?")
	if !cleanPath(path) {
		return c.deny(http.StatusBadRequest, "bad_path", map[string]string{"error": "bad_path"})
	}
	id, otherCookies := c.SplitCookies(r.Header)
	// allow is the allow answer: the owned headers are removed, except those the route sets, which overwrite a browser-sent
	// value; Cookie keeps only the cookies that are not session's. A header is never both set and removed.
	allow := func(s *Session, set map[string]string) Decision {
		d := Decision{Outcome: Allow, Set: map[string]string{}}
		for k, v := range set {
			d.Set[k] = v
		}
		for _, h := range OwnedHeaders {
			if _, ok := d.Set[h]; !ok {
				d.Remove = append(d.Remove, h)
			}
		}
		if otherCookies != "" {
			d.Set["cookie"] = otherCookies
		} else {
			d.Remove = append(d.Remove, "cookie")
		}
		if s != nil {
			d.Subject = s.Subject
		}
		return d
	}
	// The sign-in paths run before a session exists. They are routed to the service without a check; a check that arrives
	// for one anyway passes, with the owned headers stripped.
	if strings.HasPrefix(path, Prefix) {
		return allow(nil, nil)
	}
	route, ok := c.rules.match(path)
	if !ok {
		return c.deny(http.StatusNotFound, "no_route", map[string]string{"error": "no_route"})
	}
	if !route.needsSession() {
		return allow(nil, nil)
	}
	unauthenticated := func() Decision {
		redirect := route.Unauthenticated == UnauthenticatedRedirect ||
			(route.Unauthenticated == UnauthenticatedDefault && IsNavigation(r))
		login := LoginURL(r.Path)
		if redirect {
			return Decision{Outcome: Redirect, Status: http.StatusFound, Reason: "login_required", Location: login}
		}
		return c.deny(http.StatusUnauthorized, "login_required", map[string]string{"error": "login_required", "login_url": login})
	}
	if id == "" {
		return unauthenticated()
	}
	if !c.CSRFOK(r.Method, r.Header) {
		c.Emit(ctx, Event{Kind: EventDenied, Route: route.Name, Reason: "csrf"})
		return c.deny(http.StatusForbidden, "csrf", map[string]string{"error": "csrf"})
	}
	s, err := c.Load(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return unauthenticated()
	}
	if err != nil {
		return unavailable("store")
	}
	if c.policy != nil {
		res, err := c.policy.Decide(ctx, PolicyInput{Site: c.rules.Site, Route: route, Method: r.Method, Path: path,
			Subject: s.Subject, Issuer: s.Issuer, Claims: s.Claims})
		if err != nil {
			return unavailable("policy")
		}
		if !res.Allow {
			reason := "forbidden"
			if res.Misfit {
				reason = "misfit"
			}
			c.Emit(ctx, Event{Kind: EventDenied, Subject: s.Subject, Issuer: s.Issuer, Route: route.Name, Reason: reason, PolicyDigest: res.Digest})
			return c.deny(http.StatusForbidden, "forbidden", map[string]string{"error": "forbidden"})
		}
	}
	set := map[string]string{}
	switch route.Mode {
	case ModeExchange:
		tok, err := c.tokenFor(ctx, s, route.Audience)
		switch {
		case errors.Is(err, errSessionEnded):
			d := unauthenticated()
			d.SetCookies = append(d.SetCookies, c.ClearSessionCookie())
			return d
		case errors.Is(err, errExchangeRefused):
			return c.exchangeRefused(r)
		case err != nil:
			return unavailable("exchange")
		}
		set["authorization"] = "Bearer " + tok
	case ModeIdentityHeader:
		h, err := c.identityFor(ctx, s, route)
		if err != nil {
			return unavailable("identity")
		}
		set[IdentityHeader] = h
	}
	c.touch(ctx, s)
	return allow(s, set)
}
