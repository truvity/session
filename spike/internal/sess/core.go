package sess

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Kind int

const (
	Allow Kind = iota
	Redirect
	Unauthorized
	Unavailable
)

// Request is what an adapter hands the core: headers only, never a body.
type Request struct {
	Method string
	Host   string
	Path   string // path and query, as the proxy saw it
	Header http.Header
}

// Decision is what the core gives back; an adapter turns it into its protocol.
type Decision struct {
	Kind     Kind
	Status   int
	Location string
	Body     []byte
	// Set on the upstream request, overwriting what the browser sent.
	Set map[string]string
	// Removed from the upstream request.
	Remove []string
	// Set-Cookie lines for the client response.
	SetCookies []string
	// For the logs and the e2e driver.
	Subject string
}

type Core struct {
	Store      *Store
	CookieName string
	Tombstones bool // check tombstones on each request
	// Headers the allow answer owns. A browser-sent value is always replaced or removed.
	IdentityHeaders []string
}

var ownedHeaders = []string{"x-session-user", "x-session-email", "x-session-groups", "authorization", "cookie"}

func (c *Core) cookieID(h http.Header) (string, string) {
	r := &http.Request{Header: h}
	var rest []string
	id := ""
	for _, ck := range r.Cookies() {
		if ck.Name == c.CookieName {
			id = ck.Value
			continue
		}
		rest = append(rest, ck.Name+"="+ck.Value)
	}
	return id, strings.Join(rest, "; ")
}

func isNavigation(r Request) bool {
	return r.Method == http.MethodGet && r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
}

func loginURL(returnTo string) string {
	return "/_session/login?return_to=" + url.QueryEscape(returnTo)
}

// Check is the whole decision for one request.
func (c *Core) Check(ctx context.Context, r Request) Decision {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond) // a slow store is a down store
	defer cancel()
	p := r.Path
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	// Sign-in paths and public routes: no session needed. Strip the owned headers anyway.
	if strings.HasPrefix(p, "/_session/") || strings.HasPrefix(p, "/assets/") {
		return Decision{Kind: Allow, Remove: ownedHeaders[:4]}
	}
	id, otherCookies := c.cookieID(r.Header)
	deny := func() Decision {
		if isNavigation(r) {
			return Decision{Kind: Redirect, Status: http.StatusFound, Location: loginURL(r.Path)}
		}
		return Decision{Kind: Unauthorized, Status: http.StatusUnauthorized,
			Body: []byte(`{"error":"login_required","login_url":"/_session/login"}`)}
	}
	if id == "" {
		return deny()
	}
	l, err := c.Store.Get(ctx, id, c.Tombstones)
	if errors.Is(err, ErrNotFound) {
		return deny()
	}
	if err != nil {
		// fail closed
		return Decision{Kind: Unavailable, Status: http.StatusServiceUnavailable, Body: []byte(`{"error":"store_unavailable"}`)}
	}
	_, _ = c.Store.Touch(ctx, id, l)
	d := Decision{Kind: Allow, Subject: l.Rec.Sub, Set: map[string]string{
		"x-session-user":   l.Rec.Sub,
		"x-session-email":  l.Rec.Email,
		"x-session-groups": strings.Join(l.Rec.Groups, ","),
	}}
	// Route table of the spike: /api/token/ forwards the sign-in access token (stand-in for
	// the exchange mode), /refresh-demo/ re-sends the cookie. Everything else: identity headers.
	if strings.HasPrefix(p, "/api/token/") {
		d.Set["authorization"] = "Bearer " + l.Rec.AccessToken
	} else {
		d.Remove = append(d.Remove, "authorization")
	}
	if strings.HasPrefix(p, "/refresh-demo/") {
		d.SetCookies = append(d.SetCookies, c.SessionCookie(id))
	}
	// The browser's session cookie never reaches the upstream: rewrite Cookie.
	if otherCookies != "" {
		d.Set["cookie"] = otherCookies
	} else {
		d.Remove = append(d.Remove, "cookie")
	}
	return d
}

func (c *Core) SessionCookie(id string) string {
	return (&http.Cookie{Name: c.CookieName, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}).String()
}

func (c *Core) ClearCookie(name string) string {
	return (&http.Cookie{Name: name, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1}).String()
}
