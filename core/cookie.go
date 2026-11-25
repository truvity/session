package core

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

// idLen is the length of a session id in the cookie: 256 random bits, base64url without padding.
const idLen = 43

// CookieName is the session cookie of the site (S1).
func (c *Core) CookieName() string { return "__Host-" + c.rules.Site }

// BindingCookieName is the short-lived cookie that ties a sign-in transaction to the browser that started it.
func (c *Core) BindingCookieName() string { return "__Host-" + c.rules.Site + "-signin" }

// ChoiceCookieName is the cookie of the remembered choice of issuer, on a site of several issuers that remembers it (decision
// 0034): the issuer's id in the site, no secret.
func (c *Core) ChoiceCookieName() string { return "__Host-" + c.rules.Site + "-issuer" }

// ChoiceCookie is the Set-Cookie value of the remembered choice: the issuer's id, for as long as the site remembers it.
func (c *Core) ChoiceCookie(issuerID string, life time.Duration) string {
	return (&http.Cookie{Name: c.ChoiceCookieName(), Value: issuerID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(life.Seconds())}).String()
}

// NewID returns a new random id of 256 bits, base64url. It is the session id of a new session, a state or a binding value.
func NewID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("session: no randomness: " + err.Error()) // crypto/rand does not fail on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func validID(s string) bool {
	if len(s) != idLen {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// SplitCookies reads the Cookie headers. It returns the session id (the first well-formed value of the session cookie, or "")
// and the Cookie header the upstream may see: every other cookie, without session's own: the session cookie, the binding cookie
// and the remembered choice.
func (c *Core) SplitCookies(h http.Header) (id, rest string) {
	r := http.Request{Header: http.Header{"Cookie": h.Values("Cookie")}}
	name, bind, choice := c.CookieName(), c.BindingCookieName(), c.ChoiceCookieName()
	var kept []string
	for _, ck := range r.Cookies() {
		switch ck.Name {
		case name:
			if id == "" && validID(ck.Value) {
				id = ck.Value
			}
		case bind, choice:
		default:
			kept = append(kept, ck.Name+"="+ck.Value)
		}
	}
	return id, strings.Join(kept, "; ")
}

// SessionCookie is the Set-Cookie value of a session (S1): Secure, HttpOnly, SameSite=Lax, Path=/, no Domain, no Max-Age
// (the server decides the lifetime).
func (c *Core) SessionCookie(id string) string {
	return (&http.Cookie{Name: c.CookieName(), Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}).String()
}

// BindingCookie is the Set-Cookie value of a sign-in binding.
func (c *Core) BindingCookie(value string) string {
	return (&http.Cookie{Name: c.BindingCookieName(), Value: value, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(SignInLifetime.Seconds())}).String()
}

// ClearSessionCookie and ClearBindingCookie remove the cookies from the browser.
func (c *Core) ClearSessionCookie() string { return clearCookie(c.CookieName()) }

// ClearBindingCookie removes the binding cookie from the browser.
func (c *Core) ClearBindingCookie() string { return clearCookie(c.BindingCookieName()) }

func clearCookie(name string) string {
	return (&http.Cookie{Name: name, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1}).String()
}

// BindingValue reads the binding cookie, or "".
func (c *Core) BindingValue(h http.Header) string {
	r := http.Request{Header: http.Header{"Cookie": h.Values("Cookie")}}
	ck, err := r.Cookie(c.BindingCookieName())
	if err != nil || !validID(ck.Value) {
		return ""
	}
	return ck.Value
}
