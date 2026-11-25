package core

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Prefix is the one path prefix session owns on every site (decision 0004). It is not per site.
const Prefix = "/_session/"

// The paths under Prefix.
const (
	PathLogin       = Prefix + "login"
	PathSignIn      = Prefix + "signin"
	PathCallback    = Prefix + "callback"
	PathLogout      = Prefix + "logout"
	PathBackChannel = Prefix + "backchannel-logout"
	PathWhoami      = Prefix + "whoami"
	PathJWKS        = Prefix + "jwks"
)

// The defaults of decision 0004, of the first spike and of step 3.1 (decision 0016).
const (
	DefaultIdle         = 30 * time.Minute
	DefaultMax          = 8 * time.Hour
	DefaultTouchEvery   = time.Minute
	DefaultStoreTimeout = 1500 * time.Millisecond
	SignInLifetime      = 10 * time.Minute
	// DefaultExchangeTimeout bounds the part of a check that makes an exchange: the lock, a refresh, the call to the issuer
	// and the cache write. A check that waits for another's exchange waits as long.
	DefaultExchangeTimeout = 2 * time.Second
	// DefaultExchangeSkew is taken off a token's expiry: a cached token is not used, and a sign-in token is refreshed, this
	// long before the token ends.
	DefaultExchangeSkew = 30 * time.Second
	// DefaultIdentityLifetime is the life of a signed identity header (decision 0005: about a minute).
	DefaultIdentityLifetime = time.Minute
)

// Mode is what a route needs (design section 10).
type Mode string

// The route modes. ModeExchange needs the block's Issuer and ModeIdentityHeader its Identity signer (decision 0016).
const (
	ModePublic         Mode = "public"
	ModeSession        Mode = "session"
	ModeExchange       Mode = "exchange"
	ModeIdentityHeader Mode = "identity-header"
)

// Unauthenticated says what a route answers without a session (design section 5.3).
type Unauthenticated string

// The answers without a session. The empty value is the default: a redirect for a top-level navigation, a JSON 401 otherwise.
const (
	UnauthenticatedDefault  Unauthenticated = ""
	UnauthenticatedRedirect Unauthenticated = "redirect"
	Unauthenticated401      Unauthenticated = "401"
)

// Route is one row of the route table. Exactly one of Prefix and Exact is set. Routes are matched in order; the first match wins.
type Route struct {
	Name            string // the route's name: the Cedar resource id and the audit field. Defaults to its match
	Prefix          string
	Exact           string
	Mode            Mode
	Unauthenticated Unauthenticated
	// Audience is the API audience of the token for ModeExchange (required), and the aud claim of the identity header for
	// ModeIdentityHeader (optional; the site's own origin when empty).
	Audience string
}

func (r Route) matches(path string) bool {
	if r.Exact != "" {
		return path == r.Exact
	}
	return strings.HasPrefix(path, r.Prefix)
}

func (r Route) needsSession() bool { return r.Mode != ModePublic }

// Rules are what session hands the block: one site's lifetimes, host and route table.
type Rules struct {
	// Site is the site's name: the cookie is __Host-<Site>.
	Site string
	// Host is the host (and port, when it is not the default) the browser uses for the site. The CSRF check compares Origin
	// with https://<Host>.
	Host string
	// Idle and Max are the idle and the absolute lifetime of a session.
	Idle, Max time.Duration
	// TouchEvery is how often the idle time is refreshed at most.
	TouchEvery time.Duration
	// StoreTimeout bounds every store call. It must be shorter than the proxy's timeout for the check (decision 0011).
	StoreTimeout time.Duration
	// Routes is the route table.
	Routes []Route
	// ExchangeTimeout bounds the exchange of one check (lock, refresh, issuer call, cache write); ExchangeSkew is taken off
	// every token's expiry; IdentityLifetime is the life of a signed identity header.
	ExchangeTimeout, ExchangeSkew, IdentityLifetime time.Duration
	// Issuers are the site's issuers (decision 0034): the id of each in the site file and its identifier. A session whose issuer
	// is not one of them is no session, so an issuer taken out of the site file ends its sessions at the next start. The id is
	// the idp claim of the identity header (decision 0035). Empty accepts a session of any issuer, with an empty idp.
	Issuers []SiteIssuer
	// ErrorPage is the page a navigation gets when the issuer refuses the exchange for its route (decision 0005: a plain
	// error page from a template for each site). Empty is the built-in page.
	ErrorPage []byte
}

// SiteIssuer is one issuer of the site as the core knows it: its id in the site file and its identifier (the iss of its ID
// tokens).
type SiteIssuer struct {
	ID         string
	Identifier string
}

// issuerID is the site's id of the issuer identifier, or "" when the rules name no such issuer.
func (r *Rules) issuerID(identifier string) string {
	for _, is := range r.Issuers {
		if is.Identifier == identifier {
			return is.ID
		}
	}
	return ""
}

// WithDefaults returns a copy of the rules with the defaults filled in.
func (r Rules) WithDefaults() Rules {
	r.Routes = append([]Route(nil), r.Routes...)
	r.Issuers = append([]SiteIssuer(nil), r.Issuers...)
	if r.Idle == 0 {
		r.Idle = DefaultIdle
	}
	if r.Max == 0 {
		r.Max = DefaultMax
	}
	if r.TouchEvery == 0 {
		r.TouchEvery = DefaultTouchEvery
	}
	if r.StoreTimeout == 0 {
		r.StoreTimeout = DefaultStoreTimeout
	}
	if r.ExchangeTimeout == 0 {
		r.ExchangeTimeout = DefaultExchangeTimeout
	}
	if r.ExchangeSkew == 0 {
		r.ExchangeSkew = DefaultExchangeSkew
	}
	if r.IdentityLifetime == 0 {
		r.IdentityLifetime = DefaultIdentityLifetime
	}
	if len(r.ErrorPage) == 0 {
		r.ErrorPage = []byte(defaultErrorPage)
	}
	for i := range r.Routes {
		if r.Routes[i].Name == "" {
			r.Routes[i].Name = r.Routes[i].Prefix + r.Routes[i].Exact
		}
	}
	return r
}

// ValidSiteName says whether a site name can be part of a cookie name: 1 to 32 lower-case letters, digits and '-'.
func ValidSiteName(s string) bool {
	if s == "" || len(s) > 32 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// Validate refuses rules the check cannot serve.
func (r Rules) Validate() error {
	var errs []error
	if !ValidSiteName(r.Site) {
		errs = append(errs, fmt.Errorf("site %q: 1 to 32 lower-case letters, digits and '-'", r.Site))
	}
	if r.Host == "" || strings.ContainsAny(r.Host, "/ ") {
		errs = append(errs, errors.New("host: a host name, with a port when it is not 443"))
	}
	if r.Idle <= 0 || r.Max <= 0 || r.Idle > r.Max {
		errs = append(errs, errors.New("session: idle and max must be positive, and idle at most max"))
	}
	if r.StoreTimeout <= 0 {
		errs = append(errs, errors.New("store timeout must be positive"))
	}
	if r.ExchangeTimeout <= 0 || r.ExchangeSkew <= 0 || r.IdentityLifetime <= 0 {
		errs = append(errs, errors.New("the exchange timeout, the exchange skew and the identity header's lifetime must be positive"))
	}
	seenIssuer := map[string]bool{}
	for i, iss := range r.Issuers {
		if iss.ID == "" || iss.Identifier == "" || seenIssuer["id "+iss.ID] || seenIssuer[iss.Identifier] {
			errs = append(errs, fmt.Errorf("issuers[%d]: an id and an issuer identifier, each once", i))
		}
		seenIssuer["id "+iss.ID], seenIssuer[iss.Identifier] = true, true
	}
	if len(r.Routes) == 0 {
		errs = append(errs, errors.New("routes: at least one route"))
	}
	names := map[string]bool{}
	for i, rt := range r.Routes {
		at := fmt.Sprintf("routes[%d]", i)
		switch {
		case (rt.Prefix == "") == (rt.Exact == ""):
			errs = append(errs, fmt.Errorf("%s: exactly one of prefix and exact", at))
		case !strings.HasPrefix(rt.Prefix+rt.Exact, "/"):
			errs = append(errs, fmt.Errorf("%s: a match starts with /", at))
		case strings.HasPrefix(rt.Prefix+rt.Exact, Prefix):
			errs = append(errs, fmt.Errorf("%s: %s is session's own prefix", at, Prefix))
		}
		switch rt.Mode {
		case ModePublic, ModeSession:
			if rt.Audience != "" {
				errs = append(errs, fmt.Errorf("%s: mode %s takes no audience", at, rt.Mode))
			}
		case ModeExchange:
			if rt.Audience == "" {
				errs = append(errs, fmt.Errorf("%s: mode exchange needs the API audience", at))
			}
		case ModeIdentityHeader:
		default:
			errs = append(errs, fmt.Errorf("%s: mode %q: public, session, exchange or identity-header", at, rt.Mode))
		}
		if len(rt.Audience) > maxAudience || strings.ContainsAny(rt.Audience, " \t\r\n") {
			errs = append(errs, fmt.Errorf("%s: an audience of at most %d characters, without white space", at, maxAudience))
		}
		switch rt.Unauthenticated {
		case UnauthenticatedDefault, UnauthenticatedRedirect, Unauthenticated401:
		default:
			errs = append(errs, fmt.Errorf("%s: unauthenticated %q: redirect or 401", at, rt.Unauthenticated))
		}
		if rt.Mode == ModePublic && rt.Unauthenticated != UnauthenticatedDefault {
			errs = append(errs, fmt.Errorf("%s: a public route needs no session, so it has no unauthenticated answer", at))
		}
		if names[rt.Name] {
			errs = append(errs, fmt.Errorf("%s: the name %q is used twice", at, rt.Name))
		}
		names[rt.Name] = true
	}
	return errors.Join(errs...)
}

// maxAudience bounds an audience: a client id or a URL.
const maxAudience = 256

// needs says which of the block's optional dependencies the route table needs.
func (r Rules) needs() (issuer, identity bool) {
	for _, rt := range r.Routes {
		issuer = issuer || rt.Mode == ModeExchange
		identity = identity || rt.Mode == ModeIdentityHeader
	}
	return issuer, identity
}

// match returns the first route that matches the path, or false.
func (r *Rules) match(path string) (Route, bool) {
	for _, rt := range r.Routes {
		if rt.matches(path) {
			return rt, true
		}
	}
	return Route{}, false
}
