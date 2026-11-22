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
	PathCallback    = Prefix + "callback"
	PathLogout      = Prefix + "logout"
	PathBackChannel = Prefix + "backchannel-logout"
	PathWhoami      = Prefix + "whoami"
	PathJWKS        = Prefix + "jwks"
)

// The defaults of decision 0004 and of the first spike.
const (
	DefaultIdle         = 30 * time.Minute
	DefaultMax          = 8 * time.Hour
	DefaultTouchEvery   = time.Minute
	DefaultStoreTimeout = 1500 * time.Millisecond
	SignInLifetime      = 10 * time.Minute
)

// Mode is what a route needs (design section 10).
type Mode string

// The route modes. ModeExchange and ModeIdentityHeader are part of the site file's shape, but the check of this version
// refuses to start with them: the exchange client and the identity header come in later steps of the plan.
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
	Audience        string // for ModeExchange
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
}

// WithDefaults returns a copy of the rules with the defaults filled in.
func (r Rules) WithDefaults() Rules {
	r.Routes = append([]Route(nil), r.Routes...)
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
		case ModeExchange, ModeIdentityHeader:
			errs = append(errs, fmt.Errorf("%s: mode %s is not built yet", at, rt.Mode))
		default:
			errs = append(errs, fmt.Errorf("%s: mode %q: public, session, exchange or identity-header", at, rt.Mode))
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

// match returns the first route that matches the path, or false.
func (r *Rules) match(path string) (Route, bool) {
	for _, rt := range r.Routes {
		if rt.matches(path) {
			return rt, true
		}
	}
	return Route{}, false
}
