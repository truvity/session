package core

import (
	"context"
	"sync"
	"time"
)

// The route mode identity-header (design section 7, decisions 0005 and 0016): a signed identity header for apps that cannot
// handle tokens. It is a compact JWS of typ IdentityType in the header IdentityHeader, signed by the service's own key of the
// key port (published at /_session/jwks), and it lives IdentityLifetime.

const (
	// IdentityHeader is the upstream request header that carries the signed identity.
	IdentityHeader = "x-session-identity"
	// IdentityType is the JWS typ of the identity header, so that an app never takes another JWT of the service for it.
	IdentityType = "session-identity+jwt"
)

// identityCacheSize bounds the headers one process keeps for reuse.
const identityCacheSize = 4096

// identityCache keeps each signed header for half its life, so that a key on a remote driver (AWS KMS) signs about twice a
// minute for each session and audience, not on every request. It is only asked after the check has read the session, so a
// logout is seen at once whatever it holds.
type identityCache struct {
	signer Signer
	mu     sync.Mutex
	m      map[string]identityEntry
}

type identityEntry struct {
	header string
	reuse  time.Time // the end of reuse: half the header's life
}

func newIdentityCache(s Signer) *identityCache {
	return &identityCache{signer: s, m: map[string]identityEntry{}}
}

func (ic *identityCache) get(key string, now time.Time) (string, bool) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	e, ok := ic.m[key]
	if !ok || !now.Before(e.reuse) {
		return "", false
	}
	return e.header, true
}

func (ic *identityCache) put(key, header string, reuse, now time.Time) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	if len(ic.m) >= identityCacheSize {
		for k, e := range ic.m {
			if !now.Before(e.reuse) {
				delete(ic.m, k)
			}
		}
		if len(ic.m) >= identityCacheSize {
			clear(ic.m)
		}
	}
	ic.m[key] = identityEntry{header: header, reuse: reuse}
}

// Origin is the site's own origin: the iss of the identity header, and its aud when the route names no audience.
func (c *Core) Origin() string { return "https://" + c.rules.Host }

// IdentityClaims are the claims of an identity header for a session and a route, issued at now: iss the site's origin; aud the
// route's audience or the site's origin; idp the site's id of the session's issuer (decision 0035: a subject is unique only within
// its issuer, so an app keys a person by idp and sub); sub, name, email and groups from the session (groups is always a list); iat
// and exp. idp is there with one issuer too.
func (c *Core) IdentityClaims(s *Session, route Route, now time.Time) map[string]any {
	aud := route.Audience
	if aud == "" {
		aud = c.Origin()
	}
	groups := s.Claims.Groups
	if groups == nil {
		groups = []string{}
	}
	claims := map[string]any{
		"iss": c.Origin(), "aud": aud, "idp": c.rules.issuerID(s.Issuer), "sub": s.Subject, "groups": groups,
		"iat": now.Unix(), "exp": now.Add(c.rules.IdentityLifetime).Unix(),
	}
	if s.Claims.Name != "" {
		claims["name"] = s.Claims.Name
	}
	if s.Claims.Email != "" {
		claims["email"] = s.Claims.Email
	}
	return claims
}

// identityFor returns the signed identity header of the session for the route.
func (c *Core) identityFor(ctx context.Context, s *Session, route Route) (string, error) {
	now := c.now()
	key := string(s.key) + "\x00" + route.Audience
	if h, ok := c.identity.get(key, now); ok {
		return h, nil
	}
	ctx, cancel := c.bound(ctx)
	defer cancel()
	h, err := c.identity.signer.Sign(ctx, c.IdentityClaims(s, route, now))
	if err != nil {
		return "", err
	}
	c.identity.put(key, h, now.Add(c.rules.IdentityLifetime/2), now)
	return h, nil
}
