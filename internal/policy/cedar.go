// Package policy decides who may reach a route with Cedar, as a library (decision 0007): cedar-go, in-process, no I/O during a
// decision.
//
// atoom's shared parts around the engine (the signed bundle, the loading rules, the Go loader B5 and the decision test set) do
// not exist yet. Until they do, a Bundle is a local Cedar policy document loaded through the narrow Loader interface, and
// Engine keeps what the loading rules of 0007 say that does not need the signed format: compile once, swap atomically, keep
// the last good set when a reload fails, refuse a cold start without a valid set, and give every decision the digest of its set.
// Signature verification and strict schema validation are the loader's and wait for it.
//
// The entities of a decision come from the session the check already read and from the route (docs/policy.md):
//
//	principal  User::"<subject>"     attrs { issuer, email, name, groups: Set<String> }, parents Group::"<g>" for every group
//	action     Action::"<METHOD>"    GET, POST, ... as the proxy saw it
//	resource   Route::"<route name>" attrs { site, mode }
//	context    { path, method }
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"sync/atomic"

	"github.com/cedar-policy/cedar-go"

	"github.com/truvity/session/core"
)

// Bundle is one policy document as the loader read it.
type Bundle struct {
	Name     string
	Policies []byte // Cedar policy text
}

// Loader reads the current bundle. The atoom loader (B5) will replace the local one behind this interface.
type Loader interface {
	Load(ctx context.Context) (Bundle, error)
}

type compiled struct {
	set    *cedar.PolicySet
	digest string
}

// Engine is a compiled policy set that can be swapped while decisions run.
type Engine struct {
	cur atomic.Pointer[compiled]
}

// Compile parses a bundle into a policy set. The digest is the SHA-256 of the policy text.
func Compile(b Bundle) (*cedar.PolicySet, string, error) {
	set, err := cedar.NewPolicySetFromBytes(b.Name, b.Policies)
	if err != nil {
		return nil, "", fmt.Errorf("policy %s: %w", b.Name, err)
	}
	if len(maps.Collect(set.All())) == 0 {
		return nil, "", fmt.Errorf("policy %s: no policy in the bundle", b.Name)
	}
	sum := sha256.Sum256(b.Policies)
	return set, "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Start loads and compiles the first set. A cold start without a valid set is refused.
func Start(ctx context.Context, l Loader) (*Engine, error) {
	e := &Engine{}
	if err := e.Reload(ctx, l); err != nil {
		return nil, fmt.Errorf("policy: no valid set at start: %w", err)
	}
	return e, nil
}

// Reload loads and compiles a new set and swaps it in. On any error the last good set stays.
func (e *Engine) Reload(ctx context.Context, l Loader) error {
	b, err := l.Load(ctx)
	if err != nil {
		return err
	}
	set, digest, err := Compile(b)
	if err != nil {
		return err
	}
	e.cur.Store(&compiled{set: set, digest: digest})
	return nil
}

// Digest is the digest of the set in use.
func (e *Engine) Digest() string {
	if c := e.cur.Load(); c != nil {
		return c.digest
	}
	return ""
}

// Request builds the Cedar request and entities of a check.
func Request(in core.PolicyInput) (cedar.Request, cedar.EntityMap) {
	user := cedar.NewEntityUID("User", cedar.String(in.Subject))
	route := cedar.NewEntityUID("Route", cedar.String(in.Route.Name))
	groups := make([]cedar.Value, 0, len(in.Claims.Groups))
	parents := make([]cedar.EntityUID, 0, len(in.Claims.Groups))
	entities := cedar.EntityMap{}
	for _, g := range in.Claims.Groups {
		groups = append(groups, cedar.String(g))
		gid := cedar.NewEntityUID("Group", cedar.String(g))
		parents = append(parents, gid)
		entities[gid] = cedar.Entity{UID: gid}
	}
	entities[user] = cedar.Entity{UID: user, Parents: cedar.NewEntityUIDSet(parents...), Attributes: cedar.NewRecord(cedar.RecordMap{
		"issuer": cedar.String(in.Issuer),
		"email":  cedar.String(in.Claims.Email),
		"name":   cedar.String(in.Claims.Name),
		"groups": cedar.NewSet(groups...),
	})}
	entities[route] = cedar.Entity{UID: route, Attributes: cedar.NewRecord(cedar.RecordMap{
		"site": cedar.String(in.Site),
		"mode": cedar.String(string(in.Route.Mode)),
	})}
	req := cedar.Request{
		Principal: user,
		Action:    cedar.NewEntityUID("Action", cedar.String(in.Method)),
		Resource:  route,
		Context: cedar.NewRecord(cedar.RecordMap{
			"path":   cedar.String(in.Path),
			"method": cedar.String(in.Method),
		}),
	}
	return req, entities
}

var errNoSet = errors.New("policy: no set loaded")

// Decide implements core.Policy. An evaluation error in a policy makes that policy not apply, as Cedar defines; the
// decision is a deny unless another policy permits.
func (e *Engine) Decide(_ context.Context, in core.PolicyInput) (core.PolicyResult, error) {
	c := e.cur.Load()
	if c == nil {
		return core.PolicyResult{}, errNoSet
	}
	req, entities := Request(in)
	d, _ := cedar.Authorize(c.set, entities, req)
	return core.PolicyResult{Allow: d == cedar.Allow, Digest: c.digest}, nil
}

var _ core.Policy = (*Engine)(nil)
