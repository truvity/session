// Package policy decides who may reach a route with Cedar, as a library (decision 0007), on atoom's policy loader (atoom record
// 0019): the bundle is a signed document of the kind PolicyBundle, read through the source port, verified under the one key the
// site file pins, validated against its schema in strict mode and swapped in atomically. A failed reload keeps the last good set,
// a cold start without a valid set is refused, and every decision carries the SHA-384 digest of the payload of its set. A
// decision does no I/O.
//
// The entities of a decision come from the session the check already read and from the route (docs/policy.md):
//
//	principal  User::"<subject>"     attrs { issuer, email, name, groups: Set<String> }, parents Group::"<g>" for every group
//	action     Action::"<METHOD>"    GET, POST, ... as the proxy saw it; the bundle's schema declares the actions
//	resource   Route::"<route name>" attrs { site, mode }
//	context    { path, method }
//
// Schema is the schema these entities fit. A bundle's schema may differ; a request that does not fit it is a misfit and a denial.
package policy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cedar-policy/cedar-go"
	atpolicy "github.com/truvity/atoom/policy"
	"github.com/truvity/atoom/source/gen/atoom/source/v1alpha1/sourcev1alpha1connect"

	"github.com/truvity/session/core"
)

// Schema is the Cedar schema of the entities session gives a decision: the schema of the example bundle
// (examples/policy-bundle.json). The actions are the HTTP methods; a bundle that serves other methods declares them.
const Schema = `entity Group;
entity User in [Group] {
  issuer: String,
  email: String,
  name: String,
  groups: Set<String>,
};
entity Route {
  site: String,
  mode: String,
};
action "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS" appliesTo {
  principal: [User],
  resource: [Route],
  context: { path: String, method: String },
};
`

// Options are what Start needs.
type Options struct {
	// Source is the client of the source port that serves the bundle.
	Source sourcev1alpha1connect.SourceServiceClient
	// Name is the document of the bundle (the site file's policy.bundle); atoom's default policy-bundle when empty.
	Name string
	// Publisher is the one key the site file pins (policy.verify_key).
	Publisher atpolicy.Publisher
	// Log, when set, is told of every reload that is not unchanged; slog's default when nil.
	Log *slog.Logger
}

// Engine is atoom's loader for one bundle, as core.Policy.
type Engine struct {
	l *atpolicy.Loader
}

// Start reads, verifies and compiles the bundle once. A cold start without a valid set is refused.
func Start(ctx context.Context, o Options) (*Engine, error) {
	log := o.Log
	if log == nil {
		log = slog.Default()
	}
	l, err := atpolicy.New(ctx, atpolicy.Options{Source: o.Source, Name: o.Name, Publishers: []atpolicy.Publisher{o.Publisher},
		OnReload: func(out atpolicy.Outcome) {
			level := slog.LevelInfo
			if out.Result != atpolicy.Applied {
				level = slog.LevelWarn
			}
			attrs := []any{"result", out.Result.String(), "digest", out.Digest, "seq", out.Seq}
			if out.Err != nil {
				attrs = append(attrs, "error", out.Err.Error())
			}
			log.Log(context.Background(), level, "policy bundle", attrs...)
		}})
	if err != nil {
		return nil, err
	}
	return &Engine{l: l}, nil
}

// Run keeps the set current, as the source says it can (a watch of the file driver), until ctx ends.
func (e *Engine) Run(ctx context.Context) error { return e.l.Run(ctx) }

// Reload is one pass of the loader: read, verify, compile, swap; or keep the set in force.
func (e *Engine) Reload(ctx context.Context) atpolicy.Outcome { return e.l.Reload(ctx) }

// Digest is the digest of the set in force: the SHA-384 of its payload, in lower-case hex.
func (e *Engine) Digest() string { return e.l.Current().Digest() }

// Request builds the Cedar request and entities of a check.
func Request(in core.PolicyInput) atpolicy.Request {
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
	return atpolicy.Request{
		Principal: user,
		Action:    cedar.NewEntityUID("Action", cedar.String(in.Method)),
		Resource:  route,
		Context: cedar.NewRecord(cedar.RecordMap{
			"path":   cedar.String(in.Path),
			"method": cedar.String(in.Method),
		}),
		Entities: entities,
	}
}

// Decide implements core.Policy. A policy that errors counts as neither permit nor forbid, as Cedar defines. A request that
// does not fit the bundle's schema (an action it does not declare, say) is a denial with Misfit set.
func (e *Engine) Decide(_ context.Context, in core.PolicyInput) (core.PolicyResult, error) {
	d, err := e.l.Decide(Request(in))
	var misfit *atpolicy.Misfit
	if errors.As(err, &misfit) {
		return core.PolicyResult{Allow: false, Misfit: true, Digest: d.Digest}, nil
	}
	if err != nil {
		return core.PolicyResult{}, err
	}
	return core.PolicyResult{Allow: d.Allow, Digest: d.Digest}, nil
}

var _ core.Policy = (*Engine)(nil)

// PublisherFromPEM is the pinned key of the site file: a kid and a P-384 public key, PEM "PUBLIC KEY" (a SubjectPublicKeyInfo).
func PublisherFromPEM(kid, text string) (atpolicy.Publisher, error) {
	if kid == "" {
		return atpolicy.Publisher{}, errors.New("policy: the kid of the verify key is required")
	}
	block, rest := pem.Decode([]byte(text))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return atpolicy.Publisher{}, errors.New("policy: the verify key is one PEM block of the type PUBLIC KEY")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return atpolicy.Publisher{}, fmt.Errorf("policy: the verify key: %w", err)
	}
	return atpolicy.PublisherFromSPKI(kid, block.Bytes)
}
