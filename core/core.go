package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/truvity/atoom/store/gen/atoom/store/v1alpha1/storev1alpha1connect"
)

// Options are the block's dependencies and rules.
type Options struct {
	Rules Rules
	// Items is atoom's store port, as its generated client. Required.
	Items storev1alpha1connect.ItemServiceClient
	// Seal stands for atoom's seal block. Required.
	Seal Sealer
	// Policy decides who may reach a route; nil lets the route table decide alone.
	Policy Policy
	// Issuers are the clients of the issuers' token endpoints, for the route mode exchange, by issuer identifier (the iss of
	// the ID token, Record.Issuer): a session's exchange and refresh go to its own issuer (decision 0034). Required, one for
	// each of Rules.Issuers, when a route uses the mode.
	Issuers map[string]Issuer
	// Identity signs the identity header, for the route mode identity-header. Required when a route uses it.
	Identity Signer
	// Audit takes the security-audit events; nil drops them.
	Audit Auditor
	// Metrics counts checks; nil makes new counters.
	Metrics *Metrics
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Core is the session block of one site.
type Core struct {
	rules    Rules
	items    storev1alpha1connect.ItemServiceClient
	seal     Sealer
	policy   Policy
	issuers  map[string]Issuer
	identity *identityCache
	audit    Auditor
	metrics  *Metrics
	now      func() time.Time
}

// New checks the rules and returns the block.
func New(o Options) (*Core, error) {
	if o.Items == nil || o.Seal == nil {
		return nil, errors.New("session core: the store client and the sealer are required")
	}
	o.Rules = o.Rules.WithDefaults()
	if err := o.Rules.Validate(); err != nil {
		return nil, err
	}
	needIssuer, needIdentity := o.Rules.needs()
	if needIssuer && len(o.Issuers) == 0 {
		return nil, errors.New("session core: a route of mode exchange needs the issuer client")
	}
	if needIssuer {
		for _, iss := range o.Rules.Issuers {
			if o.Issuers[iss] == nil {
				return nil, fmt.Errorf("session core: a route of mode exchange needs the client of the issuer %s", iss)
			}
		}
	}
	if needIdentity && o.Identity == nil {
		return nil, errors.New("session core: a route of mode identity-header needs the identity signer")
	}
	c := &Core{rules: o.Rules, items: o.Items, seal: o.Seal, policy: o.Policy, issuers: o.Issuers, audit: o.Audit, metrics: o.Metrics, now: o.Now}
	if o.Identity != nil {
		c.identity = newIdentityCache(o.Identity)
	}
	if c.audit == nil {
		c.audit = discardAuditor{}
	}
	if c.metrics == nil {
		c.metrics = NewMetrics()
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c, nil
}

// Rules returns the rules the block runs with, defaults filled in.
func (c *Core) Rules() Rules { return c.rules }

// Metrics returns the block's counters.
func (c *Core) Metrics() *Metrics { return c.metrics }

// Emit hands a security-audit event to the Auditor and counts a refusal. It never blocks a check on the result.
func (c *Core) Emit(ctx context.Context, e Event) {
	if e.Time.IsZero() {
		e.Time = c.now()
	}
	e.Site = c.rules.Site
	if err := c.audit.Emit(ctx, e); err != nil {
		c.metrics.auditDropped.Add(1)
	}
}

// bound gives a store call its own timeout: a slow store is a down store (decision 0011).
func (c *Core) bound(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.rules.StoreTimeout)
}

// EmitAccepted hands a security-audit event to the Auditor and returns its answer. A sign-in completes only after its event is
// accepted (decision 0008), so the sign-in handler uses this one; a refusal is counted as well.
func (c *Core) EmitAccepted(ctx context.Context, e Event) error {
	if e.Time.IsZero() {
		e.Time = c.now()
	}
	e.Site = c.rules.Site
	err := c.audit.Emit(ctx, e)
	if err != nil {
		c.metrics.auditDropped.Add(1)
	}
	return err
}

// Now is the block's clock.
func (c *Core) Now() time.Time { return c.now() }
