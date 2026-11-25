// Package audit sends session's security-audit events (decision 0008) through the emitter of truvity/audit
// (github.com/truvity/audit/emitter), over atoom's transport port (decision 0023). Auditor is core.Auditor: it maps a core.Event
// to an action of session's table (Table), names the person by a pseudonym that the seal block makes, and hands the record to the
// transport. A record carries the fields of core.Event only: no header value, cookie, token or body. It never emits usage or
// billing records; there is no such action.
//
// The transport is a client of the port: the emit socket of a transport driver (Socket), to the audit writer of the environment,
// or a transport driver mounted in this process: atoom's transport/nats (NATS) or transport/sqs (SQS), or, for a run without a
// writer, Lines, which writes each record as one JSON line.
package audit

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/truvity/atoom/transport/gen/atoom/transport/v1alpha1/transportv1alpha1connect"
	"github.com/truvity/audit/emitter"

	"github.com/truvity/session/core"
)

// Label is session's domain label of the pseudonyms (audit record 0018: the label is the product's). A changed label changes
// every pseudonym.
const Label = "session-pseudonym-v1"

// DefaultTimeout bounds a best-effort emit, so that a slow transport never holds a check's answer for long (decision 0008).
const DefaultTimeout = time.Second

// Pseudonymiser makes the keyed hash of a pseudonym: internal/sealer.Sealer, over the seal block's purpose pseudonym.
type Pseudonymiser interface {
	Pseudonym(ctx context.Context, label string, input []byte, generation uint32) ([]byte, error)
}

// Options configure an Auditor.
type Options struct {
	// Transport is the client of the transport port. Required.
	Transport transportv1alpha1connect.TransportServiceClient
	// Pseudonyms makes the pseudonyms of subjects. Required.
	Pseudonyms Pseudonymiser
	// Release is session's release, a semantic version: metadata.product.version. Required.
	Release string
	// Scope is the scope of the log: metadata.log_name, and actor.user.uid session@<scope>. Required.
	Scope string
	// Policy names the policy set of a denial's record: policy.uid, the name of the site's signed bundle. Empty when the site has
	// no bundle.
	Policy string
	// Timeout bounds a best-effort emit; zero is DefaultTimeout.
	Timeout time.Duration
	// Now is the emitter's clock; nil is time.Now.
	Now func() time.Time
}

// Auditor is core.Auditor over the emitter.
type Auditor struct {
	e       *emitter.Emitter
	policy  string
	timeout time.Duration
}

// New returns an Auditor. Nothing is sent until the first event.
func New(o Options) (*Auditor, error) {
	if !emitter.ValidRelease(o.Release) {
		return nil, fmt.Errorf("audit: the release %q is not a semantic version", o.Release)
	}
	if o.Pseudonyms == nil {
		return nil, errors.New("audit: no pseudonyms")
	}
	table, err := Table()
	if err != nil {
		return nil, err
	}
	e, err := emitter.New(emitter.Config{Product: Product, Release: o.Release, Scope: o.Scope, Component: Component, Table: table,
		Transport: o.Transport, Pseudonyms: &emitter.Pseudonyms{Mac: mac{o.Pseudonyms}, Label: Label}, Now: o.Now})
	if err != nil {
		return nil, err
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return &Auditor{e: e, policy: o.Policy, timeout: timeout}, nil
}

// Emit sends one event. A sign-in waits until the transport says the record is durable, and its failure is the sign-in's (decision
// 0008: a sign-in completes only after its event is accepted). Every other event is best effort: bounded by the timeout, and when it
// fails the emitter counts it as lost, and the next record carries the total.
func (a *Auditor) Emit(ctx context.Context, e core.Event) error {
	ev, err := a.Event(e)
	if err != nil {
		return err
	}
	if e.Kind == core.EventSignIn {
		return a.e.EmitBlocking(ctx, ev)
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	return a.e.Emit(ctx, ev)
}

// Lost is the number of best-effort events this process failed to deliver.
func (a *Auditor) Lost() int64 { return a.e.Lost() }

// Record builds the record of an event without sending it, for the tests.
func (a *Auditor) Record(ctx context.Context, e core.Event) ([]byte, error) {
	ev, err := a.Event(e)
	if err != nil {
		return nil, err
	}
	rec, _, err := a.e.Record(ctx, ev)
	return rec, err
}

// Event maps a core.Event to the emitter's event (decision 0023).
func (a *Auditor) Event(e core.Event) (emitter.Event, error) {
	var name string
	status := emitter.StatusSuccess
	switch e.Kind {
	case core.EventSignIn:
		name = ActionSignIn
	case core.EventSignInFailed:
		name, status = ActionSignIn, emitter.StatusFailure
	case core.EventLogout:
		name = ActionLogout
	case core.EventBackChannelLogout:
		name = ActionBackChannelLogout
		if e.Reason != "" {
			status = emitter.StatusFailure
		}
	case core.EventDenied:
		name, status = ActionDenied, emitter.StatusFailure
	case core.EventExchange:
		name = ActionTokenExchange
		if e.Reason != "" {
			status = emitter.StatusFailure
		}
	case core.EventRefreshFailed:
		name, status = ActionRefresh, emitter.StatusFailure
	default:
		return emitter.Event{}, fmt.Errorf("audit: the event kind %q is not in session's table", e.Kind)
	}
	r := rowOf(name)
	ev := emitter.Event{
		Action: emitter.Action{Name: r.Name, ClassUID: r.Class, ActivityID: r.Activities[0].ID, ActivityName: r.Activities[0].Name},
		Status: status,
	}
	if status == emitter.StatusFailure {
		ev.StatusCode = statusCode(e.Reason)
	}
	if e.Subject != "" {
		// The subject is hashed under the seal block's key and never sent. A refusal is audited even when the pseudonym cannot be
		// made (audit record 0005); a success fails without it.
		ev.Subject = &emitter.Subject{Kind: "person", Value: e.Subject}
		ev.SubjectBestEffort = status == emitter.StatusFailure
	}
	obj := map[string]any{fieldSite: e.Site}
	for k, v := range map[string]string{fieldIssuer: e.Issuer, fieldRoute: e.Route, fieldAudience: e.Audience} {
		if _, ok := r.fields[k]; ok && v != "" {
			obj[k] = v
		}
	}
	ev.ProductObject = obj
	if r.Class == classAPIActivity {
		// session is not told which proxy asked: the transport of the check names no peer.
		ev.Caller, ev.Operation = "unknown", "check"
		if e.Route == core.PathLogout {
			ev.Operation = "logout"
		}
	}
	if e.PolicyDigest != "" && r.policy {
		pol := a.policy
		if pol == "" {
			pol = "policy"
		}
		ev.Policy = &emitter.PolicyRef{DecisionID: pol, Digest: e.PolicyDigest, Decision: emitter.DecisionDenied}
	}
	return ev, nil
}

// unrecognised is the status_code of a reason that is not a closed word: an issuer's error code is the issuer's text.
const unrecognised = "unrecognised"

// statusCode is the reason when it has the form of a status_code, and unrecognised otherwise.
func statusCode(reason string) string {
	if reason == "" {
		return unrecognised
	}
	if len(reason) > 64 {
		return unrecognised
	}
	for i := 0; i < len(reason); i++ {
		c := reason[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !letter && (i == 0 || (c < '0' || c > '9') && c != '_' && c != '.' && c != ':' && c != '-') {
			return unrecognised
		}
	}
	return reason
}

// mac is the emitter's Mac over the seal block: the tenant is the installation's own (session names none), and the epoch YYYYMM
// is the generation of the pseudonym key.
type mac struct{ p Pseudonymiser }

func (m mac) Mac(ctx context.Context, req emitter.MacRequest) ([]byte, error) {
	if req.Purpose != emitter.PseudonymPurpose || req.Tenant != "" {
		return nil, errors.New("audit: session makes pseudonyms of its own tenant only")
	}
	g, err := strconv.ParseUint(req.Epoch, 10, 32)
	if err != nil || g == 0 {
		return nil, errors.New("audit: an epoch that is not YYYYMM")
	}
	return m.p.Pseudonym(ctx, req.Label, req.Input, uint32(g))
}

var _ core.Auditor = (*Auditor)(nil)
