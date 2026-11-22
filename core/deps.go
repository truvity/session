package core

import (
	"context"
	"time"
)

// Sealer is the part of atoom's seal block that the core uses: Seal, Open and Mac by purpose. The block does not exist yet
// (decision 0006, "planned in atoom"); internal/localseal stands in for it. The interface is kept to these three calls so
// that the block replaces the stand-in without a change in the core.
//
// aad is the address the value is bound to: a value sealed under one address does not open under another.
type Sealer interface {
	Seal(ctx context.Context, purpose string, aad, plaintext []byte) ([]byte, error)
	Open(ctx context.Context, purpose string, aad, sealed []byte) ([]byte, error)
	Mac(ctx context.Context, purpose string, data []byte) ([]byte, error)
}

// The purposes the core declares to the Sealer. Keys are per purpose and installation, never per person.
const (
	PurposeSessionRecord = "session-record" // Seal and Open of a session record
	PurposeSignInRecord  = "signin-record"  // Seal and Open of a sign-in transaction
	PurposeSessionKey    = "session-key"    // Mac of a cookie id into the store key of its session
	PurposeLookupKey     = "lookup-key"     // Mac of a sid, a subject, a state or a claimed name into a store key
)

// Purposes lists every purpose the core uses, for a Sealer that wants them declared.
func Purposes() []string {
	return []string{PurposeSessionRecord, PurposeSignInRecord, PurposeSessionKey, PurposeLookupKey}
}

// Policy decides whether a person may reach a route (decision 0007). It runs in-process on every check of a route that needs
// a session, with no I/O. A nil Policy means the route table decides alone.
type Policy interface {
	Decide(ctx context.Context, in PolicyInput) (PolicyResult, error)
}

// PolicyInput is everything a decision may read: the session record the check already read and the route. No extra read.
type PolicyInput struct {
	Site    string
	Route   Route
	Method  string
	Path    string // the path without the query
	Subject string
	Issuer  string
	Claims  Claims
}

// PolicyResult is a decision and the digest of the policy set that made it, for the audit event.
type PolicyResult struct {
	Allow  bool
	Digest string
}

// Event is a security-audit event (decision 0008). Never a usage record: allowed requests are counted as metrics, not events.
// An event carries no header value, cookie, token or body.
type Event struct {
	Time         time.Time
	Kind         EventKind
	Site         string
	Subject      string // empty when no session is known
	Issuer       string
	Route        string
	Reason       string // a short machine word
	PolicyDigest string // the digest of the policy set that decided, on a policy denial
}

// EventKind names a security-audit event.
type EventKind string

// The event kinds of the core and of the sign-in handler.
const (
	EventSignIn            EventKind = "sign-in"
	EventSignInFailed      EventKind = "sign-in-failed"
	EventLogout            EventKind = "logout"
	EventBackChannelLogout EventKind = "back-channel-logout"
	EventDenied            EventKind = "denied"
)

// Auditor takes security-audit events. A check never waits on it for a decision: the core emits and goes on, and counts an
// event the Auditor refused. The emitter of truvity/audit is planned; internal/audit has the stand-in.
type Auditor interface {
	Emit(ctx context.Context, e Event) error
}

type discardAuditor struct{}

func (discardAuditor) Emit(context.Context, Event) error { return nil }
