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
	PurposeLookupKey     = "lookup-key"     // Mac of a sid, a subject, a state, a claimed name or an audience into a store key
	PurposeExchanged     = "exchanged"      // Seal and Open of a cached token for one API audience
)

// Purposes lists every purpose the core uses, for a Sealer that wants them declared.
func Purposes() []string {
	return []string{PurposeSessionRecord, PurposeSignInRecord, PurposeSessionKey, PurposeLookupKey, PurposeExchanged}
}

// Issuer is the client of the issuer's token endpoint that the check needs for the route mode exchange (decision 0005): the
// token exchange of RFC 8693, and the refresh of the sign-in token. internal/exchange is the implementation. An answer of the
// issuer that refuses the request is a *RefusedError; any other error is an outage, and the check answers it with 503.
type Issuer interface {
	// Exchange trades the session's access token for a token of the audience.
	Exchange(ctx context.Context, subjectToken, audience string) (Token, error)
	// Refresh trades the refresh token for new sign-in tokens.
	Refresh(ctx context.Context, refreshToken string) (Refreshed, error)
}

// Token is an access token and how long it lives from the moment it was issued (0 when the issuer did not say).
type Token struct {
	AccessToken string
	ExpiresIn   time.Duration
}

// Refreshed is the answer to a refresh. An empty RefreshToken or IDToken means the issuer kept the old one.
type Refreshed struct {
	Token
	RefreshToken string
	IDToken      string
}

// RefusedError is an issuer's refusal: an OAuth error answer of its token endpoint (RFC 6749 section 5.2, RFC 8693 section
// 2.2.2). Code is the OAuth error code, never the issuer's description.
type RefusedError struct {
	Code string
}

func (e *RefusedError) Error() string { return "the issuer refused: " + e.Code }

// Signer signs the claims of a signed identity header as a compact JWS, with a key of the key port (decision 0005). The key
// is the service's own, published at /_session/jwks. internal/signin.Signer is the implementation.
type Signer interface {
	Sign(ctx context.Context, claims map[string]any) (string, error)
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

// PolicyResult is a decision and the digest of the policy set that made it, for the audit event. Misfit says that the request
// did not fit the schema of the set: a denial, audited with the reason misfit.
type PolicyResult struct {
	Allow  bool
	Misfit bool
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
	Audience     string // the API audience of a token exchange
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
	EventExchange          EventKind = "token-exchange" // Reason empty when a token was issued, else why not
	EventRefreshFailed     EventKind = "refresh-failed" // the sign-in token could not be refreshed; the session ended
)

// Auditor takes security-audit events. A check never waits on it for a decision: the core emits and goes on, and counts an
// event the Auditor refused. The emitter of truvity/audit is planned; internal/audit has the stand-in.
type Auditor interface {
	Emit(ctx context.Context, e Event) error
}

type discardAuditor struct{}

func (discardAuditor) Emit(context.Context, Event) error { return nil }
