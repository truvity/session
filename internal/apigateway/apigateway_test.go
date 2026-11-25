package apigateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/apigateway"
	"github.com/truvity/session/internal/audit"
	"github.com/truvity/session/internal/sealer"
	"github.com/truvity/session/internal/sealer/sealertest"
	"github.com/truvity/session/internal/storetest"
)

type site struct {
	core *core.Core
	mem  *storetest.Store
	rec  *syncBuffer
}

// syncBuffer is the audit records the in-process transport driver wrote, one JSON line each.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// newSite is the check core as the authorizer function builds it, with the in-process store double, and the emitter of
// truvity/audit over the transport port on the in-process driver Lines: the place atoom's transport/sqs takes on Lambda.
func newSite(t *testing.T) *site {
	t.Helper()
	mem := storetest.New(nil)
	items, stop := mem.Client()
	t.Cleanup(stop)
	seal := sealertest.New(t)
	rec := &syncBuffer{}
	tr, stopTr := audit.NewLines(rec).Mount()
	t.Cleanup(stopTr)
	aud, err := audit.New(audit.Options{Transport: tr, Pseudonyms: seal.(*sealer.Sealer), Release: "0.0.0-dev", Scope: "local"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := core.New(core.Options{Items: items, Seal: seal, Issuers: map[string]core.Issuer{"https://issuer.example.test": issuer{}}, Identity: signer{}, Audit: aud, Rules: core.Rules{
		Site: "docs", Host: "docs.example.test", StoreTimeout: 300 * time.Millisecond,
		Routes: []core.Route{
			{Prefix: "/assets/", Mode: core.ModePublic},
			{Prefix: "/api/billing/", Mode: core.ModeExchange, Audience: "billing"},
			{Prefix: "/api/refused/", Mode: core.ModeExchange, Audience: "refused"},
			{Prefix: "/legacy/", Mode: core.ModeIdentityHeader},
			{Prefix: "/", Mode: core.ModeSession},
		}}})
	if err != nil {
		t.Fatal(err)
	}
	return &site{core: c, mem: mem, rec: rec}
}

// issuer and signer stand in for the issuer's token endpoint and the key port: the adapter only carries what the core decides.
// The issuer refuses the exchange for the audience "refused", and every refresh.
type issuer struct{}

func (issuer) Exchange(_ context.Context, _, audience string) (core.Token, error) {
	if audience == "refused" {
		return core.Token{}, &core.RefusedError{Code: "access_denied"}
	}
	return core.Token{AccessToken: "token-for-" + audience, ExpiresIn: time.Minute}, nil
}

func (issuer) Refresh(context.Context, string) (core.Refreshed, error) {
	return core.Refreshed{}, &core.RefusedError{Code: "invalid_grant"}
}

type signer struct{}

func (signer) Sign(_ context.Context, claims map[string]any) (string, error) {
	return "signed-identity-of-" + fmt.Sprint(claims["sub"]), nil
}

func (s *site) signIn(t *testing.T, r *core.Record) string {
	t.Helper()
	if r == nil {
		r = &core.Record{Subject: "alice", Issuer: "https://issuer.example.test", SID: "sid-1"}
	}
	id, err := s.core.Create(context.Background(), r, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// event reads a sample event of testdata with the session id in place of SESSION.
func event(t *testing.T, name, id string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.Base(name)))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(b, []byte("SESSION"), []byte(id))
}

func restEvent(t *testing.T, id, method, path string, headers map[string]string) events.APIGatewayCustomAuthorizerRequestTypeRequest {
	t.Helper()
	var ev events.APIGatewayCustomAuthorizerRequestTypeRequest
	if err := json.Unmarshal(event(t, "rest-request.json", id), &ev); err != nil {
		t.Fatal(err)
	}
	ev.HTTPMethod, ev.Path = method, path
	for k, v := range headers {
		ev.MultiValueHeaders[k] = []string{v}
	}
	return ev
}

func v2Event(t *testing.T, id, method, path string, headers map[string]string) events.APIGatewayV2CustomAuthorizerV2Request {
	t.Helper()
	var ev events.APIGatewayV2CustomAuthorizerV2Request
	if err := json.Unmarshal(event(t, "http-v2-request.json", id), &ev); err != nil {
		t.Fatal(err)
	}
	ev.RequestContext.HTTP.Method, ev.RawPath, ev.RawQueryString = method, path, ""
	for k, v := range headers {
		ev.Headers[strings.ToLower(k)] = v
	}
	return ev
}

// The context reaches the integration as $context.authorizer.<key>; API Gateway takes strings, numbers and booleans only, and
// every key is on every allow so the mapping overwrites a browser-sent value.
func checkContext(t *testing.T, ctx map[string]any, want map[string]string) {
	t.Helper()
	for _, k := range []string{apigateway.ContextSubject, apigateway.ContextAuthorization, apigateway.ContextIdentity, apigateway.ContextCookie} {
		v, ok := ctx[k]
		if !ok {
			t.Fatalf("context has no %q: %v", k, ctx)
		}
		s, ok := v.(string)
		if !ok {
			t.Fatalf("context %q is a %T, not a string", k, v)
		}
		if s != want[k] {
			t.Fatalf("context %q is %q, want %q", k, s, want[k])
		}
	}
}

func TestREST(t *testing.T) {
	s := newSite(t)
	a := &apigateway.Authorizer{Core: s.core}
	ctx := context.Background()
	id := s.signIn(t, nil)

	// A session route: an allow for the method, the person as principalId, the site's other cookies; the browser's forged
	// Authorization is overwritten by the empty value.
	ev := restEvent(t, id, "GET", "/app/x", nil)
	out, err := a.HandleREST(ctx, ev)
	if err != nil || out.PrincipalID != "alice" || out.PolicyDocument.Statement[0].Effect != "Allow" ||
		out.PolicyDocument.Statement[0].Resource[0] != ev.MethodArn {
		t.Fatalf("session route: %v %+v", err, out)
	}
	checkContext(t, out.Context, map[string]string{"subject": "alice", "cookie": "theme=dark"})

	out, err = a.HandleREST(ctx, restEvent(t, id, "GET", "/api/billing/x", nil))
	if err != nil {
		t.Fatal(err)
	}
	checkContext(t, out.Context, map[string]string{"subject": "alice", "authorization": "Bearer token-for-billing", "cookie": "theme=dark"})

	out, err = a.HandleREST(ctx, restEvent(t, id, "GET", "/legacy/x", nil))
	if err != nil {
		t.Fatal(err)
	}
	checkContext(t, out.Context, map[string]string{"subject": "alice", "identity": "signed-identity-of-alice", "cookie": "theme=dark"})

	// A public route needs no session: an allow with a principalId all the same.
	ev = restEvent(t, "", "GET", "/assets/app.js", nil)
	ev.MultiValueHeaders["Cookie"] = nil
	if out, err := a.HandleREST(ctx, ev); err != nil || out.PrincipalID != "anonymous" || out.PolicyDocument.Statement[0].Effect != "Allow" {
		t.Fatalf("public route: %v %+v", err, out)
	}

	// No session, on a navigation and on an API call: the error Unauthorized (S4), never a redirect or a deny.
	for _, accept := range []string{"text/html", "application/json"} {
		ev := restEvent(t, id, "GET", "/app/x", map[string]string{"Accept": accept})
		ev.MultiValueHeaders["Cookie"] = []string{"theme=dark"}
		if _, err := a.HandleREST(ctx, ev); !errors.Is(err, apigateway.ErrUnauthorized) || err.Error() != "Unauthorized" {
			t.Fatalf("no session (%s): %v", accept, err)
		}
	}

	// CSRF (S5): a POST without the header is a deny policy, a 403, and its audit record goes through the transport.
	out, err = a.HandleREST(ctx, restEvent(t, id, "POST", "/app/x", map[string]string{"Origin": "https://docs.example.test"}))
	if err != nil || out.PolicyDocument.Statement[0].Effect != "Deny" || out.Context["error"] != "csrf" {
		t.Fatalf("csrf: %v %+v", err, out)
	}
	if !strings.Contains(s.rec.String(), `"event_code":"denied"`) {
		t.Fatalf("no denied record through the transport: %s", s.rec.String())
	}
	out, err = a.HandleREST(ctx, restEvent(t, id, "POST", "/app/x", map[string]string{"Origin": "https://docs.example.test",
		"Sec-Fetch-Site": "same-origin", "X-Requested-With": "XMLHttpRequest"}))
	if err != nil || out.PolicyDocument.Statement[0].Effect != "Allow" {
		t.Fatalf("csrf with the header: %v %+v", err, out)
	}

	// A refused exchange and a path the check refuses are denies too: an authorizer has no 400 and no error page.
	for _, p := range []string{"/api/refused/x", "/assets/../app/x"} {
		if out, err := a.HandleREST(ctx, restEvent(t, id, "GET", p, nil)); err != nil || out.PolicyDocument.Statement[0].Effect != "Deny" {
			t.Fatalf("%s: %v %+v", p, err, out)
		}
	}

	// Fail closed: a store that is down is a function error, a 500, never an allow.
	s.mem.Down.Store(true)
	if _, err := a.HandleREST(ctx, restEvent(t, id, "GET", "/app/x", nil)); !errors.Is(err, apigateway.ErrUnavailable) {
		t.Fatalf("store down: %v", err)
	}
	s.mem.Down.Store(false)

	// A logout is seen at once, because nothing is cached: the next event is Unauthorized.
	if err := s.core.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := a.HandleREST(ctx, restEvent(t, id, "GET", "/app/x", nil)); !errors.Is(err, apigateway.ErrUnauthorized) {
		t.Fatalf("after logout: %v", err)
	}
}

func TestV2(t *testing.T) {
	s := newSite(t)
	a := &apigateway.Authorizer{Core: s.core}
	ctx := context.Background()
	id := s.signIn(t, nil)

	out, err := a.HandleV2(ctx, v2Event(t, id, "GET", "/app/x", nil))
	if err != nil || !out.IsAuthorized {
		t.Fatalf("session route: %v %+v", err, out)
	}
	checkContext(t, out.Context, map[string]string{"subject": "alice", "cookie": "theme=dark"})

	// The token travels in the context for X-Session-Token (the HTTP API reserves Authorization in parameter mapping).
	out, err = a.HandleV2(ctx, v2Event(t, id, "GET", "/api/billing/x", nil))
	if err != nil || !out.IsAuthorized {
		t.Fatalf("exchange route: %v %+v", err, out)
	}
	checkContext(t, out.Context, map[string]string{"subject": "alice", "authorization": "Bearer token-for-billing", "cookie": "theme=dark"})

	// The cookies come from their own array; a Cookie header of the event is not read.
	ev := v2Event(t, id, "GET", "/app/x", map[string]string{"cookie": "__Host-docs=" + id})
	ev.Cookies = []string{"theme=dark"}
	if _, err := a.HandleV2(ctx, ev); !errors.Is(err, apigateway.ErrUnauthorized) {
		t.Fatalf("a Cookie header beside an empty array: %v", err)
	}

	// On a named stage, rawPath begins with the stage; the route matches the path after it.
	ev = v2Event(t, id, "GET", "/live/api/billing/x", nil)
	ev.RequestContext.Stage = "live"
	if out, err := a.HandleV2(ctx, ev); err != nil || out.Context["authorization"] != "Bearer token-for-billing" {
		t.Fatalf("named stage: %v %+v", err, out)
	}

	out, err = a.HandleV2(ctx, v2Event(t, id, "DELETE", "/app/x", nil))
	if err != nil || out.IsAuthorized || out.Context["error"] != "csrf" {
		t.Fatalf("csrf: %v %+v", err, out)
	}
	s.mem.Down.Store(true)
	if _, err := a.HandleV2(ctx, v2Event(t, id, "GET", "/app/x", nil)); !errors.Is(err, apigateway.ErrUnavailable) {
		t.Fatalf("store down: %v", err)
	}
	s.mem.Down.Store(false)

	// A session whose sign-in token ended with no refresh token ends at its next exchange: Unauthorized. The check's cleared
	// cookie cannot reach the browser and is dropped; the next sign-in replaces it.
	old := s.signIn(t, &core.Record{Subject: "bob", Issuer: "https://issuer.example.test", SID: "sid-2", AccessToken: "old",
		AccessExpiry: time.Now().Add(-time.Minute).Unix()})
	if _, err := a.HandleV2(ctx, v2Event(t, old, "GET", "/api/billing/x", map[string]string{"accept": "application/json"})); !errors.Is(err, apigateway.ErrUnauthorized) {
		t.Fatalf("ended at refresh: %v", err)
	}
}

// Handle tells the shapes apart by the raw event, as the Lambda function receives it: the sample events of the fit spike.
func TestHandle(t *testing.T) {
	s := newSite(t)
	a := &apigateway.Authorizer{Core: s.core}
	ctx := context.Background()
	id := s.signIn(t, nil)

	out, err := a.Handle(ctx, event(t, "rest-request.json", id))
	if r, ok := out.(events.APIGatewayCustomAuthorizerResponse); err != nil || !ok || r.PrincipalID != "alice" {
		t.Fatalf("REST: %v %#v", err, out)
	}
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), `"policyDocument"`) || !strings.Contains(string(b), `"principalId":"alice"`) {
		t.Fatalf("REST answer: %s", b)
	}
	for _, name := range []string{"http-v2-request.json", "http-v2-no-identity-source.json"} {
		out, err := a.Handle(ctx, event(t, name, id))
		if r, ok := out.(events.APIGatewayV2CustomAuthorizerSimpleResponse); err != nil || !ok || !r.IsAuthorized {
			t.Fatalf("%s: %v %#v", name, err, out)
		}
		b, _ := json.Marshal(out)
		if !strings.Contains(string(b), `"isAuthorized":true`) {
			t.Fatalf("%s answer: %s", name, b)
		}
	}
	if _, err := a.Handle(ctx, event(t, "rest-token.json", id)); err == nil || errors.Is(err, apigateway.ErrUnauthorized) {
		t.Fatalf("a TOKEN authorizer: %v", err)
	}
	if _, err := a.Handle(ctx, []byte("{")); err == nil {
		t.Fatal("an event that does not parse")
	}
}
