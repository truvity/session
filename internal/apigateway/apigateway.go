// Package apigateway holds the adapter for the AWS API Gateway Lambda authorizer (decisions 0011, 0014 and 0030): the REST API
// REQUEST authorizer (also an HTTP API authorizer on payload 1.0) and the HTTP API authorizer on payload 2.0 with simple
// responses. It is a native Go handler, not behind the Lambda Web Adapter, and it translates between API Gateway and the check
// core and decides nothing itself.
//
// An authorizer cannot change the request or the response: only principalId and the context reach the integration, as
// $context.authorizer.<key>. So an allow carries what the other hosts set as headers in the context, under the keys of Context*,
// and the integration's parameter mapping sets the upstream headers from them and removes the browser's (S8). Every key is
// present on every allow, empty when the route sets nothing, so a mapping always overwrites a browser-sent value.
//
// A refusal has three shapes: the error Unauthorized, which API Gateway answers with a 401 ("no session", S4: the browser
// helper starts the sign-in, because an authorizer cannot redirect); a deny (the REST API's deny policy, the HTTP API's
// isAuthorized false), a 403 for every other refusal; and a function error, a 500, when the check is unavailable (fail closed).
// A Set-Cookie of the check cannot reach the browser and is dropped.
package apigateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/aws/aws-lambda-go/events"

	"github.com/truvity/session/core"
)

// Checker is the check core as the adapter sees it.
type Checker interface {
	Check(ctx context.Context, r core.Request) core.Decision
}

// ErrUnauthorized is the answer to a request without a session: API Gateway answers it with a 401. The message must be exactly
// "Unauthorized".
var ErrUnauthorized = errors.New("Unauthorized")

// ErrUnavailable is the answer when the check is unavailable: a function error, which API Gateway answers with a 500.
var ErrUnavailable = errors.New("session: the check is unavailable")

// The keys of the context of an allow. The integration's parameter mapping reads them as $context.authorizer.<key>.
const (
	// ContextSubject is the session's subject, empty on a route without a session. On the REST API it is the principalId too.
	ContextSubject = "subject"
	// ContextAuthorization is the per-API token of a route of mode exchange, "Bearer <token>". The REST API maps it to
	// Authorization; the HTTP API reserves Authorization in parameter mapping and maps it to X-Session-Token (decision 0011).
	ContextAuthorization = "authorization"
	// ContextIdentity is the signed identity header of a route of mode identity-header, for X-Session-Identity.
	ContextIdentity = "identity"
	// ContextCookie is the Cookie header the site may see: every cookie except session's own.
	ContextCookie = "cookie"
)

// anonymous is the principalId of an allow without a session (a public route): the REST API wants one on every policy.
const anonymous = "anonymous"

// Authorizer is the native handler of both API Gateway products.
type Authorizer struct {
	Core Checker
	// Log is the operational log; nil is slog.Default().
	Log *slog.Logger
}

func (a *Authorizer) log() *slog.Logger {
	if a.Log == nil {
		return slog.Default()
	}
	return a.Log
}

// Handle answers a raw authorizer event, the entry point of the Lambda function: a payload 2.0 event (version "2.0") gets the
// simple response, a REQUEST event of the REST API or of payload 1.0 the policy. A TOKEN authorizer is not supported: it sees
// no cookie.
func (a *Authorizer) Handle(ctx context.Context, raw json.RawMessage) (any, error) {
	var probe struct {
		Version string `json:"version"`
		Type    string `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("apigateway: an event that does not parse: %w", err)
	}
	switch {
	case probe.Version == "2.0":
		var ev events.APIGatewayV2CustomAuthorizerV2Request
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("apigateway: a payload 2.0 event that does not parse: %w", err)
		}
		return a.HandleV2(ctx, ev)
	case probe.Type == "REQUEST":
		var ev events.APIGatewayCustomAuthorizerRequestTypeRequest
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("apigateway: a REQUEST event that does not parse: %w", err)
		}
		return a.HandleREST(ctx, ev)
	default:
		return nil, fmt.Errorf("apigateway: an authorizer event of type %q, version %q: only REQUEST authorizers are supported", probe.Type, probe.Version)
	}
}

// HandleREST serves a REST API REQUEST authorizer, and an HTTP API authorizer on payload 1.0.
func (a *Authorizer) HandleREST(ctx context.Context, ev events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	h := http.Header{}
	if len(ev.MultiValueHeaders) > 0 {
		for k, vs := range ev.MultiValueHeaders {
			for _, v := range vs {
				h.Add(k, v)
			}
		}
	} else {
		for k, v := range ev.Headers {
			h.Set(k, v)
		}
	}
	path := ev.Path + restQuery(ev)
	d := a.Core.Check(ctx, core.Request{Method: ev.HTTPMethod, Host: h.Get("Host"), Path: path, Header: h})
	a.dropCookies(d)
	switch outcome(d) {
	case allow:
		principal := d.Subject
		if principal == "" {
			principal = anonymous
		}
		return events.APIGatewayCustomAuthorizerResponse{PrincipalID: principal, PolicyDocument: policy("Allow", ev.MethodArn),
			Context: allowContext(d)}, nil
	case unauthorized:
		return events.APIGatewayCustomAuthorizerResponse{}, ErrUnauthorized
	case deny:
		return events.APIGatewayCustomAuthorizerResponse{PrincipalID: anonymous, PolicyDocument: policy("Deny", ev.MethodArn),
			Context: map[string]any{"error": d.Reason}}, nil
	default:
		return events.APIGatewayCustomAuthorizerResponse{}, ErrUnavailable
	}
}

// HandleV2 serves an HTTP API authorizer on payload 2.0 with simple responses. The browser's cookies arrive in their own array,
// and the check gets them joined into one Cookie header.
func (a *Authorizer) HandleV2(ctx context.Context, ev events.APIGatewayV2CustomAuthorizerV2Request) (events.APIGatewayV2CustomAuthorizerSimpleResponse, error) {
	h := http.Header{}
	for k, v := range ev.Headers {
		h.Set(k, v)
	}
	h.Del("Cookie")
	if len(ev.Cookies) > 0 {
		h.Set("Cookie", strings.Join(ev.Cookies, "; "))
	}
	host := ev.RequestContext.DomainName
	if host == "" {
		host = h.Get("Host")
	}
	path := v2Path(ev)
	if ev.RawQueryString != "" {
		path += "?" + ev.RawQueryString
	}
	d := a.Core.Check(ctx, core.Request{Method: ev.RequestContext.HTTP.Method, Host: host, Path: path, Header: h})
	a.dropCookies(d)
	switch outcome(d) {
	case allow:
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: true, Context: allowContext(d)}, nil
	case unauthorized:
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{}, ErrUnauthorized
	case deny:
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: false, Context: map[string]any{"error": d.Reason}}, nil
	default:
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{}, ErrUnavailable
	}
}

type answer int

const (
	allow answer = iota
	unauthorized
	deny
	unavailable
)

// outcome maps a decision to the three refusals an authorizer has. A redirect and a 401 are both "no session"; every other
// refusal (CSRF, policy, a refused exchange, a path the check refuses, no route) is a deny, a 403.
func outcome(d core.Decision) answer {
	switch {
	case d.Outcome == core.Allow:
		return allow
	case d.Outcome == core.Unavailable:
		return unavailable
	case d.Outcome == core.Redirect, d.Status == http.StatusUnauthorized:
		return unauthorized
	default:
		return deny
	}
}

// allowContext is the context of an allow: every key, empty when the route sets nothing, so the integration's mapping always
// overwrites the browser's value. The context takes strings, numbers and booleans only.
func allowContext(d core.Decision) map[string]any {
	return map[string]any{
		ContextSubject:       d.Subject,
		ContextAuthorization: d.Set["authorization"],
		ContextIdentity:      d.Set[core.IdentityHeader],
		ContextCookie:        d.Set["cookie"],
	}
}

// dropCookies logs the Set-Cookie values of a decision, which an authorizer cannot send: the cleared cookie of a session that
// ended at a refresh. The next sign-in replaces the cookie.
func (a *Authorizer) dropCookies(d core.Decision) {
	if len(d.SetCookies) > 0 {
		a.log().Debug("apigateway: an authorizer cannot send Set-Cookie; dropped", "count", len(d.SetCookies), "reason", d.Reason)
	}
}

func policy(effect, arn string) events.APIGatewayCustomAuthorizerPolicy {
	return events.APIGatewayCustomAuthorizerPolicy{Version: "2012-10-17",
		Statement: []events.IAMPolicyStatement{{Action: []string{"execute-api:Invoke"}, Effect: effect, Resource: []string{arn}}}}
}

// restQuery rebuilds the query of a REST event, which carries it parsed: the keys sorted, each key's values in order. The check
// uses the query only for the return address of a sign-in.
func restQuery(ev events.APIGatewayCustomAuthorizerRequestTypeRequest) string {
	q := url.Values{}
	if len(ev.MultiValueQueryStringParameters) > 0 {
		for k, vs := range ev.MultiValueQueryStringParameters {
			q[k] = slices.Clone(vs)
		}
	} else {
		for k, v := range ev.QueryStringParameters {
			q.Set(k, v)
		}
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

// v2Path is the path the site sees. On a named stage the HTTP API's rawPath begins with the stage, which the route does not
// see; on the $default stage it does not.
func v2Path(ev events.APIGatewayV2CustomAuthorizerV2Request) string {
	p := ev.RawPath
	if st := ev.RequestContext.Stage; st != "" && st != "$default" {
		if rest, ok := strings.CutPrefix(p, "/"+st); ok && (rest == "" || rest[0] == '/') {
			p = rest
		}
	}
	if p == "" {
		p = "/"
	}
	return p
}
