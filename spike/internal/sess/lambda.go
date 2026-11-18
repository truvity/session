package sess

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// ErrUnauthorized is returned from the handler: API Gateway answers 401 for the error
// message "Unauthorized" (REST API REQUEST authorizer; HTTP API with no identity source).
var ErrUnauthorized = errors.New("Unauthorized")

type LambdaAuthorizer struct{ Core *Core }

func (l *LambdaAuthorizer) decide(ctx context.Context, method, path string, h http.Header) Decision {
	return l.Core.Check(ctx, Request{Method: method, Path: path, Header: h})
}

func policy(effect, arn string) events.APIGatewayCustomAuthorizerPolicy {
	return events.APIGatewayCustomAuthorizerPolicy{Version: "2012-10-17",
		Statement: []events.IAMPolicyStatement{{Action: []string{"execute-api:Invoke"}, Effect: effect, Resource: []string{arn}}}}
}

// HandleREST serves a REST API REQUEST authorizer (and an HTTP API authorizer on payload 1.0).
func (l *LambdaAuthorizer) HandleREST(ctx context.Context, ev events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	h := http.Header{}
	for k, v := range ev.Headers {
		h.Set(k, v)
	}
	d := l.decide(ctx, ev.HTTPMethod, ev.Path, h)
	switch d.Kind {
	case Allow:
		return events.APIGatewayCustomAuthorizerResponse{
			PrincipalID:    d.Subject,
			PolicyDocument: policy("Allow", ev.MethodArn),
			// Only strings, numbers and booleans are allowed in context.
			Context: map[string]interface{}{"sub": d.Subject, "email": d.Set["x-session-email"], "groups": d.Set["x-session-groups"]},
		}, nil
	case Unavailable:
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("store unavailable") // API Gateway answers 500: fails closed
	default:
		return events.APIGatewayCustomAuthorizerResponse{}, ErrUnauthorized // 401
	}
}

// HandleV2 serves an HTTP API authorizer on payload 2.0 with simple responses.
// The browser's cookies arrive in a separate "cookies" array, not in headers.
func (l *LambdaAuthorizer) HandleV2(ctx context.Context, ev events.APIGatewayV2CustomAuthorizerV2Request) (events.APIGatewayV2CustomAuthorizerSimpleResponse, error) {
	h := http.Header{}
	for k, v := range ev.Headers {
		h.Set(k, v)
	}
	if len(ev.Cookies) > 0 {
		h.Set("Cookie", strings.Join(ev.Cookies, "; "))
	}
	d := l.decide(ctx, ev.RequestContext.HTTP.Method, ev.RawPath, h)
	switch d.Kind {
	case Allow:
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: true,
			Context: map[string]interface{}{"sub": d.Subject, "email": d.Set["x-session-email"], "groups": d.Set["x-session-groups"]}}, nil
	case Unavailable:
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{}, errors.New("store unavailable")
	default:
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: false}, nil
	}
}

// SignInHandler is the second Lambda handler: the same sign-in routes behind an HTTP API
// (payload 2.0) proxy integration. Set-Cookie lines go in the response "cookies" array.
func SignInHandler(mux http.Handler) func(context.Context, events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return func(ctx context.Context, ev events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
		target := ev.RawPath
		if ev.RawQueryString != "" {
			target += "?" + ev.RawQueryString
		}
		req := httptest.NewRequest(ev.RequestContext.HTTP.Method, target, strings.NewReader(ev.Body)).WithContext(ctx)
		for k, v := range ev.Headers {
			req.Header.Set(k, v)
		}
		if len(ev.Cookies) > 0 {
			req.Header.Set("Cookie", strings.Join(ev.Cookies, "; "))
		}
		req.Host = ev.RequestContext.DomainName
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		res := rec.Result()
		out := events.APIGatewayV2HTTPResponse{StatusCode: res.StatusCode, Headers: map[string]string{}, Body: rec.Body.String(), Cookies: res.Header.Values("Set-Cookie")}
		for k := range res.Header {
			if k != "Set-Cookie" {
				out.Headers[k] = res.Header.Get(k)
			}
		}
		return out, nil
	}
}
