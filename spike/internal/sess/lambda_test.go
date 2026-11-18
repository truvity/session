package sess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

// A REST API REQUEST authorizer event, shaped like the AWS documentation sample.
const restEvent = `{
 "type":"REQUEST","methodArn":"arn:aws:execute-api:eu-west-1:000000000000:api123/prod/GET/app/x",
 "resource":"/app/{proxy+}","path":"/app/x","httpMethod":"GET",
 "headers":{"Cookie":"__Host-spike=%s; theme=dark","Accept":"text/html","Sec-Fetch-Mode":"navigate"},
 "multiValueHeaders":{"Cookie":["__Host-spike=%s; theme=dark"]},
 "queryStringParameters":{},"pathParameters":{"proxy":"x"},"stageVariables":{},
 "requestContext":{"path":"/prod/app/x","accountId":"000000000000","resourceId":"r1","stage":"prod","requestId":"req-1",
  "identity":{"sourceIp":"192.0.2.1"},"resourcePath":"/app/{proxy+}","httpMethod":"GET","apiId":"api123"}}`

// An HTTP API payload 2.0 authorizer event: cookies are a separate array.
const v2Event = `{
 "version":"2.0","type":"REQUEST","routeArn":"arn:aws:execute-api:eu-west-1:000000000000:api123/$default/GET/app/x",
 "identitySource":["__Host-spike=%s"],"routeKey":"$default","rawPath":"/app/x","rawQueryString":"",
 "cookies":["__Host-spike=%s","theme=dark"],"headers":{"accept":"text/html"},
 "requestContext":{"accountId":"000000000000","apiId":"api123","domainName":"x.example","http":{"method":"GET","path":"/app/x"},"stage":"$default"}}`

func TestLambdaAuthorizerREST(t *testing.T) {
	s := testStore(t, "")
	ctx := context.Background()
	id := NewID()
	s.Create(ctx, id, &Record{Sub: "u-1", Iss: "i", Email: "mail-a", Sid: "s"})
	l := &LambdaAuthorizer{Core: &Core{Store: s, CookieName: "__Host-spike"}}

	var ev events.APIGatewayCustomAuthorizerRequestTypeRequest
	if err := json.Unmarshal([]byte(sprintf(restEvent, id, id)), &ev); err != nil {
		t.Fatal(err)
	}
	out, err := l.HandleREST(ctx, ev)
	if err != nil || out.PolicyDocument.Statement[0].Effect != "Allow" || out.PrincipalID != "u-1" {
		t.Fatalf("allow: %v %+v", err, out)
	}
	b, _ := json.MarshalIndent(out, "", " ")
	t.Logf("REST authorizer response (what the integration can use as $context.authorizer.*):\n%s", b)
	for k, v := range out.Context {
		switch v.(type) {
		case string, float64, int, bool:
		default:
			t.Errorf("context %q has type %T: API Gateway accepts only string, number, boolean", k, v)
		}
	}
	// no session -> the 401 error; the answer is not a redirect, it cannot be
	ev.Headers = map[string]string{"Accept": "text/html"}
	if _, err := l.HandleREST(ctx, ev); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("no cookie: %v", err)
	}
	// logout is seen at once when nothing is cached: delete, then the next call is refused
	s.Delete(ctx, id)
	if err := json.Unmarshal([]byte(sprintf(restEvent, id, id)), &ev); err != nil {
		t.Fatal(err)
	}
	if _, err := l.HandleREST(ctx, ev); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("a deleted session was allowed")
	}
}

func TestLambdaAuthorizerV2(t *testing.T) {
	s := testStore(t, "")
	ctx := context.Background()
	id := NewID()
	s.Create(ctx, id, &Record{Sub: "u-2", Iss: "i", Email: "mail-b"})
	l := &LambdaAuthorizer{Core: &Core{Store: s, CookieName: "__Host-spike"}}
	var ev events.APIGatewayV2CustomAuthorizerV2Request
	if err := json.Unmarshal([]byte(sprintf(v2Event, id, id)), &ev); err != nil {
		t.Fatal(err)
	}
	out, err := l.HandleV2(ctx, ev)
	if err != nil || !out.IsAuthorized || out.Context["sub"] != "u-2" {
		t.Fatalf("v2 allow: %v %+v", err, out)
	}
	ev.Cookies = []string{"theme=dark"}
	out, _ = l.HandleV2(ctx, ev)
	if out.IsAuthorized {
		t.Fatal("allowed without the session cookie")
	}
}

func TestSignInHandlerShape(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_session/x", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1; Path=/")
		w.Header().Add("Set-Cookie", "b=2; Path=/")
		w.Header().Set("Location", "/y")
		w.WriteHeader(302)
	})
	h := SignInHandler(mux)
	out, _ := h(context.Background(), events.APIGatewayV2HTTPRequest{RawPath: "/_session/x",
		RequestContext: events.APIGatewayV2HTTPRequestContext{HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: "GET"}}})
	if out.StatusCode != 302 || len(out.Cookies) != 2 || out.Headers["Location"] != "/y" {
		t.Fatalf("%+v", out)
	}
	// the real logout handler without the CSRF header, through the Lambda shape
	f := &Flow{Core: &Core{CookieName: "__Host-spike"}}
	mux2 := http.NewServeMux()
	f.Routes(mux2)
	out, _ = SignInHandler(mux2)(context.Background(), events.APIGatewayV2HTTPRequest{RawPath: "/_session/logout",
		RequestContext: events.APIGatewayV2HTTPRequestContext{HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: "POST"}}})
	if out.StatusCode != 403 {
		t.Fatalf("logout without CSRF header: %d", out.StatusCode)
	}
}
func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }
