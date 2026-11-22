// authorizer-lambda is the native Go handler of the authorizer: the fallback of record 0012, in the same module as the
// check core. It takes the raw event, tells the HTTP API payload 2.0 event from the REST API one, and answers in the
// shape API Gateway expects (the policy, or the simple response, or the error "Unauthorized").
// For the fit spike it runs on an in-memory store inside the Lambda emulator image (lwa/Dockerfile.native). Throwaway code.
package main

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/truvity/session/spike/internal/fit"
	"github.com/truvity/session/spike/internal/sess"
)

func main() {
	core := &sess.Core{Checker: fit.NewMem(), CookieName: "__Host-spike"}
	auth := &sess.LambdaAuthorizer{Core: core}
	lambda.Start(func(ctx context.Context, raw json.RawMessage) (any, error) {
		var probe struct {
			Version string `json:"version"`
			Type    string `json:"type"`
		}
		_ = json.Unmarshal(raw, &probe)
		if probe.Version == "2.0" {
			var ev events.APIGatewayV2CustomAuthorizerV2Request
			if err := json.Unmarshal(raw, &ev); err != nil {
				return nil, err
			}
			return auth.HandleV2(ctx, ev)
		}
		var ev events.APIGatewayCustomAuthorizerRequestTypeRequest
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, err
		}
		return auth.HandleREST(ctx, ev)
	})
}
