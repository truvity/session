// authorizer-lambda is the Lambda entry point of the spike. NOT deployed anywhere.
// It exists to show the shape; the tests call the handlers with sample events instead.
package main

import "github.com/aws/aws-lambda-go/lambda"

func main() {
	// Wiring the store and core is the same as in cmd/spike. Left out on purpose:
	// the spike does not deploy to AWS.
	_ = lambda.Start
}
