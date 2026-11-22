// awsbench is the Lambda function that scripts/aws-check.sh deploys to measure the real DynamoDB service from inside the
// region: the same measurement as cmd/fitbench (internal/fit/bench.go). It makes two tables under the prefix in its
// environment, runs, drops them and returns the text of the table. Throwaway spike code, run only by the maintainer.
package main

import (
	"bytes"
	"context"
	"os"
	"strconv"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/truvity/session/spike/internal/fit"
)

func envInt(k string, d int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return d
}

func main() {
	lambda.Start(func(ctx context.Context) (map[string]string, error) {
		db, err := fit.NewDynamoAWS(ctx)
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		err = fit.Bench(ctx, db, fit.BenchOptions{Prefix: os.Getenv("BENCH_PREFIX"), N: envInt("BENCH_N", 1000), Rounds: envInt("BENCH_ROUNDS", 3),
			Concurrent: os.Getenv("BENCH_CONCURRENT") == "1"}, &out)
		return map[string]string{"region": os.Getenv("AWS_REGION"), "result": out.String()}, err
	})
}
