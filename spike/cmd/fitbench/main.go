// fitbench measures the latency of the one strongly consistent read of a check, three ways, against DynamoDB Local
// (see internal/fit/bench.go). It is NOT a measurement of the real DynamoDB service. cmd/awsbench runs the same
// measurement in a Lambda function in a real account (see scripts/aws-check.sh). Throwaway spike code.
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/truvity/session/spike/internal/fit"
)

func main() {
	n, rounds := 2000, 5
	if len(os.Args) > 1 {
		n, _ = strconv.Atoi(os.Args[1])
	}
	if len(os.Args) > 2 {
		rounds, _ = strconv.Atoi(os.Args[2])
	}
	ctx := context.Background()
	db, err := fit.NewDynamo(ctx)
	if err != nil {
		panic(err)
	}
	if err := fit.Bench(ctx, db, fit.BenchOptions{Prefix: fmt.Sprintf("fitbench-%d", time.Now().UnixNano()), N: n, Rounds: rounds, Concurrent: true}, os.Stdout); err != nil {
		panic(err)
	}
}
