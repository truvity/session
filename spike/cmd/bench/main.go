// bench measures check latency against DynamoDB Local, sequentially, one connection.
// It is NOT a measurement of the real DynamoDB service.
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/truvity/session/spike/internal/sess"
)

func stats(name string, d []time.Duration) {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	var sum time.Duration
	for _, x := range d {
		sum += x
	}
	p := func(q float64) time.Duration { return d[int(float64(len(d)-1)*q)] }
	fmt.Printf("| %-58s | %5d | %8.2f | %8.2f | %8.2f | %8.2f | %8.2f |\n", name, len(d),
		float64(sum)/float64(len(d))/1e6, float64(p(.5))/1e6, float64(p(.95))/1e6, float64(p(.99))/1e6, float64(d[len(d)-1])/1e6)
}

func run(n int, f func()) []time.Duration {
	for i := 0; i < 50; i++ { // warm-up
		f()
	}
	out := make([]time.Duration, n)
	for i := range out {
		t := time.Now()
		f()
		out[i] = time.Since(t)
	}
	return out
}

func main() {
	ctx := context.Background()
	n := 1000
	if len(os.Args) > 1 {
		n, _ = strconv.Atoi(os.Args[1])
	}
	cfg, _ := config.LoadDefaultConfig(ctx, config.WithRegion("eu-west-1"))
	db := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String("http://127.0.0.1:18000") })
	dk := sha256.Sum256([]byte("spike-data-key"))
	hk := sha256.Sum256([]byte("spike-hmac-key"))
	s := &sess.Store{DB: db, Table: "sessions", HMACKey: hk[:], DataKey: dk[:], Consist: true,
		IdleTTL: 30 * time.Minute, MaxTTL: 8 * time.Hour, TouchGap: time.Minute}
	id := sess.NewID()
	if err := s.Create(ctx, id, &sess.Record{Sub: "bench", Iss: "i", Sid: "bench-sid", AccessToken: string(make([]byte, 1500))}); err != nil {
		panic(err)
	}
	fmt.Printf("| %-58s | %5s | %8s | %8s | %8s | %8s | %8s |\n", "operation (ms)", "n", "mean", "p50", "p95", "p99", "max")
	fmt.Println("|---|---|---|---|---|---|---|")
	s.Consist = false
	stats("GetItem, eventually consistent + decrypt", run(n, func() { s.Get(ctx, id, false) }))
	s.Consist = true
	stats("GetItem, strongly consistent + decrypt", run(n, func() { s.Get(ctx, id, false) }))
	stats("GetItem + BatchGetItem of 2 tombstones (strong)", run(n, func() { s.Get(ctx, id, true) }))
	// conditional idle refresh when due: move the clock so that every call writes
	base := time.Now()
	i := 0
	stats("UpdateItem conditional (idle refresh, always due)", run(n, func() {
		i++
		s.Now = func() time.Time { return base.Add(time.Duration(i) * 2 * time.Minute / 10) }
		l, _ := s.Get(ctx, id, false)
		if l != nil {
			l.LastSeen = base.Unix() - 3600
		}
		s.Touch(ctx, id, l)
	}))
	s.Now = nil
	stats("Touch skipped (inside the gap): no write", run(n, func() {
		l, _ := s.Get(ctx, id, false)
		s.Touch(ctx, id, l)
	}))
	stats("Create (PutItem, 1.5 kB token, encrypted)", run(n/4, func() {
		s.Create(ctx, sess.NewID(), &sess.Record{Sub: "b", Iss: "i", AccessToken: string(make([]byte, 1500))})
	}))

	stats("Create with pointer items (TransactWriteItems, 3 items)", run(n/4, func() {
		s.CreateWithPointers(ctx, sess.NewID(), &sess.Record{Sub: "b", Iss: "i", Sid: "bs", AccessToken: string(make([]byte, 1500))})
	}))
	stats("Create with pointers + logout by pointer (GetItem, delete)", run(n/4, func() {
		sid := sess.NewID()
		s.CreateWithPointers(ctx, sess.NewID(), &sess.Record{Sub: "lg", Iss: "i", Sid: sid})
		s.DeleteByPointer(ctx, "i", sid, "")
	}))
	stats("Create + logout by secondary index (Query, delete)", run(n/4, func() {
		sid := sess.NewID()
		s.Create(ctx, sess.NewID(), &sess.Record{Sub: "lg2", Iss: "i", Sid: sid})
		s.DeleteByIndex(ctx, "i", sid, "")
	}))
	core := &sess.Core{Store: s, CookieName: "__Host-spike"}
	_ = core
	cl := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 1}}
	hit := func(url string) func() {
		return func() {
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("Cookie", "__Host-spike="+id)
			r, err := cl.Do(req)
			if err != nil {
				panic(err)
			}
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.StatusCode != 200 {
				panic(r.Status)
			}
		}
	}
	up := func(u string) bool {
		r, err := http.Get(u)
		if err != nil {
			return false
		}
		r.Body.Close()
		return true
	}
	stats("check over HTTP, direct to the service (tombstones on)", run(n, hit("http://127.0.0.1:18090/check/app/x")))
	if up("http://127.0.0.1:18081/") {
		stats("request through Envoy, HTTP ext_authz, upstream echo", run(n, hit("http://127.0.0.1:18081/app/x")))
		stats("request through Envoy, gRPC ext_authz, upstream echo", run(n, hit("http://127.0.0.1:18083/app/x")))
	}
	if up("http://127.0.0.1:18082/") {
		stats("request through nginx auth_request, upstream echo", run(n, hit("http://127.0.0.1:18082/app/x")))
	}
	// the same request with no auth, to the upstream directly: the baseline of the loop itself
	stats("baseline: echo upstream directly, no check", run(n, hit("http://127.0.0.1:18095/app/x")))
	s.Delete(ctx, id)
}
