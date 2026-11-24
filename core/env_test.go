package core_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	storedyn "github.com/truvity/atoom/store/dynamodb"
	"github.com/truvity/atoom/store/gen/atoom/store/v1alpha1/storev1alpha1connect"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/sealer/sealertest"
	"github.com/truvity/session/internal/storetest"
)

// clock is a settable clock shared by the core and the test double.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// env is one core over one store.
type env struct {
	core  *core.Core
	items storev1alpha1connect.ItemServiceClient
	mem   *storetest.Store // nil on DynamoDB
	clock *clock
	audit *recorder
	seal  core.Sealer
}

type recorder struct {
	mu     sync.Mutex
	events []core.Event
	fail   bool
}

func (r *recorder) Emit(_ context.Context, e core.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return fmt.Errorf("audit transport down")
	}
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) Events() []core.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]core.Event(nil), r.events...)
}

func testRules() core.Rules {
	return core.Rules{
		Site: "docs",
		Host: "docs.example.test",
		Routes: []core.Route{
			{Prefix: "/assets/", Mode: core.ModePublic},
			{Prefix: "/api/strict/", Mode: core.ModeSession, Unauthenticated: core.Unauthenticated401},
			{Prefix: "/go/", Mode: core.ModeSession, Unauthenticated: core.UnauthenticatedRedirect},
			{Name: "admin", Prefix: "/admin/", Mode: core.ModeSession},
			{Prefix: "/api/", Mode: core.ModeSession},
			{Prefix: "/app", Mode: core.ModeSession},
			{Exact: "/", Mode: core.ModeSession},
		},
	}
}

type option func(*core.Options)

// stores lists the store backends the store tests run on: the in-process double always, and atoom's store/dynamodb driver
// when SESSION_TEST_DYNAMODB names a DynamoDB Local endpoint (just test-dynamodb starts one).
func stores() []string {
	out := []string{"storetest"}
	if os.Getenv("SESSION_TEST_DYNAMODB") != "" {
		out = append(out, "dynamodb")
	}
	return out
}

func newEnv(t *testing.T, backend string, opts ...option) *env {
	t.Helper()
	clk := &clock{t: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	e := &env{clock: clk, audit: &recorder{}}
	switch backend {
	case "storetest":
		e.mem = storetest.New(clk.Now)
		items, stop := e.mem.Client()
		t.Cleanup(stop)
		e.items = items
	case "dynamodb":
		e.items = dynamoItems(t)
		// DynamoDB Local expires on its own clock; the test clock must follow the wall clock there.
		clk.t = time.Now()
	default:
		t.Fatalf("unknown backend %s", backend)
	}
	// On DynamoDB the block keeps its wraps in the session table, as a deployment does; the double keeps them apart, so that
	// the tests that count the store's items and calls see only the core's.
	seal := sealertest.New(t)
	if backend == "dynamodb" {
		seal = sealertest.On(t, e.items)
	}
	e.seal = seal
	o := core.Options{Rules: testRules(), Items: e.items, Seal: seal, Audit: e.audit, Now: clk.Now}
	for _, f := range opts {
		f(&o)
	}
	c, err := core.New(o)
	if err != nil {
		t.Fatal(err)
	}
	e.core = c
	return e
}

func dynamoItems(t *testing.T) storev1alpha1connect.ItemServiceClient {
	t.Helper()
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("eu-west-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	if err != nil {
		t.Fatal(err)
	}
	db := awsdynamodb.NewFromConfig(cfg, func(o *awsdynamodb.Options) { o.BaseEndpoint = aws.String(os.Getenv("SESSION_TEST_DYNAMODB")) })
	table := fmt.Sprintf("session-test-%d", time.Now().UnixNano())
	if err := storedyn.EnsureTable(ctx, db, table); err != nil {
		t.Fatal(err)
	}
	st, err := atoomx.DynamoDB(db, table)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		st.Stop()
		_, _ = db.DeleteTable(context.Background(), &awsdynamodb.DeleteTableInput{TableName: &table})
	})
	return st.Items
}

func (e *env) signIn(t *testing.T, sub, sid string, groups ...string) string {
	t.Helper()
	id, err := e.core.Create(context.Background(), &core.Record{Subject: sub, Issuer: "https://issuer.example.test", SID: sid,
		Claims: core.Claims{Name: "Test Person", Groups: groups}, IDToken: "id-token", AccessToken: "access-token"}, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) cookie(id string) string { return e.core.CookieName() + "=" + id }

func req(method, path string, h ...string) core.Request {
	hdr := http.Header{}
	for i := 0; i+1 < len(h); i += 2 {
		hdr.Add(h[i], h[i+1])
	}
	return core.Request{Method: method, Host: "docs.example.test", Path: path, Header: hdr}
}

func nav(path string, h ...string) core.Request {
	return req(http.MethodGet, path, append([]string{"Sec-Fetch-Mode", "navigate", "Accept", "text/html,application/xhtml+xml"}, h...)...)
}
