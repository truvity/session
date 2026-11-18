package sess

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// These tests need DynamoDB Local (DDB_ENDPOINT, default http://127.0.0.1:18000).
func testStore(t *testing.T, endpoint string) *Store {
	t.Helper()
	if endpoint == "" {
		endpoint = os.Getenv("DDB_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = "http://127.0.0.1:18000"
	}
	db := dynamodb.New(dynamodb.Options{Region: "eu-west-1", BaseEndpoint: aws.String(endpoint),
		Credentials: credentials.NewStaticCredentialsProvider("x", "x", ""), RetryMaxAttempts: 1})
	table := "t_" + NewID()[:8]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := EnsureTable(ctx, db, table); err != nil {
		t.Skipf("DynamoDB Local not reachable: %v", err)
	}
	return &Store{DB: db, Table: table, HMACKey: []byte("h"), DataKey: make([]byte, 32), Consist: true,
		IdleTTL: 30 * time.Minute, MaxTTL: 8 * time.Hour, TouchGap: time.Minute}
}

func TestSessionRoundTripAndExpiry(t *testing.T) {
	s := testStore(t, "")
	ctx := context.Background()
	id := NewID()
	if err := s.Create(ctx, id, &Record{Sub: "u1", Iss: "i", Sid: "s1", AccessToken: "secret-token"}); err != nil {
		t.Fatal(err)
	}
	l, err := s.Get(ctx, id, false)
	if err != nil || l.Rec.AccessToken != "secret-token" {
		t.Fatalf("get: %v %+v", err, l)
	}
	// The store key is a keyed hash: the id itself is not in the table.
	if _, err := s.Get(ctx, s.keyOf(id), false); !errors.Is(err, ErrNotFound) {
		t.Fatal("the stored key must not work as a cookie id")
	}
	// AES-GCM with the id as associated data: a record copied under another id does not open.
	other := NewID()
	blob, _ := s.seal(id, l.Rec)
	if _, err := s.open(other, blob); err == nil {
		t.Fatal("record opened under a different id")
	}
	// Explicit expiry checks (TTL deletion is lazy): idle and maximum.
	base := time.Now()
	s.Now = func() time.Time { return base.Add(31 * time.Minute) }
	if _, err := s.Get(ctx, id, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("idle expiry not enforced on read")
	}
	s.Now = func() time.Time { return base.Add(9 * time.Hour) }
	if _, err := s.Get(ctx, id, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("maximum lifetime not enforced on read")
	}
}

func TestTouchIsConditionalAndRateLimited(t *testing.T) {
	s := testStore(t, "")
	ctx := context.Background()
	id := NewID()
	base := time.Now()
	s.Now = func() time.Time { return base }
	s.Create(ctx, id, &Record{Sub: "u1", Iss: "i"})
	l, _ := s.Get(ctx, id, false)
	if ok, _ := s.Touch(ctx, id, l); ok {
		t.Fatal("touched inside the gap")
	}
	s.Now = func() time.Time { return base.Add(2 * time.Minute) }
	// Two replicas race to refresh the same idle time: one write wins, the other is a no-op.
	var wg sync.WaitGroup
	wins := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.Touch(ctx, id, l)
			if err != nil {
				t.Error(err)
			}
			wins <- ok
		}()
	}
	wg.Wait()
	close(wins)
	n := 0
	for w := range wins {
		if w {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly one conditional update to win, got %d", n)
	}
	l2, _ := s.Get(ctx, id, false)
	if l2.LastSeen != base.Add(2*time.Minute).Unix() {
		t.Fatal("last_seen not refreshed")
	}
}

func TestTxIsUsedOnce(t *testing.T) {
	s := testStore(t, "")
	ctx := context.Background()
	s.PutTx(ctx, "st", Tx{Verifier: "v", Nonce: "n", ReturnTo: "/x"})
	if tx, err := s.TakeTx(ctx, "st"); err != nil || tx.ReturnTo != "/x" {
		t.Fatalf("first take: %v", err)
	}
	if _, err := s.TakeTx(ctx, "st"); !errors.Is(err, ErrNotFound) {
		t.Fatal("transaction used twice")
	}
}

func TestLockAndJTI(t *testing.T) {
	s := testStore(t, "")
	ctx := context.Background()
	a, _ := s.Lock(ctx, "sess1#aud", 5*time.Second)
	b, _ := s.Lock(ctx, "sess1#aud", 5*time.Second)
	if !a || b {
		t.Fatalf("lock: first=%v second=%v", a, b)
	}
	// an expired lock can be taken again
	base := time.Now()
	s.Now = func() time.Time { return base.Add(10 * time.Second) }
	if c, _ := s.Lock(ctx, "sess1#aud", 5*time.Second); !c {
		t.Fatal("expired lock not retaken")
	}
	if f, _ := s.ClaimJTI(ctx, "j1", time.Now().Add(time.Minute)); !f {
		t.Fatal("fresh jti refused")
	}
	if f, _ := s.ClaimJTI(ctx, "j1", time.Now().Add(time.Minute)); f {
		t.Fatal("jti replay accepted")
	}
}

func TestLogoutByIndex(t *testing.T) {
	s := testStore(t, "")
	ctx := context.Background()
	ids := []string{NewID(), NewID(), NewID()}
	s.Create(ctx, ids[0], &Record{Sub: "u1", Iss: "i", Sid: "sidA"})
	s.Create(ctx, ids[1], &Record{Sub: "u1", Iss: "i", Sid: "sidB"})
	s.Create(ctx, ids[2], &Record{Sub: "u2", Iss: "i", Sid: "sidC"})
	if n, err := s.DeleteByIndex(ctx, "i", "sidA", ""); err != nil || n != 1 {
		t.Fatalf("by sid: %d %v", n, err)
	}
	if n, _ := s.DeleteByIndex(ctx, "i", "", "u1"); n != 1 { // remaining u1 session, found by sub
		t.Fatalf("by sub: %d", n)
	}
	if _, err := s.Get(ctx, ids[2], false); err != nil {
		t.Fatal("unrelated session deleted")
	}
}

// Design Q2: a logout token that arrives just after sign-in can miss the new session when the
// secondary index lags. DynamoDB Local's indexes are synchronous, so the lag cannot happen here;
// the test makes it happen by ordering: the logout runs (index query finds nothing, tombstone is
// written) BEFORE the session item exists, which is what a lagging index looks like from the
// session's side.
func TestTombstoneClosesIndexLag(t *testing.T) {
	s := testStore(t, "")
	ctx := context.Background()
	older := NewID()
	s.Create(ctx, older, &Record{Sub: "u1", Iss: "i", Sid: "sidX"})
	time.Sleep(5 * time.Millisecond)

	// logout for sid sidX: tombstone first, then the index query. Pretend the index query ran
	// before `late` was visible: late is created after, with an earlier created time.
	if err := s.PutTombstones(ctx, "i", "sidX", "u1"); err != nil {
		t.Fatal(err)
	}
	n, _ := s.DeleteByIndex(ctx, "i", "sidX", "")
	if n != 1 {
		t.Fatalf("index delete found %d", n)
	}
	// the session the index missed: written with the clock before the logout
	late := NewID()
	logoutAt := time.Now()
	s.Now = func() time.Time { return logoutAt.Add(-50 * time.Millisecond) }
	s.Create(ctx, late, &Record{Sub: "u1", Iss: "i", Sid: "sidX"})
	s.Now = nil

	// Without the tombstone check, the missed session lives on.
	if l, err := s.Get(ctx, late, false); err != nil || l == nil {
		t.Fatalf("expected the missed session to be readable without the tombstone check: %v", err)
	}
	// With it, the check refuses and deletes it.
	if _, err := s.Get(ctx, late, true); !errors.Is(err, ErrNotFound) {
		t.Fatal("tombstone check let the missed session through")
	}
	if _, err := s.Get(ctx, late, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("the missed session was not deleted by the check")
	}
	// A new sign-in (same user, new sid) after the logout is not affected.
	fresh := NewID()
	s.Create(ctx, fresh, &Record{Sub: "u1", Iss: "i", Sid: "sidY"})
	if _, err := s.Get(ctx, fresh, true); err != nil {
		t.Fatalf("a later sign-in was refused: %v", err)
	}
}

// Logout without sid: the tombstone is by subject. A session created after it survives.
func TestTombstoneBySubject(t *testing.T) {
	s := testStore(t, "")
	ctx := context.Background()
	s.PutTombstones(ctx, "i", "", "u9")
	before := NewID()
	base := time.Now()
	s.Now = func() time.Time { return base.Add(-time.Second) }
	s.Create(ctx, before, &Record{Sub: "u9", Iss: "i"})
	s.Now = func() time.Time { return base.Add(time.Second) }
	after := NewID()
	s.Create(ctx, after, &Record{Sub: "u9", Iss: "i"})
	s.Now = nil
	if _, err := s.Get(ctx, before, true); !errors.Is(err, ErrNotFound) {
		t.Fatal("older session survived a subject tombstone")
	}
	if _, err := s.Get(ctx, after, true); err != nil {
		t.Fatal("newer session refused")
	}
}

func TestFailClosedWhenStoreIsDown(t *testing.T) {
	s := testStore(t, "")
	down := testStore(t, "")
	down.DB = dynamodb.New(dynamodb.Options{Region: "eu-west-1", BaseEndpoint: aws.String("http://127.0.0.1:1"),
		Credentials: credentials.NewStaticCredentialsProvider("x", "x", ""), RetryMaxAttempts: 1})
	_ = s
	c := &Core{Store: down, CookieName: "__Host-spike"}
	h := http.Header{"Cookie": {"__Host-spike=abc"}, "Sec-Fetch-Mode": {"navigate"}, "Accept": {"text/html"}}
	d := c.Check(context.Background(), Request{Method: "GET", Path: "/app", Header: h})
	if d.Kind != Unavailable || d.Status != 503 {
		t.Fatalf("store down must answer 503, got kind=%v status=%d", d.Kind, d.Status)
	}
}

func TestOpenRedirectAndClassification(t *testing.T) {
	c := &Core{CookieName: "__Host-spike"}
	for _, tc := range []struct {
		method, mode, accept string
		want                 Kind
	}{
		{"GET", "navigate", "text/html,*/*", Redirect},
		{"GET", "cors", "application/json", Unauthorized},
		{"POST", "navigate", "text/html", Unauthorized},
		{"GET", "navigate", "application/json", Unauthorized},
	} {
		d := c.Check(context.Background(), Request{Method: tc.method, Path: "/x", Header: http.Header{"Sec-Fetch-Mode": {tc.mode}, "Accept": {tc.accept}}})
		if d.Kind != tc.want {
			t.Errorf("%v: got %v want %v", tc, d.Kind, tc.want)
		}
	}
}

// Option C: pointer items, strongly consistent lookup, no secondary index and no per-request tombstone read.
func TestPointerItemsLogout(t *testing.T) {
	s := testStore(t, "")
	ctx := context.Background()
	a, b, c := NewID(), NewID(), NewID()
	// two sign-ins with the same issuer session (same sid), one other user
	if err := s.CreateWithPointers(ctx, a, &Record{Sub: "u1", Iss: "i", Sid: "S1"}); err != nil {
		t.Fatal(err)
	}
	s.CreateWithPointers(ctx, b, &Record{Sub: "u1", Iss: "i", Sid: "S1"})
	s.CreateWithPointers(ctx, c, &Record{Sub: "u2", Iss: "i", Sid: "S2"})
	if n, err := s.DeleteByPointer(ctx, "i", "S1", ""); err != nil || n != 2 {
		t.Fatalf("by sid: %d %v", n, err)
	}
	for _, id := range []string{a, b} {
		if _, err := s.Get(ctx, id, false); !errors.Is(err, ErrNotFound) {
			t.Fatal("session survived")
		}
	}
	if _, err := s.Get(ctx, c, false); err != nil {
		t.Fatal("unrelated session gone")
	}
	// logout without sid: by subject
	if n, _ := s.DeleteByPointer(ctx, "i", "", "u2"); n != 1 {
		t.Fatalf("by sub: %d", n)
	}
}

// The one race left under option C: the logout arrives before the sign-in is stored.
func TestPointerItemsLogoutBeforeSignInFinished(t *testing.T) {
	s := testStore(t, "")
	ctx := context.Background()
	startedMs := time.Now().UnixMilli() // the callback starts
	time.Sleep(5 * time.Millisecond)
	s.PutTombstones(ctx, "i", "S9", "u9") // the logout arrives: nothing to delete yet
	if n, _ := s.DeleteByPointer(ctx, "i", "S9", ""); n != 0 {
		t.Fatal("nothing should exist yet")
	}
	// the callback now stores the session, then checks once for a tombstone newer than its start
	id := NewID()
	s.CreateWithPointers(ctx, id, &Record{Sub: "u9", Iss: "i", Sid: "S9"})
	out, err := s.SignedOutSince(ctx, "i", "S9", "u9", startedMs)
	if err != nil || !out {
		t.Fatalf("callback did not see the logout: %v %v", out, err)
	}
	s.Delete(ctx, id) // the callback ends the session it just made
	if _, err := s.Get(ctx, id, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("session lives")
	}
}
