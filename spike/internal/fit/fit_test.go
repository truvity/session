package fit

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/atoom/common/call"
	keyv1 "github.com/truvity/atoom/key/gen/atoom/key/v1alpha1"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
	"github.com/truvity/atoom/key/software"
	sourcev1 "github.com/truvity/atoom/source/gen/atoom/source/v1alpha1"
	storev1 "github.com/truvity/atoom/store/gen/atoom/store/v1alpha1"

	"github.com/truvity/session/spike/internal/sess"
)

// These tests need DynamoDB Local on 127.0.0.1:18000 (or DDB_ENDPOINT); without it they skip, like the first spike's store tests.

func env(t *testing.T, wrap func(http.Handler) http.Handler) *Env {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e, err := NewEnv(ctx, wrap)
	if err != nil {
		t.Skipf("DynamoDB Local not reachable: %v", err)
	}
	t.Cleanup(func() { e.Close(context.Background()) })
	return e
}

func rec(sub, sid string) *sess.Record {
	return &sess.Record{Sub: sub, Iss: "iss", Sid: sid, Email: sub + "@example.test", Groups: []string{"g1"}, AccessToken: "at"}
}

func TestCheckCoreOnAtomStore(t *testing.T) {
	e := env(t, nil)
	ctx := context.Background()
	id := sess.NewID()
	e.Count.Reset()
	if err := e.Store.Create(ctx, id, rec("alice", "sid1")); err != nil {
		t.Fatal(err)
	}
	t.Logf("DynamoDB calls to create a session (item + 2 index entries): %v", e.Count.Calls())
	core := &sess.Core{Checker: e.Store, CookieName: "__Host-spike"}
	h := http.Header{"Cookie": {"__Host-spike=" + id + "; theme=dark"}}
	e.Count.Reset()
	d := core.Check(ctx, sess.Request{Method: "GET", Path: "/app/x", Header: h})
	if d.Kind != sess.Allow || d.Set["x-session-user"] != "alice" || d.Set["cookie"] != "theme=dark" {
		t.Fatalf("allow expected: %+v", d)
	}
	t.Logf("DynamoDB calls for one allowed check: %v", e.Count.Calls())
	if c := e.Count.Calls(); len(c) != 1 || c["GetItem"] != 1 {
		t.Fatalf("a check must be one GetItem, got %v", c)
	}
	// a forged id, and a copy of the sealed record under another id
	for _, c := range []string{"__Host-spike=forged", ""} {
		d = core.Check(ctx, sess.Request{Method: "GET", Path: "/app/x", Header: http.Header{"Cookie": {c}, "Accept": {"text/html"}, "Sec-Fetch-Mode": {"navigate"}}})
		if d.Kind != sess.Redirect {
			t.Fatalf("redirect expected for %q: %+v", c, d)
		}
	}
	d = core.Check(ctx, sess.Request{Method: "GET", Path: "/app/x", Header: http.Header{"Cookie": {"__Host-spike=forged"}}})
	if d.Kind != sess.Unauthorized {
		t.Fatalf("401 expected: %+v", d)
	}
	// the record is bound to its id: the same item read under another id does not open
	res, err := e.Items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: []byte(e.Store.keyOf(id)), Linearizable: true}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Store.open("another-id", res.Msg.GetItem().GetValue()[16:]); err == nil {
		t.Fatal("a record opened under another id")
	}
}

func TestExpiry(t *testing.T) {
	e := env(t, nil)
	ctx := context.Background()
	// absolute lifetime: the driver's expires_at, absent to a read once past
	e.Store.MaxTTL = 1100 * time.Millisecond
	id := sess.NewID()
	if err := e.Store.Create(ctx, id, rec("bob", "s")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Store.Get(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1300 * time.Millisecond)
	if _, err := e.Store.Get(ctx, id, false); err != sess.ErrNotFound {
		t.Fatalf("past expires_at the session must be absent: %v", err)
	}
	// idle lifetime: session's own check on the header
	e.Store.MaxTTL = time.Hour
	id2 := sess.NewID()
	if err := e.Store.Create(ctx, id2, rec("bob", "s2")); err != nil {
		t.Fatal(err)
	}
	e.Store.Now = func() time.Time { return time.Now().Add(31 * time.Minute) }
	if _, err := e.Store.Get(ctx, id2, false); err != sess.ErrNotFound {
		t.Fatalf("idle expiry: %v", err)
	}
}

func TestTouchIsOneWinnerAndKeepsIndexEntries(t *testing.T) {
	e := env(t, nil)
	ctx := context.Background()
	id := sess.NewID()
	if err := e.Store.Create(ctx, id, rec("carol", "sidc")); err != nil {
		t.Fatal(err)
	}
	e.Store.Now = func() time.Time { return time.Now().Add(2 * time.Minute) } // a refresh is due
	l, err := e.Store.Get(ctx, id, false)
	if err != nil {
		t.Fatal(err)
	}
	e.Count.Reset()
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := e.Store.Touch(ctx, id, l)
			if err != nil {
				t.Error(err)
			}
			if ok {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	t.Logf("8 concurrent Touch at one version: %d winner(s); DynamoDB calls: %v", won.Load(), e.Count.Calls())
	if won.Load() != 1 {
		t.Fatalf("want one winner, got %d", won.Load())
	}
	// one Touch alone: calls
	l, _ = e.Store.Get(ctx, id, false)
	e.Store.Now = func() time.Time { return time.Now().Add(4 * time.Minute) }
	e.Count.Reset()
	if ok, err := e.Store.Touch(ctx, id, l); !ok || err != nil {
		t.Fatal(ok, err)
	}
	t.Logf("one Touch, DynamoDB calls: %v", e.Count.Calls())
	// the index entries survived the rewrite, and the version rose
	e.Store.Now = nil
	if n, err := e.Store.LogoutByIndex(ctx, "iss", "sidc", ""); err != nil || n != 1 {
		t.Fatalf("logout by index after touch: %d %v", n, err)
	}
}

func TestLogoutByIndexAndByPointer(t *testing.T) {
	e := env(t, nil)
	ctx := context.Background()
	mk := func(sub, sid string) string {
		id := sess.NewID()
		if err := e.Store.Create(ctx, id, rec(sub, sid)); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b, c := mk("dave", "s1"), mk("dave", "s2"), mk("erin", "s3")
	e.Count.Reset()
	n, err := e.Store.LogoutByIndex(ctx, "iss", "s1", "")
	t.Logf("logout by sid via index entries: deleted %d, DynamoDB calls %v", n, e.Count.Calls())
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err := e.Store.Get(ctx, a, false); err != sess.ErrNotFound {
		t.Fatal("a still there", err)
	}
	if _, err := e.Store.Get(ctx, b, false); err != nil {
		t.Fatal("b must stay", err)
	}
	if n, err = e.Store.LogoutByIndex(ctx, "iss", "", "dave"); err != nil || n != 1 {
		t.Fatal("by subject", n, err)
	}
	if _, err := e.Store.Get(ctx, c, false); err != nil {
		t.Fatal("erin must stay")
	}
	if n, _ = e.Store.LogoutByIndex(ctx, "iss", "s1", ""); n != 0 {
		t.Fatal("entries of a deleted item must be gone")
	}
	// the pointer-item variant of record 0010
	id1, id2 := sess.NewID(), sess.NewID()
	e.Count.Reset()
	tries, err := e.Store.CreateWithPointers(ctx, id1, rec("frank", "p1"))
	t.Logf("create with pointer items: %d tries, DynamoDB calls %v", tries, e.Count.Calls())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Store.CreateWithPointers(ctx, id2, rec("frank", "p2")); err != nil {
		t.Fatal(err)
	}
	e.Count.Reset()
	n, err = e.Store.LogoutByPointer(ctx, "iss", "", "frank")
	t.Logf("logout by subject via pointer: deleted %d, DynamoDB calls %v", n, e.Count.Calls())
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
}

func TestConcurrentCreatesSameSubject(t *testing.T) {
	e := env(t, nil)
	ctx := context.Background()
	const N = 16
	run := func(name string, f func(i int) (int, error)) {
		var wg sync.WaitGroup
		var tries, fails atomic.Int32
		t0 := time.Now()
		for i := 0; i < N; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, err := f(i)
				tries.Add(int32(n))
				if err != nil {
					fails.Add(1)
				}
			}()
		}
		wg.Wait()
		t.Logf("%s: %d parallel sign-ins of one subject: %d failed, %d tries in total, %v", name, N, fails.Load(), tries.Load(), time.Since(t0).Round(time.Millisecond))
	}
	run("index entries", func(i int) (int, error) {
		return 1, e.Store.Create(ctx, sess.NewID(), rec("gina", "x"+string(rune('a'+i))))
	})
	run("pointer items", func(i int) (int, error) {
		return e.Store.CreateWithPointers(ctx, sess.NewID(), rec("hank", "y"+string(rune('a'+i))))
	})
	if n, err := e.Store.LogoutByIndex(ctx, "iss", "", "gina"); err != nil || n != N {
		t.Fatalf("index: all %d sessions must be found: %d %v", N, n, err)
	}
	if n, err := e.Store.LogoutByPointer(ctx, "iss", "", "hank"); err != nil || n != N {
		t.Fatalf("pointer: all %d sessions must be found: %d %v", N, n, err)
	}
}

func TestLockJTIAndTombstone(t *testing.T) {
	e := env(t, nil)
	ctx := context.Background()
	ok, _ := e.Store.Lock(ctx, "s|aud", 400*time.Millisecond)
	ok2, _ := e.Store.Lock(ctx, "s|aud", 400*time.Millisecond)
	if !ok || ok2 {
		t.Fatalf("lock: first %v second %v", ok, ok2)
	}
	time.Sleep(600 * time.Millisecond)
	if ok3, _ := e.Store.Lock(ctx, "s|aud", time.Second); !ok3 {
		t.Fatal("an expired lock must be free again, with no 'or expired' clause")
	}
	if f, _ := e.Store.ClaimJTI(ctx, "j1", time.Now().Add(time.Minute)); !f {
		t.Fatal("first claim")
	}
	if f, _ := e.Store.ClaimJTI(ctx, "j1", time.Now().Add(time.Minute)); f {
		t.Fatal("replay must fail")
	}
	// the creation-time tombstone read of record 0010
	started := time.Now().UnixMilli()
	time.Sleep(5 * time.Millisecond)
	if err := e.Store.PutTombstone(ctx, "sid", "iss", "late"); err != nil {
		t.Fatal(err)
	}
	if at, err := e.Store.TombstoneAt(ctx, "sid", "iss", "late"); err != nil || at < started {
		t.Fatalf("tombstone newer than the start of the sign-in must be seen: %d %d %v", at, started, err)
	}
	if at, _ := e.Store.TombstoneAt(ctx, "sid", "iss", "other"); at != 0 {
		t.Fatal("no tombstone")
	}
}

func TestDeadlineAndFailClosed(t *testing.T) {
	var seen atomic.Value
	e := env(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen.Store(r.Header.Get("Connect-Timeout-Ms") + "|" + call.CorrelationID(r.Context()))
			h.ServeHTTP(w, r)
		})
	})
	ctx := call.WithCorrelationID(context.Background(), "corr-42")
	id := sess.NewID()
	if err := e.Store.Create(ctx, id, rec("ivy", "s")); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	_, _ = e.Store.Get(cctx, id, false)
	cancel()
	t.Logf("what the driver's handler saw (Connect-Timeout-Ms|correlation id): %v", seen.Load())
	if v, _ := seen.Load().(string); !strings.HasSuffix(v, "|corr-42") || !(strings.HasPrefix(v, "7") || strings.HasPrefix(v, "8")) {
		t.Fatalf("deadline and correlation id must reach the driver: %v", v)
	}
	// a slow store: the caller's deadline ends the call at the deadline, with a deadline_exceeded
	e.Count.Delay.Store(int64(400 * time.Millisecond))
	cctx, cancel = context.WithTimeout(ctx, 60*time.Millisecond)
	t0 := time.Now()
	_, err := e.Store.Get(cctx, id, false)
	cancel()
	t.Logf("slow store (+400 ms), deadline 60 ms: returned after %v with code %v", time.Since(t0).Round(time.Millisecond), connect.CodeOf(err))
	if err == nil || time.Since(t0) > 200*time.Millisecond {
		t.Fatalf("the deadline must end the call: %v", err)
	}
	// the core: a slow store is a down store, 503 after its own timeout (1.5 s)
	e.Count.Delay.Store(int64(3 * time.Second))
	core := &sess.Core{Checker: e.Store, CookieName: "__Host-spike"}
	t0 = time.Now()
	d := core.Check(ctx, sess.Request{Method: "GET", Path: "/app", Header: http.Header{"Cookie": {"__Host-spike=" + id}}})
	t.Logf("slow store (+3 s) through the core: %v after %v", d.Kind == sess.Unavailable, time.Since(t0).Round(10*time.Millisecond))
	if d.Kind != sess.Unavailable || time.Since(t0) > 2*time.Second {
		t.Fatalf("fail closed in time: %+v", d)
	}
	e.Count.Delay.Store(0)
	e.Count.Fail.Store(true)
	d = core.Check(ctx, sess.Request{Method: "GET", Path: "/app", Header: http.Header{"Cookie": {"__Host-spike=" + id}}})
	if d.Kind != sess.Unavailable {
		t.Fatalf("a failing store must be 503: %+v", d)
	}
	_, err = e.Store.Get(ctx, id, false)
	t.Logf("failing engine: code %v, reason %q, message %q", connect.CodeOf(err), Reason(err), err)
	e.Count.Fail.Store(false)
}

func TestCapabilities(t *testing.T) {
	e := env(t, nil)
	res, err := e.Items.Capabilities(context.Background(), connect.NewRequest(&storev1.CapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("store capabilities: store=%q tail_log=%v (no durability field yet)", res.Msg.GetStore(), res.Msg.GetTailLog())
	// the limits the session needs
	big := make([]byte, 390*1024)
	_, err = e.Items.Transact(context.Background(), connect.NewRequest(&storev1.TransactRequest{Puts: []*storev1.Put{{Key: []byte("big"), Value: big}}}))
	t.Logf("value of 390 KiB: code %v reason %q", connect.CodeOf(err), Reason(err))
	_, err = e.Items.Get(context.Background(), connect.NewRequest(&storev1.ItemGetRequest{Key: []byte("has space")}))
	t.Logf("key with a space: code %v reason %q", connect.CodeOf(err), Reason(err))
}

func TestKeySoftware(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	svc, err := software.New(software.Options{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	path, h := svc.Handler()
	hc, stop := Mount(path, h)
	defer stop()
	kc := keyv1alpha1connect.NewKeyStoreServiceClient(hc, "http://key", call.ClientOptions()...)
	ctx := context.Background()
	if _, err := kc.Ensure(ctx, connect.NewRequest(&keyv1.EnsureRequest{Purpose: AssertionPurpose, Algorithm: "ES384"})); err != nil {
		t.Fatal(err)
	}
	s := &Signer{Keys: kc, Kid: "k1"}
	jws, err := s.Assertion(ctx, ClaimsFor("session-spike", "https://issuer.example/realms/spike", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := s.PublicKey(ctx)
	t0 := time.Now()
	const nsign = 500
	for i := 0; i < nsign; i++ {
		if _, err := s.Assertion(ctx, ClaimsFor("session-spike", "https://issuer.example/realms/spike", time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("client assertion (ES384) through the in-process key port, software driver: %v per signature", (time.Since(t0) / nsign).Round(time.Microsecond))
	obj, err := jose.ParseSigned(jws, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := obj.Verify(pub); err != nil {
		t.Fatalf("the assertion must verify: %v", err)
	}
	var _ *ecdsa.PublicKey = pub
	_ = sha512.Sum384
	_ = base64.RawURLEncoding
	_ = big.NewInt
	// what a relying party would want and the port does not offer
	for _, c := range []struct{ p, a string }{{"client-assertion", "ES256"}, {"session-client-key", "ES384"}, {"token-signing", "ES256"}} {
		_, err := kc.Ensure(ctx, connect.NewRequest(&keyv1.EnsureRequest{Purpose: c.p, Algorithm: c.a}))
		t.Logf("Ensure(%s, %s): code %v reason %q", c.p, c.a, connect.CodeOf(err), Reason(err))
		if err == nil {
			t.Fatalf("%s/%s must be refused today", c.p, c.a)
		}
	}
	_, err = kc.Ensure(ctx, connect.NewRequest(&keyv1.EnsureRequest{Purpose: "audit-log", Algorithm: "ES256"}))
	t.Logf("Ensure(audit-log, ES256) (the only ES256 purpose): %v", err)
}

func TestSourceFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("site.jws", "site: docs\nhost: docs.example.test\n")
	sc, stop, err := NewSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ctx := context.Background()
	r, err := sc.Read(ctx, connect.NewRequest(&sourcev1.ReadRequest{Name: "site"}))
	if err != nil || !strings.HasPrefix(string(r.Msg.GetData()), "site: docs") {
		t.Fatal(err)
	}
	t.Logf("Read(site): %d bytes, version %.16s…", len(r.Msg.GetData()), r.Msg.GetVersion())
	r2, _ := sc.Read(ctx, connect.NewRequest(&sourcev1.ReadRequest{Name: "site", IfNoneMatch: r.Msg.GetVersion()}))
	if !r2.Msg.GetUnchanged() {
		t.Fatal("if_none_match must say unchanged")
	}
	for _, n := range []string{"site.yaml", "Site", "policy_bundle", "../x"} {
		_, err := sc.Read(ctx, connect.NewRequest(&sourcev1.ReadRequest{Name: n}))
		t.Logf("Read(%q): code %v reason %q", n, connect.CodeOf(err), Reason(err))
	}
	// watch: a replaced file is seen
	wctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	st, err := sc.Watch(wctx, connect.NewRequest(&sourcev1.SourceWatchRequest{Name: "site"}))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan time.Time, 1)
	go func() {
		if st.Receive() {
			got <- time.Now()
		} else {
			got <- time.Time{}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	wrote := time.Now()
	write("site.jws", "site: docs\nhost: other.example.test\n")
	select {
	case at := <-got:
		t.Logf("Watch saw a replaced file after %v", at.Sub(wrote).Round(time.Millisecond))
	case <-time.After(3 * time.Second):
		t.Fatal("no watch event")
	}
	var _ = json.Marshal
}
