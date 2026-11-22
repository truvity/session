package core_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/session/core"
)

const iss = "https://issuer.example.test"

func TestEverySignInGetsANewIDAndTheStoreKeyIsNotTheCookie(t *testing.T) {
	e := newEnv(t, "storetest")
	a := e.signIn(t, "alice", "sid-1")
	b := e.signIn(t, "alice", "sid-1")
	if a == b || len(a) != 43 {
		t.Fatalf("ids %q %q", a, b)
	}
	for _, k := range e.mem.Keys() {
		if strings.Contains(k, a) || strings.Contains(k, b) || strings.Contains(k, "alice") || strings.Contains(k, "sid-1") {
			t.Fatalf("a store key holds a cookie id or a name in clear: %s", k)
		}
	}
	// A store key used as a cookie finds nothing.
	for _, k := range e.mem.Keys() {
		if strings.HasPrefix(k, "s/") {
			if _, err := e.core.Load(context.Background(), strings.TrimPrefix(k, "s/")); !errors.Is(err, core.ErrNotFound) {
				t.Fatalf("a store key opened a session: %v", err)
			}
		}
	}
}

// A sealed record is bound to its address: copied under another session's key it does not open, so the check fails closed.
func TestARecordCopiedToAnotherKeyDoesNotOpen(t *testing.T) {
	e := newEnv(t, "storetest")
	alice := e.signIn(t, "alice", "sid-a")
	bob := e.signIn(t, "bob", "sid-b")
	aliceItem := e.mem.Item(string(sessionKeyOf(t, e, alice)))
	bobItem := e.mem.Item(string(sessionKeyOf(t, e, bob)))
	if aliceItem == nil || bobItem == nil {
		t.Fatal("items not found")
	}
	bobItem.Value = aliceItem.GetValue()
	e.mem.SetItem(bobItem)
	if _, err := e.core.Load(context.Background(), bob); err == nil || errors.Is(err, core.ErrNotFound) {
		t.Fatalf("a copied record: %v", err)
	}
	if d := e.core.Check(context.Background(), req("GET", "/api/x", "Cookie", e.cookie(bob))); d.Outcome == core.Allow {
		t.Fatalf("a copied record passed: %+v", d)
	}
}

func sessionKeyOf(t *testing.T, e *env, id string) []byte {
	t.Helper()
	m, err := e.seal.Mac(context.Background(), core.PurposeSessionKey, []byte(id))
	if err != nil {
		t.Fatal(err)
	}
	return []byte("s/" + b64(m))
}

// Back-channel logout (decision 0010): by sid it ends that sid's sessions only; by subject, all the subject's sessions.
func TestLogoutBySidAndBySubject(t *testing.T) {
	for _, backend := range stores() {
		t.Run(backend, func(t *testing.T) {
			e := newEnv(t, backend)
			ctx := context.Background()
			a1 := e.signIn(t, "alice", "sid-1")
			a2 := e.signIn(t, "alice", "sid-1")
			a3 := e.signIn(t, "alice", "sid-2")
			b1 := e.signIn(t, "bob", "sid-3")
			alive := func(id string) bool { _, err := e.core.Load(ctx, id); return err == nil }
			n, err := e.core.LogoutBy(ctx, iss, "sid-1", "")
			if err != nil || n != 2 {
				t.Fatalf("by sid: %d, %v", n, err)
			}
			if alive(a1) || alive(a2) || !alive(a3) || !alive(b1) {
				t.Fatal("logout by sid ended the wrong sessions")
			}
			n, err = e.core.LogoutBy(ctx, iss, "", "alice")
			if err != nil || n != 3 { // the two members already gone are stale and cost a failed delete
				t.Fatalf("by subject: %d, %v", n, err)
			}
			if alive(a3) || !alive(b1) {
				t.Fatal("logout by subject ended the wrong sessions")
			}
			if n, err := e.core.LogoutBy(ctx, iss, "sid-unknown", ""); err != nil || n != 0 {
				t.Fatalf("unknown sid: %d, %v", n, err)
			}
			if n, err := e.core.LogoutBy(ctx, "https://other.example.test", "sid-3", ""); err != nil || n != 0 || !alive(b1) {
				t.Fatalf("another issuer's sid: %d, %v", n, err)
			}
		})
	}
}

// The race of decision 0010: a logout that arrives while a sign-in is under way ends the session that sign-in makes.
func TestALogoutDuringTheSignInEndsTheNewSession(t *testing.T) {
	for _, backend := range stores() {
		t.Run(backend, func(t *testing.T) {
			e := newEnv(t, backend)
			ctx := context.Background()
			started := e.clock.Now()
			e.clock.Add(time.Millisecond)
			if _, err := e.core.LogoutBy(ctx, iss, "sid-1", ""); err != nil {
				t.Fatal(err)
			}
			_, err := e.core.Create(ctx, &core.Record{Subject: "alice", Issuer: iss, SID: "sid-1"}, started)
			if !errors.Is(err, core.ErrLoggedOut) {
				t.Fatalf("by sid: %v", err)
			}
			if _, err := e.core.LogoutBy(ctx, iss, "", "carol"); err != nil {
				t.Fatal(err)
			}
			_, err = e.core.Create(ctx, &core.Record{Subject: "carol", Issuer: iss, SID: "sid-9"}, started)
			if !errors.Is(err, core.ErrLoggedOut) {
				t.Fatalf("by subject: %v", err)
			}
			if e.mem != nil {
				for _, k := range e.mem.Keys() {
					if strings.HasPrefix(k, "s/") {
						t.Fatalf("a refused session was left in the store: %s", k)
					}
				}
			}
			// A sign-in that starts after the logout is not refused, even in the same second.
			e.clock.Add(time.Millisecond)
			if _, err := e.core.Create(ctx, &core.Record{Subject: "alice", Issuer: iss, SID: "sid-1"}, e.clock.Now()); err != nil {
				t.Fatalf("a later sign-in: %v", err)
			}
		})
	}
}

// Parallel sign-ins of one subject all land in its pointer item: a lost race on the pointer is read and tried again.
func TestParallelSignInsOfOneSubjectAreAllInThePointer(t *testing.T) {
	for _, backend := range stores() {
		t.Run(backend, func(t *testing.T) {
			e := newEnv(t, backend)
			ctx := context.Background()
			const n = 12
			ids := make([]string, n)
			errs := make([]error, n)
			var wg sync.WaitGroup
			for i := range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ids[i], errs[i] = e.core.Create(ctx, &core.Record{Subject: "alice", Issuer: iss, SID: fmt.Sprintf("sid-%d", i)}, e.clock.Now())
				}()
			}
			wg.Wait()
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			if got, err := e.core.LogoutBy(ctx, iss, "", "alice"); err != nil || got != n {
				t.Fatalf("logout by subject found %d of %d: %v", got, n, err)
			}
			for _, id := range ids {
				if _, err := e.core.Load(ctx, id); !errors.Is(err, core.ErrNotFound) {
					t.Fatalf("a session survived: %v", err)
				}
			}
		})
	}
}

func TestDeleteEndsTheSession(t *testing.T) {
	e := newEnv(t, "storetest")
	id := e.signIn(t, "alice", "sid-1")
	if err := e.core.Delete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.core.Load(context.Background(), id); !errors.Is(err, core.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestClaimOnce(t *testing.T) {
	e := newEnv(t, "storetest")
	ctx := context.Background()
	until := e.clock.Now().Add(time.Minute)
	first, err := e.core.ClaimOnce(ctx, "jti-1", until)
	if err != nil || !first {
		t.Fatalf("first: %v %v", first, err)
	}
	again, err := e.core.ClaimOnce(ctx, "jti-1", until)
	if err != nil || again {
		t.Fatalf("replay: %v %v", again, err)
	}
	e.clock.Add(2 * time.Minute)
	later, err := e.core.ClaimOnce(ctx, "jti-1", e.clock.Now().Add(time.Minute))
	if err != nil || !later {
		t.Fatalf("after expiry: %v %v", later, err)
	}
}

func TestASignInTransactionIsUsedOnce(t *testing.T) {
	for _, backend := range stores() {
		t.Run(backend, func(t *testing.T) {
			e := newEnv(t, backend)
			ctx := context.Background()
			state := core.NewID()
			tx := &core.SignIn{Verifier: "v", Nonce: "n", ReturnTo: "/app", BindingHash: "h", Started: e.clock.Now()}
			if err := e.core.PutSignIn(ctx, state, tx); err != nil {
				t.Fatal(err)
			}
			got, err := e.core.TakeSignIn(ctx, state)
			if err != nil || got.ReturnTo != "/app" || got.Verifier != "v" || !got.Started.Equal(tx.Started) {
				t.Fatalf("take: %+v %v", got, err)
			}
			if _, err := e.core.TakeSignIn(ctx, state); !errors.Is(err, core.ErrNotFound) {
				t.Fatalf("second take: %v", err)
			}
			if _, err := e.core.TakeSignIn(ctx, core.NewID()); !errors.Is(err, core.ErrNotFound) {
				t.Fatalf("unknown state: %v", err)
			}
		})
	}
}

func TestAnExpiredSignInTransactionIsRefused(t *testing.T) {
	e := newEnv(t, "storetest")
	ctx := context.Background()
	state := core.NewID()
	if err := e.core.PutSignIn(ctx, state, &core.SignIn{Started: e.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(core.SignInLifetime + time.Second)
	if _, err := e.core.TakeSignIn(ctx, state); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
