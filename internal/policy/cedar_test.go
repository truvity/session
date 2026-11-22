package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/policy"
)

type flaky struct {
	b   policy.Bundle
	err error
}

func (f *flaky) Load(context.Context) (policy.Bundle, error) { return f.b, f.err }

func in(sub string, groups ...string) core.PolicyInput {
	return core.PolicyInput{Site: "docs", Route: core.Route{Name: "admin", Prefix: "/admin/", Mode: core.ModeSession},
		Method: "GET", Path: "/admin/x", Subject: sub, Issuer: "https://issuer.example.test", Claims: core.Claims{Groups: groups}}
}

func TestDecide(t *testing.T) {
	l := &flaky{b: policy.Bundle{Name: "b", Policies: []byte(`
permit (principal in Group::"admins", action == Action::"GET", resource == Route::"admin");
permit (principal, action, resource == Route::"admin") when { principal.email == "root@example.test" && context.method == "GET" };
`)}}
	e, err := policy.Start(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		in    core.PolicyInput
		allow bool
	}{
		{in("alice", "admins"), true},
		{in("bob", "staff"), false},
		{func() core.PolicyInput { i := in("carol"); i.Claims.Email = "root@example.test"; return i }(), true},
		{func() core.PolicyInput { i := in("alice", "admins"); i.Method = "POST"; return i }(), false},
	} {
		res, err := e.Decide(context.Background(), tc.in)
		if err != nil || res.Allow != tc.allow || res.Digest != e.Digest() {
			t.Fatalf("%s %s: %+v %v", tc.in.Subject, tc.in.Method, res, err)
		}
	}
}

// The loading rules of decision 0007 that do not need the signed bundle: a cold start without a valid set is refused, and a
// failed reload keeps the last good set.
func TestLoadingRules(t *testing.T) {
	ctx := context.Background()
	if _, err := policy.Start(ctx, &flaky{b: policy.Bundle{Name: "b", Policies: []byte("permit (")}}); err == nil {
		t.Fatal("a broken bundle started")
	}
	if _, err := policy.Start(ctx, &flaky{b: policy.Bundle{Name: "b", Policies: []byte("// nothing\n")}}); err == nil {
		t.Fatal("an empty bundle started")
	}
	if _, err := policy.Start(ctx, &flaky{err: errors.New("source down")}); err == nil {
		t.Fatal("a cold start without a bundle started")
	}
	l := &flaky{b: policy.Bundle{Name: "b", Policies: []byte(`permit (principal, action, resource);`)}}
	e, err := policy.Start(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	good := e.Digest()
	l.b.Policies = []byte("permit (")
	if err := e.Reload(ctx, l); err == nil || e.Digest() != good {
		t.Fatal("a broken reload replaced the set")
	}
	l.err = errors.New("down")
	if err := e.Reload(ctx, l); err == nil || e.Digest() != good {
		t.Fatal("a failed load replaced the set")
	}
	if res, _ := e.Decide(ctx, in("x")); !res.Allow {
		t.Fatal("the last good set is not in use")
	}
}
