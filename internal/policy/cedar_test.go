package policy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	atpolicy "github.com/truvity/atoom/policy"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/policy"
	"github.com/truvity/session/internal/policy/policytest"
)

func in(sub string, groups ...string) core.PolicyInput {
	return core.PolicyInput{Site: "docs", Route: core.Route{Name: "admin", Prefix: "/admin/", Mode: core.ModeSession},
		Method: "GET", Path: "/admin/x", Subject: sub, Issuer: "https://issuer.example.test", Claims: core.Claims{Groups: groups}}
}

func sha384hex(b []byte) string {
	d := sha512.Sum384(b)
	return hex.EncodeToString(d[:])
}

func TestDecide(t *testing.T) {
	pub := policytest.NewPublisher(t, "p1")
	payload := policytest.Payload(t, map[string]string{
		"admins": `permit (principal in Group::"admins", action == Action::"GET", resource == Route::"admin");`,
		"root":   `permit (principal, action, resource == Route::"admin") when { principal.email == "root@example.test" && context.method == "GET" };`,
	})
	e, err := policytest.NewDir(t, pub.Sign(t, 1, payload)).Start(context.Background(), pub)
	if err != nil {
		t.Fatal(err)
	}
	// The digest is atoom's: the SHA-384 of the payload, in lower-case hex.
	if e.Digest() != sha384hex(payload) {
		t.Fatalf("digest %q, want the SHA-384 of the payload", e.Digest())
	}
	for _, tc := range []struct {
		in           core.PolicyInput
		allow, unfit bool
	}{
		{in("alice", "admins"), true, false},
		{in("bob", "staff"), false, false},
		{func() core.PolicyInput { i := in("carol"); i.Claims.Email = "root@example.test"; return i }(), true, false},
		{func() core.PolicyInput { i := in("alice", "admins"); i.Method = "POST"; return i }(), false, false},
		// A method the schema does not declare does not fit: a denial.
		{func() core.PolicyInput { i := in("alice", "admins"); i.Method = "PROPFIND"; return i }(), false, true},
	} {
		res, err := e.Decide(context.Background(), tc.in)
		if err != nil || res.Allow != tc.allow || res.Misfit != tc.unfit || res.Digest != e.Digest() {
			t.Fatalf("%s %s: %+v %v", tc.in.Subject, tc.in.Method, res, err)
		}
	}
}

// The loading rules of atoom record 0019, through session's engine: a cold start without a valid set is refused (a broken
// bundle, a bundle signed by another key, a missing bundle), and a failed reload keeps the last good set.
func TestLoadingRules(t *testing.T) {
	ctx := context.Background()
	pub := policytest.NewPublisher(t, "p1")
	other := policytest.NewPublisher(t, "p1")
	good := policytest.Payload(t, map[string]string{"all": `permit (principal, action, resource);`})
	for name, doc := range map[string][]byte{
		"a policy that does not parse":    pub.Sign(t, 1, policytest.Payload(t, map[string]string{"bad": "permit ("})),
		"a policy that does not validate": pub.Sign(t, 1, policytest.Payload(t, map[string]string{"bad": `permit (principal, action, resource) when { principal.age > 3 };`})),
		"another key":                     other.Sign(t, 1, good),
		"plain Cedar text":                []byte(`permit (principal, action, resource);`),
	} {
		if _, err := policytest.NewDir(t, doc).Start(ctx, pub); err == nil {
			t.Fatalf("%s: started", name)
		}
	}
	empty := policytest.NewDir(t, pub.Sign(t, 1, good))
	if err := os.Remove(empty.Path + "/policy-bundle.jws"); err != nil {
		t.Fatal(err)
	}
	if _, err := empty.Start(ctx, pub); err == nil {
		t.Fatal("a cold start without a bundle started")
	}

	d := policytest.NewDir(t, pub.Sign(t, 2, good))
	e, err := d.Start(ctx, pub)
	if err != nil {
		t.Fatal(err)
	}
	digest := e.Digest()
	for name, doc := range map[string][]byte{
		"a broken bundle": pub.Sign(t, 3, policytest.Payload(t, map[string]string{"bad": "permit ("})),
		"another key":     other.Sign(t, 3, good),
		"an older seq":    pub.Sign(t, 1, policytest.Payload(t, map[string]string{"none": `forbid (principal, action, resource);`})),
	} {
		d.Write(t, doc)
		if out := e.Reload(ctx); out.Result != atpolicy.Rejected || e.Digest() != digest {
			t.Fatalf("%s: %v, digest %q", name, out.Result, e.Digest())
		}
	}
	if res, _ := e.Decide(ctx, in("x")); !res.Allow {
		t.Fatal("the last good set is not in use")
	}
	deny := policytest.Payload(t, map[string]string{"none": `forbid (principal, action, resource);`})
	d.Write(t, pub.Sign(t, 3, deny))
	if out := e.Reload(ctx); out.Result != atpolicy.Applied || e.Digest() != sha384hex(deny) {
		t.Fatalf("a newer bundle: %v", out.Result)
	}
	if res, _ := e.Decide(ctx, in("x")); res.Allow {
		t.Fatal("the newer set is not in use")
	}
}

// The example bundle (examples/policy-bundle.json) has session's schema, and decides as docs/policy.md says.
func TestExampleBundle(t *testing.T) {
	payload, err := os.ReadFile("../../examples/policy-bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(payload, &b); err != nil || b.Schema != policy.Schema {
		t.Fatalf("the example's schema is not policy.Schema (%v)", err)
	}
	pub := policytest.NewPublisher(t, "p1")
	e, err := policytest.NewDir(t, pub.Sign(t, 1, payload)).Start(context.Background(), pub)
	if err != nil {
		t.Fatal(err)
	}
	other := in("bob", "staff")
	other.Route = core.Route{Name: "api", Prefix: "/api/", Mode: core.ModeExchange}
	for _, tc := range []struct {
		in    core.PolicyInput
		allow bool
	}{{in("alice", "admins"), true}, {in("bob", "staff"), false}, {other, true}} {
		if res, err := e.Decide(context.Background(), tc.in); err != nil || res.Allow != tc.allow {
			t.Fatalf("%s on %s: %+v %v", tc.in.Subject, tc.in.Route.Name, res, err)
		}
	}
}

func TestPublisherFromPEM(t *testing.T) {
	pub := policytest.NewPublisher(t, "p1")
	if _, err := policy.PublisherFromPEM("p1", pub.PEM(t)); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string][2]string{
		"no kid":       {"", pub.PEM(t)},
		"not PEM":      {"p1", "abc"},
		"two blocks":   {"p1", pub.PEM(t) + pub.PEM(t)},
		"another type": {"p1", strings.Replace(pub.PEM(t), "PUBLIC KEY", "CERTIFICATE", 2)},
	} {
		if _, err := policy.PublisherFromPEM(tc[0], tc[1]); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.PublisherFromPEM("p1", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))); err == nil {
		t.Fatal("a key that is not P-384 was accepted")
	}
}
