package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/atoom/key/awskms"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/kmstest"
	"github.com/truvity/session/internal/sealer/sealertest"
	"github.com/truvity/session/internal/signin"
)

// With the identity key on AWS KMS (atoom's key/awskms over the in-process KMS double), the reuse of decision 0016 holds: KMS
// signs a header once for each session and audience in half its life, not on every check, and the header verifies with the
// published key. A KMS that cannot be reached is a 503 once a new signature is needed.
func TestTheIdentityHeaderOnAWSKMSSignsAboutTwiceAMinute(t *testing.T) {
	fake := kmstest.New()
	fake.AddKey("alias/session/docs/identity-header")
	choices, err := atoomx.ParseKeyChoices([]string{"client-assertion=awskms:" + fake.AddKey(""), "identity-header=awskms"}, signin.Purposes())
	if err != nil {
		t.Fatal(err)
	}
	ks, err := atoomx.OpenKeys(atoomx.KeyOptions{Purposes: signin.Purposes(), Choices: choices, AliasPrefix: "session/docs",
		KMS: func() (awskms.API, error) { return fake, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ks.Stop)
	ctx := context.Background()
	b, err := sealertest.Tokens(t, ks, signin.TokenPurposes())
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := signin.Signers(b.Tokens)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := identity.JWK(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, "storetest", func(o *core.Options) {
		o.Rules = exchangeRules()
		o.Issuer = &fakeIssuer{}
		o.Identity = identity
	})
	id := e.signInWith(t, time.Time{}, "")
	signs := fake.Signs.Load()
	header := func() string {
		t.Helper()
		d := e.core.Check(ctx, req("GET", "/api/legacy/x", "Cookie", e.cookie(id)))
		if d.Outcome != core.Allow || d.Set[core.IdentityHeader] == "" {
			t.Fatalf("outcome %v reason %q", d.Outcome, d.Reason)
		}
		return d.Set[core.IdentityHeader]
	}
	first := header()
	sig, err := jose.ParseSignedCompact(first, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if sig.Signatures[0].Protected.KeyID != jwk.KeyID || sig.Signatures[0].Protected.ExtraHeaders["typ"] != core.IdentityType {
		t.Fatalf("protected header %+v", sig.Signatures[0].Protected)
	}
	if _, err := sig.Verify(jwk); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		e.clock.Add(250 * time.Millisecond) // 25 seconds in all
		if header() != first {
			t.Fatal("a new header within half its life")
		}
	}
	if n := fake.Signs.Load() - signs; n != 1 {
		t.Fatalf("%d KMS Sign calls for 101 checks in 25 s", n)
	}
	// A minute of checks, one a second: KMS signs twice.
	signs = fake.Signs.Load()
	e.clock.Add(5 * time.Second)
	for range 60 {
		header()
		e.clock.Add(time.Second)
	}
	if n := fake.Signs.Load() - signs; n != 2 {
		t.Fatalf("%d KMS Sign calls in a minute", n)
	}
	// KMS down: a check that needs a new signature is a 503.
	fake.Down.Store(true)
	e.clock.Add(31 * time.Second)
	if d := e.core.Check(ctx, req("GET", "/api/legacy/x", "Cookie", e.cookie(id))); d.Outcome != core.Unavailable || d.Reason != "identity" {
		t.Fatalf("KMS down: %+v", d)
	}
}
