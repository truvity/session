package sealer_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/truvity/atoom/blocks/seal"
	"github.com/truvity/atoom/key/awskms"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/kmstest"
	"github.com/truvity/session/internal/sealer"
	"github.com/truvity/session/internal/sealer/sealertest"
	"github.com/truvity/session/internal/storetest"
)

func TestSealOpenMac(t *testing.T) {
	ctx := context.Background()
	s := sealertest.New(t)
	a, b := core.PurposeSessionRecord, core.PurposeSignInRecord
	sealed, err := s.Seal(ctx, a, []byte("s/addr-1"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("secret")) {
		t.Fatal("the plaintext is visible")
	}
	if got, err := s.Open(ctx, a, []byte("s/addr-1"), sealed); err != nil || string(got) != "secret" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := s.Open(ctx, a, []byte("s/addr-2"), sealed); err == nil {
		t.Fatal("a value opened under another address")
	}
	if _, err := s.Open(ctx, b, []byte("s/addr-1"), sealed); err == nil {
		t.Fatal("a value opened under another purpose")
	}
	if _, err := s.Seal(ctx, core.PurposeSessionKey, nil, nil); err == nil {
		t.Fatal("a mac purpose sealed")
	}
	if _, err := s.Seal(ctx, "other", []byte("x"), nil); err == nil {
		t.Fatal("an undeclared purpose sealed")
	}
	if _, err := s.Seal(ctx, a, []byte("s/addr-1"), make([]byte, 1<<20+1)); err == nil {
		t.Fatal("an oversized value was sealed")
	}
	if _, err := s.Seal(ctx, a, []byte{0xff}, []byte("x")); err == nil {
		t.Fatal("an address that is not UTF-8 was taken")
	}
	ma, _ := s.Mac(ctx, core.PurposeSessionKey, []byte("x"))
	mb, _ := s.Mac(ctx, core.PurposeLookupKey, []byte("x"))
	ma2, _ := s.Mac(ctx, core.PurposeSessionKey, []byte("x"))
	if bytes.Equal(ma, mb) || !bytes.Equal(ma, ma2) || len(ma) != 48 {
		t.Fatal("the MAC is not per purpose and stable")
	}
	other := sealertest.New(t)
	if _, err := other.Open(ctx, a, []byte("s/addr-1"), sealed); err == nil {
		t.Fatal("a value opened under another wrapping key")
	}
}

// The wraps live in session's own store under seal/, beside the core's items, and a second instance with the same wrapping key
// opens what the first sealed (two replicas of one installation).
func TestTheWrapsLiveInSessionsStore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: the key driver wants its state directory private
		t.Fatal(err)
	}
	mem := storetest.New(nil)
	items, stop := mem.Client()
	t.Cleanup(stop)
	open := func() *sealer.Block {
		keys, err := atoomx.SoftwareKeys(dir, sealer.KeyPurposes(), "development")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(keys.Stop)
		b, err := sealer.Open(ctx, sealer.Options{Keys: keys.Keys, Items: items, Installation: "session/docs"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Stop)
		return b
	}
	one := open()
	sealed, err := one.Seal(ctx, core.PurposeSessionRecord, []byte("s/a"), []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range mem.Keys() {
		if !strings.HasPrefix(k, "seal/") {
			t.Fatalf("an item of the block outside seal/: %s", k)
		}
	}
	if mem.Len() == 0 {
		t.Fatal("no wrap in the store")
	}
	if got, err := open().Open(ctx, core.PurposeSessionRecord, []byte("s/a"), sealed); err != nil || string(got) != "v" {
		t.Fatalf("a second instance: %q %v", got, err)
	}
}

// The block needs the wrapping key from the key driver: a driver started without the block's declaration fails the start.
func TestAKeyDriverWithoutTheWrappingPurposeIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: the key driver wants its state directory private
		t.Fatal(err)
	}
	keys, err := atoomx.SoftwareKeys(dir, nil, "development")
	if err == nil {
		t.Cleanup(keys.Stop)
		items, stop := storetest.New(nil).Client()
		t.Cleanup(stop)
		if _, err := sealer.Open(context.Background(), sealer.Options{Keys: keys.Keys, Items: items, Installation: "session/docs"}); err == nil {
			t.Fatal("the block started without its wrapping key")
		}
	}
}

// With the wrapping key on AWS KMS (key/awskms over the in-process double), KMS is asked once for each data key an instance opens
// again, not for each value: a second instance opens a hundred values with one DeriveSharedSecret.
func TestTheWrappingKeyOnAWSKMS(t *testing.T) {
	ctx := context.Background()
	fake := kmstest.New()
	fake.AddAgreementKey("alias/session/docs/wrapping")
	items, stop := storetest.New(nil).Client()
	t.Cleanup(stop)
	open := func() *sealer.Block {
		choices, err := atoomx.ParseKeyChoices([]string{"wrapping=awskms"}, sealer.KeyPurposes())
		if err != nil {
			t.Fatal(err)
		}
		ks, err := atoomx.OpenKeys(atoomx.KeyOptions{Purposes: sealer.KeyPurposes(), Choices: choices, AliasPrefix: "session/docs",
			KMS: func() (awskms.API, error) { return fake, nil }})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ks.Stop)
		b, err := sealer.Open(ctx, sealer.Options{Keys: ks.For(sealer.WrappingPurpose), Items: items, Installation: "session/docs"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Stop)
		return b
	}
	one := open()
	var sealed [][]byte
	for i := range 100 {
		v, err := one.Seal(ctx, core.PurposeSessionRecord, []byte(fmt.Sprintf("s/%d", i)), []byte("v"))
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, v)
	}
	two := open()
	before := fake.Derives.Load()
	for i, v := range sealed {
		if got, err := two.Open(ctx, core.PurposeSessionRecord, []byte(fmt.Sprintf("s/%d", i)), v); err != nil || string(got) != "v" {
			t.Fatalf("open %d: %q %v", i, got, err)
		}
	}
	if n := fake.Derives.Load() - before; n != 1 {
		t.Fatalf("%d KMS calls for 100 opens", n)
	}
	// A KMS key that is not a key-agreement key fails the start.
	other := kmstest.New()
	other.AddKeyP384("alias/session/docs/wrapping")
	choices, _ := atoomx.ParseKeyChoices([]string{"wrapping=awskms"}, sealer.KeyPurposes())
	ks, err := atoomx.OpenKeys(atoomx.KeyOptions{Purposes: sealer.KeyPurposes(), Choices: choices, AliasPrefix: "session/docs",
		KMS: func() (awskms.API, error) { return other, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ks.Stop)
	if _, err := sealer.Open(ctx, sealer.Options{Keys: ks.For(sealer.WrappingPurpose), Items: items, Installation: "session/docs"}); err == nil {
		t.Fatal("a signing key served as the wrapping key")
	}
}

// The seal block's rules allow Sign and PublicKey only under the token purposes they name: the token block's.
func TestTheRulesAllowSigningOnlyUnderTheTokenPurposes(t *testing.T) {
	ctx := context.Background()
	r := sealer.Rules("client-assertion")
	for _, op := range []seal.Op{seal.OpSign, seal.OpPublicKey} {
		if _, err := r.Decide(ctx, seal.Request{Op: op, Purpose: "client-assertion"}); err != nil {
			t.Fatalf("%s under a token purpose: %v", op, err)
		}
		if _, err := r.Decide(ctx, seal.Request{Op: op, Purpose: "identity-header"}); err == nil {
			t.Fatalf("%s under a purpose not named", op)
		}
		if _, err := sealer.Rules().Decide(ctx, seal.Request{Op: op, Purpose: "client-assertion"}); err == nil {
			t.Fatalf("%s with no token purpose", op)
		}
	}
	if _, err := r.Decide(ctx, seal.Request{Op: seal.OpRotate, Purpose: "client-assertion"}); err == nil {
		t.Fatal("a rotation was allowed")
	}
}
