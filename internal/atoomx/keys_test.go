package atoomx_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/atoom/key/awskms"
	keyv1 "github.com/truvity/atoom/key/gen/atoom/key/v1alpha1"
	"github.com/truvity/atoom/key/keyid"

	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/kmstest"
	"github.com/truvity/session/internal/signin"
)

func TestKeyChoicesNameADriverForEachPurpose(t *testing.T) {
	got, err := atoomx.ParseKeyChoices([]string{
		"client-assertion=awskms:arn:aws:kms:eu-west-1:111122223333:key/00000001-0000-4000-8000-000000000000",
		"identity-header=awskms",
	}, signin.Purposes())
	if err != nil {
		t.Fatal(err)
	}
	if c := got[signin.PurposeClientAssertion]; c.Driver != atoomx.DriverAWSKMS || c.Key != "arn:aws:kms:eu-west-1:111122223333:key/00000001-0000-4000-8000-000000000000" {
		t.Fatalf("client-assertion %+v", c)
	}
	if c := got[signin.PurposeIdentityHeader]; c.Driver != atoomx.DriverAWSKMS || c.Key != "" {
		t.Fatalf("identity-header %+v", c)
	}
	// A purpose no value names is on the software driver.
	got, err = atoomx.ParseKeyChoices([]string{"identity-header=awskms:alias/site/identity"}, signin.Purposes())
	if err != nil {
		t.Fatal(err)
	}
	if got[signin.PurposeClientAssertion].Driver != atoomx.DriverSoftware || got[signin.PurposeIdentityHeader].Key != "alias/site/identity" {
		t.Fatalf("choices %+v", got)
	}
	for _, bad := range [][]string{
		{"client-assertion"},
		{"=awskms"},
		{"client-assertion="},
		{"session-record=awskms"},
		{"client-assertion=vault"},
		{"client-assertion=software:x"},
		{"client-assertion=awskms:"},
		{"client-assertion=awskms", "client-assertion=software"},
	} {
		if _, err := atoomx.ParseKeyChoices(bad, signin.Purposes()); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

func keyDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil { //nolint:gosec // G302: a directory needs its x bit; the key driver wants it private
		t.Fatal(err)
	}
	return d
}

func open(t *testing.T, fake *kmstest.KMS, values []string, stateDir string) (*atoomx.KeySet, error) {
	t.Helper()
	choices, err := atoomx.ParseKeyChoices(values, signin.Purposes())
	if err != nil {
		t.Fatal(err)
	}
	ks, err := atoomx.OpenKeys(atoomx.KeyOptions{Purposes: signin.Purposes(), Choices: choices, StateDir: stateDir, Environment: "development",
		AliasPrefix: "session/docs", KMS: func() (awskms.API, error) {
			if fake == nil {
				t.Fatal("the KMS client was asked for, with no purpose on AWS KMS")
			}
			return fake, nil
		}})
	if err == nil {
		t.Cleanup(ks.Stop)
	}
	return ks, err
}

// verify checks a compact JWS against a JWK, as the issuer and the apps do.
func verify(t *testing.T, jws string, jwk jose.JSONWebKey) {
	t.Helper()
	sig, err := jose.ParseSignedCompact(jws, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if sig.Signatures[0].Protected.KeyID != jwk.KeyID {
		t.Fatalf("kid %q, the JWKS has %q", sig.Signatures[0].Protected.KeyID, jwk.KeyID)
	}
	if _, err := sig.Verify(jwk); err != nil {
		t.Fatal(err)
	}
}

// Both purposes on AWS KMS: the client key found by the alias of its purpose under the prefix, the identity key named by its
// ARN. The kid is the key port's key_id, the key ARN and the fingerprint of its public key; the JWS verifies with the JWK; the
// digest is signed in KMS (one Sign call each), and the key never leaves it.
func TestBothPurposesOnAWSKMS(t *testing.T) {
	fake := kmstest.New()
	clientARN := fake.AddKey("alias/session/docs/client-assertion")
	identityARN := fake.AddKey("")
	ks, err := open(t, fake, []string{"client-assertion=awskms", "identity-header=awskms:" + identityARN}, "")
	if err != nil {
		t.Fatal(err)
	}
	if ks.Driver(signin.PurposeClientAssertion) != atoomx.DriverAWSKMS || ks.Driver(signin.PurposeIdentityHeader) != atoomx.DriverAWSKMS {
		t.Fatal("not on AWS KMS")
	}
	ctx := context.Background()
	client, identity, err := signin.Signers(ctx, ks)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		s   signin.Signer
		arn string
	}{{client, clientARN}, {identity, identityARN}} {
		jwk, err := c.s.JWK(ctx)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(jwk.Key)
		if err != nil {
			t.Fatal(err)
		}
		if jwk.KeyID != keyid.KMS(c.arn, spki) || !strings.HasPrefix(jwk.KeyID, c.arn+"#") {
			t.Fatalf("kid %q for %s", jwk.KeyID, c.arn)
		}
		if _, ok := jwk.Key.(*ecdsa.PublicKey); !ok || jwk.Algorithm != "ES256" {
			t.Fatalf("jwk %+v", jwk)
		}
		before := fake.Signs.Load()
		jws, err := c.s.Sign(ctx, map[string]any{"sub": "alice"})
		if err != nil {
			t.Fatal(err)
		}
		verify(t, jws, jwk)
		if fake.Signs.Load() != before+1 {
			t.Fatalf("%d KMS Sign calls for one JWS", fake.Signs.Load()-before)
		}
	}
	// The digest goes to KMS, never the message, and the port refuses a digest of another length (atoom record 0016).
	_, err = ks.For(signin.PurposeIdentityHeader).Sign(ctx, connect.NewRequest(&keyv1.SignRequest{
		Purpose: signin.PurposeIdentityHeader, Algorithm: "ES256", Digest: []byte("not a digest")}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a short digest: %v", err)
	}
	d := sha256.Sum256([]byte("x"))
	if _, err := ks.For(signin.PurposeIdentityHeader).Sign(ctx, connect.NewRequest(&keyv1.SignRequest{
		Purpose: signin.PurposeIdentityHeader, Algorithm: "ES256", Digest: d[:]})); err != nil {
		t.Fatal(err)
	}
	// The KMS driver serves only the purposes it holds.
	if _, err := ks.For(signin.PurposeIdentityHeader).PublicKey(ctx, connect.NewRequest(&keyv1.PublicKeyRequest{Purpose: "session-record"})); err == nil {
		t.Fatal("an undeclared purpose was served")
	}
}

// One purpose on each driver: the client key in a key file, the identity key on AWS KMS. Each driver is declared only its own
// purpose, so neither serves the other's.
func TestAPurposeOnEachDriver(t *testing.T) {
	fake := kmstest.New()
	fake.AddKey("alias/session/docs/identity-header")
	ks, err := open(t, fake, []string{"identity-header=awskms"}, keyDir(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	client, identity, err := signin.Signers(ctx, ks)
	if err != nil {
		t.Fatal(err)
	}
	cj, err := client.JWK(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ij, err := identity.JWK(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cj.KeyID, "#") || !strings.HasPrefix(ij.KeyID, "arn:aws:kms:") {
		t.Fatalf("kids %q (software) and %q (KMS)", cj.KeyID, ij.KeyID)
	}
	before := fake.Signs.Load()
	jws, err := client.Sign(ctx, map[string]any{"sub": "session-docs"})
	if err != nil {
		t.Fatal(err)
	}
	verify(t, jws, cj)
	if fake.Signs.Load() != before {
		t.Fatal("the software purpose signed on KMS")
	}
	for p, c := range map[string]string{signin.PurposeClientAssertion: signin.PurposeIdentityHeader, signin.PurposeIdentityHeader: signin.PurposeClientAssertion} {
		if _, err := ks.For(p).PublicKey(ctx, connect.NewRequest(&keyv1.PublicKeyRequest{Purpose: c})); err == nil {
			t.Errorf("the driver of %s served %s", p, c)
		}
	}
}

// The start fails when a KMS key is missing, of another spec or disabled: the driver never makes or replaces a key. A purpose
// on the software driver needs --key-dir; an install with every purpose on software never asks for a KMS client.
func TestTheStartRefusesAKMSKeyItCannotUse(t *testing.T) {
	ctx := context.Background()
	start := func(fake *kmstest.KMS, values ...string) error {
		ks, err := open(t, fake, values, keyDir(t))
		if err != nil {
			return err
		}
		_, _, err = signin.Signers(ctx, ks)
		return err
	}
	fake := kmstest.New()
	if err := start(fake, "client-assertion=awskms"); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("no key under the alias: %v", err)
	}
	if err := start(fake, "client-assertion=awskms:alias/nowhere"); err == nil {
		t.Fatal("started without the named key")
	}
	fake.AddKeyP384("alias/session/docs/client-assertion")
	if err := start(fake, "client-assertion=awskms"); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a P-384 key for an ES256 purpose: %v", err)
	}
	arn := fake.AddKey("")
	fake.Disable(arn)
	if err := start(fake, "identity-header=awskms:"+arn); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a disabled key: %v", err)
	}
	fake.Down.Store(true)
	if err := start(fake, "identity-header=awskms:"+fake.AddKey("")); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("KMS down: %v", err)
	}
	if _, err := open(t, kmstest.New(), []string{"identity-header=awskms"}, ""); err == nil || !strings.Contains(err.Error(), "--key-dir") {
		t.Fatalf("software without --key-dir: %v", err)
	}
	if err := start(nil); err != nil {
		t.Fatalf("all on software: %v", err)
	}
}

// A JWS of the KMS signer is ES256 in the raw r||s form of RFC 7518, not KMS's DER.
func TestTheKMSSignatureIsRawRS(t *testing.T) {
	fake := kmstest.New()
	fake.AddKey("alias/session/docs/identity-header")
	ks, err := open(t, fake, []string{"identity-header=awskms"}, keyDir(t))
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := signin.Signers(context.Background(), ks)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := identity.Sign(context.Background(), map[string]any{"sub": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(jws[strings.LastIndex(jws, ".")+1:])
	if err != nil || len(raw) != 64 {
		t.Fatalf("signature of %d octets: %v", len(raw), err)
	}
}
