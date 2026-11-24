// Package policytest makes signed policy bundles for tests: a publisher key held in memory, the payload of atoom record 0019 and
// the signed document (a JWS in the general JSON serialisation, ES384), written where the source port's file driver serves it.
// It is for tests only: the key never leaves the process.
package policytest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	atpolicy "github.com/truvity/atoom/policy"

	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/policy"
)

// Publisher is a publisher key in memory.
type Publisher struct {
	KID string
	key *ecdsa.PrivateKey
}

// NewPublisher makes a fresh P-384 key named kid.
func NewPublisher(t testing.TB, kid string) *Publisher {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Publisher{KID: kid, key: k}
}

// Pinned is the key as a host pins it.
func (p *Publisher) Pinned() atpolicy.Publisher {
	return atpolicy.Publisher{KID: p.KID, Key: &p.key.PublicKey}
}

// PEM is the public key as the site file holds it (policy.verify_key.public_key).
func (p *Publisher) PEM(t testing.TB) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

var b64 = base64.RawURLEncoding

// Sign makes the signed document of the payload at seq, of the kind PolicyBundle.
func (p *Publisher) Sign(t testing.TB, seq uint64, payload []byte) []byte {
	t.Helper()
	h, err := json.Marshal(map[string]any{"alg": "ES384", "kid": p.KID, "seq": seq, "kind": atpolicy.DefaultKind})
	if err != nil {
		t.Fatal(err)
	}
	protected, p64 := b64.EncodeToString(h), b64.EncodeToString(payload)
	d := sha512.Sum384([]byte(protected + "." + p64))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	doc, err := json.Marshal(map[string]any{"payload": p64, "signatures": []map[string]string{{"protected": protected, "signature": b64.EncodeToString(sig)}}})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// Payload is a bundle of session's schema (policy.Schema) and the policies, by id.
func Payload(t testing.TB, policies map[string]string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"schema": policy.Schema, "policies": policies})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Dir is a config directory with the signed bundle as policy-bundle.jws, served by the file driver.
type Dir struct {
	Path string
	src  *atoomx.Source
}

// NewDir writes doc as policy-bundle.jws in a new directory and mounts the file driver over it.
func NewDir(t testing.TB, doc []byte) *Dir {
	t.Helper()
	d := &Dir{Path: t.TempDir()}
	d.Write(t, doc)
	src, err := atoomx.FileSource(d.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.Stop)
	d.src = src
	return d
}

// Write replaces the bundle.
func (d *Dir) Write(t testing.TB, doc []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(d.Path, atpolicy.DefaultName+".jws"), doc, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Start starts the engine over the directory, pinned to pub.
func (d *Dir) Start(ctx context.Context, pub *Publisher) (*policy.Engine, error) {
	return policy.Start(ctx, policy.Options{Source: d.src.Source, Name: atpolicy.DefaultName, Publisher: pub.Pinned()})
}

// Engine is an engine over a bundle of session's schema and the policies, signed at seq 1.
func Engine(t testing.TB, policies map[string]string) *policy.Engine {
	t.Helper()
	pub := NewPublisher(t, "test-publisher")
	e, err := NewDir(t, pub.Sign(t, 1, Payload(t, policies))).Start(context.Background(), pub)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
