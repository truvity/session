// Package sealertest runs the seal block for tests: the wrapping key on atoom's key/software in a temporary directory, and the
// wraps in a store double of their own, so that a test that counts the items or the calls of session's store sees only the
// core's. In a deployment the wraps live in session's store, under the prefix seal/ (sealer.Open).
package sealertest

import (
	"context"
	"os"
	"testing"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/sealer"
	"github.com/truvity/session/internal/storetest"
)

// New returns a sealer over a fresh wrapping key.
func New(t testing.TB) core.Sealer {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: the key driver wants its state directory private
		t.Fatal(err)
	}
	keys, err := atoomx.SoftwareKeys(dir, sealer.KeyPurposes(), "development")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Stop)
	items, stop := storetest.New(nil).Client()
	t.Cleanup(stop)
	b, err := sealer.Open(context.Background(), sealer.Options{Keys: keys.Keys, Items: items, Installation: "session/test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	return b.Sealer
}
