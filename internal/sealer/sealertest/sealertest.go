// Package sealertest runs the seal block for tests: the wrapping key on atoom's key/software in a temporary directory, and the
// wraps in a store double of their own (New), so that a test that counts the items or the calls of session's store sees only
// the core's, or in the given store (On), as a deployment keeps them under the prefix seal/.
package sealertest

import (
	"context"
	"os"
	"testing"

	"github.com/truvity/atoom/store/gen/atoom/store/v1alpha1/storev1alpha1connect"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/sealer"
	"github.com/truvity/session/internal/storetest"
)

// New returns a sealer over a fresh wrapping key, with its wraps in a store double of their own.
func New(t testing.TB) core.Sealer {
	t.Helper()
	items, stop := storetest.New(nil).Client()
	t.Cleanup(stop)
	return On(t, items)
}

// On returns a sealer over a fresh wrapping key, with its wraps in the given store, as a deployment keeps them.
func On(t testing.TB, items storev1alpha1connect.ItemServiceClient) core.Sealer {
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
	b, err := sealer.Open(context.Background(), sealer.Options{Keys: keys.Keys, Items: items, Installation: "session/test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	return b.Sealer
}
