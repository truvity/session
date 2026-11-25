// Package sealertest runs the seal block for tests: the wrapping key on atoom's key/software in a temporary directory, and the
// wraps in a store double of their own (New), so that a test that counts the items or the calls of session's store sees only
// the core's, or in the given store (On), as a deployment keeps them under the prefix seal/. Tokens runs it with the token
// block over it, the signing keys on the drivers a test chose.
package sealertest

import (
	"context"
	"os"
	"testing"

	"github.com/truvity/atoom/blocks/token"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
	"github.com/truvity/atoom/key/route"
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
	b, err := sealer.Open(context.Background(), sealer.Options{Keys: wrapping(t), Items: items, Installation: "session/test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	return b.Sealer
}

// wrapping is a fresh wrapping key on key/software in a temporary directory.
func wrapping(t testing.TB) keyv1alpha1connect.KeyStoreServiceClient {
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
	return keys.Keys
}

// KeyClients gives the client of the key driver that holds a purpose (atoomx.KeySet).
type KeyClients interface {
	For(purpose string) keyv1alpha1connect.KeyStoreServiceClient
}

// Tokens runs the seal block over a fresh wrapping key, with its wraps in a store double of their own, and the token block
// over it, as session serve does: the token purposes' keys on the drivers of keys, behind one key/route client. The error is
// the start's, so that a test can see a key the start refuses.
func Tokens(t testing.TB, keys KeyClients, purposes []token.Purpose) (*sealer.Block, error) {
	t.Helper()
	items, stop := storetest.New(nil).Client()
	t.Cleanup(stop)
	byPurpose := map[string]keyv1alpha1connect.KeyStoreServiceClient{sealer.WrappingPurpose: wrapping(t)}
	for _, p := range purposes {
		byPurpose[p.Name] = keys.For(p.Name)
	}
	routed, err := route.New(byPurpose)
	if err != nil {
		return nil, err
	}
	b, err := sealer.Open(context.Background(), sealer.Options{Keys: routed, Items: items, Installation: "session/test", Tokens: purposes})
	if err != nil {
		return nil, err
	}
	t.Cleanup(b.Stop)
	return b, nil
}
