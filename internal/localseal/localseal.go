// Package localseal stands in for atoom's seal block until it exists (decision 0006: "The seal block ... Planned in atoom").
// It implements core.Sealer with what the spikes used and nothing more: AES-256-GCM with the address as associated data, and
// HMAC-SHA256. Its one root key is a local file; the keys of each purpose (one to seal, one to MAC) are derived from it with
// HKDF-SHA256, so no two uses share a key. All three are Go standard library calls.
//
// What it does not do, and the seal block will: data keys wrapped through the key port, rotation, the rules hook. A root key
// in a file is readable by whoever can read the file, as a software key of atoom's key/software is.
package localseal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// RootLen is the length of the root key: 256 bits.
const RootLen = 32

// format is the first byte of a sealed value, so that the seal block's envelope can be told apart later.
const format = 1

// Sealer is the stand-in.
type Sealer struct {
	aeads map[string]cipher.AEAD
	macs  map[string][]byte
}

// New derives the keys of the declared purposes from the root key.
func New(root []byte, purposes []string) (*Sealer, error) {
	if len(root) != RootLen {
		return nil, fmt.Errorf("localseal: the root key is %d bytes, not %d", len(root), RootLen)
	}
	s := &Sealer{aeads: map[string]cipher.AEAD{}, macs: map[string][]byte{}}
	for _, p := range purposes {
		k, err := hkdf.Key(sha256.New, root, nil, "truvity/session localseal v1 seal "+p, 32)
		if err != nil {
			return nil, err
		}
		mk, err := hkdf.Key(sha256.New, root, nil, "truvity/session localseal v1 mac "+p, 32)
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		s.aeads[p] = aead
		s.macs[p] = mk
	}
	return s, nil
}

// NewRoot returns a fresh random root key (tests, and `session keygen`).
func NewRoot() []byte {
	b := make([]byte, RootLen)
	if _, err := rand.Read(b); err != nil {
		panic("localseal: no randomness: " + err.Error())
	}
	return b
}

// ReadRoot reads a root key file: 64 hexadecimal characters, optionally followed by a newline. The file must not be readable
// by the group or others.
func ReadRoot(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("localseal: %s is readable by the group or others (mode %v)", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path) // #nosec G304 -- the path is the operator's start-up setting
	if err != nil {
		return nil, err
	}
	root, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(root) != RootLen {
		return nil, errors.New("localseal: the root key file must hold 64 hexadecimal characters")
	}
	return root, nil
}

var errPurpose = errors.New("localseal: a purpose that was not declared")

// Seal encrypts plaintext under the purpose's key, bound to aad.
func (s *Sealer) Seal(_ context.Context, purpose string, aad, plaintext []byte) ([]byte, error) {
	aead, ok := s.aeads[purpose]
	if !ok {
		return nil, errPurpose
	}
	out := make([]byte, 1+aead.NonceSize(), 1+aead.NonceSize()+len(plaintext)+aead.Overhead())
	out[0] = format
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[1:], plaintext, aad), nil //nolint:gosec // G407: the nonce is the random bytes read just above
}

// Open decrypts a value sealed under the purpose and the same aad.
func (s *Sealer) Open(_ context.Context, purpose string, aad, sealed []byte) ([]byte, error) {
	aead, ok := s.aeads[purpose]
	if !ok {
		return nil, errPurpose
	}
	n := aead.NonceSize()
	if len(sealed) < 1+n+aead.Overhead() || sealed[0] != format {
		return nil, errors.New("localseal: not a sealed value")
	}
	return aead.Open(nil, sealed[1:1+n], sealed[1+n:], aad)
}

// Mac is HMAC-SHA256 under the purpose's key.
func (s *Sealer) Mac(_ context.Context, purpose string, data []byte) ([]byte, error) {
	k, ok := s.macs[purpose]
	if !ok {
		return nil, errPurpose
	}
	m := hmac.New(sha256.New, k)
	m.Write(data)
	return m.Sum(nil), nil
}
