// Package sealer runs atoom's seal block (blocks/seal) for session (decision 0006): data keys per purpose and installation,
// wrapped through the key port by the wrapping key (ECDH-P384) and kept in the store port, values sealed and opened under them,
// and keyed hashes. The block is mounted in process and called through its generated client, as every port is; Sealer is
// core.Sealer over that client.
//
// session declares its purposes to the block (Purposes) and hands it its rules (Rules): the core is the block's one caller, and
// it may seal, open and hash under its own purposes in the installation's own scope, and nothing else.
package sealer

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"connectrpc.com/connect"

	"github.com/truvity/atoom/blocks/seal"
	sealv1 "github.com/truvity/atoom/blocks/seal/gen/atoom/seal/v1alpha1"
	"github.com/truvity/atoom/blocks/seal/gen/atoom/seal/v1alpha1/sealv1alpha1connect"
	"github.com/truvity/atoom/common/call"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
	"github.com/truvity/atoom/key/purpose"
	"github.com/truvity/atoom/store/gen/atoom/store/v1alpha1/storev1alpha1connect"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
)

// WrappingPurpose is the key port's purpose of the wrapping key: atoom's default name, ECDH-P384.
const WrappingPurpose = seal.DefaultWrappingPurpose

// Purposes is session's declaration to the block. A seal purpose's code is in every envelope it seals, so a code is never given
// to another purpose.
func Purposes() []seal.Purpose {
	return []seal.Purpose{
		{Name: core.PurposeSessionRecord, Use: seal.UseSeal, Code: 1},
		{Name: core.PurposeSignInRecord, Use: seal.UseSeal, Code: 2},
		{Name: core.PurposeExchanged, Use: seal.UseSeal, Code: 3},
		{Name: core.PurposeSessionKey, Use: seal.UseMac},
		{Name: core.PurposeLookupKey, Use: seal.UseMac},
	}
}

// KeyPurposes is the block's declaration to the key driver that holds the wrapping key.
func KeyPurposes() []purpose.Declaration { return seal.KeyPurposes(WrappingPurpose, Purposes()) }

// Rules are session's rules for the block: Seal, Open and Mac in the installation's own scope, making a missing data key on
// first need. Rotate, Erase, Rewrap and MarkCompromised are not the core's, and are refused on its client.
func Rules() seal.Rules {
	return seal.RulesFunc(func(_ context.Context, r seal.Request) (seal.Decision, error) {
		if r.Scope != "" {
			return seal.Decision{}, errors.New("sealer: session uses the installation's own scope only")
		}
		switch r.Op {
		case seal.OpSeal, seal.OpMac:
			return seal.Decision{MayCreate: true}, nil
		case seal.OpOpen:
			return seal.Decision{}, nil
		}
		return seal.Decision{}, fmt.Errorf("sealer: %s is not session's", r.Op)
	})
}

// Options are what Open needs.
type Options struct {
	// Keys is the client of the key driver that holds the wrapping key, started with KeyPurposes among its purposes.
	Keys keyv1alpha1connect.KeyStoreServiceClient
	// Items is the client of the store where the wraps are kept: session's own store, under the prefix seal/.
	Items storev1alpha1connect.ItemServiceClient
	// Installation names the installation in every wrap's key derivation: session/<site>.
	Installation string
}

// Block is the mounted block and the core.Sealer over its client.
type Block struct {
	*Sealer
	block *seal.Block
	stop  func()
}

// Open makes the block (it ensures the wrapping key at once, so a missing or wrong key fails the start) and mounts it.
func Open(ctx context.Context, o Options) (*Block, error) {
	b, err := seal.New(ctx, seal.Options{Keys: o.Keys, Items: o.Items, Purposes: Purposes(), Rules: Rules(), Installation: o.Installation})
	if err != nil {
		return nil, err
	}
	path, h := b.Handler()
	hc, stop := atoomx.Mount(path, h)
	return &Block{Sealer: &Sealer{C: sealv1alpha1connect.NewSealServiceClient(hc, "http://seal", call.ClientOptions()...)}, block: b,
		stop: func() { stop(); b.Close() }}, nil
}

// Stop unmounts the block and wipes its cache.
func (b *Block) Stop() { b.stop() }

// Sealer is core.Sealer over a client of the seal block. The address of a value is one part: the store key it is kept under.
// A keyed hash is labelled with its purpose.
type Sealer struct {
	C sealv1alpha1connect.SealServiceClient
}

var errAddress = errors.New("sealer: an address that is not UTF-8")

func address(aad []byte) ([]string, error) {
	if !utf8.Valid(aad) {
		return nil, errAddress
	}
	return []string{string(aad)}, nil
}

// Seal seals plaintext under the purpose, bound to aad.
func (s *Sealer) Seal(ctx context.Context, p string, aad, plaintext []byte) ([]byte, error) {
	a, err := address(aad)
	if err != nil {
		return nil, err
	}
	res, err := s.C.Seal(ctx, connect.NewRequest(&sealv1.SealRequest{Purpose: p, Address: a, Plaintext: plaintext}))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetEnvelope(), nil
}

// Open opens a value sealed under the purpose and the same aad.
func (s *Sealer) Open(ctx context.Context, p string, aad, sealed []byte) ([]byte, error) {
	a, err := address(aad)
	if err != nil {
		return nil, err
	}
	res, err := s.C.Open(ctx, connect.NewRequest(&sealv1.OpenRequest{Items: []*sealv1.OpenItem{{Purpose: p, Address: a, Envelope: sealed}}}))
	if err != nil {
		return nil, err
	}
	if pts := res.Msg.GetPlaintexts(); len(pts) == 1 {
		return pts[0], nil
	}
	return nil, errors.New("sealer: the block answered an open of one item with another count")
}

// Mac is the keyed hash of data under the purpose: HMAC-SHA384, 48 bytes.
func (s *Sealer) Mac(ctx context.Context, p string, data []byte) ([]byte, error) {
	res, err := s.C.Mac(ctx, connect.NewRequest(&sealv1.MacRequest{Purpose: p, Label: p, Input: data}))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetMac(), nil
}

var _ core.Sealer = (*Sealer)(nil)
