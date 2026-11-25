// Package sealer runs atoom's seal block (blocks/seal) for session (decision 0006): data keys per purpose and installation,
// wrapped through the key port by the wrapping key (ECDH-P384) and kept in the store port, values sealed and opened under them,
// and keyed hashes. The block is mounted in process and called through its generated client, as every port is; Sealer is
// core.Sealer over that client.
//
// Over the same seal block it runs atoom's token block (blocks/token) when the host names token purposes (Options.Tokens): the
// compact JWS of session's client assertion and identity header, signed by the seal block's Sign, and the key set of their keys
// (decision 0022).
//
// session declares its purposes to the block (Purposes) and hands it its rules (Rules): session's own code is the block's one
// caller, and it may seal, open and hash under its own purposes in the installation's own scope, sign and read the public key
// under its token purposes, and nothing else.
package sealer

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"connectrpc.com/connect"

	"github.com/truvity/atoom/blocks/seal"
	sealv1 "github.com/truvity/atoom/blocks/seal/gen/atoom/seal/v1alpha1"
	"github.com/truvity/atoom/blocks/seal/gen/atoom/seal/v1alpha1/sealv1alpha1connect"
	"github.com/truvity/atoom/blocks/token"
	"github.com/truvity/atoom/blocks/token/gen/atoom/token/v1alpha1/tokenv1alpha1connect"
	"github.com/truvity/atoom/common/call"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
	"github.com/truvity/atoom/key/purpose"
	"github.com/truvity/atoom/store/gen/atoom/store/v1alpha1/storev1alpha1connect"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
)

// WrappingPurpose is the key port's purpose of the wrapping key: atoom's default name, ECDH-P384.
const WrappingPurpose = seal.DefaultWrappingPurpose

// Purposes is session's declaration to the block: its sealing and keyed-hash purposes, then a signing purpose for each token
// purpose (token.SealPurposes). A seal purpose's code is in every envelope it seals, so a code is never given to another purpose.
func Purposes(tokens ...token.Purpose) ([]seal.Purpose, error) {
	out := []seal.Purpose{
		{Name: core.PurposeSessionRecord, Use: seal.UseSeal, Code: 1},
		{Name: core.PurposeSignInRecord, Use: seal.UseSeal, Code: 2},
		{Name: core.PurposeExchanged, Use: seal.UseSeal, Code: 3},
		{Name: core.PurposeSessionKey, Use: seal.UseMac},
		{Name: core.PurposeLookupKey, Use: seal.UseMac},
	}
	if len(tokens) == 0 {
		return out, nil
	}
	signing, err := token.SealPurposes(tokens)
	if err != nil {
		return nil, err
	}
	return append(out, signing...), nil
}

// KeyPurposes is the block's declaration to the key driver that holds the wrapping key. The token purposes' keys are declared to
// their own drivers by the host (internal/signin.Purposes).
func KeyPurposes() []purpose.Declaration {
	ps, _ := Purposes() // no token purpose: no error
	return seal.KeyPurposes(WrappingPurpose, ps)
}

// Rules are session's rules for the block: Seal, Open and Mac in the installation's own scope, making a missing data key on
// first need; Sign and PublicKey under the signing purposes named, which only the token block calls. Rotate, Erase, Rewrap and
// MarkCompromised are not session's, and are refused on its client.
func Rules(signing ...string) seal.Rules {
	return seal.RulesFunc(func(_ context.Context, r seal.Request) (seal.Decision, error) {
		if r.Scope != "" {
			return seal.Decision{}, errors.New("sealer: session uses the installation's own scope only")
		}
		switch r.Op {
		case seal.OpSeal, seal.OpMac:
			return seal.Decision{MayCreate: true}, nil
		case seal.OpOpen:
			return seal.Decision{}, nil
		case seal.OpSign, seal.OpPublicKey:
			if slices.Contains(signing, r.Purpose) {
				return seal.Decision{}, nil
			}
		}
		return seal.Decision{}, fmt.Errorf("sealer: %s is not session's", r.Op)
	})
}

// Options are what Open needs.
type Options struct {
	// Keys is the client of the key drivers that hold the wrapping key, started with KeyPurposes among its purposes, and the keys
	// of the token purposes: one client, a key/route in front of the drivers when the purposes are on more than one
	// (atoomx.KeySet.Route).
	Keys keyv1alpha1connect.KeyStoreServiceClient
	// Items is the client of the store where the wraps are kept: session's own store, under the prefix seal/.
	Items storev1alpha1connect.ItemServiceClient
	// Installation names the installation in every wrap's key derivation: session/<site>.
	Installation string
	// Tokens are the token block's purposes (internal/signin.TokenPurposes). None runs no token block.
	Tokens []token.Purpose
}

// Block is the mounted seal block and the core.Sealer over its client, and, with token purposes, the client of the token block
// mounted over it.
type Block struct {
	*Sealer
	// Tokens is the client of the token block; nil without token purposes.
	Tokens tokenv1alpha1connect.TokenServiceClient
	block  *seal.Block
	stops  []func()
}

// Open makes the seal block (it ensures the wrapping key and the key of every signing purpose at once, so a missing or wrong key
// fails the start) and mounts it; then, with token purposes, makes the token block over its client (it reads the public key of
// every token purpose at once) and mounts that.
func Open(ctx context.Context, o Options) (*Block, error) {
	purposes, err := Purposes(o.Tokens...)
	if err != nil {
		return nil, err
	}
	signing := make([]string, 0, len(o.Tokens))
	for _, p := range o.Tokens {
		signing = append(signing, p.Name)
	}
	b, err := seal.New(ctx, seal.Options{Keys: o.Keys, Items: o.Items, Purposes: purposes, Rules: Rules(signing...), Installation: o.Installation})
	if err != nil {
		return nil, err
	}
	path, h := b.Handler()
	hc, stop := atoomx.Mount(path, h)
	out := &Block{Sealer: &Sealer{C: sealv1alpha1connect.NewSealServiceClient(hc, "http://seal", call.ClientOptions()...)}, block: b,
		stops: []func(){func() { stop(); b.Close() }}}
	if len(o.Tokens) == 0 {
		return out, nil
	}
	// The token block's rules allow every call: its one caller is session's own code in this process, and the block refuses a
	// type that is not its purpose's by itself. The seal block's rules above are what bound its signatures to the token purposes.
	tb, err := token.New(ctx, token.Options{Seal: out.C, Purposes: o.Tokens, Rules: token.AllowAll()})
	if err != nil {
		out.Stop()
		return nil, err
	}
	tpath, th := tb.Handler()
	thc, tstop := atoomx.Mount(tpath, th)
	out.stops = append(out.stops, tstop)
	out.Tokens = tokenv1alpha1connect.NewTokenServiceClient(thc, "http://token", call.ClientOptions()...)
	return out, nil
}

// Stop unmounts the blocks, the token block first, and wipes the seal block's cache.
func (b *Block) Stop() {
	for _, s := range slices.Backward(b.stops) {
		s()
	}
}

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
