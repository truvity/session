package fit

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"connectrpc.com/connect"

	keyv1 "github.com/truvity/atoom/key/gen/atoom/key/v1alpha1"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
)

// AssertionPurpose is the purpose whose key signs the client assertion (private_key_jwt). The key port's purposes are a closed
// list today (key/docs/algorithms.md): none is named for a relying party's client key. The spike borrows token-signing (ES384),
// the nearest signing purpose. ES256, which the first spike used, exists only for the purpose audit-log.
const AssertionPurpose = "token-signing"

// Signer signs JWTs through a key port client.
type Signer struct {
	Keys keyv1alpha1connect.KeyStoreServiceClient
	Kid  string
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// PublicKey reads the public key of the purpose.
func (s *Signer) PublicKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	res, err := s.Keys.PublicKey(ctx, connect.NewRequest(&keyv1.PublicKeyRequest{Purpose: AssertionPurpose}))
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(res.Msg.GetSpkiDer())
	if err != nil {
		return nil, err
	}
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an EC key")
	}
	return k, nil
}

// Assertion makes the compact JWS of a private_key_jwt client assertion. The port returns an ASN.1 DER signature
// and a JWS wants the raw r||s, so this converts.
func (s *Signer) Assertion(ctx context.Context, claims map[string]any) (string, error) {
	h, _ := json.Marshal(map[string]string{"alg": "ES384", "typ": "JWT", "kid": s.Kid})
	c, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(c)
	d := sha512.Sum384([]byte(in))
	res, err := s.Keys.Sign(ctx, connect.NewRequest(&keyv1.SignRequest{Purpose: AssertionPurpose, Digest: d[:], Algorithm: "ES384"}))
	if err != nil {
		return "", err
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(res.Msg.GetSignatureDer(), &sig); err != nil {
		return "", err
	}
	raw := make([]byte, 96)
	sig.R.FillBytes(raw[:48])
	sig.S.FillBytes(raw[48:])
	return in + "." + b64(raw), nil
}

// ClaimsFor is the claim set of a client assertion.
func ClaimsFor(clientID, aud string, now time.Time) map[string]any {
	return map[string]any{"iss": clientID, "sub": clientID, "aud": aud, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": NewJTI()}
}

// NewJTI returns a random token id.
func NewJTI() string {
	b := make([]byte, 16)
	_, _ = randRead(b)
	return b64(b)
}
