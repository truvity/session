package signin

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"

	keyv1 "github.com/truvity/atoom/key/gen/atoom/key/v1alpha1"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
	"github.com/truvity/atoom/key/purpose"
	"github.com/truvity/atoom/key/signature"

	"github.com/truvity/session/core"
)

// PurposeClientAssertion is the key port's purpose whose key signs the private_key_jwt client assertion (S3). session declares
// it to the key driver (atoom 0.3.0: the key port takes any purpose its host declares).
const PurposeClientAssertion = "client-assertion"

// Purposes are the key purposes session declares.
func Purposes() []purpose.Declaration {
	return []purpose.Declaration{{Name: PurposeClientAssertion, Algorithm: purpose.ES256, Operations: []purpose.Operation{purpose.Sign}}}
}

// Signer signs JWTs with a key of the key port. The key never leaves the driver: the signer hashes, the port signs the digest,
// and the DER signature is turned into the raw r||s of a JWS.
type Signer struct {
	Keys    keyv1alpha1connect.KeyStoreServiceClient
	Purpose string
}

// Ensure makes the key if the driver has none yet.
func (s Signer) Ensure(ctx context.Context) error {
	_, err := s.Keys.Ensure(ctx, connect.NewRequest(&keyv1.EnsureRequest{Purpose: s.Purpose, Algorithm: purpose.ES256}))
	return err
}

// JWK is the public key as a JSON Web Key, with the key port's key id as kid.
func (s Signer) JWK(ctx context.Context) (jose.JSONWebKey, error) {
	res, err := s.Keys.PublicKey(ctx, connect.NewRequest(&keyv1.PublicKeyRequest{Purpose: s.Purpose}))
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	pub, err := x509.ParsePKIXPublicKey(res.Msg.GetSpkiDer())
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	return jose.JSONWebKey{Key: pub, KeyID: res.Msg.GetKeyId(), Algorithm: purpose.ES256, Use: "sig"}, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Sign makes a compact JWS of the claims, typ JWT.
func (s Signer) Sign(ctx context.Context, claims map[string]any) (string, error) {
	jwk, err := s.JWK(ctx)
	if err != nil {
		return "", err
	}
	h, err := json.Marshal(map[string]string{"alg": purpose.ES256, "typ": "JWT", "kid": jwk.KeyID})
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := b64(h) + "." + b64(c)
	d := sha256.Sum256([]byte(in))
	res, err := s.Keys.Sign(ctx, connect.NewRequest(&keyv1.SignRequest{Purpose: s.Purpose, Digest: d[:], Algorithm: purpose.ES256}))
	if err != nil {
		return "", err
	}
	if res.Msg.GetKeyId() != jwk.KeyID {
		return "", errors.New("signin: the key changed between the key id and the signature")
	}
	raw, err := signature.DERToRaw(purpose.ES256, res.Msg.GetSignatureDer())
	if err != nil {
		return "", err
	}
	return in + "." + b64(raw), nil
}

// ClientAssertion is a private_key_jwt assertion (RFC 7523): issuer and subject the client, audience the issuer's identifier
// (FAPI 2.0; Keycloak accepts it, the reference stand's finding), a new jti for every request, so an assertion is never presented
// twice (the stand's finding at logout), and a life of 60 seconds.
func (s Signer) ClientAssertion(ctx context.Context, clientID, audience string, now time.Time) (string, error) {
	return s.Sign(ctx, map[string]any{
		"iss": clientID, "sub": clientID, "aud": audience, "jti": core.NewID(),
		"iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix(),
	})
}
