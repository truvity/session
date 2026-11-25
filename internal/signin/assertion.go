package signin

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/atoom/blocks/token"
	tokenv1 "github.com/truvity/atoom/blocks/token/gen/atoom/token/v1alpha1"
	"github.com/truvity/atoom/blocks/token/gen/atoom/token/v1alpha1/tokenv1alpha1connect"
	"github.com/truvity/atoom/key/purpose"

	"github.com/truvity/session/core"
)

// The key port's purposes session declares to the key driver (atoom 0.3.0: the key port takes any purpose its host declares).
// Each has its own key, so the client assertion and the identity header never share one (decision 0016).
const (
	// PurposeClientAssertion signs the private_key_jwt client assertion (S3).
	PurposeClientAssertion = "client-assertion"
	// PurposeIdentityHeader signs the identity header of the route mode identity-header.
	PurposeIdentityHeader = "identity-header"
)

// clientAssertionType is the JWS typ of the client assertion.
const clientAssertionType = "JWT"

// Purposes are the key purposes session declares for its signing keys, each to the driver that holds it.
func Purposes() []purpose.Declaration {
	sign := []purpose.Operation{purpose.Sign}
	return []purpose.Declaration{
		{Name: PurposeClientAssertion, Algorithm: purpose.ES256, Operations: sign},
		{Name: PurposeIdentityHeader, Algorithm: purpose.ES256, Operations: sign},
	}
}

// TokenPurposes are the same purposes declared to atoom's token block (decision 0022): ES256, one type each, and the kid the key
// port's key_id (decisions 0016 and 0019).
func TokenPurposes() []token.Purpose {
	return []token.Purpose{
		{Name: PurposeClientAssertion, Algorithm: purpose.ES256, Types: []string{clientAssertionType}, Kid: token.KidKeyID},
		{Name: PurposeIdentityHeader, Algorithm: purpose.ES256, Types: []string{core.IdentityType}, Kid: token.KidKeyID},
	}
}

// Signers returns the signer of the client assertion and the signer of the identity header over the token block. The block has
// read both keys at its start (sealer.Open), so a key the deployment has not made has already failed it.
func Signers(tokens tokenv1alpha1connect.TokenServiceClient) (client, identity Signer, err error) {
	if tokens == nil {
		return Signer{}, Signer{}, errors.New("signin: no token block")
	}
	return Signer{Tokens: tokens, Purpose: PurposeClientAssertion},
		Signer{Tokens: tokens, Purpose: PurposeIdentityHeader, Typ: core.IdentityType}, nil
}

// Signer signs JWTs of one purpose through atoom's token block, which signs through the seal block and the key port. The key
// never leaves its driver.
type Signer struct {
	Tokens  tokenv1alpha1connect.TokenServiceClient
	Purpose string
	// Typ is the JWS typ; empty is JWT. The identity header's is core.IdentityType.
	Typ string
}

func (s Signer) typ() string {
	if s.Typ == "" {
		return clientAssertionType
	}
	return s.Typ
}

// JWK is the public key as a JSON Web Key, with the key port's key id as kid.
func (s Signer) JWK(ctx context.Context) (jose.JSONWebKey, error) {
	res, err := s.Tokens.KeySet(ctx, connect.NewRequest(&tokenv1.KeySetRequest{Purposes: []string{s.Purpose}}))
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	keys := res.Msg.GetKeys()
	if len(keys) != 1 {
		return jose.JSONWebKey{}, fmt.Errorf("signin: the key set of one purpose has %d keys", len(keys))
	}
	pub, err := x509.ParsePKIXPublicKey(keys[0].GetSpkiDer())
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	return jose.JSONWebKey{Key: pub, KeyID: keys[0].GetKid(), Algorithm: keys[0].GetAlgorithm(), Use: "sig"}, nil
}

// Sign makes a compact JWS of the claims, of the signer's typ: the header alg, kid and typ, the payload the claims as JSON with
// their names in order.
func (s Signer) Sign(ctx context.Context, claims map[string]any) (string, error) {
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	res, err := s.Tokens.Sign(ctx, connect.NewRequest(&tokenv1.SignRequest{Purpose: s.Purpose, Typ: s.typ(), ClaimsJson: c}))
	if err != nil {
		return "", err
	}
	return res.Msg.GetToken(), nil
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
