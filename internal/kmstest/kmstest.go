// Package kmstest is a test double of AWS KMS for atoom's key/awskms driver: the part of the KMS API the driver calls
// (awskms.API), in this process, with real P-256 keys behind it. atoom's own fake KMS is internal to its driver module, so session
// keeps this small one. No AWS account and no network are used: session's tests never call AWS (the real-AWS check is step 5 of
// the plan).
//
// It holds keys that the test makes (the deployment's keys, under an alias or by ARN), answers DescribeKey, GetPublicKey and Sign
// as KMS does for an ECC_NIST_P256 SIGN_VERIFY key, counts the Sign calls, and refuses CreateKey: session never makes its keys.
package kmstest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/truvity/atoom/key/awskms"
)

// arnPrefix is the ARN prefix of the double's keys: the account of the AWS documentation's examples, never a real one.
const arnPrefix = "arn:aws:kms:eu-west-1:111122223333:key/"

// KMS is the double. Its zero value is not usable; call New.
type KMS struct {
	mu      sync.Mutex
	keys    map[string]*Key   // by ARN
	aliases map[string]string // alias name to ARN
	n       int

	// Signs counts the Sign calls that reached the double.
	Signs atomic.Int64
	// Down makes every call fail as an unreachable KMS would (a throttling answer, which the driver maps to unavailable).
	Down atomic.Bool
}

// Key is one KMS key of the double.
type Key struct {
	ARN     string
	Spec    types.KeySpec
	State   types.KeyState
	private *ecdsa.PrivateKey
}

var _ awskms.API = (*KMS)(nil)

// New returns an empty double.
func New() *KMS { return &KMS{keys: map[string]*Key{}, aliases: map[string]string{}} }

// AddKey makes an enabled ECC_NIST_P256 signing key, as the deployment would, and names it by alias when alias is not empty
// ("alias/..."). It returns the key's ARN.
func (k *KMS) AddKey(alias string) string {
	return k.add(alias, types.KeySpecEccNistP256, elliptic.P256())
}

// AddKeyP384 makes an ECC_NIST_P384 signing key: a key of another spec than session's purposes, which the driver refuses.
func (k *KMS) AddKeyP384(alias string) string {
	return k.add(alias, types.KeySpecEccNistP384, elliptic.P384())
}

func (k *KMS) add(alias string, spec types.KeySpec, curve elliptic.Curve) string {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.n++
	arn := fmt.Sprintf("%s%08d-0000-4000-8000-000000000000", arnPrefix, k.n)
	k.keys[arn] = &Key{ARN: arn, Spec: spec, State: types.KeyStateEnabled, private: priv}
	if alias != "" {
		k.aliases[alias] = arn
	}
	return arn
}

// Disable puts a key in the state Disabled.
func (k *KMS) Disable(arn string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[arn].State = types.KeyStateDisabled
}

func (k *KMS) find(ref *string) (*Key, error) {
	if k.Down.Load() {
		return nil, &types.KMSInternalException{Message: new("the double is down")}
	}
	if ref == nil {
		return nil, &types.NotFoundException{Message: new("no key id")}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	id := *ref
	if strings.HasPrefix(id, "alias/") {
		id = k.aliases[id]
	} else if !strings.HasPrefix(id, "arn:") {
		id = arnPrefix + id
	}
	key, ok := k.keys[id]
	if !ok {
		return nil, &types.NotFoundException{Message: new("no such key")}
	}
	return key, nil
}

// DescribeKey answers the metadata of a key found by alias, ARN or key ID.
func (k *KMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	key, err := k.find(in.KeyId)
	if err != nil {
		return nil, err
	}
	created := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	return &kms.DescribeKeyOutput{KeyMetadata: &types.KeyMetadata{
		Arn: new(key.ARN), KeyId: new(strings.TrimPrefix(key.ARN, arnPrefix)), KeySpec: key.Spec, KeyUsage: types.KeyUsageTypeSignVerify,
		KeyState: key.State, Origin: types.OriginTypeAwsKms, CreationDate: &created,
	}}, nil
}

// GetPublicKey answers the SubjectPublicKeyInfo of a key.
func (k *KMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	key, err := k.find(in.KeyId)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.private.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{KeyId: new(key.ARN), PublicKey: der, KeySpec: key.Spec, KeyUsage: types.KeyUsageTypeSignVerify}, nil
}

// Sign signs a digest (MessageType DIGEST) with ECDSA_SHA_256 and answers the DER signature, as KMS does.
func (k *KMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	k.Signs.Add(1)
	key, err := k.find(in.KeyId)
	if err != nil {
		return nil, err
	}
	if key.State != types.KeyStateEnabled {
		return nil, &types.DisabledException{Message: new("disabled")}
	}
	if in.MessageType != types.MessageTypeDigest || in.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 || len(in.Message) != 32 ||
		key.Spec != types.KeySpecEccNistP256 {
		return nil, &types.InvalidKeyUsageException{Message: new("not an ES256 digest")}
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key.private, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{KeyId: new(key.ARN), Signature: sig, SigningAlgorithm: in.SigningAlgorithm}, nil
}

var errNotMade = errors.New("kmstest: session never makes or deletes its keys")

// CreateKey is refused: session runs the driver with CreateKeys off.
func (k *KMS) CreateKey(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	return nil, errNotMade
}

// CreateAlias is refused, as CreateKey.
func (k *KMS) CreateAlias(context.Context, *kms.CreateAliasInput, ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	return nil, errNotMade
}

// ScheduleKeyDeletion is refused, as CreateKey.
func (k *KMS) ScheduleKeyDeletion(context.Context, *kms.ScheduleKeyDeletionInput, ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	return nil, errNotMade
}

// DeriveSharedSecret is refused: session's purposes sign only.
func (k *KMS) DeriveSharedSecret(context.Context, *kms.DeriveSharedSecretInput, ...func(*kms.Options)) (*kms.DeriveSharedSecretOutput, error) {
	return nil, &types.InvalidKeyUsageException{Message: new("no key agreement")}
}
