// Package kmssigner adapts an AWS KMS ECC_NIST_P384 SIGN_VERIFY key to
// crypto.Signer. Private key material never leaves KMS.
package kmssigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"io"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type (
	// API is the subset of the AWS KMS client used by Signer.
	API interface {
		GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
		Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
	}

	// Signer implements crypto.Signer with ECDSA SHA-384 signatures produced by a
	// single configured AWS KMS key.
	Signer struct {
		ctx       context.Context
		client    API
		keyID     string
		publicKey *ecdsa.PublicKey
	}
)

var _ crypto.Signer = (*Signer)(nil)

// New fetches and validates the KMS public-key metadata before returning a
// signer. The supplied context is used by crypto.Signer.Sign; callers that need
// a different per-operation context can use SignContext.
func New(ctx context.Context, client API, keyID string) (*Signer, error) {
	if ctx == nil {
		return nil, fmt.Errorf("KMS signer context is required")
	}
	if client == nil {
		return nil, fmt.Errorf("KMS client is required")
	}
	if keyID == "" {
		return nil, fmt.Errorf("KMS key ID is required")
	}

	output, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("get KMS public key: %w", err)
	}
	if output == nil {
		return nil, fmt.Errorf("get KMS public key: empty response")
	}
	if output.KeySpec != types.KeySpecEccNistP384 {
		return nil, fmt.Errorf("KMS key spec must be ECC_NIST_P384, got %q", output.KeySpec)
	}
	if output.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("KMS key usage must be SIGN_VERIFY, got %q", output.KeyUsage)
	}
	if !slices.Contains(output.SigningAlgorithms, types.SigningAlgorithmSpecEcdsaSha384) {
		return nil, fmt.Errorf("KMS key does not support ECDSA_SHA_384")
	}

	parsed, err := x509.ParsePKIXPublicKey(output.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse KMS public key: %w", err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P384() {
		return nil, fmt.Errorf("KMS public key must be ECDSA P-384, got %T", parsed)
	}

	return &Signer{ctx: ctx, client: client, keyID: keyID, publicKey: publicKey}, nil
}

// Public returns the KMS key's validated P-384 public key.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign implements crypto.Signer. The randomness reader is intentionally unused:
// KMS performs ECDSA nonce generation inside its security boundary.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(s.ctx, digest, opts)
}

// SignContext signs exactly one SHA-384 digest with KMS ECDSA_SHA_384.
func (s *Signer) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("KMS sign context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("KMS sign: %w", err)
	}
	if opts == nil || opts.HashFunc() != crypto.SHA384 {
		return nil, fmt.Errorf("KMS signer requires SHA-384 signer options")
	}
	if len(digest) != crypto.SHA384.Size() {
		return nil, fmt.Errorf("KMS signer requires a %d-byte SHA-384 digest, got %d", crypto.SHA384.Size(), len(digest))
	}

	output, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          append([]byte(nil), digest...),
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha384,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS sign: %w", err)
	}
	if output == nil || len(output.Signature) == 0 {
		return nil, fmt.Errorf("KMS sign: empty signature")
	}
	if !ecdsa.VerifyASN1(s.publicKey, digest, output.Signature) {
		return nil, fmt.Errorf("KMS sign: returned signature does not verify with the configured public key")
	}
	return append([]byte(nil), output.Signature...), nil
}
