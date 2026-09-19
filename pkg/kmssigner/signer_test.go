package kmssigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type (
	fakeKMS struct {
		publicOutput *kms.GetPublicKeyOutput
		publicErr    error
		signOutput   *kms.SignOutput
		signErr      error
		signInput    *kms.SignInput
		signContext  context.Context
	}
)

func (f *fakeKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return f.publicOutput, f.publicErr
}

func (f *fakeKMS) Sign(ctx context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signContext = ctx
	f.signInput = input
	return f.signOutput, f.signErr
}

func TestSignerUsesDigestModeAndECDSASHA384(t *testing.T) {
	privateKey, client := validClient(t)
	digest := sha512.Sum384([]byte("root certificate tbs"))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	require.NoError(t, err)
	client.signOutput = &kms.SignOutput{Signature: signature}

	signer, err := New(context.Background(), client, "arn:aws:kms:eu-example-1:111122223333:key/mrk-test")
	require.NoError(t, err)
	got, err := signer.Sign(rand.Reader, digest[:], crypto.SHA384)
	require.NoError(t, err)

	assert.Equal(t, signature, got)
	assert.Equal(t, types.MessageTypeDigest, client.signInput.MessageType)
	assert.Equal(t, types.SigningAlgorithmSpecEcdsaSha384, client.signInput.SigningAlgorithm)
	assert.Equal(t, digest[:], client.signInput.Message)
	assert.Equal(t, "arn:aws:kms:eu-example-1:111122223333:key/mrk-test", aws.ToString(client.signInput.KeyId))
	assert.True(t, signer.Public().(*ecdsa.PublicKey).Equal(&privateKey.PublicKey))
}

func TestNewRejectsIncompatibleKMSMetadata(t *testing.T) {
	_, valid := validClient(t)
	tests := map[string]func(*kms.GetPublicKeyOutput){
		"wrong key spec": func(output *kms.GetPublicKeyOutput) { output.KeySpec = types.KeySpecEccNistP256 },
		"wrong usage":    func(output *kms.GetPublicKeyOutput) { output.KeyUsage = types.KeyUsageTypeEncryptDecrypt },
		"wrong algorithm": func(output *kms.GetPublicKeyOutput) {
			output.SigningAlgorithms = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}
		},
		"bad public key": func(output *kms.GetPublicKeyOutput) { output.PublicKey = []byte("not DER") },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			output := *valid.publicOutput
			output.SigningAlgorithms = append([]types.SigningAlgorithmSpec(nil), valid.publicOutput.SigningAlgorithms...)
			mutate(&output)
			_, err := New(context.Background(), &fakeKMS{publicOutput: &output}, "key")
			require.Error(t, err)
		})
	}
}

func TestNewRejectsP256PublicKeyEvenWithP384Metadata(t *testing.T) {
	_, client := validClient(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	client.publicOutput.PublicKey, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	_, err = New(context.Background(), client, "key")
	require.ErrorContains(t, err, "P-384")
}

func TestSignerRejectsWrongHashAndDigestLengthWithoutCallingKMS(t *testing.T) {
	_, client := validClient(t)
	signer, err := New(context.Background(), client, "key")
	require.NoError(t, err)

	_, err = signer.Sign(rand.Reader, make([]byte, crypto.SHA384.Size()), crypto.SHA256)
	require.ErrorContains(t, err, "SHA-384")
	assert.Nil(t, client.signInput)

	_, err = signer.Sign(rand.Reader, make([]byte, crypto.SHA384.Size()-1), crypto.SHA384)
	require.ErrorContains(t, err, "48-byte")
	assert.Nil(t, client.signInput)
}

func TestSignerRejectsInvalidOrEmptyKMSSignature(t *testing.T) {
	_, client := validClient(t)
	signer, err := New(context.Background(), client, "key")
	require.NoError(t, err)
	digest := sha512.Sum384([]byte("digest"))

	client.signOutput = &kms.SignOutput{}
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA384)
	require.ErrorContains(t, err, "empty signature")

	client.signOutput = &kms.SignOutput{Signature: []byte{0x30, 0x00}}
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA384)
	require.ErrorContains(t, err, "does not verify")
}

func TestSignerPropagatesAPIAndContextErrors(t *testing.T) {
	apiErr := errors.New("kms unavailable")
	_, err := New(context.Background(), &fakeKMS{publicErr: apiErr}, "key")
	require.ErrorIs(t, err, apiErr)

	_, client := validClient(t)
	client.signErr = apiErr
	signer, err := New(context.Background(), client, "key")
	require.NoError(t, err)
	digest := sha512.Sum384([]byte("digest"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA384)
	require.ErrorIs(t, err, apiErr)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client.signErr = nil
	client.signInput = nil
	_, err = signer.SignContext(ctx, digest[:], crypto.SHA384)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, client.signInput)
}

func validClient(t *testing.T) (*ecdsa.PrivateKey, *fakeKMS) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	return privateKey, &fakeKMS{publicOutput: &kms.GetPublicKeyOutput{
		KeySpec:           types.KeySpecEccNistP384,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha384},
		PublicKey:         publicDER,
	}}
}
