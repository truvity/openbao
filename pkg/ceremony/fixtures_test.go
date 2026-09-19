package ceremony

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"
)

// Neutral fixtures: nothing here names a real estate. The KMS key is a
// double that signs with an in-memory P-384 key behind the same interface
// the real client satisfies.
const (
	fixtureGeneration = "example-root-2026-01"
	fixtureKeyARN     = "arn:aws:kms:eu-example-1:111122223333:key/mrk-fixture"
	fixtureRootCN     = "Example Private Root 2026-01"
	fixtureOrg        = "Example Org"
	fixturePrivateCN  = "example.internal Intermediate CA"
	fixtureOriginCN   = "example.com Origin Intermediate CA"
	fixturePrivate    = "private"
	fixtureOrigin     = "origin"
	fixtureNotAfter   = "2035-12-30T00:00:00Z" // 2026-01-01 + 87600h, two leap days included
	fixtureRootMaxLen = 3
)

var fixtureNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type (
	fakeKMS struct {
		privateKey *ecdsa.PrivateKey
		publicDER  []byte
		signCalls  int
	}

	// fixtureRootOptions shapes the in-test root so refusals can be
	// exercised against roots that are not what the spec authors.
	fixtureRootOptions struct {
		maxPathLen          int
		permittedDNSDomains []string
	}
)

func (c *fakeKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{
		KeySpec:           types.KeySpecEccNistP384,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha384},
		PublicKey:         c.publicDER,
	}, nil
}

func (c *fakeKMS) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	c.signCalls++
	signature, err := ecdsa.SignASN1(rand.Reader, c.privateKey, input.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: signature}, nil
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	return kmsFor(t, privateKey)
}

func kmsFor(t *testing.T, privateKey *ecdsa.PrivateKey) *fakeKMS {
	t.Helper()
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	return &fakeKMS{privateKey: privateKey, publicDER: publicDER}
}

// fixtureKey derives a fixed P-384 key from a seed byte so goldens are
// reproducible. Test material only; never a real key.
func fixtureKey(t *testing.T, seed byte) *ecdsa.PrivateKey {
	t.Helper()
	scalar := make([]byte, 48)
	for i := range scalar {
		scalar[i] = seed + byte(i)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), scalar)
	require.NoError(t, err)
	return key
}

func fixtureRootKMS(t *testing.T) *fakeKMS {
	t.Helper()
	return kmsFor(t, fixtureKey(t, 0x11))
}

func fixtureRootSpec() RootSpec {
	return RootSpec{
		GenerationID: fixtureGeneration,
		CommonName:   fixtureRootCN,
		Organization: fixtureOrg,
		NotBefore:    fixtureNotBefore,
		Lifetime:     175200 * time.Hour,
		MaxPathLen:   fixtureRootMaxLen,
	}
}

// fixtureRoot is a root signed in-test with the fixture KMS key: P-384,
// the given path length and constraint.
func fixtureRoot(t *testing.T, client *fakeKMS, generationID string, options fixtureRootOptions) RootArtifact {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&client.privateKey.PublicKey)
	require.NoError(t, err)
	skiDigest := sha256.Sum256(spki)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(0x5eed),
		Subject:               pkix.Name{CommonName: fixtureRootCN, Organization: []string{fixtureOrg}},
		NotBefore:             fixtureNotBefore,
		NotAfter:              fixtureNotBefore.Add(175200 * time.Hour),
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            options.maxPathLen,
		SubjectKeyId:          skiDigest[:20],
		AuthorityKeyId:        skiDigest[:20],
	}
	if len(options.permittedDNSDomains) > 0 {
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = options.permittedDNSDomains
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &client.privateKey.PublicKey, client.privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return rootArtifactFromCertificate(certificate, generationID, fixtureKeyARN)
}

func targetRoot(t *testing.T, client *fakeKMS, generationID string) RootArtifact {
	t.Helper()
	return fixtureRoot(t, client, generationID, fixtureRootOptions{maxPathLen: fixtureRootMaxLen})
}

func fixtureIntermediateSpec(trustDomain, dir string) IntermediateSpec {
	spec := IntermediateSpec{
		TrustDomain:      trustDomain,
		GenerationID:     fixtureGeneration,
		Organization:     fixtureOrg,
		NotBefore:        fixtureNotBefore,
		Lifetime:         87600 * time.Hour,
		MaxPathLen:       fixtureRootMaxLen - 1,
		RootArtifactPath: filepath.Join(dir, fixtureGeneration+".yaml"),
		ArtifactPath:     filepath.Join(dir, fixtureGeneration+"-intermediate-"+trustDomain+".yaml"),
	}
	switch trustDomain {
	case fixturePrivate:
		spec.CommonName = fixturePrivateCN
		spec.PermittedDNSDomains = []string{"example.internal", "cluster.local"}
	default:
		spec.CommonName = fixtureOriginCN
	}
	return spec
}

func fixtureCSR(t *testing.T, key *ecdsa.PrivateKey, subject pkix.Name) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: certificateRequestPEMType, Bytes: der})
}

// fixture places the artifact paths in a temp dir so the O_EXCL machinery
// runs for real.
func fixture(t *testing.T, trustDomain string) (IntermediateSpec, *fakeKMS, RootArtifact, []byte) {
	t.Helper()
	spec := fixtureIntermediateSpec(trustDomain, t.TempDir())
	client := fixtureRootKMS(t)
	root := targetRoot(t, client, fixtureGeneration)
	csrSeed := map[string]byte{fixturePrivate: 0x21, fixtureOrigin: 0x31}[trustDomain]
	csr := fixtureCSR(t, fixtureKey(t, csrSeed), spec.subject())
	return spec, client, root, csr
}

func pemCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
