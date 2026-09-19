package ceremony

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestCreateRootOnceThenRerunsWithoutSigning(t *testing.T) {
	client := newFakeKMS(t)
	artifactPath := filepath.Join(t.TempDir(), "root.yaml")
	options := RootOptions{KeyARN: fixtureKeyARN, ArtifactPath: artifactPath}

	first, err := CreateRoot(context.Background(), client, fixtureRootSpec(), options)
	require.NoError(t, err)
	assert.True(t, first.Signed)
	assert.Equal(t, 1, client.signCalls)
	assert.Equal(t, fixtureGeneration, first.Artifact.GenerationID)
	assert.Equal(t, fixtureKeyARN, first.Artifact.KeyARN)
	assert.NotEmpty(t, first.Artifact.CertificatePEM)
	assert.Len(t, first.Artifact.FingerprintSHA256, 64)
	assert.Len(t, first.Artifact.SubjectKeyIdentifier, 40)
	assert.Equal(t, "2045-12-27T00:00:00Z", first.Artifact.NotAfter)

	second, err := CreateRoot(context.Background(), client, fixtureRootSpec(), options)
	require.NoError(t, err)
	assert.False(t, second.Signed)
	assert.Equal(t, first.Artifact, second.Artifact)
	assert.Equal(t, 1, client.signCalls, "idempotent rerun must not call KMS Sign")
	require.FileExists(t, artifactPath+AttemptSuffix)

	var attempt Attempt
	require.NoError(t, readYAMLStrict(artifactPath+AttemptSuffix, &attempt))
	assert.Equal(t, Attempt{GenerationID: fixtureGeneration, KeyARN: fixtureKeyARN, StatePath: artifactPath, Status: AttemptStatusReserved}, attempt)

	loaded, err := LoadRootArtifact(artifactPath)
	require.NoError(t, err)
	assert.Equal(t, first.Artifact, loaded)
}

func TestCreateRootFailsClosedWhenAttemptIsAlreadyReserved(t *testing.T) {
	client := newFakeKMS(t)
	artifactPath := filepath.Join(t.TempDir(), "root.yaml")
	require.NoError(t, os.WriteFile(artifactPath+AttemptSuffix, []byte("status: signing-reserved\n"), 0o644))

	_, err := CreateRoot(context.Background(), client, fixtureRootSpec(), RootOptions{KeyARN: fixtureKeyARN, ArtifactPath: artifactPath})
	require.ErrorContains(t, err, "do not sign again")
	assert.Zero(t, client.signCalls)
}

func TestCreateRootImportsVerifiedCertificateWithoutSigning(t *testing.T) {
	client := newFakeKMS(t)
	template, err := RootTemplate(fixtureRootSpec(), &client.privateKey.PublicKey)
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &client.privateKey.PublicKey, client.privateKey)
	require.NoError(t, err)
	certificatePath := filepath.Join(t.TempDir(), "import.pem")
	require.NoError(t, os.WriteFile(certificatePath, pemCertificate(der), 0o644))

	result, err := CreateRoot(context.Background(), client, fixtureRootSpec(), RootOptions{
		KeyARN:                fixtureKeyARN,
		ArtifactPath:          filepath.Join(t.TempDir(), "root.yaml"),
		ImportCertificatePath: certificatePath,
	})
	require.NoError(t, err)
	assert.False(t, result.Signed)
	assert.Zero(t, client.signCalls)
}

func TestCreateRootRejectsTamperedExistingStateWithoutSigning(t *testing.T) {
	client := newFakeKMS(t)
	artifactPath := filepath.Join(t.TempDir(), "root.yaml")
	options := RootOptions{KeyARN: "key", ArtifactPath: artifactPath}
	result, err := CreateRoot(context.Background(), client, fixtureRootSpec(), options)
	require.NoError(t, err)
	client.signCalls = 0

	result.Artifact.FingerprintSHA256 = "00"
	raw, err := yaml.Marshal(result.Artifact)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(artifactPath, raw, 0o644))

	_, err = CreateRoot(context.Background(), client, fixtureRootSpec(), options)
	require.ErrorContains(t, err, "public metadata")
	assert.Zero(t, client.signCalls)
}

func TestCreateRootRejectsImportForAnotherKeyWithoutSigning(t *testing.T) {
	client := newFakeKMS(t)
	other := newFakeKMS(t)
	template, err := RootTemplate(fixtureRootSpec(), &other.privateKey.PublicKey)
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &other.privateKey.PublicKey, other.privateKey)
	require.NoError(t, err)
	certificatePath := filepath.Join(t.TempDir(), "wrong.pem")
	require.NoError(t, os.WriteFile(certificatePath, pemCertificate(der), 0o644))

	_, err = CreateRoot(context.Background(), client, fixtureRootSpec(), RootOptions{
		KeyARN:                "key",
		ArtifactPath:          filepath.Join(t.TempDir(), "root.yaml"),
		ImportCertificatePath: certificatePath,
	})
	require.ErrorContains(t, err, "does not match")
	assert.Zero(t, client.signCalls)
}

func TestCreateRootRejectsImportWithUnauthoredNameConstraintWithoutSigning(t *testing.T) {
	client := newFakeKMS(t)
	template, err := RootTemplate(fixtureRootSpec(), &client.privateKey.PublicKey)
	require.NoError(t, err)
	template.PermittedDNSDomainsCritical = true
	template.PermittedDNSDomains = []string{"example.internal", "example.com"}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &client.privateKey.PublicKey, client.privateKey)
	require.NoError(t, err)
	certificatePath := filepath.Join(t.TempDir(), "constrained.pem")
	require.NoError(t, os.WriteFile(certificatePath, pemCertificate(der), 0o644))

	_, err = CreateRoot(context.Background(), client, fixtureRootSpec(), RootOptions{
		KeyARN:                "key",
		ArtifactPath:          filepath.Join(t.TempDir(), "root.yaml"),
		ImportCertificatePath: certificatePath,
	})
	require.ErrorContains(t, err, "name constraints")
	assert.Zero(t, client.signCalls)
}

func TestCreateRootRefusesAnIncompleteSpecWithoutSigning(t *testing.T) {
	for name, mutate := range map[string]func(*RootSpec){
		"no generation":     func(s *RootSpec) { s.GenerationID = "" },
		"no common name":    func(s *RootSpec) { s.CommonName = "" },
		"no notBefore":      func(s *RootSpec) { s.NotBefore = time.Time{} },
		"no lifetime":       func(s *RootSpec) { s.Lifetime = 0 },
		"unbounded pathlen": func(s *RootSpec) { s.MaxPathLen = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			spec := fixtureRootSpec()
			mutate(&spec)
			client := newFakeKMS(t)
			_, err := CreateRoot(context.Background(), client, spec, RootOptions{KeyARN: "key", ArtifactPath: filepath.Join(t.TempDir(), "root.yaml")})
			require.Error(t, err)
			assert.Zero(t, client.signCalls)
		})
	}
}

func TestRootTemplateIsDeterministicAndBoundToKey(t *testing.T) {
	firstKey := newFakeKMS(t)
	first, err := RootTemplate(fixtureRootSpec(), &firstKey.privateKey.PublicKey)
	require.NoError(t, err)
	second, err := RootTemplate(fixtureRootSpec(), &firstKey.privateKey.PublicKey)
	require.NoError(t, err)

	assert.Equal(t, first.SerialNumber, second.SerialNumber)
	assert.Equal(t, first.SubjectKeyId, second.SubjectKeyId)
	assert.Equal(t, first.NotBefore, second.NotBefore)
	assert.Equal(t, first.NotAfter, second.NotAfter)

	otherKey := newFakeKMS(t)
	other, err := RootTemplate(fixtureRootSpec(), &otherKey.privateKey.PublicKey)
	require.NoError(t, err)
	assert.NotEqual(t, first.SerialNumber, other.SerialNumber)
	assert.NotEqual(t, first.SubjectKeyId, other.SubjectKeyId)

	// The namespace is part of the serial: a root is only re-verified under
	// the namespace it was created with.
	namespaced := fixtureRootSpec()
	namespaced.SerialNamespace = "another-namespace"
	moved, err := RootTemplate(namespaced, &firstKey.privateKey.PublicKey)
	require.NoError(t, err)
	assert.NotEqual(t, first.SerialNumber, moved.SerialNumber)
	explicit := fixtureRootSpec()
	explicit.SerialNamespace = DefaultSerialNamespace
	same, err := RootTemplate(explicit, &firstKey.privateKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, first.SerialNumber, same.SerialNumber, "empty means the default namespace")
}

func TestRootTemplateFollowsTheAuthoredConstraints(t *testing.T) {
	key := newFakeKMS(t)

	// Three CA layers below it, no name constraint at all (no
	// NameConstraints extension, not an empty critical one).
	template, err := RootTemplate(fixtureRootSpec(), &key.privateKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, fixtureRootMaxLen, template.MaxPathLen)
	assert.False(t, template.PermittedDNSDomainsCritical)
	assert.Empty(t, template.PermittedDNSDomains)

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.privateKey.PublicKey, key.privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.Equal(t, fixtureRootMaxLen, certificate.MaxPathLen)
	assert.False(t, certificate.PermittedDNSDomainsCritical)
	assert.Empty(t, certificate.PermittedDNSDomains)
	require.NoError(t, validateRootCertificate(certificate, template, &key.privateKey.PublicKey))

	// A spec that authors a constraint gets it, critical.
	constrained := fixtureRootSpec()
	constrained.PermittedDNSDomains = []string{"example.internal"}
	template, err = RootTemplate(constrained, &key.privateKey.PublicKey)
	require.NoError(t, err)
	assert.True(t, template.PermittedDNSDomainsCritical)
	assert.Equal(t, []string{"example.internal"}, template.PermittedDNSDomains)

	// Path length zero is "leaves only", never "unbounded".
	leavesOnly := fixtureRootSpec()
	leavesOnly.MaxPathLen = 0
	template, err = RootTemplate(leavesOnly, &key.privateKey.PublicKey)
	require.NoError(t, err)
	der, err = x509.CreateCertificate(rand.Reader, template, template, &key.privateKey.PublicKey, key.privateKey)
	require.NoError(t, err)
	certificate, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.True(t, certificate.MaxPathLenZero)
}
