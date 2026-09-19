package ceremony

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// signedFixture runs both intermediate ceremonies against the KMS double
// into one directory, the way a repository holds committed artifacts, and
// returns that directory with the specs relative to it.
func signedFixture(t *testing.T) (string, map[string]IntermediateSpec) {
	t.Helper()
	dir := t.TempDir()
	client := fixtureRootKMS(t)
	root := targetRoot(t, client, fixtureGeneration)

	rootRaw, err := yaml.Marshal(root)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, fixtureGeneration+".yaml"), rootRaw, 0o644))

	specs := map[string]IntermediateSpec{}
	for trustDomain, seed := range map[string]byte{fixturePrivate: 0x21, fixtureOrigin: 0x31} {
		spec := fixtureIntermediateSpec(trustDomain, dir)
		plan, err := PrepareIntermediate(spec, root, fixtureCSR(t, fixtureKey(t, seed), spec.subject()))
		require.NoError(t, err)
		_, err = SignIntermediate(context.Background(), client, plan, IntermediateOptions{KeyARN: fixtureKeyARN, ConfirmTemplateSHA256: plan.TemplateSHA256})
		require.NoError(t, err)

		relative := fixtureIntermediateSpec(trustDomain, "")
		specs[trustDomain] = relative
	}
	return dir, specs
}

// Anything that installs a committed intermediate must be able to prove,
// from the spec alone, that it is what the spec declares.
func TestLoadSignedIntermediateProvesTheCommittedArtifacts(t *testing.T) {
	dir, specs := signedFixture(t)

	for trustDomain, spec := range specs {
		signed, err := LoadSignedIntermediate(spec, dir)
		require.NoError(t, err, trustDomain)

		assert.Equal(t, spec.CommonName, signed.Certificate.Subject.CommonName)
		assert.True(t, signed.Certificate.IsCA)
		assert.Equal(t, spec.MaxPathLen, signed.Certificate.MaxPathLen)
		require.NoError(t, signed.Certificate.CheckSignatureFrom(signed.Root))
		assert.NotEmpty(t, signed.Proof)

		// The chain is what OpenBAO imports: the issuer first, the root
		// after it, so every leaf below gets a complete ca_chain.
		chain := decodeChain(t, signed.ChainPEM)
		require.Len(t, chain, 2, trustDomain)
		assert.True(t, chain[0].Equal(signed.Certificate), "%s: the intermediate comes first", trustDomain)
		assert.True(t, chain[1].Equal(signed.Root), "%s: the root follows it", trustDomain)
		assert.True(t, strings.HasSuffix(signed.ChainPEM, "-----END CERTIFICATE-----\n"))
	}
}

// The constrained domain's name constraint and the other domain's lack of
// one are the difference between the two chains, and an installer must
// not be able to swap the artifacts without noticing.
func TestLoadSignedIntermediateRefusesTheOtherDomainsArtifact(t *testing.T) {
	dir, specs := signedFixture(t)
	private, origin := specs[fixturePrivate], specs[fixtureOrigin]

	originRaw, err := os.ReadFile(filepath.Join(dir, origin.ArtifactPath))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, private.ArtifactPath), originRaw, 0o644))

	_, err = LoadSignedIntermediate(private, dir)
	require.ErrorContains(t, err, "holds the origin intermediate")

	// Relabelled to pass the label check, it still fails the re-derived
	// template.
	relabelled := strings.Replace(string(originRaw), "trustDomain: origin", "trustDomain: private", 1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, private.ArtifactPath), []byte(relabelled), 0o644))
	_, err = LoadSignedIntermediate(private, dir)
	require.Error(t, err)
}

func TestLoadSignedIntermediateRefusesAMissingOrTamperedArtifact(t *testing.T) {
	dir, specs := signedFixture(t)
	private := specs[fixturePrivate]

	missing := private
	missing.ArtifactPath = "nowhere.yaml"
	_, err := LoadSignedIntermediate(missing, dir)
	require.Error(t, err)

	raw, err := os.ReadFile(filepath.Join(dir, private.ArtifactPath))
	require.NoError(t, err)
	tampered := strings.Replace(string(raw), "templateSha256: ", "templateSha256: 0", 1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, private.ArtifactPath), []byte(tampered), 0o644))
	_, err = LoadSignedIntermediate(private, dir)
	require.Error(t, err)
}

func decodeChain(t *testing.T, chain string) []*x509.Certificate {
	t.Helper()
	var certificates []*x509.Certificate
	for _, block := range strings.SplitAfter(chain, "-----END CERTIFICATE-----\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		certificate, err := decodeSingleCertificate([]byte(block))
		require.NoError(t, err)
		certificates = append(certificates, certificate)
	}
	return certificates
}
