package ceremony

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntermediateTemplateGolden(t *testing.T) {
	for _, trustDomain := range []string{fixturePrivate, fixtureOrigin} {
		t.Run(trustDomain, func(t *testing.T) {
			spec, _, root, csr := fixture(t, trustDomain)
			// Paths are part of the text; pin them to a stable layout.
			spec.RootArtifactPath = "pki/" + spec.GenerationID + ".yaml"
			spec.ArtifactPath = "pki/" + spec.GenerationID + "-intermediate-" + trustDomain + ".yaml"
			plan, err := PrepareIntermediate(spec, root, csr)
			require.NoError(t, err)
			again, err := PrepareIntermediate(spec, root, csr)
			require.NoError(t, err)
			assert.Equal(t, plan.TemplateSHA256, again.TemplateSHA256, "the template hash must not depend on the throwaway preview key")

			goldenPath := filepath.Join("testdata", "intermediate-"+trustDomain+".golden")
			got := plan.Text()
			if os.Getenv("UPDATE_GOLDEN") != "" {
				require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o755))
				require.NoError(t, os.WriteFile(goldenPath, []byte(got), 0o644))
				return
			}
			want, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "UPDATE_GOLDEN=1 writes the golden")
			assert.Equal(t, string(want), got)
		})
	}
}

func TestSignIntermediateSignsOnceThenRerunsWithoutSigning(t *testing.T) {
	for _, trustDomain := range []string{fixturePrivate, fixtureOrigin} {
		t.Run(trustDomain, func(t *testing.T) {
			spec, client, root, csr := fixture(t, trustDomain)
			plan, err := PrepareIntermediate(spec, root, csr)
			require.NoError(t, err)
			options := IntermediateOptions{KeyARN: fixtureKeyARN, ConfirmTemplateSHA256: plan.TemplateSHA256}

			first, err := SignIntermediate(context.Background(), client, plan, options)
			require.NoError(t, err)
			assert.True(t, first.Signed)
			assert.Equal(t, 1, client.signCalls)
			assert.Equal(t, trustDomain, first.Artifact.TrustDomain)
			assert.Equal(t, plan.TemplateSHA256, first.Artifact.TemplateSHA256)
			assert.Equal(t, fixtureNotAfter, first.Artifact.NotAfter)
			assert.Equal(t, root.SubjectKeyIdentifier, first.Artifact.AuthorityKeyIdentifier)
			assert.NotEmpty(t, first.Proof)
			require.FileExists(t, spec.ArtifactPath)
			require.FileExists(t, spec.ArtifactPath+AttemptSuffix)

			tbs := sha256.Sum256(first.Certificate.RawTBSCertificate)
			assert.Equal(t, plan.TemplateSHA256, hex.EncodeToString(tbs[:]), "KMS signed exactly the confirmed bytes")

			second, err := SignIntermediate(context.Background(), client, plan, options)
			require.NoError(t, err)
			assert.False(t, second.Signed)
			assert.Equal(t, first.Artifact, second.Artifact)
			assert.Equal(t, first.Proof, second.Proof)
			assert.Equal(t, 1, client.signCalls, "idempotent rerun must not call KMS Sign")
		})
	}
}

func TestSignIntermediateFailsClosedWhenAttemptIsAlreadyReserved(t *testing.T) {
	spec, client, root, csr := fixture(t, fixturePrivate)
	require.NoError(t, os.WriteFile(spec.ArtifactPath+AttemptSuffix, []byte("status: signing-reserved\n"), 0o644))
	plan, err := PrepareIntermediate(spec, root, csr)
	require.NoError(t, err)

	_, err = SignIntermediate(context.Background(), client, plan, IntermediateOptions{KeyARN: fixtureKeyARN, ConfirmTemplateSHA256: plan.TemplateSHA256})
	require.ErrorContains(t, err, "do not sign again")
	assert.Zero(t, client.signCalls)
	assert.NoFileExists(t, spec.ArtifactPath)
}

func TestSignIntermediateRefusesTemplateHashMismatchBeforeReserving(t *testing.T) {
	spec, client, root, csr := fixture(t, fixturePrivate)
	plan, err := PrepareIntermediate(spec, root, csr)
	require.NoError(t, err)

	for _, confirm := range []string{"", "deadbeef", plan.TemplateSHA256[1:] + "0"} {
		_, err = SignIntermediate(context.Background(), client, plan, IntermediateOptions{KeyARN: fixtureKeyARN, ConfirmTemplateSHA256: confirm})
		require.ErrorContains(t, err, "does not match the template to be signed")
	}
	assert.Zero(t, client.signCalls)
	assert.NoFileExists(t, spec.ArtifactPath+AttemptSuffix, "a refused confirmation must not consume the attempt")
}

func TestSignIntermediateRefusesKeyThatIsNotTheRoot(t *testing.T) {
	spec, _, root, csr := fixture(t, fixturePrivate)
	plan, err := PrepareIntermediate(spec, root, csr)
	require.NoError(t, err)
	stranger := newFakeKMS(t)

	_, err = SignIntermediate(context.Background(), stranger, plan, IntermediateOptions{KeyARN: fixtureKeyARN, ConfirmTemplateSHA256: plan.TemplateSHA256})
	require.ErrorContains(t, err, "not the key behind the committed root")
	assert.Zero(t, stranger.signCalls)
	assert.NoFileExists(t, spec.ArtifactPath+AttemptSuffix)
}

func TestSignIntermediateRejectsTamperedExistingStateWithoutSigning(t *testing.T) {
	spec, client, root, csr := fixture(t, fixtureOrigin)
	plan, err := PrepareIntermediate(spec, root, csr)
	require.NoError(t, err)
	options := IntermediateOptions{KeyARN: fixtureKeyARN, ConfirmTemplateSHA256: plan.TemplateSHA256}
	_, err = SignIntermediate(context.Background(), client, plan, options)
	require.NoError(t, err)
	client.signCalls = 0

	raw, err := os.ReadFile(spec.ArtifactPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(spec.ArtifactPath, bytes.Replace(raw, []byte("fingerprintSha256: "), []byte("fingerprintSha256: 00"), 1), 0o644))

	_, err = SignIntermediate(context.Background(), client, plan, options)
	require.ErrorContains(t, err, "public metadata")
	assert.Zero(t, client.signCalls)
}

func TestPrepareIntermediateRefusesBadRequests(t *testing.T) {
	spec, client, root, _ := fixture(t, fixturePrivate)
	good := fixtureKey(t, 0x21)

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	goodCSR := fixtureCSR(t, good, spec.subject())
	block, _ := pem.Decode(goodCSR)
	tampered := append([]byte(nil), block.Bytes...)
	tampered[len(tampered)-1] ^= 0x01
	tamperedCSR := pem.EncodeToMemory(&pem.Block{Type: certificateRequestPEMType, Bytes: tampered})

	sanRequest := &x509.CertificateRequest{Subject: spec.subject(), DNSNames: []string{"gateway.example.internal"}}
	withSAN, err := x509.CreateCertificateRequest(rand.Reader, sanRequest, good)
	require.NoError(t, err)

	cases := []struct {
		name string
		csr  []byte
		want string
	}{
		{"p256 key", fixtureCSR(t, p256, spec.subject()), "must be on P-384"},
		{"bad signature", tamperedCSR, "self-signature verification failed"},
		{
			"wrong subject",
			fixtureCSR(t, good, pkix.Name{CommonName: fixtureOriginCN, Organization: []string{fixtureOrg}}),
			"does not match the authored private intermediate subject",
		},
		{"subject missing organization", fixtureCSR(t, good, pkix.Name{CommonName: spec.CommonName}), "does not match the authored private intermediate subject"},
		{"root key reused", fixtureCSR(t, client.privateKey, spec.subject()), "root's own key"},
		{"subject alternative names", pem.EncodeToMemory(&pem.Block{Type: certificateRequestPEMType, Bytes: withSAN}), "must not request subject alternative names"},
		{"not a csr", []byte(root.CertificatePEM), "exactly one CERTIFICATE REQUEST PEM block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PrepareIntermediate(spec, root, tc.csr)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestPrepareIntermediateRefusesRootsThatCannotCarryIt(t *testing.T) {
	spec, client, _, csr := fixture(t, fixturePrivate)

	shallow := fixtureRoot(t, client, spec.GenerationID, fixtureRootOptions{maxPathLen: fixtureRootMaxLen - 1})
	_, err := PrepareIntermediate(spec, shallow, csr)
	require.ErrorContains(t, err, "root maxPathLen must be exactly 3")

	unbounded := fixtureRoot(t, client, spec.GenerationID, fixtureRootOptions{maxPathLen: -1})
	_, err = PrepareIntermediate(spec, unbounded, csr)
	require.ErrorContains(t, err, "root maxPathLen must be exactly 3")

	// A root that only permits two suffixes would make every cluster.local
	// leaf fail below a private intermediate that permits it.
	constrained := fixtureRoot(t, client, spec.GenerationID, fixtureRootOptions{
		maxPathLen:          fixtureRootMaxLen,
		permittedDNSDomains: []string{"example.internal", "example.com"},
	})
	_, err = PrepareIntermediate(spec, constrained, csr)
	require.ErrorContains(t, err, `would permit "cluster.local"`)

	// The same root can still carry an intermediate whose permitted names
	// sit inside its own.
	spec.PermittedDNSDomains = []string{"example.internal"}
	_, err = PrepareIntermediate(spec, constrained, csr)
	require.NoError(t, err)

	foreign := targetRoot(t, client, "example-root-2099-01")
	spec.PermittedDNSDomains = []string{"example.internal", "cluster.local"}
	_, err = PrepareIntermediate(spec, foreign, csr)
	require.ErrorContains(t, err, "belongs to generation")

	forged := targetRoot(t, newFakeKMS(t), spec.GenerationID)
	forged.FingerprintSHA256 = "00"
	_, err = PrepareIntermediate(spec, forged, csr)
	require.ErrorContains(t, err, "public metadata")

	tooLong := spec
	tooLong.Lifetime *= 3
	_, err = PrepareIntermediate(tooLong, targetRoot(t, client, spec.GenerationID), csr)
	require.ErrorContains(t, err, "not within the root's")
}

func TestConstrainedIntermediateIsCriticalAndUnconstrainedHasNone(t *testing.T) {
	signed := func(trustDomain string) *x509.Certificate {
		spec, client, root, csr := fixture(t, trustDomain)
		plan, err := PrepareIntermediate(spec, root, csr)
		require.NoError(t, err)
		result, err := SignIntermediate(context.Background(), client, plan, IntermediateOptions{KeyARN: fixtureKeyARN, ConfirmTemplateSHA256: plan.TemplateSHA256})
		require.NoError(t, err)
		return result.Certificate
	}
	nameConstraints := func(certificate *x509.Certificate) (pkix.Extension, bool) {
		for _, extension := range certificate.Extensions {
			if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 30}) {
				return extension, true
			}
		}
		return pkix.Extension{}, false
	}

	private := signed(fixturePrivate)
	extension, present := nameConstraints(private)
	require.True(t, present, "the constrained intermediate must carry name constraints")
	assert.True(t, extension.Critical, "the name constraints must be critical")
	assert.True(t, private.PermittedDNSDomainsCritical)
	assert.Equal(t, []string{"example.internal", "cluster.local"}, private.PermittedDNSDomains)
	assert.Equal(t, []string{allIPv4, allIPv6}, ipRangeStrings(private.ExcludedIPRanges))
	assert.Equal(t, fixtureRootMaxLen-1, private.MaxPathLen)

	origin := signed(fixtureOrigin)
	_, present = nameConstraints(origin)
	assert.False(t, present, "the unconstrained intermediate must carry no name constraints")
	assert.Empty(t, origin.PermittedDNSDomains)
	assert.Empty(t, origin.ExcludedIPRanges)
	assert.Equal(t, fixtureRootMaxLen-1, origin.MaxPathLen)
}

func TestIntermediateSerialIsDeterministicPerDomainAndKey(t *testing.T) {
	spec, _, root, csr := fixture(t, fixturePrivate)
	plan, err := PrepareIntermediate(spec, root, csr)
	require.NoError(t, err)

	other := spec
	other.TrustDomain = fixtureOrigin
	other.CommonName = fixtureOriginCN
	other.PermittedDNSDomains = nil
	otherPlan, err := PrepareIntermediate(other, root, fixtureCSR(t, fixtureKey(t, 0x21), other.subject()))
	require.NoError(t, err)
	assert.NotEqual(t, plan.Template.SerialNumber, otherPlan.Template.SerialNumber, "the serial covers the trust domain")
	assert.Equal(t, plan.Template.SubjectKeyId, otherPlan.Template.SubjectKeyId, "the SKI is the key's alone")

	rekeyed, err := PrepareIntermediate(spec, root, fixtureCSR(t, fixtureKey(t, 0x41), spec.subject()))
	require.NoError(t, err)
	assert.NotEqual(t, plan.Template.SerialNumber, rekeyed.Template.SerialNumber, "the serial covers the CSR key")
	assert.NotEqual(t, plan.TemplateSHA256, rekeyed.TemplateSHA256)
}

func TestPrepareIntermediateRefusesAnIncompleteSpec(t *testing.T) {
	for name, mutate := range map[string]func(*IntermediateSpec){
		"no trust domain":       func(s *IntermediateSpec) { s.TrustDomain = "" },
		"a trust domain path":   func(s *IntermediateSpec) { s.TrustDomain = "../private" },
		"no common name":        func(s *IntermediateSpec) { s.CommonName = "" },
		"no artifact path":      func(s *IntermediateSpec) { s.ArtifactPath = "" },
		"no lifetime":           func(s *IntermediateSpec) { s.Lifetime = 0 },
		"an unbounded path len": func(s *IntermediateSpec) { s.MaxPathLen = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			spec, _, root, csr := fixture(t, fixturePrivate)
			mutate(&spec)
			_, err := PrepareIntermediate(spec, root, csr)
			require.Error(t, err)
		})
	}
}
