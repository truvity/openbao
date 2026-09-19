package ceremony

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	emergencyName = "openbao.example.internal"
)

var emergencyNotBefore = time.Date(2026, 12, 12, 11, 0, 0, 0, time.UTC)

func emergencyCSR(t *testing.T, key *ecdsa.PrivateKey, template *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: certificateRequestPEMType, Bytes: der})
}

func emergencyFixture(t *testing.T) (EmergencyServerSpec, *fakeKMS, RootArtifact, *ecdsa.PrivateKey) {
	t.Helper()
	spec := EmergencyServerSpec{
		GenerationID:     fixtureGeneration,
		DNSName:          emergencyName,
		NotBefore:        emergencyNotBefore,
		Lifetime:         DefaultEmergencyServerLifetime,
		RootArtifactPath: "pki/" + fixtureGeneration + ".yaml",
	}
	client := fixtureRootKMS(t)
	return spec, client, targetRoot(t, client, fixtureGeneration), fixtureKey(t, 0x42)
}

// The whole break-glass path against the KMS double: nothing is signed for
// a hash nobody reviewed, the reviewed one is signed once, and the leaf
// verifies against the root ALONE, for the endpoint, as a TLS server --
// which is what every OpenBAO client does with it.
func TestEmergencyServerSignsOnceForTheReviewedTemplate(t *testing.T) {
	spec, client, root, key := emergencyFixture(t)
	csr := emergencyCSR(t, key, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: emergencyName},
		DNSNames: []string{emergencyName},
	})

	plan, err := PrepareEmergencyServer(spec, root, csr)
	require.NoError(t, err)
	assert.Len(t, plan.TemplateSHA256, 64)
	assert.Contains(t, plan.Text(), "signed DIRECTLY by the root")
	assert.Contains(t, plan.Text(), "168h0m0s")

	again, err := PrepareEmergencyServer(spec, root, csr)
	require.NoError(t, err)
	assert.Equal(t, plan.TemplateSHA256, again.TemplateSHA256, "a second reviewer derives the same hash offline")

	_, err = SignEmergencyServer(context.Background(), client, plan, EmergencyServerOptions{KeyARN: fixtureKeyARN, ConfirmTemplateSHA256: "00"})
	require.ErrorContains(t, err, "does not match the template")
	assert.Zero(t, client.signCalls, "no signature for an unreviewed template")

	confirmed := EmergencyServerOptions{KeyARN: fixtureKeyARN, ConfirmTemplateSHA256: plan.TemplateSHA256}
	result, err := SignEmergencyServer(context.Background(), client, plan, confirmed)
	require.NoError(t, err)
	assert.Equal(t, 1, client.signCalls)
	assert.NotEmpty(t, result.Proof)

	leaf := result.Certificate
	rootCert, err := decodeSingleCertificate([]byte(root.CertificatePEM))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	_, err = leaf.Verify(x509.VerifyOptions{DNSName: emergencyName, Roots: roots, CurrentTime: emergencyNotBefore.Add(time.Hour),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	require.NoError(t, err, "a client with the root verifies the leaf with no intermediate")

	_, err = leaf.Verify(x509.VerifyOptions{DNSName: "openbao-0.openbao-internal", Roots: roots, CurrentTime: emergencyNotBefore.Add(time.Hour)})
	assert.Error(t, err, "the leaf serves the endpoint and nothing else")

	expired := emergencyNotBefore.Add(DefaultEmergencyServerLifetime + time.Minute)
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: emergencyName, Roots: roots, CurrentTime: expired})
	assert.Error(t, err, "a week, then it is gone")

	assert.False(t, leaf.IsCA)
	assert.Equal(t, []string{emergencyName}, leaf.DNSNames)
	assert.Empty(t, leaf.IPAddresses)
	assert.Equal(t, x509.KeyUsageDigitalSignature, leaf.KeyUsage)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, leaf.ExtKeyUsage)
	assert.Equal(t, rootCert.SubjectKeyId, leaf.AuthorityKeyId)
	assert.True(t, leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey))

	block, _ := pem.Decode(result.CertificatePEM)
	require.NotNil(t, block)
	assert.Equal(t, leaf.Raw, block.Bytes)
}

// An empty subject with the name as its only SAN is what `openssl req
// -subj /` produces; it is the same request.
func TestEmergencyServerAcceptsAnEmptySubject(t *testing.T) {
	spec, _, root, key := emergencyFixture(t)
	_, err := PrepareEmergencyServer(spec, root, emergencyCSR(t, key, &x509.CertificateRequest{DNSNames: []string{emergencyName}}))
	require.NoError(t, err)
}

func TestEmergencyServerRefusesAnythingElse(t *testing.T) {
	spec, _, root, key := emergencyFixture(t)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for name, csr := range map[string][]byte{
		"a P-256 key":         emergencyCSR(t, p256, &x509.CertificateRequest{DNSNames: []string{emergencyName}}),
		"another name":        emergencyCSR(t, key, &x509.CertificateRequest{DNSNames: []string{emergencyName, "openbao.openbao.svc"}}),
		"an IP address":       emergencyCSR(t, key, &x509.CertificateRequest{DNSNames: []string{emergencyName}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}),
		"another common name": emergencyCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "openbao"}}),
		"an organization":     emergencyCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: emergencyName, Organization: []string{"x"}}}),
		"not a request":       []byte("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := PrepareEmergencyServer(spec, root, csr)
			assert.Error(t, err)
		})
	}

	rootKey := fixtureKey(t, 0x11)
	_, err = PrepareEmergencyServer(spec, root, emergencyCSR(t, rootKey, &x509.CertificateRequest{DNSNames: []string{emergencyName}}))
	assert.ErrorContains(t, err, "root's own key")

	early := spec
	early.NotBefore = time.Date(2025, 8, 1, 0, 0, 0, 0, time.UTC)
	_, err = PrepareEmergencyServer(early, root, emergencyCSR(t, key, &x509.CertificateRequest{DNSNames: []string{emergencyName}}))
	assert.ErrorContains(t, err, "not within the root's")
}

func TestEmergencyServerSpecRefusals(t *testing.T) {
	_, _, root, key := emergencyFixture(t)
	csr := emergencyCSR(t, key, &x509.CertificateRequest{DNSNames: []string{emergencyName}})

	for name, mutate := range map[string]func(*EmergencyServerSpec){
		"a wildcard":            func(s *EmergencyServerSpec) { s.DNSName = "*.example.internal" },
		"a single label":        func(s *EmergencyServerSpec) { s.DNSName = "openbao" },
		"an empty label":        func(s *EmergencyServerSpec) { s.DNSName = "openbao..example.internal" },
		"an unpinned notBefore": func(s *EmergencyServerSpec) { s.NotBefore = time.Time{} },
		"no lifetime":           func(s *EmergencyServerSpec) { s.Lifetime = 0 },
		"a standing credential": func(s *EmergencyServerSpec) { s.Lifetime = MaxEmergencyServerLifetime + time.Hour },
		"another generation":    func(s *EmergencyServerSpec) { s.GenerationID = "example-root-2099-01" },
	} {
		t.Run(name, func(t *testing.T) {
			spec, _, _, _ := emergencyFixture(t)
			mutate(&spec)
			_, err := PrepareEmergencyServer(spec, root, csr)
			assert.Error(t, err)
		})
	}
}

// A root that constrains its names refuses a leaf outside them before
// anything is signed: that leaf would fail every verifier.
func TestEmergencyServerRefusesANameTheRootDoesNotPermit(t *testing.T) {
	spec, client, _, key := emergencyFixture(t)
	constrained := fixtureRoot(t, client, fixtureGeneration, fixtureRootOptions{
		maxPathLen:          fixtureRootMaxLen,
		permittedDNSDomains: []string{"example.com"},
	})
	_, err := PrepareEmergencyServer(spec, constrained, emergencyCSR(t, key, &x509.CertificateRequest{DNSNames: []string{emergencyName}}))
	assert.ErrorContains(t, err, "would fail every verifier")
}

// The KMS key must be the committed root's: a leaf of any other key would
// verify nowhere, and signing it would still fire the alarm.
func TestEmergencyServerRefusesAKeyThatIsNotTheRoot(t *testing.T) {
	spec, _, root, key := emergencyFixture(t)
	plan, err := PrepareEmergencyServer(spec, root, emergencyCSR(t, key, &x509.CertificateRequest{DNSNames: []string{emergencyName}}))
	require.NoError(t, err)

	other := newFakeKMS(t)
	_, err = SignEmergencyServer(context.Background(), other, plan, EmergencyServerOptions{KeyARN: fixtureKeyARN, ConfirmTemplateSHA256: plan.TemplateSHA256})
	require.ErrorContains(t, err, "not the key behind the committed root")
	assert.Zero(t, other.signCalls)
}
