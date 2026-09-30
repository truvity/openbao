package approvercheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certificatesFile writes a rendered set of Certificates: a good leaf, a
// leaf that names no key (cert-manager's default is RSA, which the chart's
// policies refuse), a leaf with a foreign host, and a CA.
func certificatesFile(t *testing.T) string {
	t.Helper()

	body := `---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: good, namespace: from-chart}
spec:
  secretName: good
  duration: 720h
  dnsNames: [api.east.example.internal]
  privateKey: {algorithm: ECDSA, size: 384}
  issuerRef: {name: example-private, kind: ClusterIssuer, group: cert-manager.io}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: default-key}
spec:
  secretName: default-key
  duration: 720h
  dnsNames: [api.east.example.internal]
  issuerRef: {name: example-private, kind: ClusterIssuer, group: cert-manager.io}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: foreign}
spec:
  secretName: foreign
  duration: 720h
  dnsNames: [api.evil.example.com]
  privateKey: {algorithm: ECDSA, size: 384}
  issuerRef: {name: example-private, kind: ClusterIssuer, group: cert-manager.io}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: not-a-certificate}
`
	path := filepath.Join(t.TempDir(), "certs.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestRequestsForCertificatesAreDecidedLikeTheRealOnes(t *testing.T) {
	certs, err := LoadCertificates(certificatesFile(t))
	require.NoError(t, err)
	require.Len(t, certs, 3)

	requests, err := RequestsForCertificates(certs, "")
	require.NoError(t, err)
	require.Len(t, requests, 3)
	assert.Equal(t, "good-1", requests[0].Name)
	assert.Equal(t, "from-chart", requests[0].Namespace, "the Certificate's own namespace")

	policies := loadChartPolicies(t)
	want := map[string]string{"good-1": OutcomeApproved, "default-key-1": OutcomeDenied, "foreign-1": OutcomeDenied}
	for i := range requests {
		res := Review(context.Background(), nil, policies, &requests[i], Options{})
		assert.Equal(t, want[requests[i].Name], res.Outcome, res.String())
	}

	// The default key is RSA, the reason the second one is refused.
	res := Review(context.Background(), nil, policies, &requests[1], Options{})
	assert.Contains(t, res.Detail, "algorithm")
}

func TestRequestsForCertificatesNamespaceOverrides(t *testing.T) {
	certs, err := LoadCertificates(certificatesFile(t))
	require.NoError(t, err)

	requests, err := RequestsForCertificates(certs, "ci-tenant")
	require.NoError(t, err)
	for _, cr := range requests {
		assert.Equal(t, "ci-tenant", cr.Namespace)
	}
}

func TestRequestsForCertificatesCarryTheCAShapeAndSubject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: ca, namespace: app}
spec:
  secretName: ca
  isCA: true
  commonName: ca
  duration: 720h
  usages: [cert sign]
  subject: {organizations: [Example B.V.], countries: [NL]}
  uris: ["https://example.com/"]
  ipAddresses: ["192.0.2.1"]
  privateKey: {algorithm: ECDSA, size: 256}
  issuerRef: {name: example-private, kind: ClusterIssuer, group: cert-manager.io}
`), 0o600))
	certs, err := LoadCertificates(path)
	require.NoError(t, err)

	requests, err := RequestsForCertificates(certs, "")
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.True(t, requests[0].Spec.IsCA)

	csr, err := decodeCSR(requests[0].Spec.Request)
	require.NoError(t, err)
	assert.Equal(t, []string{"Example B.V."}, csr.Subject.Organization)
	assert.Equal(t, []string{"NL"}, csr.Subject.Country)
	require.Len(t, csr.URIs, 1)
	require.Len(t, csr.IPAddresses, 1)
	alg, size, err := publicKeyAlgorithmAndSize(csr.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", string(alg))
	assert.Equal(t, 256, size)
}

const certificateHead = "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: c}\nspec:\n  secretName: c\n  "

func TestRequestsForCertificatesRefuseWhatItCannotBuild(t *testing.T) {
	for name, body := range map[string]string{
		"bad curve":   "privateKey: {algorithm: ECDSA, size: 100}",
		"weak rsa":    "privateKey: {algorithm: RSA, size: 1024}",
		"bad alg":     "privateKey: {algorithm: DSA}",
		"bad address": "ipAddresses: [not-an-ip]",
	} {
		path := filepath.Join(t.TempDir(), "c.yaml")
		require.NoError(t, os.WriteFile(path, []byte(certificateHead+body+"\n"), 0o600))
		certs, err := LoadCertificates(path)
		require.NoError(t, err, name)
		_, err = RequestsForCertificates(certs, "")
		assert.Error(t, err, name)
	}
}

func TestLoadCertificatesRefusesAFileWithNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "none.yaml")
	require.NoError(t, os.WriteFile(path, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n"), 0o600))
	_, err := LoadCertificates(path)
	assert.ErrorContains(t, err, "no Certificate documents")
}

func TestLoadPolicyFiles(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.yaml")
	require.NoError(t, os.WriteFile(empty, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n"), 0o600))

	// One path is LoadPolicies, an empty file included.
	_, err := LoadPolicyFiles(empty)
	assert.ErrorContains(t, err, "no CertificateRequestPolicy documents found")

	// An empty piece is tolerated next to a full one, in either order.
	for _, paths := range [][]string{{chartPolicies, empty}, {empty, chartPolicies}} {
		policies, err := LoadPolicyFiles(paths...)
		require.NoError(t, err)
		assert.Len(t, policies, 3)
	}

	// The same file twice is twice the policies: the caller's business.
	policies, err := LoadPolicyFiles(chartPolicies, chartPolicies)
	require.NoError(t, err)
	assert.Len(t, policies, 6)

	// No policy anywhere, and a file that cannot be read, are errors.
	_, err = LoadPolicyFiles(empty, empty)
	assert.ErrorContains(t, err, "no CertificateRequestPolicy documents found")
	_, err = LoadPolicyFiles(chartPolicies, "/nonexistent.yaml")
	assert.Error(t, err)
}
