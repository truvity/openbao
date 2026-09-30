package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const chartPolicies = "../../tests/golden/openbao-consumers/approver-policy.yaml"

// requestFile writes one CertificateRequest for issuer/dns to a file.
func requestFile(t *testing.T, issuer, kind, dns string, curve elliptic.Curve) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{}, DNSNames: []string{dns},
	}, key)
	require.NoError(t, err)
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	body := fmt.Sprintf(`apiVersion: cert-manager.io/v1
kind: CertificateRequest
metadata: {name: leaf-1, namespace: app}
spec:
  duration: 720h
  request: %s
  issuerRef: {name: %s, kind: %s, group: cert-manager.io}
`, base64.StdEncoding.EncodeToString(csr), issuer, kind)
	path := filepath.Join(t.TempDir(), "crs.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func runCLI(t *testing.T, args ...string) (code int, out, errOut string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code = run(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestOfflineExitCodes(t *testing.T) {
	good := requestFile(t, "example-private", "ClusterIssuer", "api.east.example.internal", elliptic.P384())
	code, out, _ := runCLI(t, "--policies", chartPolicies, "--requests", good)
	assert.Equal(t, 0, code, out)
	assert.Contains(t, out, "approved: 1")
	assert.Contains(t, out, "OK:")

	bad := requestFile(t, "example-private", "ClusterIssuer", "api.evil.example.com", elliptic.P384())
	code, out, _ = runCLI(t, "--policies", chartPolicies, "--requests", bad)
	assert.Equal(t, 1, code, out)
	assert.Contains(t, out, "denied: 1")
	assert.Contains(t, out, "FAIL")

	orphan := requestFile(t, "example-unknown", "ClusterIssuer", "x.example.com", elliptic.P384())
	code, out, _ = runCLI(t, "--policies", chartPolicies, "--requests", orphan)
	assert.Equal(t, 1, code, out)
	assert.Contains(t, out, "unprocessed: 1")
}

func TestIdentitySignerIsSkippedOnlyWhenNamed(t *testing.T) {
	identity := requestFile(t, "example-identity", "ClusterIssuer", "x.example.com", elliptic.P256())

	code, out, _ := runCLI(t, "--policies", chartPolicies, "--requests", identity)
	assert.Equal(t, 1, code, "no policy covers it and nothing said another approver owns it: "+out)

	code, out, _ = runCLI(t, "--policies", chartPolicies, "--requests", identity, "--identity-signer", "clusterissuers.cert-manager.io/example-identity")
	assert.Equal(t, 0, code, out)
	assert.Contains(t, out, "skipped: 1")
}

// certificatesFile writes one Certificate for issuer/dns to a file.
func certificatesFile(t *testing.T, dns string) string {
	t.Helper()

	body := fmt.Sprintf(`apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: leaf}
spec:
  secretName: leaf
  duration: 720h
  dnsNames: [%s]
  privateKey: {algorithm: ECDSA, size: 384}
  issuerRef: {name: example-private, kind: ClusterIssuer, group: cert-manager.io}
`, dns)
	path := filepath.Join(t.TempDir(), "certs.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestCertificatesAreCheckedOffline(t *testing.T) {
	code, out, _ := runCLI(t, "--policies", chartPolicies, "--certificates", certificatesFile(t, "api.east.example.internal"), "--namespace", "ci-tenant")
	assert.Equal(t, 0, code, out)
	assert.Contains(t, out, "ci-tenant/leaf-1")
	assert.Contains(t, out, "approved: 1")

	code, out, _ = runCLI(t, "--policies", chartPolicies, "--certificates", certificatesFile(t, "api.evil.example.com"))
	assert.Equal(t, 1, code, out)
	assert.Contains(t, out, "denied: 1")

	// Requests and certificates are checked together.
	good := requestFile(t, "example-private", "ClusterIssuer", "api.east.example.internal", elliptic.P384())
	code, out, _ = runCLI(t, "--policies", chartPolicies, "--requests", good, "--certificates", certificatesFile(t, "api.east.example.internal"))
	assert.Equal(t, 0, code, out)
	assert.Contains(t, out, "approved: 2")
}

func TestPoliciesMayBeGivenMoreThanOnce(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.yaml")
	require.NoError(t, os.WriteFile(empty, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n"), 0o600))

	good := requestFile(t, "example-private", "ClusterIssuer", "api.east.example.internal", elliptic.P384())
	code, out, _ := runCLI(t, "--policies", empty, "--policies", chartPolicies, "--requests", good)
	assert.Equal(t, 0, code, out)
	assert.Contains(t, out, "3 policies")
}

func TestUsageErrors(t *testing.T) {
	good := requestFile(t, "example-private", "ClusterIssuer", "api.east.example.internal", elliptic.P384())
	for name, args := range map[string][]string{
		"no policies":               {"--requests", good},
		"neither requests nor live": {"--policies", chartPolicies},
		"both requests and live":    {"--policies", chartPolicies, "--requests", good, "--live"},
		"certificates and live":     {"--policies", chartPolicies, "--certificates", "x.yaml", "--live"},
		"namespace alone":           {"--policies", chartPolicies, "--requests", good, "--namespace", "x"},
		"certificates missing":      {"--policies", chartPolicies, "--certificates", "/nonexistent.yaml"},
		"context without live":      {"--policies", chartPolicies, "--requests", good, "--context", "x"},
		"blanket check offline":     {"--policies", chartPolicies, "--requests", good, "--require-blanket-approver-off"},
		"policies file missing":     {"--policies", "/nonexistent.yaml", "--requests", good},
		"requests file missing":     {"--policies", chartPolicies, "--requests", "/nonexistent.yaml"},
		"unknown flag":              {"--bogus"},
	} {
		code, _, _ := runCLI(t, args...)
		assert.Equal(t, 2, code, name)
	}
}

// writeKubeconfig writes two clusters, current-context on "first".
func writeKubeconfig(t *testing.T) string {
	t.Helper()

	cfg := clientcmdapi.NewConfig()
	for name, server := range map[string]string{"first": "https://first.example.internal:6443", "second": "https://second.example.internal:6443"} {
		cfg.Clusters[name] = &clientcmdapi.Cluster{Server: server}
		cfg.AuthInfos[name] = &clientcmdapi.AuthInfo{Token: "t"}
		cfg.Contexts[name] = &clientcmdapi.Context{Cluster: name, AuthInfo: name}
	}
	cfg.CurrentContext = "first"

	path := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, clientcmd.WriteToFile(*cfg, path))
	return path
}

// The trap --context exists for: without it the kubeconfig's
// current-context decides which cluster is checked.
func TestContextSelectsTheClusterAndTheRunSaysWhich(t *testing.T) {
	path := writeKubeconfig(t)

	_, _, target, err := buildClients(path, "")
	require.NoError(t, err)
	assert.Contains(t, target, `context "first"`)
	assert.Contains(t, target, "first.example.internal")

	_, _, target, err = buildClients(path, "second")
	require.NoError(t, err)
	assert.Contains(t, target, `context "second"`)
	assert.Contains(t, target, "second.example.internal")

	_, _, _, err = buildClients(path, "third")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `no context "third"`)
}

const extraPolicies = "../../tests/golden/openbao-consumers/approver-extra-policies.yaml"

// commonNameRequest writes one CertificateRequest that carries a
// commonName and nothing else -- the shape a per-database CA policy allows.
func commonNameRequest(t *testing.T, namespace, issuer, kind, cn string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	require.NoError(t, err)
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	body := fmt.Sprintf(`apiVersion: cert-manager.io/v1
kind: CertificateRequest
metadata: {name: leaf-1, namespace: %s}
spec:
  duration: 720h
  usages: [digital signature, key encipherment]
  request: %s
  issuerRef: {name: %s, kind: %s, group: cert-manager.io}
`, namespace, base64.StdEncoding.EncodeToString(csr), issuer, kind)
	path := filepath.Join(t.TempDir(), "crs.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// approverPolicy.extraPolicies render policies approvercheck evaluates like
// any other: the issuer, the namespace and the commonName all count.
func TestExtraPoliciesAreEvaluated(t *testing.T) {
	ok := commonNameRequest(t, "example-app", "example-selfsigned-bootstrap", "ClusterIssuer", "example-app")
	code, out, _ := runCLI(t, "--policies", extraPolicies, "--requests", ok)
	assert.Equal(t, 0, code, out)
	assert.Contains(t, out, "approved: 1")

	// The same request from another namespace rides no policy.
	elsewhere := commonNameRequest(t, "other", "example-selfsigned-bootstrap", "ClusterIssuer", "example-app")
	code, out, _ = runCLI(t, "--policies", extraPolicies, "--requests", elsewhere)
	assert.Equal(t, 1, code, out)

	// A commonName the policy does not name is denied.
	wrongCN := commonNameRequest(t, "example-app", "example-selfsigned-bootstrap", "ClusterIssuer", "somebody-else")
	code, out, _ = runCLI(t, "--policies", extraPolicies, "--requests", wrongCN)
	assert.Equal(t, 1, code, out)
	assert.Contains(t, out, "denied: 1")

	// The per-database CA policy: a namespaced Issuer, its namespace only.
	db := commonNameRequest(t, "example-db", "example-db-ca", "Issuer", "example-db-primary")
	code, out, _ = runCLI(t, "--policies", extraPolicies, "--requests", db)
	assert.Equal(t, 0, code, out)
	dbElsewhere := commonNameRequest(t, "example-app", "example-db-ca", "Issuer", "example-db-primary")
	code, _, _ = runCLI(t, "--policies", extraPolicies, "--requests", dbElsewhere)
	assert.Equal(t, 1, code)
}
