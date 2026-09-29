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

func TestUsageErrors(t *testing.T) {
	good := requestFile(t, "example-private", "ClusterIssuer", "api.east.example.internal", elliptic.P384())
	for name, args := range map[string][]string{
		"no policies":               {"--requests", good},
		"neither requests nor live": {"--policies", chartPolicies},
		"both requests and live":    {"--policies", chartPolicies, "--requests", good, "--live"},
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
