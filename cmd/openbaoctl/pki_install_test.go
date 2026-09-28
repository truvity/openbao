package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/truvity/openbao/pkg/ceremony"
)

const (
	testDNSName     = "openbao.example.internal"
	testKubeContext = "test-context"
	testServer      = "https://cluster.example:6443"
)

// testChain is one self-signed test root and one leaf it signed, the way
// sign-emergency-server's output and an operator's openssl key would
// arrive on disk.
type testChain struct {
	rootCert *x509.Certificate
	rootPEM  []byte

	leafCert *x509.Certificate
	leafPEM  []byte
	keyPEM   []byte
}

// newTestRoot is a throwaway self-signed P-384 CA, the stand-in for the
// KMS root in these tests.
func newTestRoot(t *testing.T, notBefore time.Time) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test break-glass root"},
		NotBefore:             notBefore.Add(-24 * time.Hour),
		NotAfter:              notBefore.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01},
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	return rootKey, rootCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}

// newTestLeaf signs one break-glass-shaped leaf under rootCert/rootKey.
// isCA lets a test build the one shape install-emergency-server must
// refuse: a "leaf" that is itself a CA.
func newTestLeaf(
	t *testing.T, rootKey *ecdsa.PrivateKey, rootCert *x509.Certificate, notBefore time.Time, lifetime time.Duration, isCA bool,
) (*x509.Certificate, []byte, []byte) {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	keyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		keyUsage |= x509.KeyUsageCertSign
	}

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: testDNSName},
		DNSNames:              []string{testDNSName},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(lifetime),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		AuthorityKeyId:        rootCert.SubjectKeyId,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return leafCert, leafPEM, keyPEM
}

func newTestChain(t *testing.T, notBefore time.Time, lifetime time.Duration) testChain {
	t.Helper()

	rootKey, rootCert, rootPEM := newTestRoot(t, notBefore)
	leafCert, leafPEM, keyPEM := newTestLeaf(t, rootKey, rootCert, notBefore, lifetime, false)

	return testChain{rootCert: rootCert, rootPEM: rootPEM, leafCert: leafCert, leafPEM: leafPEM, keyPEM: keyPEM}
}

func writeTemp(t *testing.T, name string, content []byte) string {
	t.Helper()

	path := t.TempDir() + "/" + name
	require.NoError(t, writeNew(path, content))

	return path
}

func baseOptions(t *testing.T, chain testChain, now time.Time, kube kubeFactory) installEmergencyServerOptions {
	t.Helper()

	return installEmergencyServerOptions{
		certificatePath: writeTemp(t, "tls.crt", chain.leafPEM),
		privateKeyPath:  writeTemp(t, "tls.key", chain.keyPEM),
		caBundlePath:    writeTemp(t, "ca.crt", chain.rootPEM),
		namespace:       "test-ns",
		secretName:      defaultSecretName,
		certKey:         defaultCertDataKey,
		keyKey:          defaultKeyDataKey,
		caKey:           defaultCADataKey,
		kubeContext:     testKubeContext,
		yes:             true,
		in:              strings.NewReader(""),
		now:             func() time.Time { return now },
		kube:            kube,
	}
}

// fakeKube is the test kubeFactory: a fake clientset plus a stub server
// URL, standing in for what clientcmd would have resolved a real context
// to.
func fakeKube(clientset kubernetes.Interface, server string) kubeFactory {
	return func(string, string) (kubernetes.Interface, string, error) { return clientset, server, nil }
}

func TestRunInstallEmergencyServer_CreatesSecret(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)
	clientset := fake.NewSimpleClientset()

	var out bytes.Buffer
	require.NoError(t, runInstallEmergencyServer(context.Background(), &out, baseOptions(t, chain, now, fakeKube(clientset, testServer))))

	secret, err := clientset.CoreV1().Secrets("test-ns").Get(context.Background(), defaultSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, corev1.SecretTypeTLS, secret.Type)
	assert.Equal(t, chain.leafPEM, secret.Data[defaultCertDataKey])
	assert.Equal(t, chain.keyPEM, secret.Data[defaultKeyDataKey])
	assert.Equal(t, chain.rootPEM, secret.Data[defaultCADataKey])

	assert.Contains(t, out.String(), "created Secret test-ns/"+defaultSecretName)
	assert.NotContains(t, out.String(), string(chain.keyPEM), "the private key must never be printed")
}

func TestRunInstallEmergencyServer_UpdatesSecretPreservingMetadata(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)

	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        defaultSecretName,
			Namespace:   "test-ns",
			Annotations: map[string]string{"cert-manager.io/certificate-name": "openbao-tls"},
			Labels:      map[string]string{"app.kubernetes.io/managed-by": "cert-manager"},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			defaultCertDataKey: []byte("stale certificate"),
			defaultKeyDataKey:  []byte("stale key"),
			defaultCADataKey:   []byte("stale ca"),
			"extra":            []byte("keep me"),
		},
	}
	clientset := fake.NewSimpleClientset(existing)

	var out bytes.Buffer
	require.NoError(t, runInstallEmergencyServer(context.Background(), &out, baseOptions(t, chain, now, fakeKube(clientset, testServer))))

	secret, err := clientset.CoreV1().Secrets("test-ns").Get(context.Background(), defaultSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "openbao-tls", secret.Annotations["cert-manager.io/certificate-name"])
	assert.Equal(t, "cert-manager", secret.Labels["app.kubernetes.io/managed-by"])
	assert.Equal(t, []byte("keep me"), secret.Data["extra"])
	assert.Equal(t, chain.leafPEM, secret.Data[defaultCertDataKey])
	assert.Contains(t, out.String(), "updated Secret test-ns/"+defaultSecretName)
}

func TestRunInstallEmergencyServer_RefusesKeyMismatch(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)
	other := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)

	options := baseOptions(t, chain, now, fakeKube(fake.NewSimpleClientset(), testServer))
	options.privateKeyPath = writeTemp(t, "other.key", other.keyPEM)

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestRunInstallEmergencyServer_RefusesWrongChain(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)
	other := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)

	options := baseOptions(t, chain, now, fakeKube(fake.NewSimpleClientset(), testServer))
	options.caBundlePath = writeTemp(t, "wrong-ca.crt", other.rootPEM)

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not chain")
}

func TestRunInstallEmergencyServer_RefusesExpired(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-48*time.Hour), 24*time.Hour) // NotAfter 24h ago

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, baseOptions(t, chain, now, fakeKube(fake.NewSimpleClientset(), testServer)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestRunInstallEmergencyServer_RefusesLifetimeOverCap(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), 45*24*time.Hour) // over the 30-day cap

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, baseOptions(t, chain, now, fakeKube(fake.NewSimpleClientset(), testServer)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cap")
}

func TestRunInstallEmergencyServer_RequiresConfirmation(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)
	clientset := fake.NewSimpleClientset()

	options := baseOptions(t, chain, now, fakeKube(clientset, testServer))
	options.yes = false
	options.in = strings.NewReader("no\n")

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not confirmed")

	_, getErr := clientset.CoreV1().Secrets("test-ns").Get(context.Background(), defaultSecretName, metav1.GetOptions{})
	assert.True(t, apierrors.IsNotFound(getErr), "nothing should be written without confirmation")
}

func TestRunInstallEmergencyServer_RefusesEmptyKubeContext(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)

	options := baseOptions(t, chain, now, fakeKube(fake.NewSimpleClientset(), testServer))
	options.kubeContext = ""

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--kube-context")
	assert.Contains(t, err.Error(), "required")
}

func TestRunInstallEmergencyServer_PlanNamesTheClusterContextAndServer(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)

	var out bytes.Buffer
	options := baseOptions(t, chain, now, fakeKube(fake.NewSimpleClientset(), testServer))
	require.NoError(t, runInstallEmergencyServer(context.Background(), &out, options))

	assert.Contains(t, out.String(), "context:")
	assert.Contains(t, out.String(), testKubeContext)
	assert.Contains(t, out.String(), "api server:")
	assert.Contains(t, out.String(), testServer)
}

func TestRunInstallEmergencyServer_RefusesCALeaf(t *testing.T) {
	now := time.Now().UTC()
	notBefore := now.Add(-time.Hour)
	rootKey, rootCert, rootPEM := newTestRoot(t, notBefore)
	_, leafPEM, keyPEM := newTestLeaf(t, rootKey, rootCert, notBefore, ceremony.DefaultEmergencyServerLifetime, true)

	options := installEmergencyServerOptions{
		certificatePath: writeTemp(t, "tls.crt", leafPEM),
		privateKeyPath:  writeTemp(t, "tls.key", keyPEM),
		caBundlePath:    writeTemp(t, "ca.crt", rootPEM),
		namespace:       "test-ns",
		secretName:      defaultSecretName,
		certKey:         defaultCertDataKey,
		keyKey:          defaultKeyDataKey,
		caKey:           defaultCADataKey,
		kubeContext:     testKubeContext,
		yes:             true,
		in:              strings.NewReader(""),
		now:             func() time.Time { return now },
		kube:            fakeKube(fake.NewSimpleClientset(), testServer),
	}

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CA")
}

func TestRunInstallEmergencyServer_TypedConfirmationWrites(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)
	clientset := fake.NewSimpleClientset()

	options := baseOptions(t, chain, now, fakeKube(clientset, testServer))
	options.yes = false
	options.in = strings.NewReader("yes\n")

	require.NoError(t, runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, options))

	_, err := clientset.CoreV1().Secrets("test-ns").Get(context.Background(), defaultSecretName, metav1.GetOptions{})
	require.NoError(t, err)
}
