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
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/truvity/openbao/pkg/ceremony"
)

const testDNSName = "openbao.example.internal"

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

func newTestChain(t *testing.T, notBefore time.Time, lifetime time.Duration) testChain {
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

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: testDNSName},
		DNSNames:              []string{testDNSName},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
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
		yes:             true,
		in:              strings.NewReader(""),
		now:             func() time.Time { return now },
		kube:            kube,
	}
}

func fakeKube(clientset kubernetes.Interface) kubeFactory {
	return func(string, string) (kubernetes.Interface, error) { return clientset, nil }
}

func TestRunInstallEmergencyServer_CreatesSecret(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)
	clientset := fake.NewSimpleClientset()

	var out bytes.Buffer
	require.NoError(t, runInstallEmergencyServer(context.Background(), &out, baseOptions(t, chain, now, fakeKube(clientset))))

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
	require.NoError(t, runInstallEmergencyServer(context.Background(), &out, baseOptions(t, chain, now, fakeKube(clientset))))

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

	options := baseOptions(t, chain, now, fakeKube(fake.NewSimpleClientset()))
	options.privateKeyPath = writeTemp(t, "other.key", other.keyPEM)

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestRunInstallEmergencyServer_RefusesWrongChain(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)
	other := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)

	options := baseOptions(t, chain, now, fakeKube(fake.NewSimpleClientset()))
	options.caBundlePath = writeTemp(t, "wrong-ca.crt", other.rootPEM)

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not chain")
}

func TestRunInstallEmergencyServer_RefusesExpired(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-48*time.Hour), 24*time.Hour) // NotAfter 24h ago

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, baseOptions(t, chain, now, fakeKube(fake.NewSimpleClientset())))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestRunInstallEmergencyServer_RefusesLifetimeOverCap(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), 45*24*time.Hour) // over the 30-day cap

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, baseOptions(t, chain, now, fakeKube(fake.NewSimpleClientset())))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cap")
}

func TestRunInstallEmergencyServer_RequiresConfirmation(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)

	options := baseOptions(t, chain, now, func(string, string) (kubernetes.Interface, error) {
		return nil, errors.New("kube must not be reached without confirmation")
	})
	options.yes = false
	options.in = strings.NewReader("no\n")

	err := runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not confirmed")
}

func TestRunInstallEmergencyServer_TypedConfirmationWrites(t *testing.T) {
	now := time.Now().UTC()
	chain := newTestChain(t, now.Add(-time.Hour), ceremony.DefaultEmergencyServerLifetime)
	clientset := fake.NewSimpleClientset()

	options := baseOptions(t, chain, now, fakeKube(clientset))
	options.yes = false
	options.in = strings.NewReader("yes\n")

	require.NoError(t, runInstallEmergencyServer(context.Background(), &bytes.Buffer{}, options))

	_, err := clientset.CoreV1().Secrets("test-ns").Get(context.Background(), defaultSecretName, metav1.GetOptions{})
	require.NoError(t, err)
}
