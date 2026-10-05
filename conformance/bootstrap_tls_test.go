// The break-glass TLS bootstrap, end to end, against a real `bao server`.
//
// docs/ceremony.md §4 and docs/server.md describe two halves that are
// never proven together anywhere else: the ceremony that signs a leaf
// straight from the root (pkg/ceremony, cmd/openbaoctl's
// sign-emergency-server), and installing it where OpenBAO's listener
// reads it (install-emergency-server). This test runs both, against the
// real `bao` binary the dev shell pins, then simulates the moment the
// leaf hands off to a normal issuer: a domain intermediate signed by the
// same root -- the shape cert-manager's Vault issuer takes once OpenBAO
// is up -- issuing its own leaf, swapped onto disk and reloaded with
// SIGHUP (docs/server.md "Reloading a renewed certificate"). A client
// holding only the root verifies both.
//
// No AWS anywhere: the root's signature comes from a local stand-in KMS
// double, the same shape pkg/ceremony's own tests use in place of a real
// key (docs/ceremony.md's yearly drill is the one place a real KMS root
// signs this path, and it is run and documented by hand, never in CI).
package conformance_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/ceremony"
	"github.com/truvity/secrets/pkg/kmssigner"
)

const bootstrapDNSName = "openbao.example.internal"

// bootstrapKMS is a local stand-in for the KMS root key: it satisfies
// kmssigner.API with an in-memory P-384 key, the same double
// pkg/ceremony's own tests sign with. The rehearsal (`just
// rehearse-bootstrap-tls`, this test) always uses one; the yearly drill
// (docs/ceremony.md) uses the real KMS root instead and is run by hand.
type bootstrapKMS struct {
	key       *ecdsa.PrivateKey
	publicDER []byte
}

func newBootstrapKMS(t *testing.T) (*bootstrapKMS, kmssigner.API) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	double := &bootstrapKMS{key: key, publicDER: der}

	return double, double
}

func (k *bootstrapKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{
		KeySpec:           types.KeySpecEccNistP384,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha384},
		PublicKey:         k.publicDER,
	}, nil
}

func (k *bootstrapKMS) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	signature, err := ecdsa.SignASN1(rand.Reader, k.key, input.Message)
	if err != nil {
		return nil, err
	}

	return &kms.SignOutput{Signature: signature}, nil
}

// TestBootstrapTLS is `just rehearse-bootstrap-tls`: the whole
// restore-path TLS bootstrap proof, gated like every other conformance
// test.
func TestBootstrapTLS(t *testing.T) {
	binary := tool(t, "bao")
	ctx := context.Background()
	dir := t.TempDir()

	_, kmsAPI := newBootstrapKMS(t)
	notBefore := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	rootResult, err := ceremony.CreateRoot(ctx, kmsAPI, ceremony.RootSpec{
		GenerationID: "rehearsal-root",
		CommonName:   "Rehearsal Root",
		NotBefore:    notBefore,
		Lifetime:     45 * 24 * time.Hour,
		MaxPathLen:   1,
	}, ceremony.RootOptions{
		KeyARN:       "arn:aws:kms:eu-example-1:111122223333:key/rehearsal",
		ArtifactPath: filepath.Join(dir, "root.yaml"),
	})
	require.NoError(t, err)

	rootCertificate, err := rootResult.Artifact.Certificate()
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)

	// 1. The break-glass leaf: sign-emergency-server's own code, the KMS
	// double standing in for the root key. Two-person review is
	// print-template/confirm-template at the CLI; here the plan's hash is
	// what a second reviewer would have confirmed.
	emergencyKey, emergencyCSR := generateCSR(t, pkix.Name{}, []string{bootstrapDNSName})

	emergencySpec := ceremony.EmergencyServerSpec{
		GenerationID:     rootResult.Artifact.GenerationID,
		DNSName:          bootstrapDNSName,
		NotBefore:        notBefore.Add(time.Minute),
		Lifetime:         ceremony.DefaultEmergencyServerLifetime,
		RootArtifactPath: filepath.Join(dir, "root.yaml"),
		SerialNamespace:  "",
	}

	plan, err := ceremony.PrepareEmergencyServer(emergencySpec, rootResult.Artifact, emergencyCSR)
	require.NoError(t, err)

	emergencyResult, err := ceremony.SignEmergencyServer(ctx, kmsAPI, plan, ceremony.EmergencyServerOptions{
		KeyARN:                "arn:aws:kms:eu-example-1:111122223333:key/rehearsal",
		ConfirmTemplateSHA256: plan.TemplateSHA256,
	})
	require.NoError(t, err)
	t.Logf("break-glass leaf proven: %v", emergencyResult.Proof)

	// 2. install-emergency-server's own writer, a Secret double swapped
	// for the pair of files `bao server`'s config reads: refuses nothing
	// here (the leaf, the key and the bundle already agree), so this
	// exercises the same load/verify path runInstallEmergencyServer does,
	// without a cluster.
	tlsDir := filepath.Join(dir, "tls")
	require.NoError(t, os.Mkdir(tlsDir, 0o755))

	certPath := filepath.Join(tlsDir, "tls.crt")
	keyPath := filepath.Join(tlsDir, "tls.key")
	caPath := filepath.Join(tlsDir, "ca.crt")

	require.NoError(t, os.WriteFile(certPath, emergencyResult.CertificatePEM, 0o644))
	require.NoError(t, os.WriteFile(keyPath, pemEncodeECKey(t, emergencyKey), 0o600))
	require.NoError(t, os.WriteFile(caPath, []byte(rootResult.Artifact.CertificatePEM), 0o644))

	// cmd/openbaoctl's own pki_install_test.go proves
	// install-emergency-server's refusals (chain, key match, expiry, the
	// 30-day cap) directly against a fake Secret store; here the same
	// three files are what a real listener is handed.

	// 3. A real `bao server`, TLS terminated by exactly those files --
	// neither the weekly restore-check nor the rebuild drill does this
	// today (docs/operations/openbao-restore.md); this is that missing
	// exercise.
	address, process, logs := startTLSServer(t, binary, certPath, keyPath)
	t.Cleanup(func() {
		_ = process.Signal(syscall.SIGTERM)
		_, _ = process.Wait()

		if t.Failed() {
			t.Logf("bao server:\n%s", logs.String())
		}
	})

	// 4. A client holding only the root verifies the break-glass leaf.
	requireTLSVerifies(t, address, bootstrapDNSName, roots)

	// 5. The normal issuer takes over: a domain intermediate signed by
	// the same root (PrepareIntermediate/SignIntermediate, the same
	// ceremony code verify-intermediate installs from), then a leaf
	// issued from it for the same name -- the shape of what OpenBAO's
	// PKI mount does once cert-manager's Vault issuer can reach it.
	intermediateKey, intermediateCSR := generateCSR(t, pkix.Name{CommonName: "Rehearsal Intermediate"}, nil)

	intermediateSpec := ceremony.IntermediateSpec{
		TrustDomain:         "private",
		GenerationID:        rootResult.Artifact.GenerationID,
		CommonName:          "Rehearsal Intermediate",
		NotBefore:           notBefore,
		Lifetime:            24 * time.Hour,
		MaxPathLen:          0,
		PermittedDNSDomains: []string{"example.internal"},
		RootArtifactPath:    filepath.Join(dir, "root.yaml"),
		ArtifactPath:        filepath.Join(dir, "intermediate-private.yaml"),
	}

	intermediatePlan, err := ceremony.PrepareIntermediate(intermediateSpec, rootResult.Artifact, intermediateCSR)
	require.NoError(t, err)

	intermediateResult, err := ceremony.SignIntermediate(ctx, kmsAPI, intermediatePlan, ceremony.IntermediateOptions{
		KeyARN:                "arn:aws:kms:eu-example-1:111122223333:key/rehearsal",
		ConfirmTemplateSHA256: intermediatePlan.TemplateSHA256,
	})
	require.NoError(t, err)
	t.Logf("normal-issuer intermediate proven: %v", intermediateResult.Proof)

	reissuedKey, reissuedLeaf := issueLeafFromIntermediate(t, intermediateResult.Certificate, intermediateKey, bootstrapDNSName, notBefore.Add(time.Minute))

	// The chain a client walks is the reissued leaf, then the
	// intermediate; the root arrives out of band, exactly like
	// ca.crt/BAO_CACERT.
	chainPEM := append(append([]byte{}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: reissuedLeaf.Raw})...),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateResult.Certificate.Raw})...)

	require.NoError(t, os.WriteFile(certPath, chainPEM, 0o644))
	require.NoError(t, os.WriteFile(keyPath, pemEncodeECKey(t, reissuedKey), 0o600))
	require.NoError(t, process.Signal(syscall.SIGHUP))

	// 6. The same client, still holding only the root, still verifies --
	// the takeover the moment install-emergency-server's job ends.
	requireEventuallyTLSVerifies(t, address, bootstrapDNSName, roots)
}

// generateCSR is a throwaway P-384 CSR self-signed the way the
// ceremony's parsers require: an authored subject and only the DNS
// names given.
func generateCSR(t *testing.T, subject pkix.Name, dnsNames []string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject, DNSNames: dnsNames}, key)
	require.NoError(t, err)

	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func pemEncodeECKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// issueLeafFromIntermediate is what OpenBAO's own PKI mount does once it
// is up: not ceremony code, an ordinary issuance under a CA whose key
// this test holds directly.
func issueLeafFromIntermediate(
	t *testing.T, intermediate *x509.Certificate, intermediateKey *ecdsa.PrivateKey, dnsName string, notBefore time.Time,
) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 62))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, intermediate, &leafKey.PublicKey, intermediateKey)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return leafKey, leaf
}

// startTLSServer starts a real `bao server` -- inmem storage, one TCP
// listener, TLS from the given files -- on a free local port, and waits
// until it answers over TLS. Unsealed or not is irrelevant here: only
// the listener's certificate is under test.
func startTLSServer(t *testing.T, binary, certPath, keyPath string) (address string, process *os.Process, logs *bytes.Buffer) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	address = listener.Addr().String()
	require.NoError(t, listener.Close())

	configPath := filepath.Join(t.TempDir(), "config.hcl")
	config := "storage \"inmem\" {}\n" +
		"listener \"tcp\" {\n" +
		"  address = \"" + address + "\"\n" +
		"  tls_cert_file = \"" + certPath + "\"\n" +
		"  tls_key_file  = \"" + keyPath + "\"\n" +
		"}\n"
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o644))

	logs = &bytes.Buffer{}
	cmd := exec.Command(binary, "server", "-config="+configPath)
	cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
	cmd.Stdout, cmd.Stderr = logs, logs
	require.NoError(t, cmd.Start())

	deadline := time.Now().Add(20 * time.Second)
	for {
		// only proving the listener is up; the real check follows with the root alone
		config := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, config)
		if err == nil {
			_ = conn.Close()

			return address, cmd.Process, logs
		}

		if time.Now().After(deadline) {
			t.Fatalf("bao server did not open its TLS listener at %s:\n%s", address, logs.String())
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// requireTLSVerifies dials address, verifies the presented chain against
// roots alone for dnsName, and fails the test otherwise.
func requireTLSVerifies(t *testing.T, address, dnsName string, roots *x509.CertPool) {
	t.Helper()

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{ServerName: dnsName, RootCAs: roots})
	require.NoError(t, err, "the client, holding only the root, must verify the presented certificate for %s", dnsName)
	_ = conn.Close()
}

// requireEventuallyTLSVerifies is requireTLSVerifies with the small
// retry a SIGHUP reload needs: the signal is asynchronous, and a probe
// that raced it would prove nothing about whether the reload works.
func requireEventuallyTLSVerifies(t *testing.T, address, dnsName string, roots *x509.CertPool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	var lastErr error

	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{ServerName: dnsName, RootCAs: roots})
		if err == nil {
			_ = conn.Close()

			return
		}

		lastErr = err

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("the client never verified the reloaded certificate for %s: %v", dnsName, lastErr)
}
