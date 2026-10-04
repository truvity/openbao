package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/truvity/openbao/pkg/ceremony"
)

// fakeKMS is a stand-in for AWS KMS: it signs with an in-memory P-384 key
// behind the same interface pkg/kmssigner talks to. Nothing here reaches
// AWS. This is the same shape pkg/ceremony's own tests use, reimplemented
// here because it is a test-only, unexported type on that side.
type fakeKMS struct {
	privateKey *ecdsa.PrivateKey
	publicDER  []byte
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	return &fakeKMS{privateKey: privateKey, publicDER: publicDER}
}

func (c *fakeKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{
		KeySpec:           types.KeySpecEccNistP384,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha384},
		PublicKey:         c.publicDER,
	}, nil
}

func (c *fakeKMS) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	signature, err := ecdsa.SignASN1(rand.Reader, c.privateKey, input.Message)
	if err != nil {
		return nil, err
	}

	return &kms.SignOutput{Signature: signature}, nil
}

const fixtureKeyARN = "arn:aws:kms:eu-central-1:111122223333:key/mrk-fixture"

// newCSR builds a minimal P-384 certificate request carrying exactly the
// subject a ceremony spec authors (common name and organization): the
// ceremony checks the CSR's subject matches the spec's before it ever
// looks at KMS, and takes only the CSR's public key from there on.
func newCSR(t *testing.T, commonName, organization string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CSR key: %v", err)
	}

	subject := pkix.Name{CommonName: commonName}
	if organization != "" {
		subject.Organization = []string{organization}
	}

	template := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// ceremonyFixture is a validContract() rooted at a fresh temp directory,
// with its artifact directory created, ready for a real (fake-KMS-backed)
// ceremony to write into.
func ceremonyFixture(t *testing.T) *Contract {
	t.Helper()

	contract := validContract()
	contract.dir = t.TempDir()

	if err := os.MkdirAll(contract.ArtifactPath(""), 0o755); err != nil {
		t.Fatalf("mkdir artifact dir: %v", err)
	}

	return contract
}

func createTestRoot(t *testing.T, contract *Contract, client *fakeKMS) ceremony.RootArtifact {
	t.Helper()

	spec, err := contract.RootSpec("example-root-2026-01")
	if err != nil {
		t.Fatalf("RootSpec: %v", err)
	}

	result, err := ceremony.CreateRoot(context.Background(), client, spec, ceremony.RootOptions{
		KeyARN:       fixtureKeyARN,
		ArtifactPath: contract.RootArtifactPath("example-root-2026-01"),
	})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	if !result.Signed {
		t.Fatal("CreateRoot should have signed a fresh root")
	}

	return result.Artifact
}

func signTestIntermediate(t *testing.T, client *fakeKMS, spec ceremony.IntermediateSpec, root ceremony.RootArtifact) ceremony.IntermediateArtifact {
	t.Helper()

	csr := newCSR(t, spec.CommonName, spec.Organization)

	plan, err := ceremony.PrepareIntermediate(spec, root, csr)
	if err != nil {
		t.Fatalf("PrepareIntermediate: %v", err)
	}

	result, err := ceremony.SignIntermediate(context.Background(), client, plan, ceremony.IntermediateOptions{
		KeyARN:                fixtureKeyARN,
		ConfirmTemplateSHA256: plan.TemplateSHA256,
	})
	if err != nil {
		t.Fatalf("SignIntermediate: %v", err)
	}

	if !result.Signed {
		t.Fatal("SignIntermediate should have signed a fresh intermediate")
	}

	return result.Artifact
}

func TestTrustAnchorsRoundTrip(t *testing.T) {
	contract := ceremonyFixture(t)
	client := newFakeKMS(t)

	createTestRoot(t, contract, client)

	anchors, err := contract.TrustAnchors()
	if err != nil {
		t.Fatalf("TrustAnchors: %v", err)
	}

	if len(anchors) != 1 {
		t.Fatalf("TrustAnchors() = %d anchors, want 1", len(anchors))
	}

	if anchors[0].GenerationID != "example-root-2026-01" {
		t.Fatalf("anchor generation = %q", anchors[0].GenerationID)
	}

	if anchors[0].NotAfter.Before(time.Now()) {
		t.Fatalf("anchor should not be expired yet: %v", anchors[0].NotAfter)
	}
}

func TestTrustAnchorsRefusesUntrustedNameCollision(t *testing.T) {
	contract := ceremonyFixture(t)
	client := newFakeKMS(t)

	createTestRoot(t, contract, client)

	// Corrupt the artifact's recorded fingerprint in place: TrustAnchors
	// must re-derive the fingerprint from certificatePem and refuse a
	// mismatch, rather than trust the file on the strength of its path.
	path := contract.RootArtifactPath("example-root-2026-01")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}

	tampered := flipFingerprint(t, string(raw))
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write tampered artifact: %v", err)
	}

	if _, err := contract.TrustAnchors(); err == nil {
		t.Fatal("TrustAnchors should refuse a tampered artifact")
	}
}

// flipFingerprint corrupts the fingerprintSha256 line of a committed
// artifact by one hex character, leaving every other line untouched.
func flipFingerprint(t *testing.T, raw string) string {
	t.Helper()

	const marker = "fingerprintSha256: "

	at := strings.Index(raw, marker)
	if at < 0 {
		t.Fatal("artifact has no fingerprintSha256 field")
	}

	flip := at + len(marker) + 4 // well inside the hex digest, past any prefix

	digit := raw[flip]
	replacement := byte('0')

	if digit == '0' {
		replacement = '1'
	}

	return raw[:flip] + string(replacement) + raw[flip+1:]
}

func TestDNSIntermediateRoundTrip(t *testing.T) {
	contract := ceremonyFixture(t)
	client := newFakeKMS(t)

	root := createTestRoot(t, contract, client)

	spec, err := contract.DNSIntermediateSpec("internal", "example-root-2026-01")
	if err != nil {
		t.Fatalf("DNSIntermediateSpec: %v", err)
	}

	signed, err := IntermediateSigned(spec)
	if err != nil {
		t.Fatalf("IntermediateSigned: %v", err)
	}

	if signed {
		t.Fatal("IntermediateSigned should be false before the ceremony's second phase")
	}

	signTestIntermediate(t, client, spec, root)

	signed, err = IntermediateSigned(spec)
	if err != nil {
		t.Fatalf("IntermediateSigned: %v", err)
	}

	if !signed {
		t.Fatal("IntermediateSigned should be true once the artifact is committed")
	}

	result, err := contract.LoadSignedIntermediate(spec)
	if err != nil {
		t.Fatalf("LoadSignedIntermediate: %v", err)
	}

	if result.Certificate.Subject.CommonName != "internal.example.org Intermediate CA" {
		t.Fatalf("unexpected common name %q", result.Certificate.Subject.CommonName)
	}
}

func TestEnvironmentCARoundTrip(t *testing.T) {
	contract := ceremonyFixture(t)
	client := newFakeKMS(t)

	root := createTestRoot(t, contract, client)

	// The environment CA is signed directly by the root (no shared
	// intermediate step required first, by design: it is a peer of the
	// domain intermediate, not signed by it).
	spec, err := contract.EnvironmentCASpec("workload", "dev", "dev.internal.example.org", "example-root-2026-01")
	if err != nil {
		t.Fatalf("EnvironmentCASpec: %v", err)
	}

	if spec.TrustDomain != "workload-dev" {
		t.Fatalf("TrustDomain = %q, want %q", spec.TrustDomain, "workload-dev")
	}

	if got, want := filepath.Base(spec.ArtifactPath), "example-root-2026-01-intermediate-workload-dev.yaml"; got != want {
		t.Fatalf("artifact path = %q, want basename %q", got, want)
	}

	signTestIntermediate(t, client, spec, root)

	result, err := contract.LoadSignedIntermediate(spec)
	if err != nil {
		t.Fatalf("LoadSignedIntermediate: %v", err)
	}

	if result.Certificate.Subject.CommonName != "dev.internal.example.org Workload Identity CA" {
		t.Fatalf("unexpected common name %q", result.Certificate.Subject.CommonName)
	}
}

// TestEnvironmentCACustomArtifactPattern proves that an estate adopting a
// ceremony whose per-environment artifacts predate this package's naming
// convention can keep its existing file name exactly, with
// EnvironmentCA.ArtifactPattern, and needs no rename.
func TestEnvironmentCACustomArtifactPattern(t *testing.T) {
	contract := ceremonyFixture(t)
	client := newFakeKMS(t)

	// A legacy name shape unrelated to IntermediateArtifactName's own
	// convention: no "-intermediate-" infix, no domain name at all.
	contract.TrustDomains.URI[0].EnvironmentCA.ArtifactPattern = "{generation}-legacy-identity-{environment}.yaml"

	root := createTestRoot(t, contract, client)

	spec, err := contract.EnvironmentCASpec("workload", "dev", "dev.internal.example.org", "example-root-2026-01")
	if err != nil {
		t.Fatalf("EnvironmentCASpec: %v", err)
	}

	if got, want := filepath.Base(spec.ArtifactPath), "example-root-2026-01-legacy-identity-dev.yaml"; got != want {
		t.Fatalf("artifact path = %q, want basename %q", got, want)
	}

	signTestIntermediate(t, client, spec, root)

	if _, err := contract.LoadSignedIntermediate(spec); err != nil {
		t.Fatalf("LoadSignedIntermediate: %v", err)
	}
}

func TestEnvironmentCARefusesEnvironmentNotRootSigned(t *testing.T) {
	contract := ceremonyFixture(t)

	if _, err := contract.EnvironmentCASpec("workload", "prod", "prod.internal.example.org", "example-root-2026-01"); err == nil {
		t.Fatal("EnvironmentCASpec should refuse an environment not in rootSignedEnvironments")
	}
}

func TestSpecsCarryContractSerialNamespace(t *testing.T) {
	contract := ceremonyFixture(t)
	contract.SerialNamespace = "example-private-pki"

	rootSpec, err := contract.RootSpec("example-root-2026-01")
	if err != nil {
		t.Fatalf("RootSpec: %v", err)
	}

	if rootSpec.SerialNamespace != "example-private-pki" {
		t.Fatalf("RootSpec.SerialNamespace = %q", rootSpec.SerialNamespace)
	}

	dnsSpec, err := contract.DNSIntermediateSpec("internal", "example-root-2026-01")
	if err != nil {
		t.Fatalf("DNSIntermediateSpec: %v", err)
	}

	if dnsSpec.SerialNamespace != "example-private-pki" {
		t.Fatalf("DNSIntermediateSpec.SerialNamespace = %q", dnsSpec.SerialNamespace)
	}

	uriSpec, err := contract.URIIntermediateSpec("workload", "example-root-2026-01")
	if err != nil {
		t.Fatalf("URIIntermediateSpec: %v", err)
	}

	if uriSpec.SerialNamespace != "example-private-pki" {
		t.Fatalf("URIIntermediateSpec.SerialNamespace = %q", uriSpec.SerialNamespace)
	}

	caSpec, err := contract.EnvironmentCASpec("workload", "dev", "dev.internal.example.org", "example-root-2026-01")
	if err != nil {
		t.Fatalf("EnvironmentCASpec: %v", err)
	}

	if caSpec.SerialNamespace != "example-private-pki" {
		t.Fatalf("EnvironmentCASpec.SerialNamespace = %q", caSpec.SerialNamespace)
	}

	emergencySpec, err := contract.EmergencyServerSpec("example-root-2026-01", "emergency.edge.example.org", time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("EmergencyServerSpec: %v", err)
	}

	if emergencySpec.SerialNamespace != "example-private-pki" {
		t.Fatalf("EmergencyServerSpec.SerialNamespace = %q", emergencySpec.SerialNamespace)
	}
}

// One default, in one place: a contract that leaves serialNamespace out hands
// every ceremony spec an EMPTY namespace, so pkg/ceremony's own default
// (`private-pki`, documented as the default in docs/pki.md and
// docs/reference.md) is what every serial is derived under -- never a second
// default kept in this package.
func TestSpecsWithoutSerialNamespaceUseTheCeremonyDefault(t *testing.T) {
	if ceremony.DefaultSerialNamespace != "private-pki" {
		t.Fatalf("ceremony.DefaultSerialNamespace = %q: the docs name private-pki", ceremony.DefaultSerialNamespace)
	}

	contract := ceremonyFixture(t)
	contract.SerialNamespace = ""

	rootSpec, err := contract.RootSpec("example-root-2026-01")
	if err != nil {
		t.Fatalf("RootSpec: %v", err)
	}

	dnsSpec, err := contract.DNSIntermediateSpec("internal", "example-root-2026-01")
	if err != nil {
		t.Fatalf("DNSIntermediateSpec: %v", err)
	}

	caSpec, err := contract.EnvironmentCASpec("workload", "dev", "dev.internal.example.org", "example-root-2026-01")
	if err != nil {
		t.Fatalf("EnvironmentCASpec: %v", err)
	}

	for name, got := range map[string]string{"root": rootSpec.SerialNamespace, "dns": dnsSpec.SerialNamespace, "environment CA": caSpec.SerialNamespace} {
		if got != "" {
			t.Errorf("%s spec carries serial namespace %q, want empty (the ceremony default applies)", name, got)
		}
	}
}

func TestEmergencyServerSpec(t *testing.T) {
	contract := ceremonyFixture(t)
	notBefore := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	spec, err := contract.EmergencyServerSpec("example-root-2026-01", "emergency.edge.example.org", notBefore)
	if err != nil {
		t.Fatalf("EmergencyServerSpec: %v", err)
	}

	if spec.DNSName != "emergency.edge.example.org" {
		t.Fatalf("DNSName = %q", spec.DNSName)
	}

	if spec.Lifetime != ceremony.DefaultEmergencyServerLifetime {
		t.Fatalf("Lifetime = %v, want the default", spec.Lifetime)
	}
}

func TestEmergencyServerSpecRefusals(t *testing.T) {
	contract := ceremonyFixture(t)
	notBefore := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		dnsName string
	}{
		{"wildcard", "*.edge.example.org"},
		{"not under a require-trusted domain", "emergency.internal.example.org"},
		{"not under any domain", "emergency.example.net"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := contract.EmergencyServerSpec("example-root-2026-01", test.dnsName, notBefore); err == nil {
				t.Fatalf("EmergencyServerSpec(%q) should have been refused", test.dnsName)
			}
		})
	}
}
