// Package ceremony performs the certificate ceremonies of a private PKI
// whose root key lives in AWS KMS (ECC P-384, SIGN_VERIFY, multi-region)
// and never leaves it.
//
// There are three ceremonies, and each asks the root key for exactly one
// signature:
//
//   - CreateRoot: the root's self-signature, once per root generation.
//   - SignIntermediate: a domain intermediate from a CSR whose key never
//     leaves OpenBAO, in two steps -- PrepareIntermediate builds the exact
//     certificate and its template hash offline, and signing needs that
//     hash back (print-template, then confirm-template).
//   - SignEmergencyServer: the break-glass, a short-lived server leaf
//     straight from the root for the one moment OpenBAO cannot issue its
//     own serving certificate. Same two steps.
//
// Every committed ceremony writes a public artifact (RootArtifact,
// IntermediateArtifact) and, before it signs, a durable .attempt
// reservation next to it. The reservation is never removed: an ambiguous
// failure (the KMS call may or may not have produced a signature) fails
// closed on every rerun instead of asking the root key for a second one.
//
// Nothing here is a Pulumi resource and nothing runs during a preview. The
// KMS key and its custody (key policy, Sign alarm) are pkg/custody's.
package ceremony

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	// AttemptSuffix is appended to an artifact's path to name its signing
	// reservation.
	AttemptSuffix = ".attempt"

	// AttemptStatusReserved is the only status an attempt file carries: it
	// was written before the one signing call and is never rewritten.
	AttemptStatusReserved = "signing-reserved"

	// DefaultSerialNamespace prefixes the domain-separation labels of every
	// deterministic serial when a spec leaves SerialNamespace empty.
	DefaultSerialNamespace = "private-pki"

	artifactFileMode          = 0o644
	certificatePEMType        = "CERTIFICATE"
	certificateRequestPEMType = "CERTIFICATE REQUEST"
)

type (
	// RootArtifact is the complete public record of a root ceremony. It
	// intentionally contains no credential, private key material, digest or
	// signature request.
	RootArtifact struct {
		GenerationID         string `yaml:"generationId"`
		KeyARN               string `yaml:"keyArn"`
		CertificatePEM       string `yaml:"certificatePem"`
		FingerprintSHA256    string `yaml:"fingerprintSha256"`
		SubjectKeyIdentifier string `yaml:"subjectKeyIdentifier"`
		NotAfter             string `yaml:"notAfter"`
	}

	// IntermediateArtifact is the public record of one signed domain
	// intermediate. Like RootArtifact it holds no key material.
	IntermediateArtifact struct {
		GenerationID           string `yaml:"generationId"`
		TrustDomain            string `yaml:"trustDomain"`
		KeyARN                 string `yaml:"keyArn"`
		CertificatePEM         string `yaml:"certificatePem"`
		FingerprintSHA256      string `yaml:"fingerprintSha256"`
		SubjectKeyIdentifier   string `yaml:"subjectKeyIdentifier"`
		AuthorityKeyIdentifier string `yaml:"authorityKeyIdentifier"`
		TemplateSHA256         string `yaml:"templateSha256"`
		NotAfter               string `yaml:"notAfter"`
	}

	// Attempt is the durable public reservation written before the only
	// allowed KMS signing request. Its continued presence makes an ambiguous
	// failure fail closed instead of silently issuing a second signature.
	Attempt struct {
		GenerationID string `yaml:"generationId"`
		TrustDomain  string `yaml:"trustDomain,omitempty"`
		KeyARN       string `yaml:"keyArn"`
		StatePath    string `yaml:"statePath"`
		Status       string `yaml:"status"`
	}
)

// LoadRootArtifact reads a committed root artifact. Nothing about the root
// is trusted until a ceremony has re-parsed and checked it.
func LoadRootArtifact(path string) (RootArtifact, error) {
	var artifact RootArtifact
	if err := readYAMLStrict(path, &artifact); err != nil {
		return RootArtifact{}, fmt.Errorf("read root artifact %s: %w", path, err)
	}
	return artifact, nil
}

// LoadIntermediateArtifact reads a committed intermediate artifact.
func LoadIntermediateArtifact(path string) (IntermediateArtifact, error) {
	var artifact IntermediateArtifact
	if err := readYAMLStrict(path, &artifact); err != nil {
		return IntermediateArtifact{}, err
	}
	return artifact, nil
}

// Certificate re-parses the artifact's certificate and checks that the
// public metadata beside it was derived from that certificate.
func (a RootArtifact) Certificate() (*x509.Certificate, error) {
	certificate, err := decodeSingleCertificate([]byte(a.CertificatePEM))
	if err != nil {
		return nil, err
	}
	if expected := rootArtifactFromCertificate(certificate, a.GenerationID, a.KeyARN); a != expected {
		return nil, fmt.Errorf("public metadata does not match certificatePem")
	}
	return certificate, nil
}

func rootArtifactFromCertificate(certificate *x509.Certificate, generationID, keyARN string) RootArtifact {
	fingerprint := sha256.Sum256(certificate.Raw)
	return RootArtifact{
		GenerationID:         generationID,
		KeyARN:               keyARN,
		CertificatePEM:       string(pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: certificate.Raw})),
		FingerprintSHA256:    strings.ToUpper(hex.EncodeToString(fingerprint[:])),
		SubjectKeyIdentifier: strings.ToUpper(hex.EncodeToString(certificate.SubjectKeyId)),
		NotAfter:             certificate.NotAfter.UTC().Format(time.RFC3339),
	}
}

func readYAMLStrict(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	return decoder.Decode(into)
}

func decodeSingleCertificate(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != certificatePEMType || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("certificatePem must contain exactly one CERTIFICATE PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificatePem: %w", err)
	}
	return certificate, nil
}

func readCertificateFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != certificatePEMType || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("file must contain exactly one CERTIFICATE PEM block")
	}
	return block.Bytes, nil
}

// writeArtifactExclusive persists a completed ceremony artifact: created
// without overwrite, fsynced, parent directory fsynced.
func writeArtifactExclusive(path string, artifact any) error {
	raw, err := yaml.Marshal(artifact)
	if err != nil {
		return fmt.Errorf("marshal ceremony state: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, artifactFileMode)
	if err != nil {
		return fmt.Errorf("create ceremony state without overwrite: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return fmt.Errorf("write ceremony state: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync ceremony state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close ceremony state: %w", err)
	}
	if err := syncParentDirectory(path); err != nil {
		return fmt.Errorf("sync ceremony state directory: %w", err)
	}
	ok = true
	return nil
}

// writeAttemptExclusive reserves the one signing call. Unlike an artifact,
// a reservation that was created is never removed on a later error: its
// presence is what makes every rerun fail closed.
func writeAttemptExclusive(path string, attempt Attempt) error {
	raw, err := yaml.Marshal(attempt)
	if err != nil {
		return fmt.Errorf("marshal ceremony attempt: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, artifactFileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("ceremony attempt already reserved at %s; do not sign again—verify the existing state or abandon this generation: %w", path, err)
		}
		return fmt.Errorf("reserve ceremony attempt: %w", err)
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return fmt.Errorf("write ceremony attempt; reservation retained to fail closed: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync ceremony attempt; reservation retained to fail closed: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close ceremony attempt; reservation retained to fail closed: %w", err)
	}
	if err := syncParentDirectory(path); err != nil {
		return fmt.Errorf("sync ceremony attempt directory; reservation retained to fail closed: %w", err)
	}
	return nil
}

func syncParentDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
