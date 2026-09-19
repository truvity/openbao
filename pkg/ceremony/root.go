package ceremony

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"slices"
	"time"

	"github.com/truvity/openbao/pkg/kmssigner"
)

type (
	// RootSpec is everything a root certificate is built from. All of it is
	// authored; the KMS key contributes only its public key.
	RootSpec struct {
		GenerationID string
		CommonName   string
		// Organization is omitted from the subject when empty.
		Organization string
		NotBefore    time.Time
		Lifetime     time.Duration
		// MaxPathLen counts the CA certificates the root admits below it.
		// A root is always bounded: 0 means "leaves only", never
		// "unbounded".
		MaxPathLen int
		// PermittedDNSDomains empty means no name-constraints extension at
		// all, which is not the same as an empty critical one.
		PermittedDNSDomains []string
		// SerialNamespace prefixes the serial's domain-separation label;
		// empty means DefaultSerialNamespace. It is part of every serial,
		// so an existing root is only re-verified under the namespace it
		// was created with.
		SerialNamespace string
	}

	// RootOptions names the deployed KMS key and where the artifact goes.
	RootOptions struct {
		KeyARN       string
		ArtifactPath string
		// ImportCertificatePath verifies and records a root certificate
		// that already exists instead of signing a new one.
		ImportCertificatePath string
	}

	// RootResult reports whether this invocation performed the one KMS
	// signing call.
	RootResult struct {
		Artifact RootArtifact
		Signed   bool
	}
)

// CreateRoot validates an existing artifact idempotently, imports an
// existing certificate, or creates and persists a new root certificate.
// An existing artifact is always checked first, so a rerun never signs
// again.
func CreateRoot(ctx context.Context, client kmssigner.API, spec RootSpec, options RootOptions) (*RootResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ceremony context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.KeyARN == "" || options.ArtifactPath == "" {
		return nil, fmt.Errorf("key ARN and artifact path are required")
	}
	if err := spec.validate(); err != nil {
		return nil, err
	}

	signer, err := kmssigner.New(ctx, client, options.KeyARN)
	if err != nil {
		return nil, err
	}
	publicKey := signer.Public().(*ecdsa.PublicKey)
	template, err := RootTemplate(spec, publicKey)
	if err != nil {
		return nil, err
	}

	var existing RootArtifact
	err = readYAMLStrict(options.ArtifactPath, &existing)
	if err == nil {
		if err := validateRootArtifact(existing, template, publicKey, spec.GenerationID, options.KeyARN); err != nil {
			return nil, fmt.Errorf("existing ceremony state is invalid: %w", err)
		}
		return &RootResult{Artifact: existing, Signed: false}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read ceremony state: %w", err)
	}

	var certificateDER []byte
	if options.ImportCertificatePath != "" {
		certificateDER, err = readCertificateFile(options.ImportCertificatePath)
		if err != nil {
			return nil, fmt.Errorf("import root certificate: %w", err)
		}
	} else {
		attempt := Attempt{
			GenerationID: spec.GenerationID,
			KeyARN:       options.KeyARN,
			StatePath:    options.ArtifactPath,
			Status:       AttemptStatusReserved,
		}
		certificateDER, err = signOnce(options.ArtifactPath, attempt, template, template, signer.Public(), signer)
		if err != nil {
			return nil, fmt.Errorf("root certificate: %w", err)
		}
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, fmt.Errorf("parse root certificate: %w", err)
	}
	if err := validateRootCertificate(certificate, template, publicKey); err != nil {
		return nil, fmt.Errorf("validate root certificate: %w", err)
	}

	artifact := rootArtifactFromCertificate(certificate, spec.GenerationID, options.KeyARN)
	if err := writeArtifactExclusive(options.ArtifactPath, artifact); err != nil {
		return nil, err
	}
	return &RootResult{Artifact: artifact, Signed: options.ImportCertificatePath == ""}, nil
}

// RootTemplate is the exact root certificate the spec and the KMS public
// key determine: a deterministic serial, the SKI (and AKI, self-signed)
// SHA-256[:20] of the public key, and the authored constraints.
func RootTemplate(spec RootSpec, publicKey *ecdsa.PublicKey) (*x509.Certificate, error) {
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	spkiHash := sha256.Sum256(spki)
	ski := append([]byte(nil), spkiHash[:20]...)

	template := &x509.Certificate{
		SerialNumber:          deterministicSerial(serialLabel(spec.SerialNamespace, "root"), spec.GenerationID, spki),
		Subject:               subject(spec.CommonName, spec.Organization),
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotBefore.Add(spec.Lifetime),
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            spec.MaxPathLen,
		MaxPathLenZero:        spec.MaxPathLen == 0,
		SubjectKeyId:          ski,
		AuthorityKeyId:        append([]byte(nil), ski...),
	}
	// A name constraint is emitted, critical, only when the spec authors
	// one; otherwise the root has no NameConstraints extension at all.
	if len(spec.PermittedDNSDomains) != 0 {
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = append([]string(nil), spec.PermittedDNSDomains...)
	}
	return template, nil
}

func (s RootSpec) validate() error {
	if s.GenerationID == "" || s.CommonName == "" {
		return fmt.Errorf("root spec requires a generation ID and a common name")
	}
	if s.NotBefore.IsZero() || s.Lifetime <= 0 {
		return fmt.Errorf("root spec requires a fixed notBefore and a positive lifetime")
	}
	if s.MaxPathLen < 0 {
		return fmt.Errorf("root maxPathLen must be bounded (0 or more), got %d", s.MaxPathLen)
	}
	return nil
}

// signOnce is the one signing path every committed ceremony shares. It
// durably reserves <artifactPath>.attempt and only then performs the single
// signing call; the reservation is never removed, so an ambiguous outcome
// fails closed on every rerun instead of asking KMS for a second signature.
func signOnce(artifactPath string, attempt Attempt, template, parent *x509.Certificate, publicKey crypto.PublicKey, signer crypto.Signer) ([]byte, error) {
	if err := writeAttemptExclusive(artifactPath+AttemptSuffix, attempt); err != nil {
		return nil, err
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("create certificate after durable attempt reservation; the generation must be abandoned on an ambiguous KMS outcome: %w", err)
	}
	return certificateDER, nil
}

func validateRootCertificate(certificate, template *x509.Certificate, publicKey *ecdsa.PublicKey) error {
	if certificate.SignatureAlgorithm != x509.ECDSAWithSHA384 || certificate.PublicKeyAlgorithm != x509.ECDSA {
		return fmt.Errorf("certificate must use ECDSA with SHA-384")
	}
	certKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certKey.Equal(publicKey) {
		return fmt.Errorf("certificate public key does not match the configured KMS key")
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return fmt.Errorf("self-signature verification failed: %w", err)
	}
	identityMatches := certificate.SerialNumber.Cmp(template.SerialNumber) == 0 &&
		sameSubject(certificate.Subject, template.Subject) &&
		sameSubject(certificate.Issuer, template.Subject)
	if !identityMatches {
		return fmt.Errorf("certificate identity or deterministic serial does not match the authored template")
	}
	if !certificate.NotBefore.Equal(template.NotBefore) || !certificate.NotAfter.Equal(template.NotAfter) {
		return fmt.Errorf("certificate validity does not match the authored template")
	}
	if certificate.KeyUsage != template.KeyUsage || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.MaxPathLen != template.MaxPathLen {
		return fmt.Errorf("certificate CA constraints do not match the authored template")
	}
	if !bytes.Equal(certificate.SubjectKeyId, template.SubjectKeyId) || !bytes.Equal(certificate.AuthorityKeyId, template.AuthorityKeyId) {
		return fmt.Errorf("certificate key identifiers do not match the KMS public key")
	}
	// Exactly the authored constraint: none when the template has none (an
	// imported root carrying a constraint the spec does not author is
	// refused), critical and equal when it has one.
	if certificate.PermittedDNSDomainsCritical != template.PermittedDNSDomainsCritical ||
		!slices.Equal(certificate.PermittedDNSDomains, template.PermittedDNSDomains) ||
		len(certificate.ExcludedDNSDomains) != 0 ||
		len(certificate.PermittedIPRanges) != 0 || len(certificate.ExcludedIPRanges) != 0 ||
		len(certificate.PermittedEmailAddresses) != 0 || len(certificate.ExcludedEmailAddresses) != 0 ||
		len(certificate.PermittedURIDomains) != 0 || len(certificate.ExcludedURIDomains) != 0 {
		return fmt.Errorf("certificate name constraints do not match the authored template")
	}
	return nil
}

func validateRootArtifact(artifact RootArtifact, template *x509.Certificate, publicKey *ecdsa.PublicKey, generationID, keyARN string) error {
	certificate, err := decodeSingleCertificate([]byte(artifact.CertificatePEM))
	if err != nil {
		return err
	}
	if err := validateRootCertificate(certificate, template, publicKey); err != nil {
		return err
	}
	if expected := rootArtifactFromCertificate(certificate, generationID, keyARN); artifact != expected {
		return fmt.Errorf("public metadata does not match certificatePem")
	}
	return nil
}

func subject(commonName, organization string) pkix.Name {
	name := pkix.Name{CommonName: commonName}
	if organization != "" {
		name.Organization = []string{organization}
	}
	return name
}

func sameSubject(got, want pkix.Name) bool {
	return reflect.DeepEqual(got.ToRDNSequence(), want.ToRDNSequence())
}

// serialLabel is the domain-separation label of one kind of serial:
// "<namespace>-<kind>-serial-v1".
func serialLabel(namespace, kind string) string {
	if namespace == "" {
		namespace = DefaultSerialNamespace
	}
	return namespace + "-" + kind + "-serial-v1"
}

// deterministicSerial binds a serial to its inputs so reruns and reviews
// derive the same number: SHA-256 over the label and the NUL-separated
// inputs, 20 bytes, positive, never zero.
func deterministicSerial(label string, parts ...any) *big.Int {
	input := []byte(label)
	for _, part := range parts {
		input = append(input, 0)
		switch value := part.(type) {
		case string:
			input = append(input, value...)
		case []byte:
			input = append(input, value...)
		}
	}
	digest := sha256.Sum256(input)
	serial := append([]byte(nil), digest[:20]...)
	serial[0] &= 0x7f
	if allZero(serial) {
		serial[len(serial)-1] = 1
	}
	return new(big.Int).SetBytes(serial)
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
