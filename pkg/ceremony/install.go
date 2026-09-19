package ceremony

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"
)

type (
	// SignedIntermediate is one committed domain intermediate, proven, and
	// the bytes an installer hands OpenBAO.
	SignedIntermediate struct {
		// Spec is what this certificate must be.
		Spec        IntermediateSpec
		Artifact    IntermediateArtifact
		Certificate *x509.Certificate
		Root        *x509.Certificate
		// ChainPEM is the certificate followed by the root that signed it,
		// the order OpenBAO's `<mount>/intermediate/set-signed` reads: the
		// issuer being installed first, its parents after. Importing the
		// parent with it is what lets OpenBAO serve a complete `ca_chain`
		// for every leaf below. The root arrives as a keyless issuer: its
		// private half is in KMS and has never been anywhere else.
		ChainPEM string
		// Proof is one line per property verified, for an installer's log
		// and for a second reviewer to reproduce.
		Proof []string
	}
)

// LoadSignedIntermediate reads one trust domain's committed ceremony
// artifacts and proves, offline and without any credential, that the
// certificate about to be installed is the one the spec declares:
// re-derived template, authored subject, path length, validity and name
// constraints, signed by the committed root, with public metadata that
// matches its own PEM.
//
// It is deliberately the same verification the ceremony ran before it
// wrote the artifact, minus the certificate request, which never leaves
// OpenBAO: the certificate carries the public key that request carried,
// and every other property is re-derived from the spec. An installer that
// skipped this would be importing a CA on the strength of a file path.
//
// baseDir is where the spec's artifact paths are relative to ("" or "."
// for the working directory).
func LoadSignedIntermediate(spec IntermediateSpec, baseDir string) (*SignedIntermediate, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}

	root, err := LoadRootArtifact(filepath.Join(baseDir, spec.RootArtifactPath))
	if err != nil {
		return nil, err
	}

	artifact, err := LoadIntermediateArtifact(filepath.Join(baseDir, spec.ArtifactPath))
	if err != nil {
		return nil, fmt.Errorf("read the %s intermediate artifact %s: %w", spec.TrustDomain, spec.ArtifactPath, err)
	}

	return VerifySignedIntermediate(spec, root, artifact)
}

// VerifySignedIntermediate is LoadSignedIntermediate over artifacts already
// in memory.
func VerifySignedIntermediate(spec IntermediateSpec, rootArtifact RootArtifact, artifact IntermediateArtifact) (*SignedIntermediate, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}

	root, err := parseIntermediateRoot(rootArtifact, spec)
	if err != nil {
		return nil, fmt.Errorf("root artifact %s: %w", spec.RootArtifactPath, err)
	}

	if artifact.TrustDomain != spec.TrustDomain || artifact.GenerationID != spec.GenerationID {
		return nil, fmt.Errorf("intermediate artifact %s holds the %s intermediate of generation %q, not the %s one of %q",
			spec.ArtifactPath, artifact.TrustDomain, artifact.GenerationID, spec.TrustDomain, spec.GenerationID)
	}

	certificate, err := decodeSingleCertificate([]byte(artifact.CertificatePEM))
	if err != nil {
		return nil, fmt.Errorf("intermediate artifact %s: %w", spec.ArtifactPath, err)
	}

	key, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("intermediate artifact %s does not carry an ECDSA public key", spec.ArtifactPath)
	}

	template, err := IntermediateTemplate(spec, root, key)
	if err != nil {
		return nil, err
	}

	// The plan the ceremony would have built for this certificate. The
	// request is reconstructed from the certificate's own public key: that
	// pair was proven when the ceremony signed, and what matters here is
	// that the certificate still matches the re-derived template.
	plan := &IntermediatePlan{
		Spec:           spec,
		RootArtifact:   rootArtifact,
		Root:           root,
		Request:        &x509.CertificateRequest{PublicKey: key, PublicKeyAlgorithm: x509.ECDSA},
		Template:       template,
		TemplateSHA256: artifact.TemplateSHA256,
	}

	result, err := validateIntermediateArtifact(artifact, plan, artifact.KeyARN)
	if err != nil {
		return nil, fmt.Errorf("committed %s intermediate %s: %w", spec.TrustDomain, spec.ArtifactPath, err)
	}

	return &SignedIntermediate{
		Spec:        spec,
		Artifact:    result.Artifact,
		Certificate: result.Certificate,
		Root:        root,
		ChainPEM:    chainPEM(artifact.CertificatePEM, rootArtifact.CertificatePEM),
		Proof:       result.Proof,
	}, nil
}

// chainPEM concatenates PEM blocks with exactly one newline between them,
// whatever trailing whitespace the artifacts carry.
func chainPEM(blocks ...string) string {
	trimmed := make([]string, 0, len(blocks))
	for _, block := range blocks {
		trimmed = append(trimmed, strings.TrimSpace(block))
	}

	return strings.Join(trimmed, "\n") + "\n"
}
