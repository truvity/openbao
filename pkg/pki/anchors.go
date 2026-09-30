package pki

import (
	"crypto/x509"
	"fmt"
	"time"
)

// TrustAnchor is one root certificate the estate trusts: what a verifier
// needs in order to validate a leaf issued anywhere under that root.
// Public material only.
type TrustAnchor struct {
	// GenerationID is the root generation, and the name every distributed
	// copy of this anchor is filed under.
	GenerationID string
	// CertificatePEM is the root certificate, exactly as the ceremony
	// committed it.
	CertificatePEM string
	// FingerprintSHA256 is the certificate's SHA-256, upper-case hex --
	// what an operator compares on a host.
	FingerprintSHA256 string
	// NotAfter is when trusting this anchor stops meaning anything.
	NotAfter time.Time
}

// TrustAnchors returns the committed root certificate of every generation
// Migration.TrustedGenerations names, in the authored order.
//
// This is the join between the contract and what is actually distributed: a
// generation is trusted because it is listed there AND its ceremony
// artifact exists, is the certificate the contract describes, and is
// self-signed. A generation listed before its ceremony ran is a promise
// nothing can keep, so it is an error rather than an empty anchor -- every
// trust bundle is built from this list.
func (c *Contract) TrustAnchors() ([]TrustAnchor, error) {
	anchors := make([]TrustAnchor, 0, len(c.Migration.TrustedGenerations))

	for _, id := range c.Migration.TrustedGenerations {
		generation := c.RootGeneration(id)
		if generation == nil {
			// Validate already refuses this; repeated so this method
			// cannot be misused on an unvalidated Contract.
			return nil, fmt.Errorf("pki: migration.trustedGenerations names unknown generation %q", id)
		}

		anchor, err := c.loadTrustAnchor(generation)
		if err != nil {
			return nil, err
		}

		anchors = append(anchors, *anchor)
	}

	return anchors, nil
}

func (c *Contract) loadTrustAnchor(generation *RootGeneration) (*TrustAnchor, error) {
	artifactPath := c.ArtifactPath(RootArtifactName(generation.ID))

	artifact, err := c.loadRootArtifact(artifactPath)
	if err != nil {
		return nil, fmt.Errorf(
			"pki: generation %q is trusted but its ceremony artifact %s cannot be read: %w",
			generation.ID, artifactPath, err,
		)
	}

	if artifact.GenerationID != generation.ID {
		return nil, fmt.Errorf("%s: generationId %q is not %q", artifactPath, artifact.GenerationID, generation.ID)
	}

	// Re-derives the certificate from the artifact and checks that the
	// public metadata beside it (fingerprint, subject key identifier)
	// really was derived from that certificate.
	certificate, err := artifact.Certificate()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", artifactPath, err)
	}

	if err := checkAnchor(generation, certificate); err != nil {
		return nil, fmt.Errorf("%s: %w", artifactPath, err)
	}

	return &TrustAnchor{
		GenerationID:      generation.ID,
		CertificatePEM:    artifact.CertificatePEM,
		FingerprintSHA256: artifact.FingerprintSHA256,
		NotAfter:          certificate.NotAfter,
	}, nil
}

// checkAnchor re-derives from the certificate everything the contract
// authored for it. A swapped or edited file therefore fails here, where it
// is still only a render.
func checkAnchor(generation *RootGeneration, certificate *x509.Certificate) error {
	if !certificate.IsCA || !certificate.BasicConstraintsValid {
		return fmt.Errorf("certificate is not a CA")
	}

	if certificate.Subject.CommonName != generation.Certificate.Subject.CommonName {
		return fmt.Errorf("subject common name %q is not the authored %q",
			certificate.Subject.CommonName, generation.Certificate.Subject.CommonName)
	}

	// A trust anchor is trusted by being distributed, not by anything
	// above it, so it must be its own issuer and carry its own signature.
	if certificate.Subject.String() != certificate.Issuer.String() {
		return fmt.Errorf("certificate is not self-signed: issuer %q", certificate.Issuer.String())
	}

	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return fmt.Errorf("certificate does not verify against its own key: %w", err)
	}

	return nil
}
