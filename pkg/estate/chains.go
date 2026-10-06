package estate

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/truvity/secrets/pkg/model"
)

type (
	// Chains loads signed certificates from where the ceremony committed
	// them. A loader re-proves each one against the contract before it
	// returns it: the apply imports what it is given.
	Chains interface {
		// DomainIntermediate is a trust domain's intermediate of a root
		// generation.
		DomainIntermediate(trustDomain, generationID string) (Chain, error)
		// EnvironmentCA is one environment's root-signed identity CA, for the
		// environment's private zone.
		EnvironmentCA(environment, zone, generationID string) (Chain, error)
	}

	// Chain is one signed certificate as the ceremony committed it.
	Chain struct {
		// PEM is the certificate first, then its parents.
		PEM string
		// ArtifactPath and FingerprintSHA256 say which artifact it is.
		ArtifactPath      string
		FingerprintSHA256 string
	}
)

// PrivateZone is one environment's private zone.
func (d *Desired) PrivateZone(environment string) (string, error) {
	at := slices.IndexFunc(d.in.Clusters, func(c Cluster) bool { return c.Name == environment })
	if at < 0 || d.in.Clusters[at].PrivateZone == "" {
		return "", fmt.Errorf("estate: %s identity environment CA: no cluster inputs", environment)
	}

	return d.in.Clusters[at].PrivateZone, nil
}

// SignedChain is apply.Options.SignedChain for this state: the chain the
// server imports for each External issuer, from chains.
func (d *Desired) SignedChain(ctx context.Context, logger *slog.Logger, chains Chains) func(model.IssuerRef) (string, error) {
	if logger == nil {
		logger = slog.Default()
	}

	return func(ref model.IssuerRef) (string, error) { return d.signedChain(ctx, logger, chains, ref) }
}

// signedChain is the chain the server imports for one External issuer: THE
// COMMITTED ARTIFACT, NEVER A FRESH SIGNATURE. The root key signs once, in
// the ceremony; the loader re-proves the artifact against the contract
// before the server is touched, so a wrong or swapped file fails the
// preview, not the apply. Nothing here can sign.
func (d *Desired) signedChain(ctx context.Context, logger *slog.Logger, chains Chains, ref model.IssuerRef) (string, error) {
	if chains == nil {
		return "", fmt.Errorf("estate: %s is external and no chain loader is given", ref)
	}

	generation := d.PKI.Root.GenerationID

	if ref.Namespace != "" {
		identity := d.in.PKI.Contract.URITrustDomain(d.in.PKI.Identity)
		if identity == nil || ref.Issuer != identity.EnvironmentCAIssuerName(ref.Namespace) {
			return "", fmt.Errorf("estate: %s is no external issuer this state declares", ref)
		}

		zone, err := d.PrivateZone(ref.Namespace)
		if err != nil {
			return "", err
		}

		chain, err := chains.EnvironmentCA(ref.Namespace, zone, generation)
		if err != nil {
			return "", fmt.Errorf("%s identity environment CA: %w", ref.Namespace, err)
		}

		logger.InfoContext(ctx, "installing a signed root-signed identity environment CA",
			slog.String("environment", ref.Namespace), slog.String("issuer", ref.Issuer),
			slog.String("artifact", chain.ArtifactPath), slog.String("fingerprint_sha256", chain.FingerprintSHA256))

		return chain.PEM, nil
	}

	at := slices.IndexFunc(d.PKI.Domains, func(domain DomainAuthority) bool { return domain.IssuerName == ref.Issuer })
	if at < 0 {
		return "", fmt.Errorf("estate: %s is no domain intermediate", ref)
	}

	domain := &d.PKI.Domains[at]

	chain, err := chains.DomainIntermediate(domain.TrustDomain, generation)
	if err != nil {
		return "", fmt.Errorf("%s domain intermediate: %w", domain.TrustDomain, err)
	}

	logger.InfoContext(ctx, "installing a signed domain intermediate",
		slog.String("trust_domain", domain.TrustDomain), slog.String("mount", domain.Mount), slog.String("issuer", domain.IssuerName),
		slog.String("artifact", chain.ArtifactPath), slog.String("fingerprint_sha256", chain.FingerprintSHA256))

	return chain.PEM, nil
}
