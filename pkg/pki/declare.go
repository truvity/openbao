package pki

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/truvity/openbao/pkg/ceremony"
)

// ceremonyGeneration is RootGeneration plus the state gate every signing
// ceremony shares: only a preparing or active generation may sign. A
// retiring or retired generation's key still exists (custody never deletes
// it out from under a leaf that has not expired yet), but nothing new is
// ever signed with it again.
func (c *Contract) ceremonyGeneration(id string) (*RootGeneration, error) {
	generation := c.RootGeneration(id)
	if generation == nil {
		return nil, fmt.Errorf("pki: unknown root generation %q", id)
	}

	if generation.State != GenerationPreparing && generation.State != GenerationActive {
		return nil, fmt.Errorf("pki: root generation %q is %s and cannot perform a certificate ceremony", generation.ID, generation.State)
	}

	return generation, nil
}

// RootSpec is the authored root generation as [ceremony.CreateRoot] takes
// it.
func (c *Contract) RootSpec(generationID string) (ceremony.RootSpec, error) {
	generation, err := c.ceremonyGeneration(generationID)
	if err != nil {
		return ceremony.RootSpec{}, err
	}

	notBefore, err := time.Parse(time.RFC3339, generation.Certificate.NotBefore)
	if err != nil {
		return ceremony.RootSpec{}, fmt.Errorf("pki: parse root generation notBefore: %w", err)
	}

	lifetime, err := time.ParseDuration(generation.Lifetime)
	if err != nil {
		return ceremony.RootSpec{}, fmt.Errorf("pki: parse root generation lifetime: %w", err)
	}

	return ceremony.RootSpec{
		GenerationID:        generation.ID,
		CommonName:          generation.Certificate.Subject.CommonName,
		Organization:        generation.Certificate.Subject.Organization,
		NotBefore:           notBefore,
		Lifetime:            lifetime,
		MaxPathLen:          generation.Certificate.MaxPathLen,
		PermittedDNSDomains: slices.Clone(generation.Certificate.PermittedDNSDomains),
		SerialNamespace:     c.SerialNamespace,
	}, nil
}

// RootArtifactPath is where generationID's own ceremony artifact is (or
// will be) committed, relative to the caller's working directory.
func (c *Contract) RootArtifactPath(generationID string) string {
	return c.ArtifactPath(RootArtifactName(generationID))
}

// DNSIntermediateSpec derives the authored template inputs for a DNS trust
// domain's intermediate. The domain must be declared below generationID,
// and the generation must be able to sign.
func (c *Contract) DNSIntermediateSpec(domainName, generationID string) (ceremony.IntermediateSpec, error) {
	domain := c.DNSTrustDomain(domainName)
	if domain == nil {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: no dns trust domain named %q", domainName)
	}

	if domain.RootGeneration != generationID {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: trust domain %s is declared below root generation %q, not %q",
			domainName, domain.RootGeneration, generationID)
	}

	generation, err := c.ceremonyGeneration(generationID)
	if err != nil {
		return ceremony.IntermediateSpec{}, err
	}

	notBefore, err := time.Parse(time.RFC3339, generation.Certificate.NotBefore)
	if err != nil {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: parse root generation notBefore: %w", err)
	}

	lifetime, err := time.ParseDuration(domain.Lifetimes.DomainIntermediate)
	if err != nil {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: parse %s domainIntermediate lifetime: %w", domainName, err)
	}

	// An empty list means no name-constraints extension at all, which is
	// not the same as an empty extension.
	var permitted []string
	if len(domain.DomainIntermediate.PermittedDNSDomains) != 0 {
		permitted = slices.Clone(domain.DomainIntermediate.PermittedDNSDomains)
	}

	return ceremony.IntermediateSpec{
		TrustDomain:         domainName,
		GenerationID:        generationID,
		CommonName:          domain.DomainIntermediate.Subject.CommonName,
		Organization:        domain.DomainIntermediate.Subject.Organization,
		NotBefore:           notBefore,
		Lifetime:            lifetime,
		MaxPathLen:          domain.DomainIntermediate.MaxPathLen,
		PermittedDNSDomains: permitted,
		RootArtifactPath:    c.RootArtifactPath(generationID),
		ArtifactPath:        c.ArtifactPath(IntermediateArtifactName(generationID, domainName, "")),
		SerialNamespace:     c.SerialNamespace,
	}, nil
}

// URIIntermediateSpec derives the authored template inputs for a URI trust
// domain's shared intermediate (the CA every environment's own issuing CA
// -- or, once RootSignedEnvironments takes over, its per-environment CA --
// is signed by until it is signed by the root directly). The domain must be
// declared below generationID, and the generation must be able to sign.
func (c *Contract) URIIntermediateSpec(domainName, generationID string) (ceremony.IntermediateSpec, error) {
	domain := c.URITrustDomain(domainName)
	if domain == nil {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: no uri trust domain named %q", domainName)
	}

	if domain.RootGeneration != generationID {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: trust domain %s is declared below root generation %q, not %q",
			domainName, domain.RootGeneration, generationID)
	}

	generation, err := c.ceremonyGeneration(generationID)
	if err != nil {
		return ceremony.IntermediateSpec{}, err
	}

	notBefore, err := time.Parse(time.RFC3339, generation.Certificate.NotBefore)
	if err != nil {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: parse root generation notBefore: %w", err)
	}

	lifetime, err := time.ParseDuration(domain.Lifetimes.DomainIntermediate)
	if err != nil {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: parse %s domainIntermediate lifetime: %w", domainName, err)
	}

	return ceremony.IntermediateSpec{
		TrustDomain:         domainName,
		GenerationID:        generationID,
		CommonName:          domain.DomainIntermediate.Subject.CommonName,
		Organization:        domain.DomainIntermediate.Subject.Organization,
		NotBefore:           notBefore,
		Lifetime:            lifetime,
		MaxPathLen:          domain.DomainIntermediate.MaxPathLen,
		PermittedURIDomains: slices.Clone(domain.DomainIntermediate.PermittedURIDomains),
		RootArtifactPath:    c.RootArtifactPath(generationID),
		ArtifactPath:        c.ArtifactPath(IntermediateArtifactName(generationID, domainName, "")),
		SerialNamespace:     c.SerialNamespace,
	}, nil
}

// EnvironmentCASpec derives the authored template inputs for one
// environment's own issuing CA, signed DIRECTLY by the root -- one level
// shorter than URIIntermediateSpec's shared intermediate, with no CA of its
// own below it. The environment must already be in the domain's
// Environments AND in RootSignedEnvironments, and the generation must be
// able to sign.
//
// value is the environment's own value for [ZonePlaceholder] (its SPIFFE
// trust domain, typically): both the subject and the one URI constraint
// are derived from it here, never authored per environment in the
// contract, because there is exactly one of THIS domain's authored
// EnvironmentCA template but one certificate per environment.
func (c *Contract) EnvironmentCASpec(domainName, environment, value, generationID string) (ceremony.IntermediateSpec, error) {
	domain := c.URITrustDomain(domainName)
	if domain == nil {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: no uri trust domain named %q", domainName)
	}

	if domain.RootGeneration != generationID {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: trust domain %s is declared below root generation %q, not %q",
			domainName, domain.RootGeneration, generationID)
	}

	if domain.EnvironmentCA == nil {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: trust domain %s declares no environmentCA", domainName)
	}

	if !slices.Contains(domain.Environments, environment) {
		return ceremony.IntermediateSpec{}, fmt.Errorf(
			"pki: environment %q has no issuing CA yet under trust domain %s (trustDomains.uri[%s].environments); it needs one before it can get a root-signed CA",
			environment, domainName, domainName)
	}

	if !slices.Contains(domain.RootSignedEnvironments, environment) {
		return ceremony.IntermediateSpec{}, fmt.Errorf(
			"pki: environment %q is not in trustDomains.uri[%s].rootSignedEnvironments", environment, domainName)
	}

	if strings.TrimSpace(value) == "" {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: environment %q: no value given for %s", environment, ZonePlaceholder)
	}

	generation, err := c.ceremonyGeneration(generationID)
	if err != nil {
		return ceremony.IntermediateSpec{}, err
	}

	notBefore, err := time.Parse(time.RFC3339, generation.Certificate.NotBefore)
	if err != nil {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: parse root generation notBefore: %w", err)
	}

	lifetime, err := time.ParseDuration(domain.Lifetimes.ClusterIntermediate)
	if err != nil {
		return ceremony.IntermediateSpec{}, fmt.Errorf("pki: parse %s clusterIntermediate lifetime: %w", domainName, err)
	}

	return ceremony.IntermediateSpec{
		TrustDomain:  environmentCATrustDomain(domainName, environment),
		GenerationID: generationID,
		CommonName:   value + " " + domain.EnvironmentCA.CommonNameSuffix,
		Organization: generation.Certificate.Subject.Organization,
		NotBefore:    notBefore,
		Lifetime:     lifetime,
		MaxPathLen:   domain.EnvironmentCA.MaxPathLen,
		// No DNS subtree, and an exact host match: unlike the shared
		// intermediate's own constraint (which may permit a whole
		// subtree of environments), this one environment's own CA
		// constrains to that environment's value alone.
		PermittedURIDomains: []string{value},
		RootArtifactPath:    c.RootArtifactPath(generationID),
		ArtifactPath:        c.ArtifactPath(IntermediateArtifactName(generationID, domainName, environment)),
		SerialNamespace:     c.SerialNamespace,
	}, nil
}

// environmentCATrustDomain is the ceremony's own trust-domain label for one
// environment's root-signed CA -- part of the deterministic serial and of
// the artifact's own trustDomain field, kept apart from the domain's own
// name so two environments' CAs, signed under the same root generation,
// never derive the same serial.
func environmentCATrustDomain(domainName, environment string) string {
	return domainName + "-" + environment
}

// EmergencyServerSpec derives the break-glass declaration: the generation
// must be the active one AND trusted fleet-wide (a leaf of a root nobody
// trusts restores nothing), and dnsName must sit under a DNS trust domain
// that requires trust.
func (c *Contract) EmergencyServerSpec(generationID, dnsName string, notBefore time.Time) (ceremony.EmergencyServerSpec, error) {
	generation := c.RootGeneration(generationID)
	if generation == nil {
		return ceremony.EmergencyServerSpec{}, fmt.Errorf("pki: root generation %q is not declared", generationID)
	}

	if generation.State != GenerationActive {
		return ceremony.EmergencyServerSpec{}, fmt.Errorf(
			"pki: root generation %q is %s; only the active generation signs a break-glass leaf", generationID, generation.State)
	}

	if !slices.Contains(c.Migration.TrustedGenerations, generationID) {
		return ceremony.EmergencyServerSpec{}, fmt.Errorf(
			"pki: root generation %q is not in migration.trustedGenerations: no client would trust its leaf", generationID)
	}

	if strings.Contains(dnsName, "*") {
		return ceremony.EmergencyServerSpec{}, fmt.Errorf("pki: %q must not be a wildcard", dnsName)
	}

	var under bool

	for i := range c.TrustDomains.DNS {
		domain := &c.TrustDomains.DNS[i]
		if domain.RequireTrusted && domain.RootGeneration == generationID && isNameUnderDomain(dnsName, domain.Suffix) {
			under = true

			break
		}
	}

	if !under {
		return ceremony.EmergencyServerSpec{}, fmt.Errorf("pki: %q is not under a dns trust domain that requires trust", dnsName)
	}

	if notBefore.IsZero() {
		return ceremony.EmergencyServerSpec{}, fmt.Errorf("pki: notBefore is required: the template, and so its hash, must be reproducible")
	}

	return ceremony.EmergencyServerSpec{
		GenerationID:     generationID,
		DNSName:          dnsName,
		NotBefore:        notBefore.UTC().Truncate(time.Second),
		Lifetime:         ceremony.DefaultEmergencyServerLifetime,
		RootArtifactPath: c.RootArtifactPath(generationID),
		SerialNamespace:  c.SerialNamespace,
	}, nil
}

// LoadSignedIntermediate proves one trust domain intermediate's (or one
// environment CA's) committed artifact against the contract and the
// committed root, offline, and returns the chain OpenBAO imports. Pass a
// spec from [Contract.DNSIntermediateSpec], [Contract.URIIntermediateSpec]
// or [Contract.EnvironmentCASpec]: every artifact path on it already
// resolves relative to the contract's own directory.
func (c *Contract) LoadSignedIntermediate(spec ceremony.IntermediateSpec) (*ceremony.SignedIntermediate, error) {
	return ceremony.LoadSignedIntermediate(spec, "")
}

// IntermediateSigned reports whether a trust domain intermediate's (or one
// environment CA's) artifact has been signed and committed yet, from
// spec.ArtifactPath alone -- so a caller can gate everything downstream of
// a ceremony's additive-only first phase (the CSR only, no issuer named,
// nothing imported) on this, the same way before running the ceremony's
// second phase (signing, committing, and only then installing the result).
func IntermediateSigned(spec ceremony.IntermediateSpec) (bool, error) {
	_, err := os.Stat(spec.ArtifactPath)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}

	return false, err
}
