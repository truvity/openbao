package ceremony

import (
	"fmt"
	"path/filepath"
	"time"
)

type (
	// Hierarchy is a KMS-rooted PKI authored as one file: the root, the
	// domain intermediates below it, and the break-glass server name. It is
	// what openbaoctl reads; a program that already holds its own contract
	// builds RootSpec, IntermediateSpec and EmergencyServerSpec directly.
	//
	// Artifact paths are relative to the file's directory.
	Hierarchy struct {
		// SerialNamespace prefixes every deterministic serial's label; empty
		// means DefaultSerialNamespace. Never change it for an existing root.
		SerialNamespace string                  `yaml:"serialNamespace,omitempty"`
		Root            HierarchyRoot           `yaml:"root"`
		Intermediates   []HierarchyIntermediate `yaml:"intermediates,omitempty"`
		EmergencyServer *HierarchyEmergency     `yaml:"emergencyServer,omitempty"`
	}

	// HierarchySubject is a certificate subject: a common name and an
	// optional organization.
	HierarchySubject struct {
		CommonName   string `yaml:"commonName"`
		Organization string `yaml:"organization,omitempty"`
	}

	// HierarchyRoot is one root generation.
	HierarchyRoot struct {
		GenerationID string           `yaml:"generationId"`
		Subject      HierarchySubject `yaml:"subject"`
		// NotBefore is RFC 3339; Lifetime is a Go duration ("175200h").
		NotBefore           string   `yaml:"notBefore"`
		Lifetime            string   `yaml:"lifetime"`
		MaxPathLen          int      `yaml:"maxPathLen"`
		PermittedDNSDomains []string `yaml:"permittedDnsDomains,omitempty"`
		Artifact            string   `yaml:"artifact"`
	}

	// HierarchyIntermediate is one domain intermediate below the root. Its
	// validity starts with the root's, and its path length defaults to one
	// less than the root's -- an ordinary domain intermediate, with an
	// environment issuing CA (or a project CA) still expected below it. An
	// intermediate carries DNS constraints, URI constraints, both or
	// neither -- a DNS-shaped domain (the existing "private"/"origin"
	// kind) permits none, and a URI-only identity domain permits none.
	HierarchyIntermediate struct {
		TrustDomain         string           `yaml:"trustDomain"`
		Subject             HierarchySubject `yaml:"subject"`
		Lifetime            string           `yaml:"lifetime"`
		PermittedDNSDomains []string         `yaml:"permittedDnsDomains,omitempty"`
		// PermittedURIDomains constrains a workload-identity domain
		// intermediate to the trust domain(s) its SPIFFE URIs may name
		// (docs/decisions/0002-workload-mtls-service-and-identity-roles.md).
		// It carries no DNS constraint of its own, and a DNS-shaped
		// intermediate carries none of these.
		PermittedURIDomains []string `yaml:"permittedUriDomains,omitempty"`
		// MaxPathLen overrides the default (the root's own minus one).
		// Set it for a leaf-issuing CA signed directly by the root with
		// nothing of its own below it -- for example a per-environment
		// issuing CA under a workload-identity domain -- which may spend
		// more of the root's budget at once than an ordinary domain
		// intermediate does: RFC 5280's pathLenConstraint only bounds how
		// many CA certificates may follow, it does not require each level
		// to consume exactly one unit of it. [IntermediateSpec.validate]
		// still requires it to be non-negative and strictly less than the
		// root's own maxPathLen.
		MaxPathLen *int   `yaml:"maxPathLen,omitempty"`
		Artifact   string `yaml:"artifact"`
	}

	// HierarchyEmergency is the one name a break-glass leaf may serve.
	HierarchyEmergency struct {
		DNSName string `yaml:"dnsName"`
		// Lifetime defaults to DefaultEmergencyServerLifetime.
		Lifetime string `yaml:"lifetime,omitempty"`
	}
)

// LoadHierarchy reads a hierarchy file strictly (an unknown key is an
// error) and resolves its artifact paths against the file's directory.
func LoadHierarchy(path string) (*Hierarchy, error) {
	var hierarchy Hierarchy
	if err := readYAMLStrict(path, &hierarchy); err != nil {
		return nil, fmt.Errorf("read hierarchy %s: %w", path, err)
	}

	if hierarchy.Root.Artifact == "" {
		return nil, fmt.Errorf("hierarchy %s: root.artifact is required", path)
	}
	for i := range hierarchy.Intermediates {
		if hierarchy.Intermediates[i].Artifact == "" {
			return nil, fmt.Errorf("hierarchy %s: the %q intermediate's artifact is required", path, hierarchy.Intermediates[i].TrustDomain)
		}
	}

	base := filepath.Dir(path)
	hierarchy.Root.Artifact = filepath.Join(base, hierarchy.Root.Artifact)
	for i := range hierarchy.Intermediates {
		hierarchy.Intermediates[i].Artifact = filepath.Join(base, hierarchy.Intermediates[i].Artifact)
	}

	if _, err := hierarchy.RootSpec(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i := range hierarchy.Intermediates {
		trustDomain := hierarchy.Intermediates[i].TrustDomain
		if seen[trustDomain] {
			return nil, fmt.Errorf("hierarchy declares the %q intermediate twice", trustDomain)
		}
		seen[trustDomain] = true
		if _, err := hierarchy.Intermediate(trustDomain); err != nil {
			return nil, err
		}
	}
	if hierarchy.EmergencyServer != nil {
		// Any fixed start will do: this checks the name and the lifetime,
		// the start is the operator's to pin at signing time.
		if _, err := hierarchy.EmergencyServerSpec(time.Unix(0, 0)); err != nil {
			return nil, err
		}
	}
	return &hierarchy, nil
}

// RootSpec is the root as a ceremony takes it.
func (h *Hierarchy) RootSpec() (RootSpec, error) {
	notBefore, lifetime, err := validity(h.Root.NotBefore, h.Root.Lifetime)
	if err != nil {
		return RootSpec{}, fmt.Errorf("root %s: %w", h.Root.GenerationID, err)
	}
	if h.Root.Artifact == "" {
		return RootSpec{}, fmt.Errorf("root %s: artifact is required", h.Root.GenerationID)
	}
	spec := RootSpec{
		GenerationID:        h.Root.GenerationID,
		CommonName:          h.Root.Subject.CommonName,
		Organization:        h.Root.Subject.Organization,
		NotBefore:           notBefore,
		Lifetime:            lifetime,
		MaxPathLen:          h.Root.MaxPathLen,
		PermittedDNSDomains: h.Root.PermittedDNSDomains,
		SerialNamespace:     h.SerialNamespace,
	}
	if err := spec.validate(); err != nil {
		return RootSpec{}, err
	}
	return spec, nil
}

// Intermediate is the named domain intermediate as a ceremony takes it.
func (h *Hierarchy) Intermediate(trustDomain string) (IntermediateSpec, error) {
	for i := range h.Intermediates {
		intermediate := &h.Intermediates[i]
		if intermediate.TrustDomain != trustDomain {
			continue
		}
		notBefore, lifetime, err := validity(h.Root.NotBefore, intermediate.Lifetime)
		if err != nil {
			return IntermediateSpec{}, fmt.Errorf("%s intermediate: %w", trustDomain, err)
		}
		maxPathLen := h.Root.MaxPathLen - 1
		if intermediate.MaxPathLen != nil {
			maxPathLen = *intermediate.MaxPathLen
		}
		spec := IntermediateSpec{
			TrustDomain:         trustDomain,
			GenerationID:        h.Root.GenerationID,
			CommonName:          intermediate.Subject.CommonName,
			Organization:        intermediate.Subject.Organization,
			NotBefore:           notBefore,
			Lifetime:            lifetime,
			MaxPathLen:          maxPathLen,
			PermittedDNSDomains: intermediate.PermittedDNSDomains,
			PermittedURIDomains: intermediate.PermittedURIDomains,
			RootArtifactPath:    h.Root.Artifact,
			ArtifactPath:        intermediate.Artifact,
			SerialNamespace:     h.SerialNamespace,
		}
		if err := spec.validate(); err != nil {
			return IntermediateSpec{}, err
		}
		return spec, nil
	}
	known := make([]string, 0, len(h.Intermediates))
	for i := range h.Intermediates {
		known = append(known, h.Intermediates[i].TrustDomain)
	}
	return IntermediateSpec{}, fmt.Errorf("unknown trust domain %q (declared: %v)", trustDomain, known)
}

// EmergencyServerSpec is the break-glass leaf, starting at notBefore, as a
// ceremony takes it.
func (h *Hierarchy) EmergencyServerSpec(notBefore time.Time) (EmergencyServerSpec, error) {
	if h.EmergencyServer == nil {
		return EmergencyServerSpec{}, fmt.Errorf("the hierarchy declares no emergencyServer name")
	}
	lifetime := DefaultEmergencyServerLifetime
	if h.EmergencyServer.Lifetime != "" {
		parsed, err := time.ParseDuration(h.EmergencyServer.Lifetime)
		if err != nil {
			return EmergencyServerSpec{}, fmt.Errorf("emergencyServer lifetime: %w", err)
		}
		lifetime = parsed
	}
	spec := EmergencyServerSpec{
		GenerationID:     h.Root.GenerationID,
		DNSName:          h.EmergencyServer.DNSName,
		NotBefore:        notBefore.UTC().Truncate(time.Second),
		Lifetime:         lifetime,
		RootArtifactPath: h.Root.Artifact,
		SerialNamespace:  h.SerialNamespace,
	}
	if err := spec.validate(); err != nil {
		return EmergencyServerSpec{}, err
	}
	return spec, nil
}

func validity(notBefore, lifetime string) (time.Time, time.Duration, error) {
	start, err := time.Parse(time.RFC3339, notBefore)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("notBefore: %w", err)
	}
	duration, err := time.ParseDuration(lifetime)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("lifetime: %w", err)
	}
	return start, duration, nil
}
