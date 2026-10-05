package pki

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/truvity/secrets/pkg/model"
)

// The derivation: a validated [Contract] plus the facts it cannot know (the
// environments, their zones, the names an external catalog supplies) become
// the authorities, roles and mounts of a [model.Desired]. Everything a
// deployed CA is named after -- its mount, its issuer, its roles -- is
// decided here and nowhere else, so two callers built on the same contract
// can never disagree about what a path is called, and a name that changes is
// a change to the contract a reviewer can see.

type (
	// Environment is one environment's inputs to the derivation: the
	// per-domain facts the contract deliberately does not author.
	Environment struct {
		// Name is the OpenBAO namespace's name.
		Name string
		// Zones maps a trust domain's name to this environment's value for
		// [ZonePlaceholder] there: its DNS zone for a DNS domain, its
		// trust domain (a host) for a URI domain.
		Zones map[string]string
		// Catalog holds the allowed names of every role whose names.source
		// is [NameSourceCatalog], keyed by [CatalogKey]. Each list is the
		// external catalog's answer for this environment.
		Catalog map[string][]string
		// PendingCAs names the URI trust domains whose root-signed CA for
		// THIS environment has not been through the ceremony's second
		// phase (the signed certificate is not committed yet). Nothing is
		// derived for such an environment in that domain: its mount and
		// key exist only through [github.com/truvity/secrets/pkg/apply]'s
		// BootstrapEnvironmentCA, and the installed CA, its roles and
		// everything that follows them appear once the artifact does.
		PendingCAs []string
	}

	// Authority is one CA the contract declares: a domain intermediate in
	// the root namespace, or one environment's issuing CA in that
	// environment's namespace.
	Authority struct {
		// Domain is the trust domain's name, Kind its shape.
		Domain string
		Kind   string
		// Environment is "" for a domain intermediate.
		Environment string
		// Mount is the PKI mount that holds it, in the namespace of
		// Environment ("" is root).
		Mount string
		// Issuer is its OpenBAO issuer (and key) name.
		Issuer       string
		CommonName   string
		Organization string
		KeyCurve     string
		// TTL is what the signer puts in the certificate: a Go duration.
		TTL           string
		MaxPathLength int
		// PermittedDNSDomains and PermittedURIDomains are its name
		// constraints; both empty means it carries none.
		PermittedDNSDomains []string
		PermittedURIDomains []string
		// External marks a CA signed outside OpenBAO, by the root: its
		// certificate is the committed ceremony artifact at ArtifactPath.
		// Every other authority is signed inside OpenBAO by SignedBy.
		External     bool
		SignedBy     *model.IssuerRef
		ArtifactPath string
		// Roles are the leaf roles on this authority (Issuer filled),
		// CredentialRoles the roles that sign a caller's own CSR.
		Roles           []model.PKIRole
		CredentialRoles []model.CredentialRole

		mountDescription string
	}

	// Derivation is every authority the contract declares for a set of
	// environments, in authored order: domain intermediates first (DNS
	// domains, then URI), and each environment's issuing CAs in the same
	// order.
	Derivation struct {
		// Domains are the root namespace's authorities: the domain
		// intermediates. A trust domain with no shared intermediate has
		// none.
		Domains []Authority
		// Issuing are the environments' issuing CAs, environment by
		// environment in the order the environments were given.
		Issuing []Authority
	}
)

// CatalogKey is the key of [Environment.Catalog] for a role.
func CatalogKey(domain, role string) string { return domain + "/" + role }

// allIPRanges excludes every IP SAN from a constrained CA: nothing this
// contract signs has one.
var allIPRanges = []string{"0.0.0.0/0", "::/0"}

// Derive computes the contract's authorities for the given environments.
// The contract must already be valid. Every environment gets every DNS
// trust domain; a URI trust domain reaches only the environments it lists.
//
// It refuses what it could not derive whole: a zone the contract needs and
// the environment does not have, a catalog role with no names, a domain
// below a generation that is not the active one.
func (c *Contract) Derive(environments []Environment) (*Derivation, error) {
	generation := c.activeGeneration()
	if generation == nil {
		return nil, fmt.Errorf("pki: the contract declares no active root generation")
	}

	derivation := &Derivation{}

	for i := range c.TrustDomains.DNS {
		domain := &c.TrustDomains.DNS[i]
		if domain.RootGeneration != generation.ID {
			return nil, fmt.Errorf("pki: trust domain %s is declared below root generation %q, not the active %q",
				domain.Name, domain.RootGeneration, generation.ID)
		}

		derivation.Domains = append(derivation.Domains, c.dnsDomainAuthority(domain, generation))
	}

	for i := range c.TrustDomains.URI {
		domain := &c.TrustDomains.URI[i]
		if domain.RootGeneration != generation.ID {
			return nil, fmt.Errorf("pki: trust domain %s is declared below root generation %q, not the active %q",
				domain.Name, domain.RootGeneration, generation.ID)
		}

		if domain.hasSharedIntermediate() {
			derivation.Domains = append(derivation.Domains, c.uriDomainAuthority(domain, generation))
		}
	}

	for i := range environments {
		environment := &environments[i]

		for j := range c.TrustDomains.DNS {
			authority, err := c.dnsIssuingAuthority(&c.TrustDomains.DNS[j], generation, environment)
			if err != nil {
				return nil, err
			}

			derivation.Issuing = append(derivation.Issuing, authority)
		}

		for j := range c.TrustDomains.URI {
			domain := &c.TrustDomains.URI[j]
			if !slices.Contains(domain.Environments, environment.Name) || slices.Contains(environment.PendingCAs, domain.Name) {
				continue
			}

			authority, err := c.uriIssuingAuthority(domain, generation, environment)
			if err != nil {
				return nil, err
			}

			derivation.Issuing = append(derivation.Issuing, authority)
		}
	}

	return derivation, nil
}

func (c *Contract) activeGeneration() *RootGeneration {
	for i := range c.Generations {
		if c.Generations[i].State == GenerationActive {
			return &c.Generations[i]
		}
	}

	return nil
}

// domainMountPath is the root-namespace mount that holds a domain's
// intermediate.
func (p Placement) domainMountPath(domain string) string {
	if p.DomainMount != "" {
		return p.DomainMount
	}

	return "pki-" + domain
}

// issuingMountPath is the mount, in each environment, that holds a domain's
// issuing CA.
func (p Placement) issuingMountPath(domain string) string {
	if p.IssuingMount != "" {
		return p.IssuingMount
	}

	return "pki-" + domain
}

// DomainMountPath is where the domain intermediate of a DNS trust domain
// lives, in the root namespace.
func (d *DNSTrustDomain) DomainMountPath() string { return d.Placement.domainMountPath(d.Name) }

// IssuingMountPath is the mount, inside every environment's namespace, that
// holds the domain's issuing CA and its roles.
func (d *DNSTrustDomain) IssuingMountPath() string { return d.Placement.issuingMountPath(d.Name) }

// DomainMountPath is [DNSTrustDomain.DomainMountPath] for a URI trust
// domain that has a shared intermediate.
func (d *URITrustDomain) DomainMountPath() string { return d.Placement.domainMountPath(d.Name) }

// IssuingMountPath is [DNSTrustDomain.IssuingMountPath] for a URI trust
// domain.
func (d *URITrustDomain) IssuingMountPath() string { return d.Placement.issuingMountPath(d.Name) }

func describe(template, fallback, commonName, domain, environment string) string {
	if template == "" {
		template = fallback
	}

	replacer := strings.NewReplacer("{commonName}", commonName, "{domain}", domain, "{environment}", environment)

	return replacer.Replace(template)
}

const (
	defaultDomainMountDescription  = "{commonName}; signs environment issuing CAs only"
	defaultIssuingMountDescription = "{commonName}; the {domain} chain's leaves in {environment}"
)

// nameConstraints is the extension a constrained authority carries: its
// permitted subtrees, and no IP address at all. An authority with no
// permitted subtree carries no extension.
func nameConstraints(dnsDomains, uriDomains []string) *model.NameConstraints {
	if len(dnsDomains) == 0 && len(uriDomains) == 0 {
		return nil
	}

	return &model.NameConstraints{
		PermittedDNSDomains: slices.Clone(dnsDomains),
		PermittedURIDomains: slices.Clone(uriDomains),
		ExcludedIPRanges:    slices.Clone(allIPRanges),
	}
}

func (c *Contract) dnsDomainAuthority(domain *DNSTrustDomain, generation *RootGeneration) Authority {
	intermediate := &domain.DomainIntermediate

	return Authority{
		Domain:              domain.Name,
		Kind:                KindDNS,
		Mount:               domain.DomainMountPath(),
		Issuer:              intermediate.Name,
		CommonName:          intermediate.Subject.CommonName,
		Organization:        intermediate.Subject.Organization,
		KeyCurve:            intermediate.KeyCurve,
		TTL:                 domain.Lifetimes.DomainIntermediate,
		MaxPathLength:       intermediate.MaxPathLen,
		PermittedDNSDomains: slices.Clone(intermediate.PermittedDNSDomains),
		External:            true,
		ArtifactPath:        c.ArtifactPath(IntermediateArtifactName(generation.ID, domain.Name, "")),
		mountDescription: describe(domain.Placement.DomainMountDescription, defaultDomainMountDescription,
			intermediate.Subject.CommonName, domain.Name, ""),
	}
}

func (c *Contract) uriDomainAuthority(domain *URITrustDomain, generation *RootGeneration) Authority {
	intermediate := &domain.DomainIntermediate

	return Authority{
		Domain:              domain.Name,
		Kind:                KindURI,
		Mount:               domain.DomainMountPath(),
		Issuer:              intermediate.Name,
		CommonName:          intermediate.Subject.CommonName,
		Organization:        intermediate.Subject.Organization,
		KeyCurve:            intermediate.KeyCurve,
		TTL:                 domain.Lifetimes.DomainIntermediate,
		MaxPathLength:       intermediate.MaxPathLen,
		PermittedURIDomains: slices.Clone(intermediate.PermittedURIDomains),
		External:            true,
		ArtifactPath:        c.ArtifactPath(IntermediateArtifactName(generation.ID, domain.Name, "")),
		mountDescription: describe(domain.Placement.DomainMountDescription, defaultDomainMountDescription,
			intermediate.Subject.CommonName, domain.Name, ""),
	}
}

func issuingSuffix(ca IssuingCA) string {
	if ca.CommonNameSuffix != "" {
		return ca.CommonNameSuffix
	}

	return DefaultIssuingCACommonNameSuffix
}

func zoneOf(environment *Environment, domain string) (string, error) {
	zone := strings.TrimSpace(environment.Zones[domain])
	if zone == "" {
		return "", fmt.Errorf("pki: environment %s has no value for %s in trust domain %s", environment.Name, ZonePlaceholder, domain)
	}

	return zone, nil
}

func (c *Contract) dnsIssuingAuthority(domain *DNSTrustDomain, generation *RootGeneration, environment *Environment) (Authority, error) {
	zone, err := zoneOf(environment, domain.Name)
	if err != nil {
		return Authority{}, err
	}

	intermediate := &domain.DomainIntermediate
	issuer := intermediate.Name + "-" + environment.Name
	commonName := zone + " " + issuingSuffix(domain.IssuingCA)

	roles := make([]model.PKIRole, 0, len(domain.Roles))

	for i := range domain.Roles {
		authored := &domain.Roles[i]

		names, err := roleNames(authored, domain.Name, zone, environment)
		if err != nil {
			return Authority{}, fmt.Errorf("pki: %s %s role %s: %w", environment.Name, domain.Name, authored.Name, err)
		}

		if len(names) == 0 {
			return Authority{}, fmt.Errorf("pki: %s %s role %s resolves to no allowed domain, so it could sign nothing",
				environment.Name, domain.Name, authored.Name)
		}

		roles = append(roles, model.PKIRole{
			Name:             authored.Name,
			Issuer:           issuer,
			AllowedDomains:   names,
			AllowBareDomains: authored.Names.Bare,
			AllowSubdomains:  authored.Names.Subdomains,
			AllowWildcards:   authored.AllowWildcard,
			Server:           authored.Usage.Server,
			Client:           authored.Usage.Client,
			KeyCurve:         authored.KeyCurve,
			TTL:              authored.Lifetimes.Default,
			MaxTTL:           authored.Lifetimes.Maximum,
			RenewBefore:      authored.Lifetimes.RenewBefore,
		})
	}

	credentials := make([]model.CredentialRole, 0, len(domain.CredentialRoles))

	for i := range domain.CredentialRoles {
		authored := &domain.CredentialRoles[i]

		credentials = append(credentials, model.CredentialRole{
			Name:          authored.Name,
			Issuer:        issuer,
			SubjectMount:  authored.SubjectMount,
			CNValidations: slices.Clone(authored.CNValidations),
			Server:        authored.Usage.Server,
			Client:        authored.Usage.Client,
			KeyCurve:      authored.KeyCurve,
			TTL:           authored.Lifetimes.Default,
			MaxTTL:        authored.Lifetimes.Maximum,
		})
	}

	return Authority{
		Domain:              domain.Name,
		Kind:                KindDNS,
		Environment:         environment.Name,
		Mount:               domain.IssuingMountPath(),
		Issuer:              issuer,
		CommonName:          commonName,
		Organization:        generation.Certificate.Subject.Organization,
		KeyCurve:            c.Global.KeyCurve,
		TTL:                 domain.Lifetimes.ClusterIntermediate,
		MaxPathLength:       intermediate.MaxPathLen - 1,
		PermittedDNSDomains: issuingPermittedDomains(domain, zone),
		SignedBy:            &model.IssuerRef{Mount: domain.DomainMountPath(), Issuer: intermediate.Name},
		Roles:               roles,
		CredentialRoles:     credentials,
		mountDescription: describe(domain.Placement.IssuingMountDescription, defaultIssuingMountDescription,
			commonName, domain.Name, environment.Name),
	}, nil
}

func (c *Contract) uriIssuingAuthority(domain *URITrustDomain, generation *RootGeneration, environment *Environment) (Authority, error) {
	value, err := zoneOf(environment, domain.Name)
	if err != nil {
		return Authority{}, err
	}

	role := &domain.Role

	var (
		issuer, commonName string
		signedBy           *model.IssuerRef
		external           bool
		artifact           string
		maxPathLength      int
		keyCurve           = c.Global.KeyCurve
	)

	if domain.IsRootSigned(environment.Name) {
		issuer = domain.EnvironmentCAIssuerName(environment.Name)
		commonName = value + " " + domain.EnvironmentCA.CommonNameSuffix
		maxPathLength = domain.EnvironmentCA.MaxPathLen
		keyCurve = domain.EnvironmentCA.KeyCurve
		external = true
		artifact = c.ArtifactPath(domain.EnvironmentCAArtifactName(generation.ID, environment.Name))
	} else {
		issuer = domain.DomainIntermediate.Name + "-" + environment.Name
		commonName = value + " " + issuingSuffix(domain.IssuingCA)
		maxPathLength = domain.DomainIntermediate.MaxPathLen - 1
		signedBy = &model.IssuerRef{Mount: domain.DomainMountPath(), Issuer: domain.DomainIntermediate.Name}
	}

	return Authority{
		Domain:       domain.Name,
		Kind:         KindURI,
		Environment:  environment.Name,
		Mount:        domain.IssuingMountPath(),
		Issuer:       issuer,
		CommonName:   commonName,
		Organization: generation.Certificate.Subject.Organization,
		KeyCurve:     keyCurve,
		TTL:          domain.Lifetimes.ClusterIntermediate,
		// This environment's own trust domain alone, an exact host match:
		// the CA cannot mint another environment's identity even if a
		// role were ever misconfigured to allow it.
		PermittedURIDomains: []string{value},
		MaxPathLength:       maxPathLength,
		External:            external,
		SignedBy:            signedBy,
		ArtifactPath:        artifact,
		Roles: []model.PKIRole{{
			Name:           role.Name,
			Issuer:         issuer,
			AllowedURISANs: []string{role.URISAN(value)},
			Server:         role.Usage.Server,
			Client:         role.Usage.Client,
			KeyCurve:       role.KeyCurve,
			TTL:            role.Lifetimes.Default,
			MaxTTL:         role.Lifetimes.Maximum,
			RenewBefore:    role.Lifetimes.RenewBefore,
		}},
		mountDescription: describe(domain.Placement.IssuingMountDescription, defaultIssuingMountDescription,
			commonName, domain.Name, environment.Name),
	}, nil
}

// roleNames resolves one role's name shape for one environment:
// environment-zone substitutes the environment's value, static is literal,
// catalog is the caller's list.
func roleNames(role *LeafRole, domain, zone string, environment *Environment) ([]string, error) {
	switch role.Names.Source {
	case NameSourceEnvironmentZone:
		names := make([]string, 0, len(role.Names.Patterns))
		for _, pattern := range role.Names.Patterns {
			names = append(names, strings.ReplaceAll(pattern, ZonePlaceholder, zone))
		}

		return names, nil
	case NameSourceStatic:
		return slices.Clone(role.Names.Patterns), nil
	case NameSourceCatalog:
		return slices.Clone(environment.Catalog[CatalogKey(domain, role.Name)]), nil
	default:
		return nil, fmt.Errorf("unknown name source %q", role.Names.Source)
	}
}

// issuingPermittedDomains is the issuing CA's name constraint: the
// environment's own zone, plus whatever the domain intermediate permits
// beside its suffix (a name constraint applies to the whole chain below it,
// so an issuing CA constrained to its zone alone would reject a role that
// signs names elsewhere in the intermediate's list). An unconstrained domain
// intermediate gives an unconstrained issuing CA.
func issuingPermittedDomains(domain *DNSTrustDomain, zone string) []string {
	if len(domain.DomainIntermediate.PermittedDNSDomains) == 0 {
		return nil
	}

	permitted := []string{zone}

	for _, constraint := range domain.DomainIntermediate.PermittedDNSDomains {
		if constraint == domain.Suffix || slices.Contains(permitted, constraint) {
			continue
		}

		permitted = append(permitted, constraint)
	}

	return permitted
}

// issuer builds the model's issuer for this authority.
func (a *Authority) issuer() model.PKIIssuer {
	return model.PKIIssuer{
		Name:            a.Issuer,
		CommonName:      a.CommonName,
		Organization:    a.Organization,
		KeyCurve:        a.KeyCurve,
		TTL:             a.TTL,
		MaxPathLength:   a.MaxPathLength,
		NameConstraints: nameConstraints(a.PermittedDNSDomains, a.PermittedURIDomains),
		SignedBy:        a.SignedBy,
		External:        a.External,
	}
}

// RootMounts is the root namespace's mounts for the domain intermediates,
// in authored order. Two domains that share a mount share it: the mount is
// created once, from the first, and the others are further issuers in it.
// The first issuer of a mount is its default.
func (d *Derivation) RootMounts() []model.PKIMount {
	var mounts []model.PKIMount

	for i := range d.Domains {
		domain := &d.Domains[i]
		issuer := domain.issuer()

		if at := slices.IndexFunc(mounts, func(m model.PKIMount) bool { return m.Path == domain.Mount }); at >= 0 {
			mounts[at].Issuers = append(mounts[at].Issuers, issuer)

			continue
		}

		mounts = append(mounts, model.PKIMount{
			Path:            domain.Mount,
			Description:     domain.mountDescription,
			DefaultLeaseTTL: domain.TTL,
			MaxLeaseTTL:     domain.TTL,
			DefaultIssuer:   domain.Issuer,
			Issuers:         []model.PKIIssuer{issuer},
		})
	}

	return mounts
}

// EnvironmentMounts is one environment's mounts for its issuing CAs and
// their roles. Authorities that share a mount share it; the mount's lease
// bounds are the longest default and the longest maximum any leaf role on
// it declares (the CA itself is imported, not issued, so its own lifetime is
// not bounded by them).
func (d *Derivation) EnvironmentMounts(environment string) ([]model.PKIMount, error) {
	var mounts []model.PKIMount

	for i := range d.Issuing {
		issuing := &d.Issuing[i]
		if issuing.Environment != environment {
			continue
		}

		issuer := issuing.issuer()

		if at := slices.IndexFunc(mounts, func(m model.PKIMount) bool { return m.Path == issuing.Mount }); at >= 0 {
			mounts[at].Issuers = append(mounts[at].Issuers, issuer)
			mounts[at].Roles = append(mounts[at].Roles, slices.Clone(issuing.Roles)...)
			mounts[at].CredentialRoles = append(mounts[at].CredentialRoles, slices.Clone(issuing.CredentialRoles)...)

			continue
		}

		mounts = append(mounts, model.PKIMount{
			Path:            issuing.Mount,
			Description:     issuing.mountDescription,
			DefaultIssuer:   issuing.Issuer,
			Issuers:         []model.PKIIssuer{issuer},
			Roles:           slices.Clone(issuing.Roles),
			CredentialRoles: slices.Clone(issuing.CredentialRoles),
		})
	}

	for i := range mounts {
		mount := &mounts[i]

		defaultTTL, maxTTL, err := leafLeaseBounds(mount.Path, mount.Roles)
		if err != nil {
			return nil, fmt.Errorf("pki: %s issuing mount: %w", environment, err)
		}

		mount.DefaultLeaseTTL, mount.MaxLeaseTTL = defaultTTL, maxTTL
	}

	return mounts, nil
}

// leafLeaseBounds is what an issuing mount may hand out: the longest default
// and the longest maximum any of its roles declares.
func leafLeaseBounds(mount string, roles []model.PKIRole) (defaultTTL, maxTTL string, err error) {
	var longestDefault, longestMax time.Duration

	for i := range roles {
		role := &roles[i]

		ttl, err := time.ParseDuration(role.TTL)
		if err != nil {
			return "", "", fmt.Errorf("role %s ttl: %w", role.Name, err)
		}

		most, err := time.ParseDuration(role.MaxTTL)
		if err != nil {
			return "", "", fmt.Errorf("role %s max ttl: %w", role.Name, err)
		}

		if ttl > longestDefault {
			longestDefault, defaultTTL = ttl, role.TTL
		}

		if most > longestMax {
			longestMax, maxTTL = most, role.MaxTTL
		}
	}

	if longestMax == 0 {
		return "", "", fmt.Errorf("mount %s declares no leaf role", mount)
	}

	return defaultTTL, maxTTL, nil
}

// Apply adds the derivation to a desired state: the domain intermediates to
// the root namespace's PKI mounts, and each environment's issuing CAs to
// the namespace of that name. A mount the desired state already holds keeps
// its own path, description, lease bounds and default issuer, and receives
// the derived issuers and roles after what it already has -- the way a
// retiring chain and its replacement share one mount while both are trusted.
// An environment with authorities but no namespace is an error.
func (d *Derivation) Apply(desired *model.Desired) error {
	desired.Root.PKI = mergeMounts(desired.Root.PKI, d.RootMounts())

	environments := map[string]bool{}

	for i := range d.Issuing {
		environments[d.Issuing[i].Environment] = true
	}

	for i := range desired.Namespaces {
		namespace := &desired.Namespaces[i]
		if !environments[namespace.Name] {
			continue
		}

		mounts, err := d.EnvironmentMounts(namespace.Name)
		if err != nil {
			return err
		}

		namespace.PKI = mergeMounts(namespace.PKI, mounts)

		delete(environments, namespace.Name)
	}

	for environment := range environments {
		return fmt.Errorf("pki: environment %q has issuing CAs but the desired state has no such namespace", environment)
	}

	return nil
}

// mergeMounts adds mounts to base: a mount whose path base holds gains the
// issuers and roles, any other is appended.
func mergeMounts(base, add []model.PKIMount) []model.PKIMount {
	for i := range add {
		mount := &add[i]

		at := slices.IndexFunc(base, func(m model.PKIMount) bool { return m.Path == mount.Path })
		if at < 0 {
			base = append(base, *mount)

			continue
		}

		base[at].Issuers = append(base[at].Issuers, mount.Issuers...)
		base[at].Roles = append(base[at].Roles, mount.Roles...)
		base[at].CredentialRoles = append(base[at].CredentialRoles, mount.CredentialRoles...)
	}

	return base
}
