package pki

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/truvity/secrets/pkg/model"
)

// generationInfo is what a trust domain needs to know about the root
// generation it is declared under: its own lifetime (for the trust
// domain's lifetime ordering) and its maxPathLen (for the domain
// intermediate's own, one level shorter).
type generationInfo struct {
	Lifetime   time.Duration
	MaxPathLen int
}

// Validate enforces immutable crypto, authority lifetime, root custody,
// generation-reference, alert, and migration-policy invariants. Load calls
// it; a Contract built any other way (a test fixture, a generated one)
// should call it explicitly before any other method trusts it.
func (c *Contract) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("pki: schemaVersion must be %d, got %d", SchemaVersion, c.SchemaVersion)
	}

	if err := c.Global.validate(); err != nil {
		return err
	}

	generationLifetimes, err := validateGenerations(c.Generations, c.hasTrustDomains())
	if err != nil {
		return err
	}

	usedNames := map[string]string{}

	for i := range c.TrustDomains.DNS {
		domain := &c.TrustDomains.DNS[i]
		if err := domain.validate(c.Global, generationLifetimes); err != nil {
			return err
		}

		if err := claimName(usedNames, domain.Name, "trustDomains.dns["+domain.Name+"]"); err != nil {
			return err
		}

		if err := claimName(usedNames, domain.DomainIntermediate.Name, "trustDomains.dns["+domain.Name+"].domainIntermediate.name"); err != nil {
			return err
		}
	}

	for i := range c.TrustDomains.URI {
		domain := &c.TrustDomains.URI[i]
		if err := domain.validate(c.Global, generationLifetimes); err != nil {
			return err
		}

		if err := claimName(usedNames, domain.Name, "trustDomains.uri["+domain.Name+"]"); err != nil {
			return err
		}

		if domain.hasSharedIntermediate() {
			if err := claimName(usedNames, domain.DomainIntermediate.Name, "trustDomains.uri["+domain.Name+"].domainIntermediate.name"); err != nil {
				return err
			}
		}

		// Issuer names are unique across a server (the apply names its
		// resources after them), so the issuer of each root-signed
		// environment CA must not be another authority's name either.
		for _, environment := range domain.Environments {
			if !domain.IsRootSigned(environment) {
				continue
			}

			owner := "trustDomains.uri[" + domain.Name + "].environmentCA issuer for " + environment
			if err := claimName(usedNames, domain.EnvironmentCAIssuerName(environment), owner); err != nil {
				return err
			}
		}
	}

	for i := range c.Generations {
		id := c.Generations[i].ID
		if owner, taken := usedNames[id]; taken {
			return fmt.Errorf("pki: rootGeneration id %q collides with %s", id, owner)
		}
	}

	// Alerts, sign alerts and the trust bundle serve trust domains. A
	// contract with none may leave them out; anything it does state is
	// still checked.
	needed := c.hasTrustDomains()

	if err := c.Alerts.validate(generationLifetimes, c.TrustDomains, needed); err != nil {
		return err
	}

	if err := c.SignAlerts.validate(needed); err != nil {
		return err
	}

	if err := c.Migration.validate(generationLifetimes, needed); err != nil {
		return err
	}

	// A leaf is only as good as the trust of whatever verifies it. A
	// domain that RequireTrusted authored must have its active
	// generation in the trust bundle, or every leaf it signs is
	// worthless to that verifier even while the mount looks healthy.
	for i := range c.TrustDomains.DNS {
		domain := &c.TrustDomains.DNS[i]
		if domain.RequireTrusted && !slices.Contains(c.Migration.TrustedGenerations, domain.RootGeneration) {
			return fmt.Errorf(
				"pki: trustDomains.dns[%s].rootGeneration %q is not in migration.trustedGenerations, but the domain requires it",
				domain.Name, domain.RootGeneration)
		}
	}

	return nil
}

func (c *Contract) hasTrustDomains() bool {
	return len(c.TrustDomains.DNS)+len(c.TrustDomains.URI) > 0
}

// claimName records that a name (a trust domain's own name or its domain
// intermediate's OpenBAO issuer name) is now taken, refusing a collision.
// Every trust domain name, every domain intermediate name and every root
// generation ID must be pairwise distinct: they may all sit in the same
// OpenBAO namespace or the same artifact directory, and a collision there
// is not a cosmetic problem.
func claimName(used map[string]string, name, owner string) error {
	if existing, taken := used[name]; taken {
		return fmt.Errorf(
			"pki: name %q is used by both %s and %s; every trust domain, domain intermediate name and root generation id must be distinct",
			name, existing, owner,
		)
	}

	used[name] = owner

	return nil
}

func (g Global) validate() error {
	if !g.Immutable {
		return fmt.Errorf("pki: global.immutable must be true")
	}

	if g.KeyAlgorithm == "" || g.KeyCurve == "" || g.SignatureAlgorithm == "" || g.MinimumTLSVersion == "" {
		return fmt.Errorf("pki: global.keyAlgorithm, keyCurve, signatureAlgorithm and minimumTlsVersion are all required")
	}

	for _, extra := range g.AdditionalLeafKeyCurves {
		if extra == g.KeyCurve {
			return fmt.Errorf("pki: global.additionalLeafKeyCurves must not repeat global.keyCurve %q", g.KeyCurve)
		}
	}

	return nil
}

func validateGenerations(generations []RootGeneration, needDR bool) (map[string]generationInfo, error) {
	if len(generations) == 0 {
		return nil, fmt.Errorf("pki: at least one rootGeneration is required")
	}

	infos := make(map[string]generationInfo, len(generations))
	active := 0

	for i := range generations {
		generation := &generations[i]
		path := fmt.Sprintf("rootGenerations[%d]", i)

		if generation.ID == "" {
			return nil, fmt.Errorf("pki: %s.id is required", path)
		}

		if _, exists := infos[generation.ID]; exists {
			return nil, fmt.Errorf("pki: %s.id %q is duplicated", path, generation.ID)
		}

		lifetime, err := parsePositiveDuration(path+".lifetime", generation.Lifetime)
		if err != nil {
			return nil, err
		}

		if err := generation.Certificate.validate(path+".certificate", lifetime); err != nil {
			return nil, err
		}

		infos[generation.ID] = generationInfo{Lifetime: lifetime, MaxPathLen: generation.Certificate.MaxPathLen}

		if err := generation.Custody.validate(path+".custody", needDR); err != nil {
			return nil, err
		}

		switch generation.State {
		case GenerationPreparing, GenerationActive, GenerationRetiring, GenerationRetired:
		default:
			return nil, fmt.Errorf("pki: %s.state %q is not allowed (valid: %s, %s, %s, %s)",
				path, generation.State, GenerationPreparing, GenerationActive, GenerationRetiring, GenerationRetired)
		}

		if generation.State == GenerationActive {
			active++
		}
	}

	if active != 1 {
		return nil, fmt.Errorf("pki: exactly one rootGeneration must be active, got %d", active)
	}

	return infos, nil
}

func (rc RootCertificate) validate(path string, lifetime time.Duration) error {
	notBefore, err := time.Parse(time.RFC3339, rc.NotBefore)
	if err != nil || rc.NotBefore != notBefore.UTC().Format(time.RFC3339) {
		return fmt.Errorf("pki: %s.notBefore %q must be a canonical UTC RFC3339 timestamp", path, rc.NotBefore)
	}

	if strings.TrimSpace(rc.Subject.CommonName) == "" {
		return fmt.Errorf("pki: %s.subject.commonName is required", path)
	}

	if strings.TrimSpace(rc.Subject.Organization) == "" {
		return fmt.Errorf("pki: %s.subject.organization is required", path)
	}

	if rc.MaxPathLen < 1 {
		return fmt.Errorf("pki: %s.maxPathLen must be at least 1: a root that can sign no CA below it signs nothing at all", path)
	}

	// A name constraint on a long-lived root would fix a domain list for
	// the life of the key. Constraints belong to the trust domains' own
	// intermediates.
	if len(rc.PermittedDNSDomains) != 0 {
		return fmt.Errorf(
			"pki: %s.permittedDnsDomains must be empty; name constraints live on a trust domain's domainIntermediate, not on the root",
			path,
		)
	}

	if notBefore.Add(lifetime).Before(notBefore) {
		return fmt.Errorf("pki: %s lifetime overflows notBefore", path)
	}

	return nil
}

func (rc RootCustody) validate(path string, needDR bool) error {
	if rc.Provider != custodyProviderAWSKMS {
		return fmt.Errorf("pki: %s.provider must be %q", path, custodyProviderAWSKMS)
	}

	if !isAWSAccountID(rc.AccountID) {
		return fmt.Errorf("pki: %s.accountId must be a 12-digit AWS account ID", path)
	}

	if strings.TrimSpace(rc.Profile) == "" {
		return fmt.Errorf("pki: %s.profile is required", path)
	}

	if rc.Region == "" {
		return fmt.Errorf("pki: %s.region is required", path)
	}

	if strings.TrimSpace(rc.TrustedPrincipalARNPattern) == "" {
		return fmt.Errorf("pki: %s.trustedPrincipalArnPattern is required", path)
	}

	// A contract with no trust domain has no leaf to protect against a
	// regional loss, so the replica is optional there: but stated at all,
	// it is stated whole.
	dr := rc.DisasterRecovery
	if needDR || dr.Mode != "" || dr.Region != "" {
		if dr.Mode == "" {
			return fmt.Errorf("pki: %s.disasterRecovery.mode is required", path)
		}

		if dr.Region == "" || dr.Region == rc.Region {
			return fmt.Errorf("pki: %s.disasterRecovery.region must be set and differ from the primary region", path)
		}
	}

	return nil
}

// validate checks a DNS trust domain: its lifetime ordering, its root
// generation reference, its domain intermediate, and every role it offers.
func (d *DNSTrustDomain) validate(global Global, generations map[string]generationInfo) error {
	path := "trustDomains.dns[" + d.Name + "]"

	if d.Name == "" {
		return fmt.Errorf("pki: a dns trust domain has no name")
	}

	if d.Suffix == "" {
		return fmt.Errorf("pki: %s.suffix is required", path)
	}

	rootLifetime, rootMaxPathLen, err := checkGenerationRef(path, d.RootGeneration, generations)
	if err != nil {
		return err
	}

	leafDefault, leafMaximum, err := d.Lifetimes.validate(path, rootLifetime, true)
	if err != nil {
		return err
	}

	if err := d.DomainIntermediate.validate(path+".domainIntermediate", global, d.Suffix, rootMaxPathLen); err != nil {
		return err
	}

	if err := d.Placement.validate(path); err != nil {
		return err
	}

	if err := validateLeafRoles(path+".roles", d.Roles, global, d.Suffix, d.DomainIntermediate.PermittedDNSDomains, leafDefault, leafMaximum); err != nil {
		return err
	}

	return validateCredentialRoles(path+".credentialRoles", d.CredentialRoles, d.Roles, global, leafDefault, leafMaximum)
}

// validate checks the domain intermediate's template: a DNS-safe issuer
// name, an Intermediate-identifying subject, the fleet key curve, a path
// length shorter than the root's, and -- for a domain the caller wants
// name-constrained -- a constraint that includes the domain's own suffix.
func (d DomainIntermediate) validate(path string, global Global, suffix string, rootMaxPathLen int) error {
	if !isDNSName(d.Name) {
		return fmt.Errorf("pki: %s.name %q must be a DNS-safe issuer name", path, d.Name)
	}

	if strings.TrimSpace(d.Subject.CommonName) == "" {
		return fmt.Errorf("pki: %s.subject.commonName is required", path)
	}

	if strings.TrimSpace(d.Subject.Organization) == "" {
		return fmt.Errorf("pki: %s.subject.organization is required", path)
	}

	if d.KeyCurve != global.KeyCurve {
		return fmt.Errorf("pki: %s.keyCurve must be %q (global.keyCurve), got %q", path, global.KeyCurve, d.KeyCurve)
	}

	if d.MaxPathLen < 0 || d.MaxPathLen != rootMaxPathLen-1 {
		return fmt.Errorf(
			"pki: %s.maxPathLen must be %d (one less than its root generation's %d): a domain intermediate spends exactly one level of the root's budget",
			path, rootMaxPathLen-1, rootMaxPathLen,
		)
	}

	if len(d.PermittedDNSDomains) == 0 {
		return nil
	}

	if !slices.ContainsFunc(d.PermittedDNSDomains, func(constraint string) bool { return strings.EqualFold(constraint, suffix) }) {
		return fmt.Errorf("pki: %s.permittedDnsDomains must include the trust domain's own suffix %q", path, suffix)
	}

	seen := map[string]struct{}{}

	for i, constraint := range d.PermittedDNSDomains {
		if !isDNSName(constraint) {
			return fmt.Errorf("pki: %s.permittedDnsDomains[%d] %q is not a DNS domain", path, i, constraint)
		}

		key := strings.ToLower(constraint)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("pki: %s.permittedDnsDomains[%d] %q is duplicated", path, i, constraint)
		}

		seen[key] = struct{}{}
	}

	return nil
}

// validate checks a URI trust domain: its lifetime ordering, its root
// generation reference, its URI-shaped intermediate and role, and the
// per-environment allow-lists that are this domain's only lever.
func (d *URITrustDomain) validate(global Global, generations map[string]generationInfo) error {
	path := "trustDomains.uri[" + d.Name + "]"

	if d.Name == "" {
		return fmt.Errorf("pki: a uri trust domain has no name")
	}

	rootLifetime, rootMaxPathLen, err := checkGenerationRef(path, d.RootGeneration, generations)
	if err != nil {
		return err
	}

	shared := d.hasSharedIntermediate()

	leafDefault, leafMaximum, err := d.Lifetimes.validate(path, rootLifetime, shared)
	if err != nil {
		return err
	}

	if shared {
		if err := d.DomainIntermediate.validate(path+".domainIntermediate", global, rootMaxPathLen); err != nil {
			return err
		}
	} else if d.EnvironmentCA == nil {
		return fmt.Errorf("pki: %s declares neither domainIntermediate nor environmentCA: nothing would sign its environments", path)
	}

	if err := d.Placement.validate(path); err != nil {
		return err
	}

	if err := d.Role.validate(path+".role", global, leafDefault, leafMaximum); err != nil {
		return err
	}

	if len(d.Environments) == 0 {
		return fmt.Errorf("pki: %s.environments must name at least one environment", path)
	}

	seenEnvironments := map[string]struct{}{}

	for i, environment := range d.Environments {
		envPath := fmt.Sprintf("%s.environments[%d]", path, i)
		if !isDNSLabel(environment) {
			return fmt.Errorf("pki: %s %q is not a bare environment name", envPath, environment)
		}

		if _, duplicate := seenEnvironments[environment]; duplicate {
			return fmt.Errorf("pki: %s duplicates %q", envPath, environment)
		}

		seenEnvironments[environment] = struct{}{}
	}

	if len(d.RootSignedEnvironments) == 0 && shared {
		if d.EnvironmentCA != nil {
			return fmt.Errorf("pki: %s.environmentCA is declared but rootSignedEnvironments is empty", path)
		}

		return nil
	}

	if d.EnvironmentCA == nil {
		return fmt.Errorf("pki: %s.rootSignedEnvironments is declared but environmentCA is not", path)
	}

	// The root's budget below the shared intermediate (when there is
	// one) or below the root itself.
	ceiling := rootMaxPathLen
	if shared {
		ceiling = d.DomainIntermediate.MaxPathLen
	}

	if err := d.EnvironmentCA.validate(path+".environmentCA", global, ceiling, shared); err != nil {
		return err
	}

	seenRootSigned := map[string]struct{}{}

	for i, environment := range d.RootSignedEnvironments {
		envPath := fmt.Sprintf("%s.rootSignedEnvironments[%d]", path, i)
		if _, declared := seenEnvironments[environment]; !declared {
			return fmt.Errorf(
				"pki: %s %q is not in %s.environments %v: an environment needs an issuing CA before it can get the root-signed one",
				envPath, environment, path, d.Environments,
			)
		}

		if _, duplicate := seenRootSigned[environment]; duplicate {
			return fmt.Errorf("pki: %s duplicates %q", envPath, environment)
		}

		seenRootSigned[environment] = struct{}{}
	}

	// With no shared intermediate every environment is root-signed, so
	// a list that says otherwise contradicts the domain.
	if !shared && len(d.RootSignedEnvironments) != 0 && len(seenRootSigned) != len(seenEnvironments) {
		return fmt.Errorf(
			"pki: %s.rootSignedEnvironments %v must name every environment %v: with no shared domainIntermediate there is no other way to sign one",
			path, d.RootSignedEnvironments, d.Environments)
	}

	return nil
}

// validate checks the URI domain intermediate's template: the same
// authority checks a DNS domain intermediate carries, plus its own URI
// constraint (which may be empty: some estates constrain only at the
// per-environment CA, never at the shared intermediate).
func (d URIDomainIntermediate) validate(path string, global Global, rootMaxPathLen int) error {
	if !isDNSName(d.Name) {
		return fmt.Errorf("pki: %s.name %q must be a DNS-safe issuer name", path, d.Name)
	}

	if strings.TrimSpace(d.Subject.CommonName) == "" {
		return fmt.Errorf("pki: %s.subject.commonName is required", path)
	}

	if strings.TrimSpace(d.Subject.Organization) == "" {
		return fmt.Errorf("pki: %s.subject.organization is required", path)
	}

	if d.KeyCurve != global.KeyCurve {
		return fmt.Errorf("pki: %s.keyCurve must be %q (global.keyCurve), got %q", path, global.KeyCurve, d.KeyCurve)
	}

	if d.MaxPathLen < 0 || d.MaxPathLen != rootMaxPathLen-1 {
		return fmt.Errorf(
			"pki: %s.maxPathLen must be %d (one less than its root generation's %d)",
			path, rootMaxPathLen-1, rootMaxPathLen,
		)
	}

	seen := map[string]struct{}{}

	for i, constraint := range d.PermittedURIDomains {
		if strings.TrimSpace(constraint) == "" {
			return fmt.Errorf("pki: %s.permittedUriDomains[%d] is empty", path, i)
		}

		if _, duplicate := seen[constraint]; duplicate {
			return fmt.Errorf("pki: %s.permittedUriDomains[%d] %q is duplicated", path, i, constraint)
		}

		seen[constraint] = struct{}{}
	}

	return nil
}

// validate checks the per-environment CA template: the fleet curve
// (subject to Global.AdditionalLeafKeyCurves, though this is a CA, not a
// leaf -- an authority never uses the exception), and a path length
// strictly shorter than the sibling domain intermediate's -- signed
// directly by the root, one level shorter, because nothing sits between it
// and the leaf it issues.
func (ca EnvironmentCA) validate(path string, global Global, ceiling int, shared bool) error {
	if ca.KeyCurve != global.KeyCurve {
		return fmt.Errorf("pki: %s.keyCurve must be %q (global.keyCurve), got %q", path, global.KeyCurve, ca.KeyCurve)
	}

	if ca.MaxPathLen < 0 || ca.MaxPathLen >= ceiling {
		what := "the root's own maxPathLen"
		if shared {
			what = "the domain's own intermediate maxPathLen"
		}

		return fmt.Errorf(
			"pki: %s.maxPathLen must be non-negative and strictly less than %s %d: this CA is signed directly by the root, one level shorter",
			path, what, ceiling,
		)
	}

	if strings.TrimSpace(ca.CommonNameSuffix) == "" {
		return fmt.Errorf("pki: %s.commonNameSuffix is required", path)
	}

	if ca.ArtifactPattern != "" && !strings.Contains(ca.ArtifactPattern, "{environment}") {
		return fmt.Errorf(
			"pki: %s.artifactPattern must contain \"{environment}\": without it, every environment's CA would share one file",
			path,
		)
	}

	if ca.IssuerNamePattern != "" {
		if !strings.Contains(ca.IssuerNamePattern, "{environment}") {
			return fmt.Errorf(
				"pki: %s.issuerNamePattern must contain \"{environment}\": without it, every environment's CA would share one issuer name",
				path,
			)
		}

		if !isDNSName(strings.ReplaceAll(ca.IssuerNamePattern, "{environment}", "environment")) {
			return fmt.Errorf("pki: %s.issuerNamePattern %q must be a DNS-safe issuer name", path, ca.IssuerNamePattern)
		}
	}

	return nil
}

// validate checks the identity-shaped role: it must sign at least one use,
// hold to a permitted key curve, and its lifetimes must sit inside the
// domain's own.
func (r URIRole) validate(path string, global Global, leafDefault, leafMaximum time.Duration) error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("pki: %s.name is required", path)
	}

	if strings.TrimSpace(r.URISANPattern) == "" {
		return fmt.Errorf("pki: %s.uriSanPattern is required", path)
	}

	if !r.Usage.Server && !r.Usage.Client {
		return fmt.Errorf("pki: %s.usage must allow server or client use", path)
	}

	if !global.leafKeyCurveAllowed(r.KeyCurve) {
		return fmt.Errorf("pki: %s.keyCurve %q is neither global.keyCurve %q nor one of global.additionalLeafKeyCurves", path, r.KeyCurve, global.KeyCurve)
	}

	return r.Lifetimes.validate(path+".lifetimes", leafDefault, leafMaximum)
}

// validate requires every declared role to sign at least one use, hold to
// a permitted key curve, offer a name shape the domain's own constraint
// admits (when it has one), allow a wildcard only from a catalog source,
// and hold lifetimes inside the domain's own.
func validateLeafRoles(path string, roles []LeafRole, global Global, suffix string, permitted []string, leafDefault, leafMaximum time.Duration) error {
	if len(roles) == 0 {
		return fmt.Errorf("pki: %s must declare at least one role", path)
	}

	seen := map[string]struct{}{}

	for i := range roles {
		role := &roles[i]
		rolePath := fmt.Sprintf("%s[%d]", path, i)

		if strings.TrimSpace(role.Name) == "" {
			return fmt.Errorf("pki: %s.name is required", rolePath)
		}

		if _, duplicate := seen[role.Name]; duplicate {
			return fmt.Errorf("pki: %s duplicates role name %q", rolePath, role.Name)
		}

		seen[role.Name] = struct{}{}

		if !global.leafKeyCurveAllowed(role.KeyCurve) {
			return fmt.Errorf("pki: %s.keyCurve %q is neither global.keyCurve %q nor one of global.additionalLeafKeyCurves", rolePath, role.KeyCurve, global.KeyCurve)
		}

		// A wildcard is allowed only where the names come from a caller
		// catalog, which is the narrowing that makes it safe: the
		// allowed list IS the declared catalog, so nothing can ask for a
		// wildcard the catalog does not already name. An authored
		// pattern carries no such bound -- a wildcard there would widen
		// every name the pattern can produce.
		if role.AllowWildcard && role.Names.Source != NameSourceCatalog {
			return fmt.Errorf(
				"pki: %s.allowWildcardCertificates may be true only where names.source is %q,"+
					" so that a wildcard is a declared catalog entry rather than an authored pattern",
				rolePath, NameSourceCatalog)
		}

		if !role.Usage.Server && !role.Usage.Client {
			return fmt.Errorf("pki: %s.usage must allow server or client use", rolePath)
		}

		if err := role.Names.validate(rolePath+".names", suffix, permitted); err != nil {
			return err
		}

		if err := role.Lifetimes.validate(rolePath+".lifetimes", leafDefault, leafMaximum); err != nil {
			return err
		}
	}

	return nil
}

// validate checks a role's name shape against the trust domain's own
// suffix (the representative value substituted for [ZonePlaceholder]: the
// real per-environment zone is never authored here, so the domain's own
// suffix stands in for it, which resolves every pattern to the same
// concrete shape a real environment's zone would) and, when the domain
// intermediate carries one, its DNS name constraint. permitted is the
// domain intermediate's own PermittedDNSDomains; nil means unconstrained.
func (n NameShape) validate(path, suffix string, permitted []string) error {
	if !n.Bare && !n.Subdomains {
		return fmt.Errorf("pki: %s must admit the bare name, subdomains, or both", path)
	}

	switch n.Source {
	case NameSourceCatalog:
		if len(n.Patterns) != 0 {
			return fmt.Errorf("pki: %s.patterns must be empty for source %q: the caller's catalog is the list", path, n.Source)
		}

		return nil
	case NameSourceEnvironmentZone, NameSourceStatic:
	default:
		return fmt.Errorf(
			"pki: %s.source %q is not allowed (valid: %s, %s, %s)",
			path, n.Source, NameSourceEnvironmentZone, NameSourceStatic, NameSourceCatalog,
		)
	}

	if len(n.Patterns) == 0 {
		return fmt.Errorf("pki: %s.patterns must not be empty for source %q", path, n.Source)
	}

	for i, pattern := range n.Patterns {
		patternPath := fmt.Sprintf("%s.patterns[%d]", path, i)

		var concrete string

		switch n.Source {
		case NameSourceEnvironmentZone:
			if pattern != ZonePlaceholder && !strings.HasSuffix(pattern, "."+ZonePlaceholder) {
				return fmt.Errorf("pki: %s %q must be %q or end with %q", patternPath, pattern, ZonePlaceholder, "."+ZonePlaceholder)
			}
			// The real per-environment zone is never authored here; the
			// domain's own suffix stands in for it, so the pattern's
			// SHAPE (does it sit within the domain's own constraint) is
			// checked the same way for every environment.
			concrete = strings.TrimSuffix(pattern, ZonePlaceholder) + suffix
		case NameSourceStatic:
			concrete = pattern
		}

		if !isDNSName(concrete) {
			return fmt.Errorf("pki: %s %q is not a DNS name shape", patternPath, pattern)
		}

		// A role admitting names the chain's constraint rejects would
		// sign certificates no verifier accepts.
		if len(permitted) != 0 && !nameIsPermitted(concrete, permitted) {
			return fmt.Errorf(
				"pki: %s %q is outside the domain intermediate's name constraint %v",
				patternPath, pattern, permitted,
			)
		}
	}

	return nil
}

func (l LeafLifetimes) validate(path string, leafDefault, leafMaximum time.Duration) error {
	roleDefault, err := parsePositiveDuration(path+".default", l.Default)
	if err != nil {
		return err
	}

	roleMaximum, err := parsePositiveDuration(path+".maximum", l.Maximum)
	if err != nil {
		return err
	}

	if roleMaximum > leafMaximum || roleDefault > leafDefault || roleDefault > roleMaximum {
		return fmt.Errorf(
			"pki: %s must satisfy maximum <= trust domain leafMaximum, default <= trust domain leafDefault, default <= maximum",
			path,
		)
	}

	if l.RenewBefore == "" {
		return nil
	}

	renewBefore, err := parsePositiveDuration(path+".renewBefore", l.RenewBefore)
	if err != nil {
		return err
	}

	if renewBefore >= roleDefault {
		return fmt.Errorf("pki: %s.renewBefore must be shorter than default", path)
	}

	return nil
}

// validate checks a trust domain's lifetime ordering against its root
// generation's own lifetime, and returns the leaf default/maximum every
// role or the URI role must sit inside.
func (l Lifetimes) validate(path string, rootLifetime time.Duration, needDomainIntermediate bool) (leafDefault, leafMaximum time.Duration, err error) {
	// Above the cluster intermediate sits the root, or -- with a shared
	// intermediate -- the domain intermediate and then the root.
	parent := rootLifetime

	if needDomainIntermediate {
		domainLifetime, err := parsePositiveDuration(path+".lifetimes.domainIntermediate", l.DomainIntermediate)
		if err != nil {
			return 0, 0, err
		}

		if rootLifetime <= domainLifetime {
			return 0, 0, errLifetimeOrdering(path)
		}

		parent = domainLifetime
	} else if l.DomainIntermediate != "" {
		return 0, 0, fmt.Errorf("pki: %s.lifetimes.domainIntermediate is set but the domain has no domainIntermediate", path)
	}

	clusterLifetime, err := parsePositiveDuration(path+".lifetimes.clusterIntermediate", l.ClusterIntermediate)
	if err != nil {
		return 0, 0, err
	}

	leafDefault, err = parsePositiveDuration(path+".lifetimes.leafDefault", l.LeafDefault)
	if err != nil {
		return 0, 0, err
	}

	leafMaximum, err = parsePositiveDuration(path+".lifetimes.leafMaximum", l.LeafMaximum)
	if err != nil {
		return 0, 0, err
	}

	renewBefore, err := parsePositiveDuration(path+".lifetimes.renewBefore", l.RenewBefore)
	if err != nil {
		return 0, 0, err
	}

	validOrdering := parent > clusterLifetime &&
		clusterLifetime > leafMaximum &&
		leafMaximum >= leafDefault &&
		leafDefault > renewBefore

	if !validOrdering {
		return 0, 0, errLifetimeOrdering(path)
	}

	return leafDefault, leafMaximum, nil
}

func errLifetimeOrdering(path string) error {
	return fmt.Errorf(
		"pki: %s lifetimes must satisfy root > domain intermediate (when there is one) > cluster intermediate > leaf maximum >= leaf default > renewBefore",
		path,
	)
}

// checkGenerationRef resolves a trust domain's rootGeneration reference and
// returns that generation's own lifetime and root maxPathLen.
func checkGenerationRef(path, generationID string, generations map[string]generationInfo) (time.Duration, int, error) {
	info, ok := generations[generationID]
	if !ok {
		return 0, 0, fmt.Errorf("pki: %s.rootGeneration references unknown generation %q", path, generationID)
	}

	return info.Lifetime, info.MaxPathLen, nil
}

func (a Alerts) validate(generations map[string]generationInfo, domains TrustDomains, needed bool) error {
	if a.Enabled {
		return fmt.Errorf("pki: alerts.enabled must remain false until an alert consumer exists")
	}

	if !needed && a.Thresholds == (AlertThresholds{}) {
		return nil
	}

	rootThreshold, err := parsePositiveDuration("alerts.thresholds.rootGeneration", a.Thresholds.RootGeneration)
	if err != nil {
		return err
	}

	domainThreshold, err := parsePositiveDuration("alerts.thresholds.domainIntermediate", a.Thresholds.DomainIntermediate)
	if err != nil {
		return err
	}

	clusterThreshold, err := parsePositiveDuration("alerts.thresholds.clusterIntermediate", a.Thresholds.ClusterIntermediate)
	if err != nil {
		return err
	}

	leafThreshold, err := parsePositiveDuration("alerts.thresholds.leaf", a.Thresholds.Leaf)
	if err != nil {
		return err
	}

	validThresholdOrdering := rootThreshold > domainThreshold &&
		domainThreshold > clusterThreshold &&
		clusterThreshold > leafThreshold

	if !validThresholdOrdering {
		return fmt.Errorf("pki: alert thresholds must satisfy root generation > domain intermediate > cluster intermediate > leaf")
	}

	for id, info := range generations {
		if rootThreshold >= info.Lifetime {
			return fmt.Errorf("pki: alerts.thresholds.rootGeneration must be shorter than rootGeneration %q lifetime", id)
		}
	}

	for i := range domains.DNS {
		domain := &domains.DNS[i]

		domainLifetime, _ := time.ParseDuration(domain.Lifetimes.DomainIntermediate)
		clusterLifetime, _ := time.ParseDuration(domain.Lifetimes.ClusterIntermediate)
		leafLifetime, _ := time.ParseDuration(domain.Lifetimes.LeafDefault)

		if domainThreshold >= domainLifetime || clusterThreshold >= clusterLifetime || leafThreshold >= leafLifetime {
			return fmt.Errorf("pki: alerts thresholds must be shorter than the corresponding %s trust-domain lifetimes", domain.Name)
		}
	}

	return nil
}

func (s SignAlerts) validate(needed bool) error {
	if len(s.Notify) == 0 && !needed {
		return nil
	}

	if len(s.Notify) == 0 {
		return fmt.Errorf("pki: signAlerts.notify must name at least one recipient of every root-key Sign")
	}

	seen := map[string]struct{}{}

	for i, address := range s.Notify {
		path := fmt.Sprintf("signAlerts.notify[%d]", i)
		if address != strings.ToLower(strings.TrimSpace(address)) {
			return fmt.Errorf("pki: %s must be a lowercase address without surrounding space", path)
		}

		local, domain, ok := strings.Cut(address, "@")
		if !ok || local == "" || domain == "" || strings.ContainsAny(address, " \t") || !strings.Contains(domain, ".") {
			return fmt.Errorf("pki: %s %q is not an email address", path, address)
		}

		if _, duplicate := seen[address]; duplicate {
			return fmt.Errorf("pki: %s duplicates %q", path, address)
		}

		seen[address] = struct{}{}
	}

	return nil
}

func (m Migration) validate(generations map[string]generationInfo, needed bool) error {
	if len(m.TrustedGenerations) == 0 && !needed {
		return nil
	}

	if len(m.TrustedGenerations) == 0 {
		return fmt.Errorf("pki: migration.trustedGenerations must not be empty")
	}

	seenGenerations := map[string]struct{}{}

	for i, id := range m.TrustedGenerations {
		if _, ok := generations[id]; !ok {
			return fmt.Errorf("pki: migration.trustedGenerations[%d] references unknown generation %q", i, id)
		}

		if _, duplicate := seenGenerations[id]; duplicate {
			return fmt.Errorf("pki: migration.trustedGenerations[%d] duplicates generation %q", i, id)
		}

		seenGenerations[id] = struct{}{}
	}

	return nil
}

func parsePositiveDuration(path, value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("pki: %s %q must be a positive Go duration", path, value)
	}

	return duration, nil
}

func isAWSAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}

	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}

func isNameUnderDomain(name, domain string) bool {
	name = strings.ToLower(name)
	domain = strings.ToLower(domain)

	return name != domain && strings.HasSuffix(name, "."+domain)
}

// nameIsPermitted applies an X.509 DNS name constraint: a permitted domain
// admits itself and every name below it.
func nameIsPermitted(name string, permitted []string) bool {
	for _, domain := range permitted {
		if strings.EqualFold(name, domain) || isNameUnderDomain(name, domain) {
			return true
		}
	}

	return false
}

// isDNSName accepts a lower-case dotted DNS name of valid labels.
func isDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}

	for _, label := range strings.Split(name, ".") {
		if !isDNSLabel(label) {
			return false
		}
	}

	return true
}

func isDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}

	for _, char := range label {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}

	return true
}

// validate checks the mount paths and description templates. Both mounts
// have a default, so an empty value is fine; a value that is stated must be
// usable.
func (p Placement) validate(path string) error {
	for name, value := range map[string]string{"domainMount": p.DomainMount, "issuingMount": p.IssuingMount} {
		if value != "" && !isMountPath(value) {
			return fmt.Errorf("pki: %s.%s %q must be a lowercase mount path (letters, digits, '-' and '_')", path, name, value)
		}
	}

	for name, template := range map[string]string{
		"domainMountDescription":  p.DomainMountDescription,
		"issuingMountDescription": p.IssuingMountDescription,
	} {
		rest := template
		for _, known := range []string{"{commonName}", "{domain}", "{environment}"} {
			rest = strings.ReplaceAll(rest, known, "")
		}

		if strings.ContainsAny(rest, "{}") {
			return fmt.Errorf("pki: %s.%s %q has a placeholder other than {commonName}, {domain} and {environment}", path, name, template)
		}
	}

	if strings.Contains(p.DomainMountDescription, "{environment}") {
		return fmt.Errorf("pki: %s.domainMountDescription must not use {environment}: the domain's mount is not per environment", path)
	}

	return nil
}

// validateCredentialRoles checks the roles that sign a caller's own CSR:
// each names the mount its subject is read from, is usable, is short and
// never renewed, and does not share a name with a leaf role (they sit on the
// same mount).
func validateCredentialRoles(path string, roles []CredentialRole, leafRoles []LeafRole, global Global, leafDefault, leafMaximum time.Duration) error {
	seen := map[string]struct{}{}

	for i := range leafRoles {
		seen[leafRoles[i].Name] = struct{}{}
	}

	for i := range roles {
		role := &roles[i]
		rolePath := fmt.Sprintf("%s[%d]", path, i)

		if strings.TrimSpace(role.Name) == "" {
			return fmt.Errorf("pki: %s.name is required", rolePath)
		}

		if _, duplicate := seen[role.Name]; duplicate {
			return fmt.Errorf("pki: %s duplicates role name %q", rolePath, role.Name)
		}

		seen[role.Name] = struct{}{}

		if strings.TrimSpace(role.SubjectMount) == "" {
			return fmt.Errorf("pki: %s.subjectMount is required: the common name is the caller's own alias name on it", rolePath)
		}

		if !role.Usage.Server && !role.Usage.Client {
			return fmt.Errorf("pki: %s.usage must allow server or client use", rolePath)
		}

		for _, validation := range role.CNValidations {
			if validation != model.CNValidationEmail && validation != model.CNValidationHostname {
				return fmt.Errorf("pki: %s.cnValidations %q is not one of %s, %s", rolePath, validation, model.CNValidationEmail, model.CNValidationHostname)
			}
		}

		if err := model.ValidateOrganizationalUnit(role.OrganizationalUnit); err != nil {
			return fmt.Errorf("pki: %s.organizationalUnit: %w", rolePath, err)
		}

		if !global.leafKeyCurveAllowed(role.KeyCurve) {
			return fmt.Errorf("pki: %s.keyCurve %q is neither global.keyCurve %q nor one of global.additionalLeafKeyCurves", rolePath, role.KeyCurve, global.KeyCurve)
		}

		if role.Lifetimes.RenewBefore != "" {
			return fmt.Errorf("pki: %s.lifetimes.renewBefore must be empty: a credential is minted for one use, never renewed", rolePath)
		}

		if err := role.Lifetimes.validate(rolePath+".lifetimes", leafDefault, leafMaximum); err != nil {
			return err
		}
	}

	return nil
}

// isMountPath accepts what OpenBAO takes as a single-segment mount path
// here: lowercase letters, digits, '-' and '_'.
func isMountPath(value string) bool {
	if value == "" {
		return false
	}

	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}

	return true
}
