// Package pki is the authored contract of a KMS-rooted private PKI: one or
// more root-key generations, the trust domains signed below them, the leaf
// roles each domain offers per environment, and the migration and alerting
// policy that goes with a root that can never be re-signed.
//
// It is the layer above [github.com/truvity/openbao/pkg/ceremony]: this
// package decides WHAT is signed -- the subjects, lifetimes, name
// constraints and path lengths a domain's certificates must carry, and the
// invariants that make the whole hierarchy self-consistent -- and hands the
// mechanical HOW (deterministic serials, the CSR/root checks, the .attempt
// reservation, the one KMS signing call) to pkg/ceremony's spec builders.
// Nothing in this package signs anything or holds a credential.
//
// A contract is authored once as YAML ([Load]) and never edited to change
// what a root already signed: a new domain, a new environment or a new
// generation is added beside what exists, and [Validate] refuses anything
// that would contradict it (see docs/pki.md).
package pki

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	// SchemaVersion is the only schema version [Load] accepts. A contract
	// bumps it, deliberately, when a change to this package would read an
	// existing file differently than before.
	SchemaVersion = 1

	// KindDNS is a trust domain whose leaves carry DNS names: a suffix, an
	// optional DNS name constraint on the domain intermediate, and a list
	// of leaf roles shaped by [NameShape].
	KindDNS = "dns"
	// KindURI is a workload-identity-shaped trust domain: a URI name
	// constraint instead of a DNS one (or none at all), one leaf role per
	// environment issuing a URI SAN alone, and an explicit per-environment
	// allow-list rather than "every environment automatically". See
	// docs/pki.md.
	KindURI = "uri"

	// NameSourceEnvironmentZone substitutes [ZonePlaceholder] in each
	// pattern with the environment's own value for this domain (its DNS
	// zone, typically). The contract never spells the value out, so it
	// never becomes a second owner of it.
	NameSourceEnvironmentZone = "environment-zone"
	// NameSourceStatic takes a role's patterns literally: an authored
	// domain (or domain suffix), the same for every environment.
	NameSourceStatic = "static"
	// NameSourceCatalog means the allowed names are supplied by the
	// caller at render time -- an external catalog this contract does not
	// own -- rather than authored as patterns here. Only a role using this
	// source may allow a wildcard certificate ([LeafRole.AllowWildcard]):
	// the caller's catalog IS the declared list, so nothing can ask for a
	// wildcard the catalog itself does not already name, which an authored
	// pattern can never guarantee.
	NameSourceCatalog = "catalog"

	// ZonePlaceholder in a role's or a URI role's pattern stands for the
	// environment's own value in that trust domain, supplied by the caller
	// (never authored in the contract, so the contract is never a second
	// owner of it).
	ZonePlaceholder = "{zone}"

	// GenerationPreparing is a generation whose custody exists but has not
	// yet become the fleet's active one; a ceremony may still sign under
	// it.
	GenerationPreparing = "preparing"
	// GenerationActive is the one generation every trust domain below the
	// root is declared under. Exactly one generation is GenerationActive.
	GenerationActive = "active"
	// GenerationRetiring is a generation no longer signing new material
	// but not yet fully drained.
	GenerationRetiring = "retiring"
	// GenerationRetired is a generation that never signs again.
	GenerationRetired = "retired"

	// DefaultArtifactDir is where a generation's committed ceremony
	// artifacts live, relative to the directory the contract file itself
	// is in, when the contract does not name ArtifactDir explicitly.
	DefaultArtifactDir = "pki-roots"

	// intermediateArtifactInfix sits between a generation ID and a trust
	// domain (and, for a per-environment CA, the environment) in the file
	// name of a signed intermediate, so every ceremony artifact of one
	// generation sorts next to its root.
	intermediateArtifactInfix = "-intermediate-"

	custodyProviderAWSKMS = "aws-kms"
)

type (
	// Contract is the whole authored policy: every root generation, every
	// trust domain, and the migration and alerting policy that goes with
	// them. Load it with [Load]; every exported method on it assumes
	// [Contract.Validate] has already passed.
	Contract struct {
		SchemaVersion int `yaml:"schemaVersion"`
		// ArtifactDir is where ceremony artifacts are committed, relative
		// to the contract file's own directory. Empty means
		// [DefaultArtifactDir].
		ArtifactDir string `yaml:"artifactDir,omitempty"`
		// SerialNamespace prefixes every deterministic serial's
		// domain-separation label (see
		// [github.com/truvity/openbao/pkg/ceremony]); empty means that
		// package's own default. NEVER CHANGE IT once a generation has
		// signed: the serial is derived from it, so an existing root or
		// intermediate fails re-verification rather than being silently
		// re-derived under a new one. An estate adopting an existing
		// ceremony (one that predates this package) sets this to
		// whatever label its own code used to derive serials with, so
		// that migrating to this package changes nothing about what is
		// already signed.
		SerialNamespace string           `yaml:"serialNamespace,omitempty"`
		Global          Global           `yaml:"global"`
		Generations     []RootGeneration `yaml:"rootGenerations"`
		TrustDomains    TrustDomains     `yaml:"trustDomains"`
		Alerts          Alerts           `yaml:"alerts"`
		SignAlerts      SignAlerts       `yaml:"signAlerts"`
		Migration       Migration        `yaml:"migration"`

		// dir is the directory Load read the contract from, absolute or
		// relative to the caller's working directory; artifact paths are
		// resolved against it. Unexported: not part of the authored
		// document.
		dir string
	}

	// Global is the crypto policy every authority and every leaf in the
	// contract holds to, without exception -- immutable so that a
	// subordinate authority or a leaf role can never quietly weaken it.
	Global struct {
		// Immutable must be true. The field exists so a reader of the
		// YAML sees the policy name its own invariant, rather than
		// depending on code nobody authoring the file can see.
		Immutable          bool   `yaml:"immutable"`
		KeyAlgorithm       string `yaml:"keyAlgorithm"`
		KeyCurve           string `yaml:"keyCurve"`
		SignatureAlgorithm string `yaml:"signatureAlgorithm"`
		MinimumTLSVersion  string `yaml:"minimumTlsVersion"`
		// AdditionalLeafKeyCurves allow-lists a LEAF role's own key curve
		// to differ from KeyCurve; every CA above the leaf -- the root,
		// every domain intermediate, every environment issuing CA --
		// still signs with KeyCurve regardless. This exists for the one
		// shape a caller's own client cannot be told to change (a CSI
		// driver, an SDK, ...) that always generates a fixed curve, and
		// where the signer refuses a CSR narrower than the role's own
		// key_bits rather than accepting or downgrading it. Declaring the
		// exception here, once, is the difference between "this curve is
		// deliberate" and a silent policy drift role by role.
		AdditionalLeafKeyCurves []string `yaml:"additionalLeafKeyCurves,omitempty"`
	}

	// RootGeneration describes one immutable root-key generation and its
	// custody. Overlap between two generations is authored by adding
	// another one, never by editing a generation in place: whatever a root
	// key already signed cannot be unsigned.
	RootGeneration struct {
		ID          string          `yaml:"id"`
		Lifetime    string          `yaml:"lifetime"`
		Certificate RootCertificate `yaml:"certificate"`
		Custody     RootCustody     `yaml:"custody"`
		State       string          `yaml:"state"`
	}

	// RootCertificate is the immutable public certificate template for one
	// root generation. Its fixed activation time makes a rerun or an
	// import reproducible; the serial and subject-key identifier are
	// derived from the KMS public key, never authored.
	//
	// PermittedDNSDomains must be empty: a long-lived root does not encode
	// a domain list, the trust domains' own intermediates do (their
	// [DomainIntermediate.PermittedDNSDomains]). The field stays so the
	// ceremony template stays general (it emits a constraint only when one
	// is authored) and so a refusal can name it.
	RootCertificate struct {
		NotBefore           string   `yaml:"notBefore"`
		Subject             Subject  `yaml:"subject"`
		MaxPathLen          int      `yaml:"maxPathLen"`
		PermittedDNSDomains []string `yaml:"permittedDnsDomains,omitempty"`
	}

	// Subject is a CA certificate's subject: a common name and an optional
	// organization. One type serves the root and every domain intermediate.
	Subject struct {
		CommonName   string `yaml:"commonName"`
		Organization string `yaml:"organization,omitempty"`
	}

	// RootCustody names the AWS KMS key a generation's root lives in and
	// who may reach it. It is public information -- account, region, role
	// name pattern -- never a credential.
	RootCustody struct {
		// Provider must be "aws-kms": the only custody
		// [github.com/truvity/openbao/pkg/custody] and
		// [github.com/truvity/openbao/pkg/kmssigner] support today.
		Provider  string `yaml:"provider"`
		AccountID string `yaml:"accountId"`
		// Profile is the AWS shared-config profile a ceremony starts from.
		Profile string `yaml:"profile"`
		Region  string `yaml:"region"`
		// TrustedPrincipalARNPattern is who [pkg/custody] lets administer
		// or sign with the key: an IAM role ARN pattern (glob), checked
		// against the account above.
		TrustedPrincipalARNPattern string           `yaml:"trustedPrincipalArnPattern"`
		DisasterRecovery           DisasterRecovery `yaml:"disasterRecovery"`
	}

	// DisasterRecovery is a generation's multi-region replica.
	DisasterRecovery struct {
		Mode   string `yaml:"mode"`
		Region string `yaml:"region"`
	}

	// TrustDomains groups every trust domain by shape: DNS-shaped domains
	// (a suffix, leaf roles shaped by [NameShape]) and URI-shaped,
	// workload-identity domains (docs/pki.md). Either list may be empty; a
	// contract with no URI domain at all is an ordinary DNS-only PKI.
	TrustDomains struct {
		DNS []DNSTrustDomain `yaml:"dns,omitempty"`
		URI []URITrustDomain `yaml:"uri,omitempty"`
	}

	// DNSTrustDomain is one DNS authority below a root generation: the
	// domain intermediate the root signs, the lifetimes of everything
	// under it, and the leaf roles its environments' mounts offer.
	DNSTrustDomain struct {
		Name           string `yaml:"name"`
		Suffix         string `yaml:"suffix"`
		RootGeneration string `yaml:"rootGeneration"`
		// RequireTrusted marks a domain whose active generation must
		// always appear in [Migration.TrustedGenerations]: a leaf this
		// domain issues is worthless to whatever verifies it (a
		// tunnel/proxy terminating at the edge, say) even while the
		// mount that signs it looks perfectly healthy. A domain trusted
		// only by workloads that already hold the chain some other way
		// (mTLS between this estate's own services) leaves this false.
		RequireTrusted     bool               `yaml:"requireTrusted,omitempty"`
		DomainIntermediate DomainIntermediate `yaml:"domainIntermediate"`
		Lifetimes          Lifetimes          `yaml:"lifetimes"`
		Roles              []LeafRole         `yaml:"roles"`
	}

	// DomainIntermediate is the certificate template of a DNS trust
	// domain's intermediate, the first CA under the root. Name is its
	// OpenBAO issuer name.
	DomainIntermediate struct {
		Name                string   `yaml:"name"`
		Subject             Subject  `yaml:"subject"`
		KeyCurve            string   `yaml:"keyCurve"`
		MaxPathLen          int      `yaml:"maxPathLen"`
		PermittedDNSDomains []string `yaml:"permittedDnsDomains,omitempty"`
	}

	// URITrustDomain is a workload-identity trust domain (docs/pki.md): a
	// PARALLEL intermediate under a root generation, carrying a URI name
	// constraint instead of a DNS one. It is its own type, not
	// DNSTrustDomain, because its shape genuinely differs: no DNS suffix,
	// no per-role name patterns, one role, and an explicit
	// per-environment allow-list rather than a DNS domain's roles list.
	URITrustDomain struct {
		Name               string                `yaml:"name"`
		RootGeneration     string                `yaml:"rootGeneration"`
		DomainIntermediate URIDomainIntermediate `yaml:"domainIntermediate"`
		Lifetimes          Lifetimes             `yaml:"lifetimes"`
		// Environments is which environments get an issuing CA and the
		// role under this domain. THIS LIST IS THE ONLY LEVER: adding a
		// name here is the entire change needed to reach another
		// environment.
		Environments []string `yaml:"environments"`
		Role         URIRole  `yaml:"role"`
		// EnvironmentCA, set, lets each of RootSignedEnvironments' own
		// issuing CA be signed DIRECTLY by the root instead of by
		// DomainIntermediate, one level shorter than it, with nothing of
		// its own below it. See docs/pki.md, "per-environment identity
		// CAs".
		EnvironmentCA *EnvironmentCA `yaml:"environmentCA,omitempty"`
		// RootSignedEnvironments is a SUBSET of Environments: which of
		// them have their own issuing CA signed directly by the root
		// rather than by DomainIntermediate. Requires EnvironmentCA.
		RootSignedEnvironments []string `yaml:"rootSignedEnvironments,omitempty"`
	}

	// URIDomainIntermediate is a URI trust domain's intermediate
	// certificate template: a URI name constraint (or none) and no DNS
	// constraint at all.
	URIDomainIntermediate struct {
		Name                string   `yaml:"name"`
		Subject             Subject  `yaml:"subject"`
		KeyCurve            string   `yaml:"keyCurve"`
		MaxPathLen          int      `yaml:"maxPathLen"`
		PermittedURIDomains []string `yaml:"permittedUriDomains,omitempty"`
	}

	// EnvironmentCA is the certificate template every one of
	// RootSignedEnvironments' own issuing CA shares: signed directly by
	// the KMS root, one level shorter than DomainIntermediate (leaves
	// only, typically MaxPathLen 0), because nothing sits between it and
	// the leaf it issues. The subject and the URI constraint are derived
	// per environment (see [URITrustDomain] and docs/pki.md), never
	// authored per environment here.
	EnvironmentCA struct {
		KeyCurve   string `yaml:"keyCurve"`
		MaxPathLen int    `yaml:"maxPathLen"`
		// CommonNameSuffix is appended to an environment's own value for
		// [ZonePlaceholder] to form its root-signed CA's subject, e.g.
		// value "dev.internal.example.org" and suffix "Workload Identity
		// CA" giving "dev.internal.example.org Workload Identity CA".
		// Authored here, once, rather than derived from the role's own
		// name: there is exactly one of it, the same reason
		// [URIDomainIntermediate.Subject] is authored rather than
		// derived.
		CommonNameSuffix string `yaml:"commonNameSuffix"`
		// ArtifactPattern overrides the file name of a per-environment
		// root-signed CA's committed ceremony artifact, relative to
		// ArtifactDir. It must contain "{environment}"; "{generation}" is
		// optional. Empty means the library default,
		// [IntermediateArtifactName](generationID, the domain's own
		// name, environment).
		//
		// An estate adopting a ceremony whose per-environment artifacts
		// predate this package sets this to whatever name its own code
		// already used, so migrating to this package renames no file and
		// needs no new .attempt reservation for an artifact that is
		// already signed and committed.
		ArtifactPattern string `yaml:"artifactPattern,omitempty"`
	}

	// URIRole is the one leaf role a URI trust domain's issuing CA offers:
	// a URI SAN alone (no DNS SAN, no IP SAN).
	URIRole struct {
		Name          string        `yaml:"name"`
		URISANPattern string        `yaml:"uriSanPattern"`
		Usage         Usage         `yaml:"usage"`
		KeyCurve      string        `yaml:"keyCurve"`
		Lifetimes     LeafLifetimes `yaml:"lifetimes"`
	}

	// LeafRole is one leaf profile on a DNS trust domain's per-environment
	// mount: the shape of the names it may sign, the key usages, the key
	// curve, and its lifetimes.
	LeafRole struct {
		Name     string    `yaml:"name"`
		Names    NameShape `yaml:"names"`
		Usage    Usage     `yaml:"usage"`
		KeyCurve string    `yaml:"keyCurve"`
		// AllowWildcard admits a wildcard certificate; only legal when
		// Names.Source is [NameSourceCatalog] (see its doc).
		AllowWildcard bool          `yaml:"allowWildcardCertificates,omitempty"`
		Lifetimes     LeafLifetimes `yaml:"lifetimes"`
	}

	// NameShape is what a role's allowed domains look like. Bare admits
	// the domain itself, Subdomains admits names below it; a role with
	// neither could sign nothing.
	NameShape struct {
		Source     string   `yaml:"source"`
		Patterns   []string `yaml:"patterns,omitempty"`
		Bare       bool     `yaml:"bare"`
		Subdomains bool     `yaml:"subdomains"`
	}

	// Usage is which TLS uses a role's or a URI role's certificates are
	// signed for.
	Usage struct {
		Server bool `yaml:"server"`
		Client bool `yaml:"client"`
	}

	// LeafLifetimes bound one role's leaves within its trust domain's own
	// leaf lifetimes. RenewBefore is omitted for a role whose leaves are
	// never renewed.
	LeafLifetimes struct {
		Default     string `yaml:"default"`
		Maximum     string `yaml:"maximum"`
		RenewBefore string `yaml:"renewBefore,omitempty"`
	}

	// Lifetimes bounds a trust domain's authorities and leaves, strictly
	// decreasing from the root down: RootGeneration.Lifetime >
	// DomainIntermediate > ClusterIntermediate > LeafMaximum >=
	// LeafDefault > RenewBefore.
	Lifetimes struct {
		DomainIntermediate  string `yaml:"domainIntermediate"`
		ClusterIntermediate string `yaml:"clusterIntermediate"`
		LeafDefault         string `yaml:"leafDefault"`
		LeafMaximum         string `yaml:"leafMaximum"`
		RenewBefore         string `yaml:"renewBefore"`
	}

	// Alerts is when a certificate approaching expiry should page someone.
	// It has nothing to do with SignAlerts below.
	Alerts struct {
		Enabled    bool            `yaml:"enabled"`
		Thresholds AlertThresholds `yaml:"thresholds"`
	}

	// AlertThresholds is how far before expiry each layer of the hierarchy
	// should alert.
	AlertThresholds struct {
		RootGeneration      string `yaml:"rootGeneration"`
		DomainIntermediate  string `yaml:"domainIntermediate"`
		ClusterIntermediate string `yaml:"clusterIntermediate"`
		Leaf                string `yaml:"leaf"`
	}

	// SignAlerts is who is told that a root key SIGNED. After the
	// ceremony a root key signs only a handful of times in its life --
	// the root certificate itself, one domain intermediate per trust
	// domain, one issuing CA per root-signed environment -- so every
	// signature after that is an incident, and Notify must name at least
	// one recipient: a root nobody would hear sign is not one this
	// contract admits.
	SignAlerts struct {
		Notify []string `yaml:"notify"`
	}

	// Migration is the trust bundle: which root generations are actually
	// distributed and trusted right now.
	Migration struct {
		// TrustedGenerations lists the generations whose root certificate
		// is committed under ArtifactDir and distributed to every
		// verifier. A generation named here with no committed artifact
		// fails [Contract.TrustAnchors]: trusted must mean something a
		// verifier can act on, not an intention.
		TrustedGenerations []string `yaml:"trustedGenerations"`
	}
)

// Load reads a contract from path, strictly (an unknown key is an error),
// and validates it.
func Load(path string) (*Contract, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read contract %s: %w", path, err)
	}

	var contract Contract
	if err := readYAMLStrict(raw, &contract); err != nil {
		return nil, fmt.Errorf("read contract %s: %w", path, err)
	}

	contract.dir = pathDir(path)

	if err := contract.Validate(); err != nil {
		return nil, err
	}

	return &contract, nil
}

func readYAMLStrict(raw []byte, into any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)

	return decoder.Decode(into)
}

func pathDir(p string) string {
	dir := path.Dir(filepathToSlash(p))
	if dir == "" {
		return "."
	}

	return dir
}

func filepathToSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// ArtifactDirectory is where this contract's ceremony artifacts are
// committed, relative to the contract file's own directory.
func (c *Contract) ArtifactDirectory() string {
	if c.ArtifactDir != "" {
		return c.ArtifactDir
	}

	return DefaultArtifactDir
}

// ArtifactPath resolves a ceremony artifact's path (relative to the
// contract file's own directory) to a path relative to the caller's
// working directory, so it can be opened without the caller re-deriving
// [Contract.dir].
func (c *Contract) ArtifactPath(relative string) string {
	return path.Join(c.dir, c.ArtifactDirectory(), relative)
}

// RootArtifactName is the file name of one root generation's own ceremony
// artifact.
func RootArtifactName(generationID string) string {
	return generationID + ".yaml"
}

// IntermediateArtifactName is the file name of one trust domain's signed
// intermediate under one root generation, optionally further qualified by
// an environment (a per-environment, root-signed issuing CA). It sits
// beside that generation's root artifact.
func IntermediateArtifactName(generationID, trustDomain string, environment string) string {
	name := generationID + intermediateArtifactInfix + trustDomain
	if environment != "" {
		name += "-" + environment
	}

	return name + ".yaml"
}

// environmentCAArtifactName is the file name of one environment's
// root-signed CA artifact under this domain: [EnvironmentCA.ArtifactPattern]
// with its placeholders substituted, or the library default,
// [IntermediateArtifactName], when the domain sets no pattern.
func (d *URITrustDomain) environmentCAArtifactName(generationID, environment string) string {
	if d.EnvironmentCA == nil || d.EnvironmentCA.ArtifactPattern == "" {
		return IntermediateArtifactName(generationID, d.Name, environment)
	}

	name := d.EnvironmentCA.ArtifactPattern
	name = strings.ReplaceAll(name, "{generation}", generationID)
	name = strings.ReplaceAll(name, "{environment}", environment)

	return name
}

// RootGeneration returns the authored generation with this ID, or nil.
func (c *Contract) RootGeneration(id string) *RootGeneration {
	for i := range c.Generations {
		if c.Generations[i].ID == id {
			return &c.Generations[i]
		}
	}

	return nil
}

// DNSTrustDomain returns the authored DNS trust domain with this name, or
// nil.
func (c *Contract) DNSTrustDomain(name string) *DNSTrustDomain {
	for i := range c.TrustDomains.DNS {
		if c.TrustDomains.DNS[i].Name == name {
			return &c.TrustDomains.DNS[i]
		}
	}

	return nil
}

// URITrustDomain returns the authored URI trust domain with this name, or
// nil.
func (c *Contract) URITrustDomain(name string) *URITrustDomain {
	for i := range c.TrustDomains.URI {
		if c.TrustDomains.URI[i].Name == name {
			return &c.TrustDomains.URI[i]
		}
	}

	return nil
}

// TrustDomainNames lists the name of every trust domain this contract
// declares, DNS domains first, in authored order.
func (c *Contract) TrustDomainNames() []string {
	names := make([]string, 0, len(c.TrustDomains.DNS)+len(c.TrustDomains.URI))
	for i := range c.TrustDomains.DNS {
		names = append(names, c.TrustDomains.DNS[i].Name)
	}

	for i := range c.TrustDomains.URI {
		names = append(names, c.TrustDomains.URI[i].Name)
	}

	return names
}

// leafKeyCurveAllowed reports whether curve is Global.KeyCurve or one of
// Global.AdditionalLeafKeyCurves.
func (g Global) leafKeyCurveAllowed(curve string) bool {
	if curve == g.KeyCurve {
		return true
	}

	for _, extra := range g.AdditionalLeafKeyCurves {
		if curve == extra {
			return true
		}
	}

	return false
}
