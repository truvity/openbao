package model

import (
	"fmt"
	"strings"
)

// Key curves an issuer, a role or a credential role may name: every key
// is ECDSA.
const (
	CurveP256 = "P-256"
	CurveP384 = "P-384"
	CurveP521 = "P-521"
)

// CurveBits is the key size OpenBAO generates (key_type ec) for a curve.
var CurveBits = map[string]int{CurveP256: 256, CurveP384: 384, CurveP521: 521}

// CNValidationEmail and CNValidationHostname are the ways a credential
// role's common name may be required to read.
const (
	CNValidationEmail    = "email"
	CNValidationHostname = "hostname"
)

type (
	// PKIMount is one PKI secrets engine: the issuers whose keys it holds
	// and the roles that sign with them.
	//
	// A mount may hold several issuers at once -- the old and the new CA
	// through a migration, one path serving both -- and each role names
	// the issuer it signs with, so which issuer the mount calls default
	// never decides what a role signs.
	PKIMount struct {
		Path        string `yaml:"path"`
		Description string `yaml:"description,omitempty"`
		// DefaultLeaseTTL and MaxLeaseTTL bound every lease the mount
		// hands out: Go durations.
		DefaultLeaseTTL string `yaml:"defaultLeaseTtl"`
		MaxLeaseTTL     string `yaml:"maxLeaseTtl"`
		// DefaultIssuer is pinned as the mount's default (it never follows
		// the latest issuer). The mount's URLs, CRL and auto-tidy are
		// configured once it exists, and before any certificate is signed
		// on the mount: a certificate carries the AIA and CRL URLs its
		// issuing mount had when it was signed.
		DefaultIssuer   string           `yaml:"defaultIssuer"`
		Issuers         []PKIIssuer      `yaml:"issuers"`
		Roles           []PKIRole        `yaml:"roles,omitempty"`
		CredentialRoles []CredentialRole `yaml:"credentialRoles,omitempty"`
	}

	// PKIIssuer is one CA whose key OpenBAO generates inside the mount and
	// never exports. Exactly one of SelfSigned, SignedBy and External says
	// who signs its certificate.
	PKIIssuer struct {
		// Name is the issuer's name and its key's name. Names are unique
		// across the server: the apply names resources and outputs after
		// them.
		Name         string `yaml:"name"`
		CommonName   string `yaml:"commonName"`
		Organization string `yaml:"organization,omitempty"`
		KeyCurve     string `yaml:"keyCurve"`
		// TTL, MaxPathLength and NameConstraints are what the signer puts
		// in the certificate. For an External issuer they record what the
		// external signer is expected to put there; the apply does not
		// sign it and does not check them.
		TTL             string           `yaml:"ttl,omitempty"`
		MaxPathLength   int              `yaml:"maxPathLength"`
		NameConstraints *NameConstraints `yaml:"nameConstraints,omitempty"`
		// SelfSigned makes a root inside OpenBAO.
		SelfSigned bool `yaml:"selfSigned,omitempty"`
		// SignedBy is an issuer of a mount declared earlier, which signs
		// this one's request inside OpenBAO.
		SignedBy *IssuerRef `yaml:"signedBy,omitempty"`
		// External is signed outside OpenBAO -- by a root whose key is
		// elsewhere. The apply exports the certificate request and imports
		// the chain the caller supplies.
		External bool `yaml:"external,omitempty"`
	}

	// IssuerRef names an issuer: the namespace ("" is root), the mount,
	// the issuer.
	IssuerRef struct {
		Namespace string `yaml:"namespace,omitempty"`
		Mount     string `yaml:"mount"`
		Issuer    string `yaml:"issuer"`
	}

	// NameConstraints is the name-constraints extension a signer puts on
	// a CA certificate. Every list is optional; an empty one is left out.
	NameConstraints struct {
		PermittedDNSDomains     []string `yaml:"permittedDnsDomains,omitempty"`
		ExcludedIPRanges        []string `yaml:"excludedIpRanges,omitempty"`
		PermittedEmailAddresses []string `yaml:"permittedEmailAddresses,omitempty"`
		PermittedURIDomains     []string `yaml:"permittedUriDomains,omitempty"`
	}

	// PKIRole is one leaf profile for host names: what it may sign, with
	// which issuer, for how long. Everything a role does not allow is
	// refused by the apply whatever is written here: no templated or glob
	// domains, no any-name, no IP, URI or other SAN, no localhost, no
	// e-mail protection; a common name, when present, must be a host name.
	PKIRole struct {
		Name string `yaml:"name"`
		// Issuer is one of the mount's issuers.
		Issuer           string   `yaml:"issuer,omitempty"`
		AllowedDomains   []string `yaml:"allowedDomains"`
		AllowBareDomains bool     `yaml:"allowBareDomains"`
		AllowSubdomains  bool     `yaml:"allowSubdomains"`
		// AllowWildcards admits a wildcard certificate. An exact wildcard
		// entry in AllowedDomains matches as a bare domain, so a role may
		// sign exactly the wildcards it lists and nothing deeper.
		AllowWildcards bool   `yaml:"allowWildcardCertificates"`
		Server         bool   `yaml:"server"`
		Client         bool   `yaml:"client"`
		KeyCurve       string `yaml:"keyCurve"`
		TTL            string `yaml:"ttl"`
		MaxTTL         string `yaml:"maxTtl"`
		// RenewBefore is when a consumer should renew. It is not an
		// OpenBAO setting; it travels with the role so the consumers'
		// configuration can be derived from the same row.
		RenewBefore string `yaml:"renewBefore,omitempty"`
	}

	// CredentialRole signs a CSR for the caller and nobody else: the only
	// common name it accepts is the caller's own entity alias name on
	// SubjectMount -- for a login whose user claim is `sub`, the token's
	// subject. It offers `sign` only, so the key is always the caller's,
	// and stores nothing, so its revocation model is its short life.
	CredentialRole struct {
		Name string `yaml:"name"`
		// Issuer is one of the mount's issuers.
		Issuer string `yaml:"issuer"`
		// SubjectMount is the auth mount, in the same namespace, whose
		// alias name the common name must equal.
		SubjectMount string `yaml:"subjectMount"`
		// CNValidations is how the common name must read.
		CNValidations []string `yaml:"cnValidations"`
		Server        bool     `yaml:"server"`
		Client        bool     `yaml:"client"`
		KeyCurve      string   `yaml:"keyCurve"`
		TTL           string   `yaml:"ttl"`
		MaxTTL        string   `yaml:"maxTtl"`
	}
)

// String is `<namespace>/<mount>/<issuer>`, `root` for root.
func (r IssuerRef) String() string {
	namespace := r.Namespace
	if namespace == "" {
		namespace = "root"
	}

	return namespace + "/" + r.Mount + "/" + r.Issuer
}

// Validate refuses a mount that could not be applied as it reads.
func (m *PKIMount) Validate() error {
	if strings.TrimSpace(m.Path) == "" {
		return fmt.Errorf("a PKI mount has no path")
	}

	if err := lifetime("PKI mount "+m.Path+" lease", m.DefaultLeaseTTL, m.MaxLeaseTTL); err != nil {
		return err
	}

	if len(m.Issuers) == 0 {
		return fmt.Errorf("PKI mount %q holds no issuer", m.Path)
	}

	issuers := map[string]bool{}

	for i := range m.Issuers {
		issuer := &m.Issuers[i]
		if err := issuer.Validate(); err != nil {
			return fmt.Errorf("PKI mount %q: %w", m.Path, err)
		}

		if issuers[issuer.Name] {
			return fmt.Errorf("PKI mount %q declares issuer %q twice", m.Path, issuer.Name)
		}

		issuers[issuer.Name] = true
	}

	if !issuers[m.DefaultIssuer] {
		return fmt.Errorf("PKI mount %q defaults to issuer %q, which it does not hold", m.Path, m.DefaultIssuer)
	}

	roles := map[string]bool{}
	claim := func(name, issuer string) error {
		if roles[name] {
			return fmt.Errorf("PKI mount %q declares role %q twice", m.Path, name)
		}

		roles[name] = true

		if !issuers[issuer] {
			return fmt.Errorf("PKI mount %q: role %q signs with issuer %q, which the mount does not hold", m.Path, name, issuer)
		}

		return nil
	}

	for i := range m.Roles {
		role := &m.Roles[i]
		if err := role.Validate(); err != nil {
			return fmt.Errorf("PKI mount %q: %w", m.Path, err)
		}

		if err := claim(role.Name, role.Issuer); err != nil {
			return err
		}
	}

	for i := range m.CredentialRoles {
		role := &m.CredentialRoles[i]
		if err := role.Validate(); err != nil {
			return fmt.Errorf("PKI mount %q: %w", m.Path, err)
		}

		if err := claim(role.Name, role.Issuer); err != nil {
			return err
		}
	}

	return nil
}

// Validate refuses an issuer with no name, no subject or an unknown curve,
// one that is signed by nobody or by two signers at once, and a CA signed
// inside OpenBAO with no lifetime or a negative path length.
func (i *PKIIssuer) Validate() error {
	if strings.TrimSpace(i.Name) == "" {
		return fmt.Errorf("an issuer has no name")
	}

	if strings.TrimSpace(i.CommonName) == "" {
		return fmt.Errorf("issuer %q has no common name", i.Name)
	}

	if _, ok := CurveBits[i.KeyCurve]; !ok {
		return fmt.Errorf("issuer %q: unknown key curve %q (P-256, P-384, P-521)", i.Name, i.KeyCurve)
	}

	sources := 0
	for _, set := range []bool{i.SelfSigned, i.SignedBy != nil, i.External} {
		if set {
			sources++
		}
	}

	if sources != 1 {
		return fmt.Errorf("issuer %q must be exactly one of selfSigned, signedBy and external", i.Name)
	}

	if i.MaxPathLength < 0 {
		return fmt.Errorf("issuer %q has a negative path length; an unbounded CA is never declared", i.Name)
	}

	if i.External {
		return nil
	}

	if _, err := durationSeconds(i.TTL); err != nil {
		return fmt.Errorf("issuer %q: %w", i.Name, err)
	}

	if i.SignedBy != nil && (i.SignedBy.Mount == "" || i.SignedBy.Issuer == "") {
		return fmt.Errorf("issuer %q is signed by %+v, which names no mount or issuer", i.Name, *i.SignedBy)
	}

	return nil
}

// Validate refuses a role that signs no name, a wildcard pattern it could
// not bound, or for longer than it allows.
func (r *PKIRole) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("a PKI role has no name")
	}

	if len(r.AllowedDomains) == 0 {
		return fmt.Errorf("PKI role %q allows no domain, so it could sign nothing", r.Name)
	}

	for _, domain := range r.AllowedDomains {
		if strings.TrimSpace(domain) == "" || strings.Contains(domain, "{{") {
			return fmt.Errorf("PKI role %q allows %q, which is not a domain", r.Name, domain)
		}
	}

	if !r.AllowBareDomains && !r.AllowSubdomains {
		return fmt.Errorf("PKI role %q allows neither bare domains nor subdomains, so it could sign nothing", r.Name)
	}

	if !r.Server && !r.Client {
		return fmt.Errorf("PKI role %q signs certificates usable for nothing", r.Name)
	}

	if _, ok := CurveBits[r.KeyCurve]; !ok {
		return fmt.Errorf("PKI role %q: unknown key curve %q", r.Name, r.KeyCurve)
	}

	return lifetime("PKI role "+r.Name, r.TTL, r.MaxTTL)
}

// Validate refuses a credential role that reads the subject from nowhere,
// signs certificates usable for nothing, or lives longer than it allows.
func (r *CredentialRole) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("a credential role has no name")
	}

	if strings.TrimSpace(r.SubjectMount) == "" {
		return fmt.Errorf("credential role %q names no mount to read the subject from", r.Name)
	}

	if !r.Client && !r.Server {
		return fmt.Errorf("credential role %q signs certificates usable for nothing", r.Name)
	}

	for _, validation := range r.CNValidations {
		if validation != CNValidationEmail && validation != CNValidationHostname {
			return fmt.Errorf("credential role %q: unknown common-name validation %q", r.Name, validation)
		}
	}

	if _, ok := CurveBits[r.KeyCurve]; !ok {
		return fmt.Errorf("credential role %q: unknown key curve %q", r.Name, r.KeyCurve)
	}

	return lifetime("credential role "+r.Name, r.TTL, r.MaxTTL)
}
