package estate

import (
	"fmt"
	"slices"
	"strings"

	"github.com/truvity/secrets/pkg/builder"
	"github.com/truvity/secrets/pkg/model"
	"github.com/truvity/secrets/pkg/pki"
)

// credentialCommonName is the only common name a credential PKI role signs:
// the caller's own subject, as its roster login recorded it.
const credentialCommonName = "roster-subject"

type (
	// PrivatePKI is the authority chain the server serves. Root and Domains
	// are the contract's (pkg/pki). Root is NOT a mount: its key lives
	// outside the server and signs exactly once, in the ceremony; the server
	// only holds the certificates it signed. Legacy is the self-signed
	// chain, still declared because its mounts and roles are what the server
	// holds.
	PrivatePKI struct {
		Root    RootAuthority     `yaml:"root"`
		Domains []DomainAuthority `yaml:"domains"`
		Legacy  LegacyAuthorities `yaml:"legacy"`
	}

	// RootAuthority is the contract's active root generation.
	RootAuthority struct {
		GenerationID  string `yaml:"generationId"`
		CommonName    string `yaml:"commonName"`
		Organization  string `yaml:"organization"`
		Custody       string `yaml:"custody"`
		KeyCurve      string `yaml:"keyCurve"`
		TTL           string `yaml:"ttl"`
		MaxPathLength int    `yaml:"maxPathLength"`
		ArtifactPath  string `yaml:"artifactPath"`
	}

	// DomainAuthority is one trust domain's intermediate: the first CA under
	// the root, in a root-namespace mount, carrying the name constraint when
	// its domain has one.
	DomainAuthority struct {
		TrustDomain      string   `yaml:"trustDomain"`
		Mount            string   `yaml:"mount"`
		IssuerName       string   `yaml:"issuerName"`
		CommonName       string   `yaml:"commonName"`
		Organization     string   `yaml:"organization"`
		KeyCurve         string   `yaml:"keyCurve"`
		TTL              string   `yaml:"ttl"`
		MaxPathLength    int      `yaml:"maxPathLength"`
		PermittedDomains []string `yaml:"permittedDomains"`
		// PermittedURIDomains is a URI trust domain's shape of the same idea.
		PermittedURIDomains []string `yaml:"permittedUriDomains,omitempty"`
		// ArtifactPath is where the ceremony writes this intermediate's
		// signed certificate, and where the import reads it back.
		ArtifactPath string `yaml:"artifactPath"`
	}

	// LegacyAuthorities is the self-signed chain's root and intermediate.
	LegacyAuthorities struct {
		Root   PKIAuthority `yaml:"root"`
		Parent PKIAuthority `yaml:"parent"`
	}

	// PKIAuthority describes one legacy CA and the mount whose internal key
	// holds it.
	PKIAuthority struct {
		Mount           string `yaml:"mount"`
		IssuerName      string `yaml:"issuerName"`
		CommonName      string `yaml:"commonName"`
		TTL             string `yaml:"ttl"`
		MaxPathLength   int    `yaml:"maxPathLength"`
		PermittedDomain string `yaml:"permittedDomain"`
	}

	// IssuingCA is one environment's issuing CA in one trust domain, offering
	// the leaf roles the contract declares. Its key never leaves the
	// environment's namespace.
	IssuingCA struct {
		TrustDomain         string   `yaml:"trustDomain"`
		Mount               string   `yaml:"mount"`
		IssuerName          string   `yaml:"issuerName"`
		CommonName          string   `yaml:"commonName"`
		Organization        string   `yaml:"organization"`
		KeyCurve            string   `yaml:"keyCurve"`
		TTL                 string   `yaml:"ttl"`
		MaxPathLength       int      `yaml:"maxPathLength"`
		PermittedDomains    []string `yaml:"permittedDomains"`
		PermittedURIDomains []string `yaml:"permittedUriDomains,omitempty"`
		// External marks an issuing CA the root signs directly, outside the
		// server, never one signed by another issuer declared here.
		External bool `yaml:"external,omitempty"`
		// Policy grants sign on every role below it, and AuthRole is the
		// cert-manager login that carries that policy.
		Policy   string          `yaml:"policy"`
		AuthRole string          `yaml:"authRole"`
		Roles    []model.PKIRole `yaml:"roles"`
		// CredentialRoles sign people's CSRs. They sit on this issuer and are
		// granted to credential groups only, never to Policy.
		CredentialRoles []CredentialRole `yaml:"credentialRoles,omitempty"`
	}

	// EnvironmentPKI is the legacy environment intermediate and its one
	// constrained leaf role.
	EnvironmentPKI struct {
		PKIAuthority `yaml:",inline"`
		Domain       string `yaml:"domain"`
		LeafRole     string `yaml:"leafRole"`
		LeafTTL      string `yaml:"leafTtl"`
		LeafMaxTTL   string `yaml:"leafMaxTtl"`
	}

	// CredentialRole is a PKI role that signs a person's CSR, on one of the
	// environment's issuing CAs: never cert-manager's.
	CredentialRole struct {
		Name string `yaml:"name"`
		// CommonName is what the certificate may be issued to: the caller's
		// own subject on SubjectMount, and nobody else's.
		CommonName    string   `yaml:"commonName"`
		SubjectMount  string   `yaml:"subjectMount"`
		CNValidations []string `yaml:"cnValidations"`
		Server        bool     `yaml:"server"`
		Client        bool     `yaml:"client"`
		KeyCurve      string   `yaml:"keyCurve"`
		TTL           string   `yaml:"ttl"`
		MaxTTL        string   `yaml:"maxTtl"`
	}
)

// configurePrivatePKI declares the whole authority chain: the root and the
// domain intermediates from the contract, one issuing CA per trust domain in
// every environment namespace, and beside them the legacy chain.
//
// Everything the contract declares is pkg/pki's derivation; what is this
// file's is the view of it, the policies and cert-manager logins that carry
// each issuing CA's roles, and the legacy chain.
//
// It returns each environment's cert-manager logins, by environment name,
// which ride the environment's cluster mount after everything else on it.
func configurePrivatePKI(desired *Desired, inputs *Inputs, clusters []Cluster) (map[string][]builder.Workload, error) {
	in := &inputs.PKI
	contract := in.Contract
	if contract == nil {
		return nil, fmt.Errorf("estate: the private PKI contract is required")
	}

	generation, err := ActiveGeneration(contract)
	if err != nil {
		return nil, err
	}

	if len(desired.Namespaces) == 0 {
		return nil, fmt.Errorf("estate: private PKI has no environment namespaces")
	}

	byName := make(map[string]Cluster, len(clusters))
	for i := range clusters {
		byName[clusters[i].Name] = clusters[i]
	}

	environments := make([]pki.Environment, 0, len(desired.Namespaces))

	for i := range desired.Namespaces {
		cluster, ok := byName[desired.Namespaces[i].Name]
		if !ok {
			return nil, fmt.Errorf("estate: namespace %s has no cluster inputs", desired.Namespaces[i].Name)
		}

		environment, err := pkiEnvironment(in, &cluster)
		if err != nil {
			return nil, err
		}

		environments = append(environments, environment)
	}

	derivation, err := contract.Derive(environments)
	if err != nil {
		return nil, fmt.Errorf("estate: %w", err)
	}

	desired.derivation = derivation
	desired.identityIssuers = map[string]string{}

	if identity := contract.URITrustDomain(in.Identity); identity != nil {
		for _, environment := range identity.Environments {
			desired.identityIssuers[environment] = identity.EnvironmentCAIssuerName(environment)
		}

		desired.identityRoles = []string{identity.Role.Name}
	}

	desired.PKI = PrivatePKI{
		Root: RootAuthority{
			GenerationID:  generation.ID,
			CommonName:    generation.Certificate.Subject.CommonName,
			Organization:  generation.Certificate.Subject.Organization,
			Custody:       generation.Custody.Provider,
			KeyCurve:      contract.Global.KeyCurve,
			TTL:           generation.Lifetime,
			MaxPathLength: generation.Certificate.MaxPathLen,
			ArtifactPath:  contract.RootArtifactPath(generation.ID),
		},
		Legacy: LegacyAuthorities{Root: in.Legacy.Root, Parent: in.Legacy.Parent},
	}

	for i := range derivation.Domains {
		domain := &derivation.Domains[i]

		desired.PKI.Domains = append(desired.PKI.Domains, DomainAuthority{
			TrustDomain:         domain.Domain,
			Mount:               domain.Mount,
			IssuerName:          domain.Issuer,
			CommonName:          domain.CommonName,
			Organization:        domain.Organization,
			KeyCurve:            domain.KeyCurve,
			TTL:                 domain.TTL,
			MaxPathLength:       domain.MaxPathLength,
			PermittedDomains:    slices.Clone(domain.PermittedDNSDomains),
			PermittedURIDomains: slices.Clone(domain.PermittedURIDomains),
			ArtifactPath:        domain.ArtifactPath,
		})
	}

	logins := make(map[string][]builder.Workload, len(desired.Namespaces))

	for i := range desired.Namespaces {
		namespace := &desired.Namespaces[i]

		// The legacy chain first: its role is what every live issuer still
		// names, and keeping it at the head keeps a review of an addition a
		// review of what was added.
		logins[namespace.Name] = append(logins[namespace.Name], configureLegacyEnvironmentPKI(inputs, namespace))

		for j := range derivation.Issuing {
			authority := &derivation.Issuing[j]
			if authority.Environment != namespace.Name {
				continue
			}

			login, err := configureIssuingCA(inputs, namespace, authority)
			if err != nil {
				return nil, err
			}

			logins[namespace.Name] = append(logins[namespace.Name], login)
		}
	}

	return logins, nil
}

// configureLegacyEnvironmentPKI keeps the legacy environment intermediate and
// its leaf role exactly as deployed: a chain being retired is not re-shaped.
// Its cert-manager login is returned.
func configureLegacyEnvironmentPKI(inputs *Inputs, namespace *Namespace) builder.Workload {
	legacy := &inputs.PKI.Legacy
	domain := namespace.Name + "." + legacy.Domain

	namespace.LegacyPKI = &EnvironmentPKI{
		PKIAuthority: PKIAuthority{
			Mount:           legacy.Mount,
			IssuerName:      legacy.Root.IssuerName + "-" + namespace.Name,
			CommonName:      domain + " Intermediate CA",
			TTL:             legacy.TTL,
			MaxPathLength:   0,
			PermittedDomain: domain,
		},
		Domain:     domain,
		LeafRole:   legacy.LeafRole,
		LeafTTL:    legacy.LeafTTL,
		LeafMaxTTL: legacy.LeafMaxTTL,
	}

	return certManagerLogin(inputs, legacy.LeafRole, legacy.LeafPolicy, legacy.LeafAudience, builder.Sign(legacy.Mount, legacy.LeafRole))
}

// pkiEnvironment is one environment's inputs to the library's derivation:
// the zone each trust domain substitutes for {zone}, the names the origin
// role may sign, and whether the environment's own identity CA is signed.
func pkiEnvironment(in *PKI, cluster *Cluster) (pki.Environment, error) {
	privateZone, err := zoneOf(in, cluster, in.Private)
	if err != nil {
		return pki.Environment{}, err
	}

	originZone, err := zoneOf(in, cluster, in.Origin)
	if err != nil {
		return pki.Environment{}, err
	}

	environment := pki.Environment{
		Name: cluster.Name,
		Zones: map[string]string{
			in.Private: privateZone,
			in.Origin:  originZone,
			// A workload's identity is a host in its environment's private
			// zone.
			in.Identity: privateZone,
		},
		Catalog: map[string][]string{
			pki.CatalogKey(in.Origin, in.OriginRole): slices.Clone(cluster.OriginNames),
		},
	}

	// Until an environment's own identity CA is signed it renders NOTHING of
	// the identity domain: the bootstrap creates its mount and key alone.
	if !in.Signed[cluster.Name] {
		environment.PendingCAs = []string{in.Identity}
	}

	return environment, nil
}

// configureIssuingCA records one derived issuing CA in its namespace's view,
// and returns the cert-manager login whose policy grants sign on every role
// below it.
func configureIssuingCA(inputs *Inputs, namespace *Namespace, authority *pki.Authority) (builder.Workload, error) {
	in := &inputs.PKI
	clusterIssuer, ok := in.ClusterIssuers[authority.Domain]
	if !ok {
		return builder.Workload{}, fmt.Errorf("estate: trust domain %q has no cluster issuer", authority.Domain)
	}

	policy := in.PolicyPrefix + clusterIssuer

	roles := make([]model.PKIRole, 0, len(authority.Roles))
	signs := make([]builder.Clause, 0, len(authority.Roles))

	for i := range authority.Roles {
		role := authority.Roles[i]
		// The model's issuer is filled when the view becomes the model.
		role.Issuer = ""

		roles = append(roles, role)
		signs = append(signs, builder.Sign(authority.Mount, role.Name))
	}

	credentials := make([]CredentialRole, 0, len(authority.CredentialRoles))

	for i := range authority.CredentialRoles {
		role := &authority.CredentialRoles[i]
		credentials = append(credentials, CredentialRole{
			Name:          role.Name,
			CommonName:    credentialCommonName,
			SubjectMount:  role.SubjectMount,
			CNValidations: slices.Clone(role.CNValidations),
			Server:        role.Server,
			Client:        role.Client,
			KeyCurve:      role.KeyCurve,
			TTL:           role.TTL,
			MaxTTL:        role.MaxTTL,
		})
	}

	namespace.IssuingCAs = append(namespace.IssuingCAs, IssuingCA{
		TrustDomain:         authority.Domain,
		Mount:               authority.Mount,
		IssuerName:          authority.Issuer,
		CommonName:          authority.CommonName,
		Organization:        authority.Organization,
		KeyCurve:            authority.KeyCurve,
		TTL:                 authority.TTL,
		MaxPathLength:       authority.MaxPathLength,
		PermittedDomains:    slices.Clone(authority.PermittedDNSDomains),
		PermittedURIDomains: slices.Clone(authority.PermittedURIDomains),
		External:            authority.External,
		Policy:              policy,
		AuthRole:            clusterIssuer,
		Roles:               roles,
		CredentialRoles:     credentials,
	})

	return certManagerLogin(inputs, clusterIssuer, policy, in.AudiencePrefix+clusterIssuer, signs...), nil
}

// certManagerLogin is one role on the environment's cluster mount:
// cert-manager's ServiceAccount, one audience, one policy granting sign on
// the paths given.
func certManagerLogin(in *Inputs, role, policy, audience string, signs ...builder.Clause) builder.Workload {
	return builder.Workload{Role: role, Subject: in.PKI.Subject, Audience: audience, TTL: in.Names.TokenTTL, Policy: policy, Access: signs}
}

// ActiveGeneration is the contract's one active root generation.
func ActiveGeneration(contract *pki.Contract) (*pki.RootGeneration, error) {
	for i := range contract.Generations {
		if contract.Generations[i].State == pki.GenerationActive {
			return &contract.Generations[i], nil
		}
	}

	return nil, fmt.Errorf("estate: the PKI contract declares no active root generation")
}

// zoneOf is the zone a trust domain substitutes for {zone} on one cluster:
// the origin zone for the origin domain, the private zone for the others.
func zoneOf(in *PKI, cluster *Cluster, trustDomain string) (string, error) {
	zone := cluster.PrivateZone
	if trustDomain == in.Origin {
		zone = cluster.OriginZone
	}

	if strings.TrimSpace(zone) == "" {
		return "", fmt.Errorf("estate: cluster %s has no %s zone", cluster.Name, trustDomain)
	}

	return zone, nil
}
