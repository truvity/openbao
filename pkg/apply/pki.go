package apply

import (
	"fmt"
	"strconv"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault/pkisecret"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/openbao/pkg/model"
)

// importedIssuerUsage is what an issuer signed into a mount may do: sign
// certificates and CRLs, and never be changed through its own API.
const importedIssuerUsage = "crl-signing,issuing-certificates,read-only"

type (
	// pkiMount is a registered PKI mount: the mount, its pinned default,
	// and its URL, CRL and auto-tidy configuration, which every signature
	// made on the mount waits for.
	pkiMount struct {
		ref         MountRef
		mount       *vault.Mount
		pinned      pulumi.Resource
		maintenance []pulumi.Resource
	}

	// pkiIssuer is a registered issuer: its mount, and the resource that
	// names it (the named issuer, or a self-signed root's certificate).
	pkiIssuer struct {
		mount    *pkiMount
		resource pulumi.Resource
	}
)

// authority protects a resource and adds dependencies. A CA key, its
// certificate and its mount's configuration are never replaced or
// destroyed by an ordinary Pulumi run: CA replacement is an explicit,
// overlapping-issuer migration.
func authority(base []pulumi.ResourceOption, dependencies ...pulumi.Resource) []pulumi.ResourceOption {
	return options(options(base, dependsOn(dependencies...)...), pulumi.Protect(true))
}

// pkiMount registers one PKI mount, its issuers in order, its pinned
// default and its maintenance, and its host-name roles.
func (a *applier) pkiMount(s *scope, desired *model.PKIMount) error {
	defaultTTL, err := model.DurationSeconds(desired.DefaultLeaseTTL)
	if err != nil {
		return fmt.Errorf("%s PKI mount %s: %w", s.label, desired.Path, err)
	}

	maxTTL, err := model.DurationSeconds(desired.MaxLeaseTTL)
	if err != nil {
		return fmt.Errorf("%s PKI mount %s: %w", s.label, desired.Path, err)
	}

	args := &vault.MountArgs{
		Namespace:              s.arg,
		Path:                   pulumi.String(desired.Path),
		Type:                   pulumi.String("pki"),
		DefaultLeaseTtlSeconds: pulumi.Int(defaultTTL),
		MaxLeaseTtlSeconds:     pulumi.Int(maxTTL),
	}

	if desired.Description != "" {
		args.Description = pulumi.String(desired.Description)
	}

	created, err := vault.NewMount(a.c, a.name(mountName(s, desired.Path)), args, authority(s.base, s.created)...)
	if err != nil {
		return fmt.Errorf("%s PKI mount %s: %w", s.label, desired.Path, err)
	}

	mount := &pkiMount{ref: MountRef{Namespace: s.namespace.Name, Path: desired.Path}, mount: created}
	a.mounts[mount.ref] = mount

	for i := range desired.Issuers {
		issuer := &desired.Issuers[i]

		registered, err := a.issuer(s, mount, issuer)
		if err != nil {
			return err
		}

		a.issuers[model.IssuerRef{Namespace: s.namespace.Name, Mount: desired.Path, Issuer: issuer.Name}] = registered

		if issuer.Name == desired.DefaultIssuer {
			if err := a.pinAndMaintain(s, mount, registered); err != nil {
				return err
			}
		}
	}

	for i := range desired.Roles {
		if err := a.pkiRole(s, desired, &desired.Roles[i]); err != nil {
			return err
		}
	}

	return nil
}

// issuer registers one CA inside a mount: a self-signed root, or a key and
// request whose certificate is signed by another issuer or by an external
// signer and imported back, with its parents, so the mount serves a
// complete chain.
func (a *applier) issuer(s *scope, mount *pkiMount, desired *model.PKIIssuer) (*pkiIssuer, error) {
	bits := model.CurveBits[desired.KeyCurve]
	where := s.label + "/" + mount.ref.Path + "/" + desired.Name

	if desired.SelfSigned {
		args := &pkisecret.SecretBackendRootCertArgs{
			Namespace:         s.arg,
			Backend:           mount.mount.Path,
			Type:              pulumi.String("internal"),
			CommonName:        pulumi.String(desired.CommonName),
			IssuerName:        pulumi.String(desired.Name),
			KeyName:           pulumi.String(desired.Name),
			Ttl:               pulumi.String(desired.TTL),
			Format:            pulumi.String("pem"),
			KeyType:           pulumi.String("ec"),
			KeyBits:           pulumi.Int(bits),
			MaxPathLength:     pulumi.Int(desired.MaxPathLength),
			ExcludeCnFromSans: pulumi.Bool(true),
		}

		if constraints := desired.NameConstraints; constraints != nil {
			args.PermittedDnsDomains = optionalStrings(constraints.PermittedDNSDomains)
			args.ExcludedIpRanges = optionalStrings(constraints.ExcludedIPRanges)
			args.PermittedEmailAddresses = optionalStrings(constraints.PermittedEmailAddresses)
			args.PermittedUriDomains = optionalStrings(constraints.PermittedURIDomains)
		}

		if desired.Organization != "" {
			args.Organization = pulumi.String(desired.Organization)
		}

		root, err := pkisecret.NewSecretBackendRootCert(a.c, a.name(desired.Name+"-certificate"), args,
			authority(s.base, s.created, mount.mount)...)
		if err != nil {
			return nil, fmt.Errorf("root certificate %s: %w", where, err)
		}

		a.result.Certificates[desired.Name] = root.Certificate

		return &pkiIssuer{mount: mount, resource: root}, nil
	}

	csrArgs := &pkisecret.SecretBackendIntermediateCertRequestArgs{
		Namespace:         s.arg,
		Backend:           mount.mount.Path,
		Type:              pulumi.String("internal"),
		CommonName:        pulumi.String(desired.CommonName),
		KeyName:           pulumi.String(desired.Name),
		KeyType:           pulumi.String("ec"),
		KeyBits:           pulumi.Int(bits),
		Format:            pulumi.String("pem"),
		ExcludeCnFromSans: pulumi.Bool(true),
	}

	if desired.Organization != "" {
		csrArgs.Organization = pulumi.String(desired.Organization)
	}

	// `internal`: OpenBAO generates the key inside the mount and keeps it;
	// what leaves is this request, carrying the subject and no
	// alternative name.
	csr, err := pkisecret.NewSecretBackendIntermediateCertRequest(a.c, a.name(desired.Name+"-csr"), csrArgs,
		authority(s.base, s.created, mount.mount)...)
	if err != nil {
		return nil, fmt.Errorf("certificate request %s: %w", where, err)
	}

	var (
		certificate pulumi.StringInput
		imported    pulumi.Resource
	)

	if desired.External {
		a.result.CertificateRequests[desired.Name] = csr.Csr

		chain, err := a.opts.SignedChain(model.IssuerRef{Namespace: s.namespace.Name, Mount: mount.ref.Path, Issuer: desired.Name})
		if err != nil {
			return nil, fmt.Errorf("signed chain of %s: %w", where, err)
		}

		certificate = pulumi.String(chain)
		imported = csr
	} else {
		signed, err := a.sign(s, desired, csr, where)
		if err != nil {
			return nil, err
		}

		certificate = signed.CertificateBundle
		imported = signed
	}

	set, err := pkisecret.NewSecretBackendIntermediateSetSigned(a.c, a.name(desired.Name+"-import"), &pkisecret.SecretBackendIntermediateSetSignedArgs{
		Namespace:   s.arg,
		Backend:     mount.mount.Path,
		Certificate: certificate,
	}, authority(s.base, s.created, imported)...)
	if err != nil {
		return nil, fmt.Errorf("import %s: %w", where, err)
	}

	// Index 0 is the first certificate of the chain: the issuer itself,
	// never a parent that follows it.
	named, err := pkisecret.NewSecretBackendIssuer(a.c, a.name(desired.Name+"-issuer"), &pkisecret.SecretBackendIssuerArgs{
		Namespace:  s.arg,
		Backend:    mount.mount.Path,
		IssuerRef:  set.ImportedIssuers.Index(pulumi.Int(0)),
		IssuerName: pulumi.String(desired.Name),
		Usage:      pulumi.String(importedIssuerUsage),
	}, authority(s.base, s.created, set)...)
	if err != nil {
		return nil, fmt.Errorf("name %s: %w", where, err)
	}

	return &pkiIssuer{mount: mount, resource: named}, nil
}

// sign has the signer's mount sign an issuer's request, after that mount's
// URLs and CRL configuration exist: the certificate carries them for its
// whole life.
func (a *applier) sign(
	s *scope, desired *model.PKIIssuer, csr *pkisecret.SecretBackendIntermediateCertRequest, where string,
) (*pkisecret.SecretBackendRootSignIntermediate, error) {
	signer, ok := a.issuers[*desired.SignedBy]
	if !ok {
		return nil, fmt.Errorf("%s is signed by %s, which is not registered yet", where, desired.SignedBy)
	}

	args := &pkisecret.SecretBackendRootSignIntermediateArgs{
		Backend:           signer.mount.mount.Path,
		IssuerRef:         pulumi.String(desired.SignedBy.Issuer),
		Csr:               csr.Csr,
		CommonName:        pulumi.String(desired.CommonName),
		Ttl:               pulumi.String(desired.TTL),
		Format:            pulumi.String("pem"),
		MaxPathLength:     pulumi.Int(desired.MaxPathLength),
		ExcludeCnFromSans: pulumi.Bool(true),
		UseCsrValues:      pulumi.Bool(true),
	}

	if desired.SignedBy.Namespace != "" {
		args.Namespace = pulumi.String(desired.SignedBy.Namespace)
	}

	// A name-constraints extension only where the model declares one: an
	// unconstrained parent gives an unconstrained child, and a constraint
	// the model does not declare -- even one that only excludes IP ranges
	// -- is one nobody reviewed.
	if constraints := desired.NameConstraints; constraints != nil {
		args.PermittedDnsDomains = optionalStrings(constraints.PermittedDNSDomains)
		args.ExcludedIpRanges = optionalStrings(constraints.ExcludedIPRanges)
		args.PermittedEmailAddresses = optionalStrings(constraints.PermittedEmailAddresses)
		args.PermittedUriDomains = optionalStrings(constraints.PermittedURIDomains)
	}

	waits := append([]pulumi.Resource{signer.resource, signer.mount.pinned, csr}, signer.mount.maintenance...)

	signed, err := pkisecret.NewSecretBackendRootSignIntermediate(a.c, a.name(desired.Name+"-signed"), args, authority(s.base, waits...)...)
	if err != nil {
		return nil, fmt.Errorf("sign %s: %w", where, err)
	}

	return signed, nil
}

// pinAndMaintain pins the mount's default issuer and configures its
// issuer, CRL and OCSP URLs, the CRL, and auto-tidy. Expired issuers are
// never tidied: retiring a CA is a separately reviewed, bottom-up operation
// after every descendant has drained.
func (a *applier) pinAndMaintain(s *scope, mount *pkiMount, issuer *pkiIssuer) error {
	label := mountName(s, mount.ref.Path)

	var issuerID pulumi.StringInput

	switch named := issuer.resource.(type) {
	case *pkisecret.SecretBackendIssuer:
		issuerID = named.IssuerId
	case *pkisecret.SecretBackendRootCert:
		issuerID = named.IssuerId
	default:
		return fmt.Errorf("%s: the default issuer is of an unexpected kind %T", label, issuer.resource)
	}

	pinned, err := pkisecret.NewSecretBackendConfigIssuers(a.c, a.name(label+"-default"), &pkisecret.SecretBackendConfigIssuersArgs{
		Namespace:                  s.arg,
		Backend:                    mount.mount.Path,
		Default:                    issuerID,
		DefaultFollowsLatestIssuer: pulumi.Bool(false),
	}, authority(s.base, s.created, issuer.resource)...)
	if err != nil {
		return fmt.Errorf("pin the default issuer of %s: %w", label, err)
	}

	mount.pinned = pinned

	apiPrefix := mount.ref.Path
	if s.namespace.Name != "" {
		apiPrefix = s.namespace.Name + "/" + mount.ref.Path
	}

	base := a.opts.Address + "/v1/" + apiPrefix
	waits := []pulumi.Resource{mount.mount, issuer.resource, pinned}

	urls, err := pkisecret.NewSecretBackendConfigUrls(a.c, a.name(label+"-urls"), &pkisecret.SecretBackendConfigUrlsArgs{
		Namespace:             s.arg,
		Backend:               mount.mount.Path,
		EnableTemplating:      pulumi.Bool(true),
		IssuingCertificates:   pulumi.ToStringArray([]string{base + "/issuer/{{issuer_id}}/der"}),
		CrlDistributionPoints: pulumi.ToStringArray([]string{base + "/issuer/{{issuer_id}}/crl/der"}),
		OcspServers:           pulumi.ToStringArray([]string{base + "/ocsp"}),
	}, authority(s.base, waits...)...)
	if err != nil {
		return fmt.Errorf("%s PKI URL config: %w", label, err)
	}

	crl, err := pkisecret.NewSecretBackendCrlConfig(a.c, a.name(label+"-crl"), &pkisecret.SecretBackendCrlConfigArgs{
		Namespace:              s.arg,
		Backend:                mount.mount.Path,
		AutoRebuild:            pulumi.Bool(true),
		AutoRebuildGracePeriod: pulumi.String("12h"),
		Disable:                pulumi.Bool(false),
		EnableDelta:            pulumi.Bool(true),
		DeltaRebuildInterval:   pulumi.String("15m"),
		Expiry:                 pulumi.String("72h"),
		OcspDisable:            pulumi.Bool(false),
		OcspExpiry:             pulumi.String("1h"),
	}, authority(s.base, waits...)...)
	if err != nil {
		return fmt.Errorf("%s PKI CRL config: %w", label, err)
	}

	tidy, err := pkisecret.NewBackendConfigAutoTidy(a.c, a.name(label+"-auto-tidy"), &pkisecret.BackendConfigAutoTidyArgs{
		Namespace:                            s.arg,
		Backend:                              mount.mount.Path,
		Enabled:                              pulumi.Bool(true),
		IntervalDuration:                     pulumi.String("24h"),
		SafetyBuffer:                         pulumi.String("720h"),
		IssuerSafetyBuffer:                   pulumi.String("8760h"),
		MaintainStoredCertificateCounts:      pulumi.Bool(true),
		PublishStoredCertificateCountMetrics: pulumi.Bool(true),
		TidyCertStore:                        pulumi.Bool(true),
		TidyRevokedCerts:                     pulumi.Bool(true),
		TidyRevokedCertIssuerAssociations:    pulumi.Bool(true),
		TidyExpiredIssuers:                   pulumi.Bool(false),
	}, authority(s.base, waits...)...)
	if err != nil {
		return fmt.Errorf("%s PKI auto-tidy config: %w", label, err)
	}

	mount.maintenance = []pulumi.Resource{urls, crl, tidy}

	return nil
}

// pkiRole registers one host-name role, addressed to its issuer rather
// than to whatever the mount's default happens to be, with everything it
// does not allow spelled out rather than left to a default.
func (a *applier) pkiRole(s *scope, mount *model.PKIMount, role *model.PKIRole) error {
	issuer := a.issuers[model.IssuerRef{Namespace: s.namespace.Name, Mount: mount.Path, Issuer: role.Issuer}]

	ttl, err := model.DurationSeconds(role.TTL)
	if err != nil {
		return fmt.Errorf("%s PKI role %s/%s: %w", s.label, mount.Path, role.Name, err)
	}

	maxTTL, err := model.DurationSeconds(role.MaxTTL)
	if err != nil {
		return fmt.Errorf("%s PKI role %s/%s: %w", s.label, mount.Path, role.Name, err)
	}

	args := &pkisecret.SecretBackendRoleArgs{
		Namespace:                 s.arg,
		Backend:                   issuer.mount.mount.Path,
		Name:                      pulumi.String(role.Name),
		IssuerRef:                 pulumi.String(role.Issuer),
		AllowedDomains:            pulumi.ToStringArray(role.AllowedDomains),
		AllowedDomainsTemplate:    pulumi.Bool(false),
		AllowBareDomains:          pulumi.Bool(role.AllowBareDomains),
		AllowSubdomains:           pulumi.Bool(role.AllowSubdomains),
		AllowGlobDomains:          pulumi.Bool(false),
		AllowWildcardCertificates: pulumi.Bool(role.AllowWildcards),
		AllowAnyName:              pulumi.Bool(false),
		AllowIpSans:               pulumi.Bool(false),
		AllowedUriSans:            pulumi.StringArray{},
		AllowedOtherSans:          pulumi.StringArray{},
		AllowedUserIds:            pulumi.StringArray{},
		AllowLocalhost:            pulumi.Bool(false),
		CnValidations:             pulumi.ToStringArray([]string{model.CNValidationHostname}),
		// cert-manager sends a CSR with no common name whenever a
		// Certificate names only DNS names, which is most of them.
		RequireCn:           pulumi.Bool(false),
		EmailProtectionFlag: pulumi.Bool(false),
		EnforceHostnames:    pulumi.Bool(true),
		ServerFlag:          pulumi.Bool(role.Server),
		ClientFlag:          pulumi.Bool(role.Client),
		KeyType:             pulumi.String("ec"),
		KeyBits:             pulumi.Int(model.CurveBits[role.KeyCurve]),
		Ttl:                 pulumi.String(strconv.Itoa(ttl)),
		MaxTtl:              pulumi.String(strconv.Itoa(maxTTL)),
		NoStore:             pulumi.Bool(false),
	}

	// Not protected: a leaf role holds no key, and changing what it signs
	// is an ordinary, reviewed update.
	if _, err := pkisecret.NewSecretBackendRole(a.c, a.name(role.Issuer+"-role-"+role.Name), args,
		options(s.inside, pulumi.DependsOn([]pulumi.Resource{issuer.resource}))...); err != nil {
		return fmt.Errorf("%s PKI role %s/%s: %w", s.label, mount.Path, role.Name, err)
	}

	return nil
}

// credentialRoles registers a mount's credential roles, once the auth
// mounts whose accessor their template names exist.
//
// The allowed domain is a template of the caller's alias name on the
// subject mount, matched as a bare name with subdomains, globs, wildcards
// and any-name all off, so the only common name the role accepts is the
// caller's own. The CSR's own SANs are ignored and no IP, URI or other SAN
// is allowed. `no_store` and no lease: the revocation model is the TTL.
func (a *applier) credentialRoles(s *scope, mount *model.PKIMount, accessors map[string]pulumi.StringOutput) error {
	for i := range mount.CredentialRoles {
		role := &mount.CredentialRoles[i]
		issuer := a.issuers[model.IssuerRef{Namespace: s.namespace.Name, Mount: mount.Path, Issuer: role.Issuer}]

		accessor, ok := accessors[role.SubjectMount]
		if !ok {
			return fmt.Errorf("%s credential role %s reads the subject from %s, which is no auth mount here", s.label, role.Name, role.SubjectMount)
		}

		ttl, err := model.DurationSeconds(role.TTL)
		if err != nil {
			return fmt.Errorf("%s credential role %s: %w", s.label, role.Name, err)
		}

		maxTTL, err := model.DurationSeconds(role.MaxTTL)
		if err != nil {
			return fmt.Errorf("%s credential role %s: %w", s.label, role.Name, err)
		}

		subject := pulumi.Sprintf("{{identity.entity.aliases.%s.name}}", accessor)

		args := &pkisecret.SecretBackendRoleArgs{
			Namespace:                     s.arg,
			Backend:                       issuer.mount.mount.Path,
			Name:                          pulumi.String(role.Name),
			IssuerRef:                     pulumi.String(role.Issuer),
			AllowedDomains:                pulumi.StringArray{subject},
			AllowedDomainsTemplate:        pulumi.Bool(true),
			AllowBareDomains:              pulumi.Bool(true),
			AllowSubdomains:               pulumi.Bool(false),
			AllowGlobDomains:              pulumi.Bool(false),
			AllowWildcardCertificates:     pulumi.Bool(false),
			AllowAnyName:                  pulumi.Bool(false),
			AllowIpSans:                   pulumi.Bool(false),
			AllowedUriSans:                pulumi.StringArray{},
			AllowedUriSansTemplate:        pulumi.Bool(false),
			AllowedOtherSans:              pulumi.StringArray{},
			AllowedUserIds:                pulumi.StringArray{},
			AllowLocalhost:                pulumi.Bool(false),
			CnValidations:                 pulumi.ToStringArray(role.CNValidations),
			RequireCn:                     pulumi.Bool(true),
			UseCsrCommonName:              pulumi.Bool(true),
			UseCsrSans:                    pulumi.Bool(false),
			EnforceHostnames:              pulumi.Bool(true),
			EmailProtectionFlag:           pulumi.Bool(false),
			CodeSigningFlag:               pulumi.Bool(false),
			ServerFlag:                    pulumi.Bool(role.Server),
			ClientFlag:                    pulumi.Bool(role.Client),
			BasicConstraintsValidForNonCa: pulumi.Bool(false),
			KeyType:                       pulumi.String("ec"),
			KeyBits:                       pulumi.Int(model.CurveBits[role.KeyCurve]),
			Ttl:                           pulumi.String(strconv.Itoa(ttl)),
			MaxTtl:                        pulumi.String(strconv.Itoa(maxTTL)),
			NoStore:                       pulumi.Bool(true),
			GenerateLease:                 pulumi.Bool(false),
		}

		// Protected: a credential role that disappears in a replace is a
		// window in which nobody can sign.
		if _, err := pkisecret.NewSecretBackendRole(a.c, a.name(role.Issuer+"-credential-role-"+role.Name), args,
			authority(s.inside, issuer.resource)...); err != nil {
			return fmt.Errorf("%s credential role %s: %w", s.label, role.Name, err)
		}
	}

	return nil
}

// optionalStrings is a list input, or nil for an empty list: an empty
// constraint list is left out, never sent as an empty one.
func optionalStrings(values []string) pulumi.StringArrayInput {
	if len(values) == 0 {
		return nil
	}

	return pulumi.ToStringArray(values)
}
