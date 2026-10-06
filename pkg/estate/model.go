package estate

import (
	"fmt"
	"slices"

	"github.com/truvity/secrets/pkg/model"
)

// The view ([Desired]) becomes the public model here: what pkg/apply
// converges the server onto. Everything the apply would otherwise name
// differently from what state already holds is data here: the organization
// on the legacy chain, and the Pulumi names a resource has always had
// ([Desired.LegacyResourceNames]).

var (
	// allIPRanges excludes every IP SAN from a constrained CA.
	allIPRanges = []string{"0.0.0.0/0", "::/0"}
	// unsupportedNameScope permits e-mail and URI names under a domain
	// nothing can hold: the legacy chain's way of refusing both.
	unsupportedNameScope = []string{".invalid"}
)

// Model is the desired state as the public model, ready for pkg/apply: the
// library's derivation (builder.Spec.Build) joined to the PKI.
func (d *Desired) Model() (*model.Desired, error) {
	if d.built == nil || d.derivation == nil || d.in == nil {
		return nil, fmt.Errorf("estate: the desired state was never built")
	}

	out := *d.built.Model
	out.Namespaces = slices.Clone(out.Namespaces)

	// The legacy chain is what root holds beside the jobs' logins and the
	// web UI's door: the self-signed root and its intermediate. The
	// operators' door is the bootstrap, and is never applied.
	out.Root.PKI = d.legacyRootMounts()

	for i := range d.Namespaces {
		mounts, err := d.legacyEnvironmentMounts(&d.Namespaces[i])
		if err != nil {
			return nil, err
		}

		out.Namespaces[i].PKI = mounts
	}

	// The contract's authorities join the mounts the legacy chain already
	// holds (a domain intermediate may be a second issuer in the legacy
	// intermediate's mount, an issuing CA a second issuer in the legacy
	// environment mount): the library derives them, Apply merges.
	if err := d.derivation.Apply(&out); err != nil {
		return nil, err
	}

	if err := out.Validate(); err != nil {
		return nil, err
	}

	return &out, nil
}

// legacyRootMounts is the root namespace's legacy chain: the self-signed
// root and its intermediate. The contract's domain intermediates join them,
// and the legacy issuer stays its mount's default until the switch.
func (d *Desired) legacyRootMounts() []model.PKIMount {
	legacy := &d.in.PKI.Legacy
	root, parent := &d.PKI.Legacy.Root, &d.PKI.Legacy.Parent

	return []model.PKIMount{
		{
			Path:            root.Mount,
			Description:     d.in.Text.LegacyRoot,
			DefaultLeaseTTL: root.TTL,
			MaxLeaseTTL:     root.TTL,
			DefaultIssuer:   root.IssuerName,
			Issuers: []model.PKIIssuer{{
				Name:            root.IssuerName,
				CommonName:      root.CommonName,
				Organization:    legacy.Organization,
				KeyCurve:        model.CurveP256,
				TTL:             root.TTL,
				MaxPathLength:   root.MaxPathLength,
				NameConstraints: legacyConstraints(root.PermittedDomain),
				SelfSigned:      true,
			}},
		},
		{
			Path:            parent.Mount,
			Description:     d.in.Text.LegacyParent,
			DefaultLeaseTTL: parent.TTL,
			MaxLeaseTTL:     parent.TTL,
			DefaultIssuer:   parent.IssuerName,
			Issuers: []model.PKIIssuer{{
				Name:            parent.IssuerName,
				CommonName:      parent.CommonName,
				Organization:    legacy.Organization,
				KeyCurve:        model.CurveP256,
				TTL:             parent.TTL,
				MaxPathLength:   parent.MaxPathLength,
				NameConstraints: legacyConstraints(parent.PermittedDomain),
				SignedBy:        &model.IssuerRef{Mount: root.Mount, Issuer: root.IssuerName},
			}},
		},
	}
}

// legacyEnvironmentMounts is one environment's legacy PKI: the environment
// intermediate and its leaf role. The contract's issuing CAs join it.
func (d *Desired) legacyEnvironmentMounts(namespace *Namespace) ([]model.PKIMount, error) {
	legacy := namespace.LegacyPKI
	if legacy == nil {
		return nil, fmt.Errorf("estate: %s has no legacy environment PKI, which its issuing CAs share a mount with", namespace.Name)
	}

	parent := &d.PKI.Legacy.Parent

	return []model.PKIMount{{
		Path:            legacy.Mount,
		Description:     render(d.in.Text.LegacyEnvironment, namespace.Name, ""),
		DefaultLeaseTTL: legacy.LeafTTL,
		MaxLeaseTTL:     legacy.LeafMaxTTL,
		DefaultIssuer:   legacy.IssuerName,
		Issuers: []model.PKIIssuer{{
			Name:            legacy.IssuerName,
			CommonName:      legacy.CommonName,
			Organization:    d.in.PKI.Legacy.Organization,
			KeyCurve:        model.CurveP256,
			TTL:             legacy.TTL,
			MaxPathLength:   legacy.MaxPathLength,
			NameConstraints: legacyConstraints(legacy.PermittedDomain),
			SignedBy:        &model.IssuerRef{Mount: parent.Mount, Issuer: parent.IssuerName},
		}},
		Roles: []model.PKIRole{{
			Name:             legacy.LeafRole,
			Issuer:           legacy.IssuerName,
			AllowedDomains:   []string{legacy.Domain},
			AllowBareDomains: true,
			AllowSubdomains:  true,
			Server:           true,
			Client:           true,
			KeyCurve:         model.CurveP256,
			TTL:              legacy.LeafTTL,
			MaxTTL:           legacy.LeafMaxTTL,
		}},
	}}, nil
}

// legacyConstraints is the legacy chain's name constraint: one DNS domain,
// no IP, and e-mail and URI names confined to a domain nobody holds.
func legacyConstraints(domain string) *model.NameConstraints {
	return &model.NameConstraints{
		PermittedDNSDomains:     []string{domain},
		ExcludedIPRanges:        allIPRanges,
		PermittedEmailAddresses: unsupportedNameScope,
		PermittedURIDomains:     unsupportedNameScope,
	}
}

// IdentityBootstrapCSRName is the Pulumi name of the certificate signing
// request of one environment's root-signed identity CA: named after the
// mount and the environment, because no issuer existed yet to name it
// after when the bootstrap created it.
func (d *Desired) IdentityBootstrapCSRName(environment string) string {
	identity := d.in.PKI.Contract.URITrustDomain(d.in.PKI.Identity)

	return identity.IssuingMountPath() + "-" + environment + d.in.PKI.BootstrapSuffix + "-csr"
}

// LegacyResourceNames maps the Pulumi name pkg/apply gives a resource that
// already exists under a different name to the name it has always had, so
// adopting it is an empty preview (apply.RenameFrom). pkg/apply names an
// issuer's resources after the issuer; most of this map is the legacy
// chain, whose resources were named after their mount, and every role on
// the legacy environment mount -- the restore role included, which signs
// with the private issuing CA but is the same object at the same path.
//
// Two kinds of entry are not the legacy chain, both for the identity
// domain's per-environment CAs: the bootstrap's certificate signing request
// (named after the MOUNT, before any issuer existed) and the identity roles
// of an environment PKI.LegacyRoleIssuers names (a role that moved onto the
// root-signed CA as the same object keeps the name of the issuer that first
// carried it; without the entry the preview would create the role under the
// new name and DELETE it under the old one, removing the object both name).
func (d *Desired) LegacyResourceNames() map[string]string {
	pkiIn := &d.in.PKI
	issuerSuffixes := []string{"-csr", "-signed", "-import", "-issuer"}
	renames := map[string]string{
		d.PKI.Legacy.Root.IssuerName + "-certificate": d.PKI.Legacy.Root.Mount + "-certificate",
	}

	for _, suffix := range issuerSuffixes {
		renames[d.PKI.Legacy.Parent.IssuerName+suffix] = d.PKI.Legacy.Parent.Mount + suffix
	}

	for environment, issuer := range d.identityIssuers {
		renames[issuer+"-csr"] = d.IdentityBootstrapCSRName(environment)

		if old, ok := pkiIn.LegacyRoleIssuers[environment]; ok {
			for _, role := range d.identityRoles {
				renames[issuer+"-role-"+role] = old + "-role-" + role
			}
		}
	}

	for i := range d.Namespaces {
		namespace := &d.Namespaces[i]

		legacy := namespace.LegacyPKI
		if legacy == nil {
			continue
		}

		mount := namespace.Name + "-" + legacy.Mount

		for _, suffix := range issuerSuffixes {
			renames[legacy.IssuerName+suffix] = mount + suffix
		}

		renames[legacy.IssuerName+"-role-"+legacy.LeafRole] = mount + "-role-" + legacy.LeafRole

		for j := range namespace.IssuingCAs {
			issuing := &namespace.IssuingCAs[j]
			if issuing.Mount != legacy.Mount {
				continue
			}

			for k := range issuing.Roles {
				if issuing.Roles[k].Name == pkiIn.RestoreRole {
					renames[issuing.IssuerName+"-role-"+pkiIn.RestoreRole] = mount + "-role-" + pkiIn.RestoreRole
				}
			}
		}
	}

	return renames
}
