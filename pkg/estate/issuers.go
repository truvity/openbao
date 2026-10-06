package estate

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/truvity/secrets/pkg/pki"
)

// CertManagerAudiencePrefix is what cert-manager prefixes a ClusterIssuer's
// name with when it asks Kubernetes for a token to log in with
// ([PKI.AudiencePrefix] in an estate that runs cert-manager).
const CertManagerAudiencePrefix = "vault://"

// The consumer's view of the private PKI: what a cluster's cert-manager
// needs to know to ask this server for a certificate, from the same inputs
// the server's side is derived from, so the two cannot name different paths.

type (
	// IssuerView is one cert-manager ClusterIssuer's address on this server.
	IssuerView struct {
		// Name is the ClusterIssuer.
		Name string
		// SignPath is `<issuing mount>/sign/<role>`: the one endpoint the
		// issuer's login may use.
		SignPath string
		// LoginRole is the server's JWT role the issuer logs in as.
		LoginRole string
		// Audience is the extra token audience a shared login accepts for
		// this issuer (cert-manager always asks for vault://<Name> as well).
		// Empty when the login is the issuer's own.
		Audience string
		// Policy is the certificate policy of the role it signs through.
		// Zero for a role with no lifetimes of its own (a URI role).
		Policy LeafPolicy
	}

	// LeafPolicy is what a certificate asks for through a role: the role's
	// default lifetime, when to renew, and the key the role signs (a CSR
	// that disagrees is refused, not signed weaker).
	LeafPolicy struct {
		Duration     string
		RenewBefore  string
		KeyAlgorithm string
		KeySize      int
	}

	// EnvironmentCA is one environment's root-signed identity CA as the
	// ceremony committed it, and the root that signed it: public material a
	// trust bundle distributes.
	EnvironmentCA struct {
		CertificatePEM        string
		FingerprintSHA256     string
		RootCertificatePEM    string
		RootFingerprintSHA256 string
	}
)

// Issuer is the ClusterIssuer of a trust domain, signing through role on the
// domain's issuing mount and logging in as its own name: the audience
// cert-manager asks for by default is the one the role is bound to.
func (in *PKI) Issuer(domain, role string) (IssuerView, error) {
	name, ok := in.ClusterIssuers[domain]
	if !ok {
		return IssuerView{}, fmt.Errorf("estate: trust domain %q has no cluster issuer", domain)
	}

	return in.view(name, domain, role, name, false)
}

// SharedLoginIssuer is a further ClusterIssuer, called name, that signs
// through role on domain's issuing mount but logs in as the domain's own
// login, which already carries a policy granting every role of the chain: a
// separate login would add an apply and no isolation. It asks for the extra
// audience that login accepts for it.
func (in *PKI) SharedLoginIssuer(name, domain, role string) (IssuerView, error) {
	login, ok := in.ClusterIssuers[domain]
	if !ok {
		return IssuerView{}, fmt.Errorf("estate: trust domain %q has no cluster issuer", domain)
	}

	return in.view(name, domain, role, login, true)
}

// IdentityEnvironmentSigned reports whether environment takes part in the
// identity domain AND its own root-signed CA has been through the ceremony's
// second phase. Nothing downstream of that CA (the issuer, its roles, a trust
// bundle) renders before both hold.
func (in *PKI) IdentityEnvironmentSigned(environment string) (bool, error) {
	identity := in.Contract.URITrustDomain(in.Identity)
	if identity == nil {
		return false, fmt.Errorf("estate: no uri trust domain named %q", in.Identity)
	}

	if !slices.Contains(identity.Environments, environment) {
		return false, nil
	}

	signed, err := in.Contract.EnvironmentCASigned(in.Identity, environment)
	if err != nil {
		return false, fmt.Errorf("identity environment CA signed check: %w", err)
	}

	return signed, nil
}

// IdentityIssuer is the identity ClusterIssuer of one environment, signing
// through role, or nil where [PKI.IdentityEnvironmentSigned] is false.
func (in *PKI) IdentityIssuer(environment, role string) (*IssuerView, error) {
	signed, err := in.IdentityEnvironmentSigned(environment)
	if err != nil || !signed {
		return nil, err
	}

	view, err := in.Issuer(in.Identity, role)
	if err != nil {
		return nil, err
	}

	return &view, nil
}

// IdentityEnvironmentCA reads and verifies one environment's root-signed CA
// from its committed artifact, with the root generation that signed it, or
// nil where [PKI.IdentityEnvironmentSigned] is false. zone is the caller's:
// the subject and URI constraint derive per environment.
func (in *PKI) IdentityEnvironmentCA(environment, zone string) (*EnvironmentCA, error) {
	signed, err := in.IdentityEnvironmentSigned(environment)
	if err != nil || !signed {
		return nil, err
	}

	identity := in.Contract.URITrustDomain(in.Identity)

	spec, err := in.Contract.EnvironmentCASpec(in.Identity, environment, zone, identity.RootGeneration)
	if err != nil {
		return nil, fmt.Errorf("identity environment CA: %w", err)
	}

	ca, err := in.Contract.LoadSignedIntermediate(spec)
	if err != nil {
		return nil, fmt.Errorf("identity environment CA %s: %w", spec.ArtifactPath, err)
	}

	anchors, err := in.Contract.TrustAnchors()
	if err != nil {
		return nil, fmt.Errorf("identity environment CA root: %w", err)
	}

	for _, anchor := range anchors {
		if anchor.GenerationID != identity.RootGeneration {
			continue
		}

		return &EnvironmentCA{
			CertificatePEM:        ca.Artifact.CertificatePEM,
			FingerprintSHA256:     strings.ToUpper(ca.Artifact.FingerprintSHA256),
			RootCertificatePEM:    anchor.CertificatePEM,
			RootFingerprintSHA256: strings.ToUpper(anchor.FingerprintSHA256),
		}, nil
	}

	return nil, fmt.Errorf("identity environment CA: root generation %q is not among the trusted generations", identity.RootGeneration)
}

func (in *PKI) view(name, domain, role, login string, shared bool) (IssuerView, error) {
	mount, leaf, err := in.issuingMount(domain, role)
	if err != nil {
		return IssuerView{}, err
	}

	view := IssuerView{Name: name, SignPath: mount + "/sign/" + role, LoginRole: login}
	if shared {
		view.Audience = in.AudiencePrefix + login
	}

	if leaf != nil {
		bits, err := curveBits(leaf.KeyCurve)
		if err != nil {
			return IssuerView{}, fmt.Errorf("trust domain %q role %q: %w", domain, role, err)
		}

		view.Policy = LeafPolicy{
			Duration:     leaf.Lifetimes.Default,
			RenewBefore:  leaf.Lifetimes.RenewBefore,
			KeyAlgorithm: in.Contract.Global.KeyAlgorithm,
			KeySize:      bits,
		}
	}

	return view, nil
}

// issuingMount is the issuing mount of a trust domain, and the leaf role when
// the domain is a DNS one that declares it.
func (in *PKI) issuingMount(domain, role string) (string, *pki.LeafRole, error) {
	if dns := in.Contract.DNSTrustDomain(domain); dns != nil {
		for i := range dns.Roles {
			if dns.Roles[i].Name == role {
				return dns.IssuingMountPath(), &dns.Roles[i], nil
			}
		}

		return "", nil, fmt.Errorf("estate: trust domain %q declares no %q role", domain, role)
	}

	if uri := in.Contract.URITrustDomain(domain); uri != nil {
		return uri.IssuingMountPath(), nil, nil
	}

	return "", nil, fmt.Errorf("estate: no trust domain named %q", domain)
}

// curveBits is the key size of an EC curve as cert-manager and the server
// both count it: P-384 is 384.
func curveBits(curve string) (int, error) {
	bits, err := strconv.Atoi(strings.TrimPrefix(curve, "P-"))
	if err != nil || !strings.HasPrefix(curve, "P-") {
		return 0, fmt.Errorf("key curve %q is not P-<bits>", curve)
	}

	return bits, nil
}
