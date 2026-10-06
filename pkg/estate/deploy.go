package estate

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/secrets/pkg/apply"
	"github.com/truvity/secrets/pkg/model"
)

// The stack's outputs, under the names consumers read.
const (
	// OutputNamespaces lists the environment namespaces: its presence marks
	// the configuration deployed.
	OutputNamespaces = "namespaces"
	// OutputTrustRoot is the legacy root's certificate: a public trust
	// anchor.
	OutputTrustRoot = "trustRootCaPem"
	// OutputSSHUserCAs and OutputSSHHostCAs are each environment's SSH user
	// and host CA public keys, by environment.
	OutputSSHUserCAs = "sshUserCaPublicKeys"
	OutputSSHHostCAs = "sshHostCaPublicKeys"
)

type (
	// DeployOptions is what [Deploy] needs beside the desired state.
	DeployOptions struct {
		// Address, Login, BeforeApply and OIDCClientSecrets are pkg/apply's
		// (apply.Options).
		Address           string
		Login             apply.Login
		BeforeApply       func(context.Context) error
		OIDCClientSecrets map[string]pulumi.StringInput
		// Chains loads the committed, ceremony-signed certificates the
		// server imports.
		Chains Chains
		// DomainCSROutputs names the output carrying each trust domain's
		// intermediate request, by trust domain: what the root ceremony
		// signs.
		DomainCSROutputs map[string]string
		// EnvironmentCSROutput names the output carrying every identity
		// environment CA's request, by environment, whichever phase it is in.
		EnvironmentCSROutput string
		// Logger records each signed chain installed; nil is slog.Default.
		Logger *slog.Logger
	}

	// Chains loads signed certificates from where the ceremony committed
	// them. A loader re-proves each one against the contract before it
	// returns it: the apply imports what it is given.
	Chains interface {
		// DomainIntermediate is a trust domain's intermediate of a root
		// generation.
		DomainIntermediate(trustDomain, generationID string) (Chain, error)
		// EnvironmentCA is one environment's root-signed identity CA, for the
		// environment's private zone.
		EnvironmentCA(environment, zone, generationID string) (Chain, error)
	}

	// Chain is one signed certificate as the ceremony committed it.
	Chain struct {
		// PEM is the certificate first, then its parents.
		PEM string
		// ArtifactPath and FingerprintSHA256 say which artifact it is.
		ArtifactPath      string
		FingerprintSHA256 string
	}
)

// Deploy applies the desired state through pkg/apply -- every namespace
// below root, root's jobs and web UI door, the PKI -- under the names
// existing state holds ([Desired.LegacyResourceNames]), and exports what
// consumers read: the namespaces, the legacy trust root, each environment's
// SSH CA keys, and the certificate requests the root ceremony signs.
//
// An identity environment CA that is not signed yet is bootstrapped beside
// the apply: its mount and the request of the key the server generates,
// under the name the apply will adopt once the CA is signed.
func Deploy(c *pulumi.Context, desired *Desired, opts DeployOptions) error {
	state, err := desired.Model()
	if err != nil {
		return err
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	in := desired.in
	rename := apply.RenameFrom(desired.LegacyResourceNames())

	result, err := apply.Deploy(c, state, apply.Options{
		Address:           opts.Address,
		Login:             opts.Login,
		BeforeApply:       opts.BeforeApply,
		OIDCClientSecrets: opts.OIDCClientSecrets,
		SignedChain:       desired.SignedChain(c.Context(), logger, opts.Chains),
		Rename:            rename,
	})
	if err != nil {
		return err
	}

	c.Export(OutputNamespaces, pulumi.ToStringArray(result.Namespaces))
	c.Export(OutputTrustRoot, result.Certificates[desired.PKI.Legacy.Root.IssuerName])
	c.Export(OutputSSHUserCAs, environmentKeys(result.SSHCAPublicKeys, in.Names.SSH.Mount))
	c.Export(OutputSSHHostCAs, environmentKeys(result.SSHHostCAPublicKeys, in.Names.SSH.HostMount))

	for i := range desired.PKI.Domains {
		domain := &desired.PKI.Domains[i]

		output, ok := opts.DomainCSROutputs[domain.TrustDomain]
		if !ok {
			return fmt.Errorf("estate: trust domain %s has no request output", domain.TrustDomain)
		}

		c.Export(output, result.CertificateRequests[domain.IssuerName])
	}

	identity := in.PKI.Contract.URITrustDomain(in.PKI.Identity)
	if identity == nil || len(identity.Environments) == 0 {
		return nil
	}

	generation, err := ActiveGeneration(in.PKI.Contract)
	if err != nil {
		return err
	}

	csrs := pulumi.StringMap{}

	for _, environment := range identity.Environments {
		if in.PKI.Signed[environment] {
			csrs[environment] = result.CertificateRequests[identity.EnvironmentCAIssuerName(environment)]

			continue
		}

		zone, err := desired.privateZone(environment)
		if err != nil {
			return err
		}

		csr, err := apply.BootstrapEnvironmentCA(c, result.Provider, apply.BootstrapEnvironmentCAOptions{
			Namespace:        environment,
			Mount:            identity.IssuingMountPath(),
			DefaultLeaseTTL:  identity.Role.Lifetimes.Default,
			MaxLeaseTTL:      identity.Role.Lifetimes.Maximum,
			MountDescription: render(in.Text.IdentityBootstrap, environment, ""),
			KeyName:          identity.EnvironmentCAIssuerName(environment),
			CommonName:       zone + " " + identity.EnvironmentCA.CommonNameSuffix,
			Organization:     generation.Certificate.Subject.Organization,
			KeyCurve:         identity.EnvironmentCA.KeyCurve,
			Rename:           rename,
		})
		if err != nil {
			return err
		}

		csrs[environment] = csr
	}

	c.Export(opts.EnvironmentCSROutput, csrs)

	return nil
}

// environmentKeys is the environments' public keys of one SSH mount, by
// environment.
func environmentKeys(keys map[apply.MountRef]pulumi.StringOutput, mount string) pulumi.StringMap {
	out := pulumi.StringMap{}

	for ref, key := range keys {
		if ref.Namespace != "" && ref.Path == mount {
			out[ref.Namespace] = key
		}
	}

	return out
}

// privateZone is one environment's private zone.
func (d *Desired) privateZone(environment string) (string, error) {
	at := slices.IndexFunc(d.in.Clusters, func(c Cluster) bool { return c.Name == environment })
	if at < 0 || d.in.Clusters[at].PrivateZone == "" {
		return "", fmt.Errorf("estate: %s identity environment CA: no cluster inputs", environment)
	}

	return d.in.Clusters[at].PrivateZone, nil
}

// SignedChain is apply.Options.SignedChain for this state: the chain the
// server imports for each External issuer, from chains.
func (d *Desired) SignedChain(ctx context.Context, logger *slog.Logger, chains Chains) func(model.IssuerRef) (string, error) {
	if logger == nil {
		logger = slog.Default()
	}

	return func(ref model.IssuerRef) (string, error) { return d.signedChain(ctx, logger, chains, ref) }
}

// signedChain is the chain the server imports for one External issuer: THE
// COMMITTED ARTIFACT, NEVER A FRESH SIGNATURE. The root key signs once, in
// the ceremony; the loader re-proves the artifact against the contract
// before the server is touched, so a wrong or swapped file fails the
// preview, not the apply. Nothing here can sign.
func (d *Desired) signedChain(ctx context.Context, logger *slog.Logger, chains Chains, ref model.IssuerRef) (string, error) {
	if chains == nil {
		return "", fmt.Errorf("estate: %s is external and no chain loader is given", ref)
	}

	generation := d.PKI.Root.GenerationID

	if ref.Namespace != "" {
		identity := d.in.PKI.Contract.URITrustDomain(d.in.PKI.Identity)
		if identity == nil || ref.Issuer != identity.EnvironmentCAIssuerName(ref.Namespace) {
			return "", fmt.Errorf("estate: %s is no external issuer this state declares", ref)
		}

		zone, err := d.privateZone(ref.Namespace)
		if err != nil {
			return "", err
		}

		chain, err := chains.EnvironmentCA(ref.Namespace, zone, generation)
		if err != nil {
			return "", fmt.Errorf("%s identity environment CA: %w", ref.Namespace, err)
		}

		logger.InfoContext(ctx, "installing a signed root-signed identity environment CA",
			slog.String("environment", ref.Namespace), slog.String("issuer", ref.Issuer),
			slog.String("artifact", chain.ArtifactPath), slog.String("fingerprint_sha256", chain.FingerprintSHA256))

		return chain.PEM, nil
	}

	at := slices.IndexFunc(d.PKI.Domains, func(domain DomainAuthority) bool { return domain.IssuerName == ref.Issuer })
	if at < 0 {
		return "", fmt.Errorf("estate: %s is no domain intermediate", ref)
	}

	domain := &d.PKI.Domains[at]

	chain, err := chains.DomainIntermediate(domain.TrustDomain, generation)
	if err != nil {
		return "", fmt.Errorf("%s domain intermediate: %w", domain.TrustDomain, err)
	}

	logger.InfoContext(ctx, "installing a signed domain intermediate",
		slog.String("trust_domain", domain.TrustDomain), slog.String("mount", domain.Mount), slog.String("issuer", domain.IssuerName),
		slog.String("artifact", chain.ArtifactPath), slog.String("fingerprint_sha256", chain.FingerprintSHA256))

	return chain.PEM, nil
}

// OIDCClientSecret reads an OIDC client's secret from the Secret another
// system delivers, before the apply touches the server: a client not
// delivered yet stops a preview too. The client id is read back as a check
// that the Secret is the client the mounts name. The value never reaches a
// log or an error; mark it secret.
func OIDCClientSecret(ctx context.Context, kubectl apply.Kubectl, delivered apply.DeliveredSecret, client string) (string, error) {
	id, err := delivered.Key(ctx, kubectl, "client-id")
	if err != nil {
		return "", err
	}

	if id != client {
		return "", fmt.Errorf("secret %s/%s names client %q, want %q", delivered.Namespace, delivered.Name, id, client)
	}

	return delivered.Key(ctx, kubectl, "client-secret")
}
