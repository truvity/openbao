// Package stack is the Pulumi program that applies an estate's desired state
// (pkg/estate) through pkg/apply. It is apart from pkg/estate so that the
// derivation stays free of Pulumi: an estate's configuration loaders can build
// and review the state without linking the provider SDKs.
package stack

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/secrets/pkg/apply"
	"github.com/truvity/secrets/pkg/estate"
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
	// Options is what [Deploy] needs beside the desired state.
	Options struct {
		// Address, Login, BeforeApply and OIDCClientSecrets are pkg/apply's
		// (apply.Options).
		Address           string
		Login             apply.Login
		BeforeApply       func(context.Context) error
		OIDCClientSecrets map[string]pulumi.StringInput
		// Chains loads the committed, ceremony-signed certificates the
		// server imports.
		Chains estate.Chains
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
)

// Deploy applies the desired state through pkg/apply -- every namespace below
// root, root's jobs and web UI door, the PKI -- under the names existing state
// holds (estate.Desired.LegacyResourceNames), and exports what consumers
// read: the namespaces, the legacy trust root, each environment's SSH CA
// keys, and the certificate requests the root ceremony signs.
//
// An identity environment CA that is not signed yet is bootstrapped beside
// the apply: its mount and the request of the key the server generates,
// under the name the apply adopts once it is signed.
func Deploy(c *pulumi.Context, desired *estate.Desired, opts Options) error {
	state, err := desired.Model()
	if err != nil {
		return err
	}

	in := desired.Inputs()
	rename := apply.RenameFrom(desired.LegacyResourceNames())

	result, err := apply.Deploy(c, state, apply.Options{
		Address:           opts.Address,
		Login:             opts.Login,
		BeforeApply:       opts.BeforeApply,
		OIDCClientSecrets: opts.OIDCClientSecrets,
		SignedChain:       desired.SignedChain(c.Context(), opts.Logger, opts.Chains),
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
			return fmt.Errorf("stack: trust domain %s has no request output", domain.TrustDomain)
		}

		c.Export(output, result.CertificateRequests[domain.IssuerName])
	}

	identity := in.PKI.Contract.URITrustDomain(in.PKI.Identity)
	if identity == nil || len(identity.Environments) == 0 {
		return nil
	}

	generation, err := estate.ActiveGeneration(in.PKI.Contract)
	if err != nil {
		return err
	}

	csrs := pulumi.StringMap{}

	for _, environment := range identity.Environments {
		if in.PKI.Signed[environment] {
			csrs[environment] = result.CertificateRequests[identity.EnvironmentCAIssuerName(environment)]

			continue
		}

		zone, err := desired.PrivateZone(environment)
		if err != nil {
			return err
		}

		csr, err := apply.BootstrapEnvironmentCA(c, result.Provider, apply.BootstrapEnvironmentCAOptions{
			Namespace:        environment,
			Mount:            identity.IssuingMountPath(),
			DefaultLeaseTTL:  identity.Role.Lifetimes.Default,
			MaxLeaseTTL:      identity.Role.Lifetimes.Maximum,
			MountDescription: strings.ReplaceAll(in.Text.IdentityBootstrap, "{env}", environment),
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
