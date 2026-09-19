// Package apply converges an OpenBAO server onto a [model.Desired] with the
// Pulumi vault provider.
//
// [Deploy] registers every resource directly on the caller's Pulumi
// context, not inside a component resource of its own. A component type
// would put itself into every child's URN, so a state that already runs
// under these names -- hundreds of mounts, roles, policies and protected CA
// keys -- would preview as a replacement of all of it. Registering directly
// keeps the adoption preview empty; the logical names are derived from the
// model by a fixed scheme (docs/model.md) that never changes in a minor
// version, and [Options.Rename] maps the rest.
//
// Deploy creates the provider itself, after the pre-apply hook: a login
// token is fetched only once a slow snapshot is behind it.
//
// The server must forward every request from a standby to the active node
// (`disable_standby_reads = true`) when a load balancer spreads clients
// over every pod: a standby serves reads eventually consistently, and this
// apply reads back each object it has just written.
package apply

import (
	"context"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/openbao/pkg/model"
)

// DefaultProviderName is the logical name of the provider Deploy creates.
const DefaultProviderName = "openbao"

type (
	// Options is everything Deploy needs besides the desired state.
	Options struct {
		// Address is the server's URL as its clients reach it
		// (`https://openbao.example`). The provider logs in there, and every
		// PKI mount publishes its issuer, CRL and OCSP URLs under it.
		Address string
		// Login is how the apply logs in.
		Login Login
		// ProviderName defaults to DefaultProviderName.
		ProviderName string
		// BeforeApply runs before the login on an apply, never on a
		// preview. A snapshot belongs here ([SnapshotJob]); an error stops
		// the apply before anything is touched.
		BeforeApply func(context.Context) error
		// OIDCClientSecrets is the client secret of every oidc mount, by
		// client id. It reaches the provider only, marked secret.
		OIDCClientSecrets map[string]pulumi.StringInput
		// SignedChain returns the PEM chain of an External issuer -- its
		// certificate first, then its parents -- as the external signer
		// produced it. Verify it before returning it: the apply imports
		// what it is given. Required when the state has an External issuer.
		SignedChain func(model.IssuerRef) (string, error)
		// Rename maps the logical name the apply would give a resource to
		// the name the caller's state already holds it under. It is the
		// adoption hook for state written by other code; nil keeps every
		// name.
		Rename func(string) string
		// ResourceOptions are appended to every resource Deploy registers,
		// the provider included (a parent, for instance).
		ResourceOptions []pulumi.ResourceOption
	}

	// Login is a JWT login into root that the provider uses as its token.
	Login struct {
		// Mount and Role are the auth mount and the role in root.
		Mount string
		Role  string
		// Token returns the JWT to log in with. It is called once, after
		// BeforeApply, and the result is marked secret.
		Token func(context.Context) (string, error)
		// CACertFile is the PEM file the server's certificate is verified
		// against.
		CACertFile string
	}

	// Result is what Deploy created, for the caller's exports.
	Result struct {
		Provider *vault.Provider
		// Namespaces are the environment namespaces, in model order.
		Namespaces []string
		// Certificates are the self-signed issuers' certificates, by
		// issuer name: public trust anchors.
		Certificates map[string]pulumi.StringOutput
		// CertificateRequests are the External issuers' requests, by
		// issuer name: what the external signer signs.
		CertificateRequests map[string]pulumi.StringOutput
		// SSHCAPublicKeys are the SSH mounts' CA public keys.
		SSHCAPublicKeys map[MountRef]pulumi.StringOutput
	}

	// MountRef names a mount: its namespace ("" is root) and its path.
	MountRef struct {
		Namespace string
		Path      string
	}
)

// Deploy validates the desired state, runs BeforeApply unless this is a
// preview, logs in, and registers every namespace the model owns --
// never the bootstrap door, which the login itself goes through.
func Deploy(c *pulumi.Context, desired *model.Desired, opts Options) (*Result, error) {
	if err := desired.Validate(); err != nil {
		return nil, err
	}

	a, err := newApplier(c, desired, opts)
	if err != nil {
		return nil, err
	}

	if !c.DryRun() && opts.BeforeApply != nil {
		if err := opts.BeforeApply(c.Context()); err != nil {
			return nil, err
		}
	}

	providerName := opts.ProviderName
	if providerName == "" {
		providerName = DefaultProviderName
	}

	provider, err := NewProvider(c, providerName, opts.Address, opts.Login, opts.ResourceOptions...)
	if err != nil {
		return nil, err
	}

	a.provider = provider
	a.result.Provider = provider

	for _, namespace := range desired.Applied() {
		if err := a.namespace(namespace); err != nil {
			return nil, err
		}
	}

	return a.result, nil
}

// checkInputs refuses, before anything is registered, what the model
// cannot know: a secret or chain the options lack, an issuer name used
// twice across the server, and an address that is not https.
func checkInputs(desired *model.Desired, opts *Options) error {
	if !strings.HasPrefix(opts.Address, "https://") || strings.HasSuffix(opts.Address, "/") {
		return fmt.Errorf("apply: address %q is not an https URL without a trailing slash", opts.Address)
	}

	if opts.Login.Token == nil || opts.Login.Mount == "" || opts.Login.Role == "" {
		return fmt.Errorf("apply: the login needs a mount, a role and a token")
	}

	issuers := map[string]string{}

	for _, namespace := range desired.Applied() {
		for i := range namespace.Auth {
			mount := &namespace.Auth[i]
			if mount.Type == model.MethodOIDC && opts.OIDCClientSecrets[mount.ClientID] == nil {
				return fmt.Errorf("apply: %s oidc mount %s signs in as %s, whose secret is not in OIDCClientSecrets",
					namespace.Label(), mount.Path, mount.ClientID)
			}
		}

		for i := range namespace.PKI {
			mount := &namespace.PKI[i]
			for j := range mount.Issuers {
				issuer := &mount.Issuers[j]
				where := namespace.Label() + "/" + mount.Path

				if other, taken := issuers[issuer.Name]; taken {
					return fmt.Errorf("apply: issuer %q is declared in %s and in %s; issuer names are unique across the server", issuer.Name, other, where)
				}

				issuers[issuer.Name] = where

				if issuer.External && opts.SignedChain == nil {
					return fmt.Errorf("apply: issuer %s/%s is external and no SignedChain is given", where, issuer.Name)
				}
			}
		}
	}

	return nil
}
