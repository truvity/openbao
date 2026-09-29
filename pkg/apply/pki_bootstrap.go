package apply

import (
	"fmt"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault/pkisecret"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/openbao/pkg/model"
)

// PKIRoleResourceName is the logical name [Deploy] gives a PKI role's
// Pulumi resource, derived from the issuer it signs with -- so if a role
// keeps signing the same names but moves to a different issuer (an
// environment's CA moving from a shared domain intermediate to its own
// root-signed one, see [EnvironmentCARoleRename] and
// [github.com/truvity/openbao/pkg/pki], "per-environment identity CAs"),
// this name changes too, and [Options.Rename] is what keeps the role's
// OpenBAO object ("<mount>/roles/<name>") in place across that move.
func PKIRoleResourceName(issuer, role string) string {
	return issuer + "-role-" + role
}

// PKICredentialRoleResourceName is [PKIRoleResourceName] for a
// [model.CredentialRole].
func PKICredentialRoleResourceName(issuer, role string) string {
	return issuer + "-credential-role-" + role
}

// EnvironmentCARoleRename returns the [Options.Rename] entries that keep
// a role's OpenBAO object in place when the issuer it signs with changes
// name -- for example a workload-identity environment moving from a
// shared domain intermediate's issuing CA to its own root-signed one.
//
// Without this, [Deploy]'s naming scheme ([PKIRoleResourceName]) derives
// a NEW logical name from the new issuer, so Pulumi creates that logical
// resource and DELETES the old one -- and both write the SAME OpenBAO
// path ("<mount>/roles/<role>"), so the delete removes what the create
// just wrote. The role itself has not moved: it is still the one role an
// environment's mount offers for that shape of leaf; only which issuer
// signs it has.
//
// oldIssuer is the issuer every listed role signed with before the move.
// Pass "" for an environment reaching its root-signed CA from a cold
// start -- there is no prior role to rename, and this returns nil.
// oldIssuer == newIssuer also returns nil: nothing moved.
//
// Merge the result into whatever [Options.Rename] a caller already
// builds with [ComposeRename].
func EnvironmentCARoleRename(oldIssuer, newIssuer string, roleNames ...string) map[string]string {
	if oldIssuer == "" || oldIssuer == newIssuer {
		return nil
	}

	renames := make(map[string]string, len(roleNames))
	for _, role := range roleNames {
		renames[PKIRoleResourceName(newIssuer, role)] = PKIRoleResourceName(oldIssuer, role)
	}

	return renames
}

// ComposeRename returns an [Options.Rename] function that looks a
// logical name up in overrides first (an [EnvironmentCARoleRename] map,
// typically) and falls through to base -- a caller's own Rename, or nil
// to keep every other name unchanged.
func ComposeRename(overrides map[string]string, base func(string) string) func(string) string {
	return func(name string) string {
		if kept, ok := overrides[name]; ok {
			return kept
		}

		if base != nil {
			return base(name)
		}

		return name
	}
}

type (
	// BootstrapEnvironmentCAOptions is what [BootstrapEnvironmentCA]
	// needs to create ONLY the key-generation half of one environment's
	// own root-signed CA: phase A of its two-phase ceremony
	// (docs/pki.md, "per-environment identity CAs";
	// [github.com/truvity/openbao/pkg/pki]'s own doc has the mechanism).
	// Nothing here is signed, and no issuer is named: the root cannot
	// sign a request that does not exist yet.
	BootstrapEnvironmentCAOptions struct {
		// Namespace is "" for root.
		Namespace string
		// Mount is the PKI mount path this CA's key is generated inside.
		Mount string
		// MountExists is true for an environment moving from a shared
		// domain intermediate's issuing CA to its own root-signed one
		// (the mount already exists, created by that issuing CA's own
		// desired state) and false for an environment reaching its
		// root-signed CA from a cold start (this creates the mount too,
		// and DefaultLeaseTTL/MaxLeaseTTL are then required).
		MountExists     bool
		DefaultLeaseTTL string
		MaxLeaseTTL     string
		// MountDescription is set only when this creates the mount
		// (!MountExists).
		MountDescription string
		// KeyName is the new CA's key name inside the mount --
		// [github.com/truvity/openbao/pkg/pki]'s
		// URITrustDomain.EnvironmentCAIssuerName(environment),
		// typically: the same name the CA is later named with in phase
		// B, once its certificate is signed and committed.
		KeyName      string
		CommonName   string
		Organization string
		// KeyCurve is one of [model.CurveP256], [model.CurveP384],
		// [model.CurveP521].
		KeyCurve string
		// ResourceName is OPTIONAL and legacy. The mount and the
		// certificate request are registered under exactly the names
		// [Deploy] will later give the same objects -- the mount as
		// "<namespace>-<mount>" ("<mount>" in root; slashes in the
		// namespace become "-") and the request as "<KeyName>-csr" -- so
		// phase B adopts them with no create and no delete. Set
		// ResourceName only when an earlier release of this library
		// registered them under the old scheme (the mount as
		// ResourceName+"-mount", the request as ResourceName): those
		// names become Pulumi aliases, so the existing state moves to the
		// new names in place.
		ResourceName string
		// Rename is the same [Options.Rename] the later [Deploy] is
		// given, if any; it is applied to both names exactly as Deploy
		// applies it.
		Rename func(string) string
	}
)

// BootstrapEnvironmentCA registers phase A of one environment's
// root-signed CA and returns the certificate signing request (PEM) to
// export as a Pulumi output for the offline ceremony
// ([github.com/truvity/openbao/pkg/pki] `Contract.EnvironmentCASpec` +
// [github.com/truvity/openbao/pkg/ceremony] `PrepareIntermediate`/
// `SignIntermediate`) to sign.
//
// This runs OUTSIDE [Deploy]'s generic desired-state path on purpose:
// that path calls [Options.SignedChain] synchronously for every
// `External` issuer while it builds resources, and there is no "CSR
// only, not installed yet" mode for one. Declaring this CA in the
// desired state before it is signed would therefore fail every preview
// and apply, not only this one CA's.
//
// Names: the mount and the request carry the logical names [Deploy]
// derives for the same objects (see [BootstrapEnvironmentCAOptions]), so
// moving from this phase to [Deploy] is a no-op for both.
//
// The key and its certificate request are protected: replacing them is
// an explicit, reviewed migration, never an ordinary Pulumi update. When
// !options.MountExists, the mount this registers is protected too.
func BootstrapEnvironmentCA(c *pulumi.Context, provider *vault.Provider, options BootstrapEnvironmentCAOptions) (pulumi.StringOutput, error) {
	if options.Mount == "" || options.KeyName == "" || options.CommonName == "" {
		return pulumi.StringOutput{}, fmt.Errorf("apply: bootstrap environment CA requires a mount, a key name and a common name")
	}

	bits, ok := model.CurveBits[options.KeyCurve]
	if !ok {
		return pulumi.StringOutput{}, fmt.Errorf("apply: bootstrap environment CA: unknown key curve %q", options.KeyCurve)
	}

	opts := []pulumi.ResourceOption{pulumi.Provider(provider), pulumi.Protect(true)}

	var namespace pulumi.StringPtrInput
	if options.Namespace != "" {
		namespace = pulumi.String(options.Namespace)
	}

	rename := options.Rename
	if rename == nil {
		rename = func(name string) string { return name }
	}

	mountResource := rename(mountLogicalName(options.Namespace, options.Mount))
	csrResource := rename(options.KeyName + "-csr")

	// What an earlier release named them, kept as aliases.
	var mountAliases, csrAliases []pulumi.ResourceOption

	if options.ResourceName != "" {
		mountAliases = legacyAlias(mountResource, options.ResourceName+"-mount")
		csrAliases = legacyAlias(csrResource, options.ResourceName)
	}

	dependsOn := []pulumi.Resource{}

	if !options.MountExists {
		defaultTTL, err := model.DurationSeconds(options.DefaultLeaseTTL)
		if err != nil {
			return pulumi.StringOutput{}, fmt.Errorf("apply: bootstrap environment CA mount: %w", err)
		}

		maxTTL, err := model.DurationSeconds(options.MaxLeaseTTL)
		if err != nil {
			return pulumi.StringOutput{}, fmt.Errorf("apply: bootstrap environment CA mount: %w", err)
		}

		mount, err := vault.NewMount(c, mountResource, &vault.MountArgs{
			Namespace:              namespace,
			Path:                   pulumi.String(options.Mount),
			Type:                   pulumi.String("pki"),
			Description:            pulumi.String(options.MountDescription),
			DefaultLeaseTtlSeconds: pulumi.Int(defaultTTL),
			MaxLeaseTtlSeconds:     pulumi.Int(maxTTL),
		}, append(opts, mountAliases...)...)
		if err != nil {
			return pulumi.StringOutput{}, fmt.Errorf("apply: bootstrap environment CA mount: %w", err)
		}

		dependsOn = append(dependsOn, mount)
	}

	// `internal`: OpenBAO generates the key inside the mount and keeps
	// it; what leaves is this request, carrying exactly the given
	// subject and no alternative name -- the ceremony rebuilds the
	// certificate entirely from the authored contract and takes only
	// the public key from here.
	csr, err := pkisecret.NewSecretBackendIntermediateCertRequest(c, csrResource, &pkisecret.SecretBackendIntermediateCertRequestArgs{
		Namespace:         namespace,
		Backend:           pulumi.String(options.Mount),
		Type:              pulumi.String("internal"),
		CommonName:        pulumi.String(options.CommonName),
		KeyName:           pulumi.String(options.KeyName),
		KeyType:           pulumi.String("ec"),
		KeyBits:           pulumi.Int(bits),
		Format:            pulumi.String("pem"),
		ExcludeCnFromSans: pulumi.Bool(true),
		Organization:      pulumi.String(options.Organization),
	}, append(append(opts, csrAliases...), pulumi.DependsOn(dependsOn))...)
	if err != nil {
		return pulumi.StringOutput{}, fmt.Errorf("apply: bootstrap environment CA certificate request: %w", err)
	}

	return csr.Csr, nil
}

// legacyAlias is the alias option carrying an object from its old logical
// name to its new one, or nothing when they are the same.
func legacyAlias(current, previous string) []pulumi.ResourceOption {
	if current == previous {
		return nil
	}

	return []pulumi.ResourceOption{pulumi.Aliases([]pulumi.Alias{{Name: pulumi.String(previous)}})}
}
