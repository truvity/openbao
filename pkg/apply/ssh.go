package apply

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	vaultssh "github.com/pulumi/pulumi-vault/sdk/v7/go/vault/ssh"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/openbao/pkg/model"
)

// sshMount registers the SSH engine, its CA and its roles, all protected:
// a role that disappears in a replace is a window in which nobody can
// sign, and a replaced CA is a new key every host has to be told about.
//
// The mount caps every lease at the longest role maximum, so even a role
// written wrong cannot sign past it. Its audit keys make a signing readable
// in the audit log without a hash lookup: the principals asked for and the
// serial handed back.
func (a *applier) sshMount(s *scope, desired *model.SSHMount) error {
	defaultTTL, maxTTL := 0, 0

	for i := range desired.Roles {
		ttl, err := model.DurationSeconds(desired.Roles[i].TTL)
		if err != nil {
			return fmt.Errorf("%s ssh role %s: %w", s.label, desired.Roles[i].Name, err)
		}

		most, err := model.DurationSeconds(desired.Roles[i].MaxTTL)
		if err != nil {
			return fmt.Errorf("%s ssh role %s: %w", s.label, desired.Roles[i].Name, err)
		}

		defaultTTL, maxTTL = max(defaultTTL, ttl), max(maxTTL, most)
	}

	args := &vault.MountArgs{
		Namespace:                s.arg,
		Path:                     pulumi.String(desired.Path),
		Type:                     pulumi.String("ssh"),
		DefaultLeaseTtlSeconds:   pulumi.Int(defaultTTL),
		MaxLeaseTtlSeconds:       pulumi.Int(maxTTL),
		AuditNonHmacRequestKeys:  pulumi.ToStringArray([]string{"valid_principals"}),
		AuditNonHmacResponseKeys: pulumi.ToStringArray([]string{"serial_number"}),
	}

	if desired.Description != "" {
		args.Description = pulumi.String(desired.Description)
	}

	name := mountName(s, desired.Path)

	mount, err := vault.NewMount(a.c, a.name(name), args, authority(s.inside)...)
	if err != nil {
		return fmt.Errorf("%s ssh mount %s: %w", s.label, desired.Path, err)
	}

	// Generated inside OpenBAO: the signing key is never in Pulumi's
	// state, a file or an output. Only its public half is exported.
	ca, err := vaultssh.NewSecretBackendCa(a.c, a.name(name+"-ca"), &vaultssh.SecretBackendCaArgs{
		Namespace:          s.arg,
		Backend:            mount.Path,
		GenerateSigningKey: pulumi.Bool(true),
		KeyType:            pulumi.String(desired.KeyType),
	}, authority(s.inside, mount)...)
	if err != nil {
		return fmt.Errorf("%s ssh CA %s: %w", s.label, desired.Path, err)
	}

	for i := range desired.Roles {
		role := &desired.Roles[i]

		if _, err := vaultssh.NewSecretBackendRole(a.c, a.name(name+"-sshrole-"+role.Name), sshRoleArgs(s.arg, mount.Path, role),
			authority(s.inside, mount, ca)...); err != nil {
			return fmt.Errorf("%s ssh role %s/%s: %w", s.label, desired.Path, role.Name, err)
		}
	}

	a.result.SSHCAPublicKeys[MountRef{Namespace: s.namespace.Name, Path: desired.Path}] = ca.PublicKey

	return nil
}

// sshRoleArgs is a user-certificate role with everything it does not do
// spelled out: no host certificates, no key id of the caller's choosing,
// no empty principals, no templates, no critical options, and no extension
// beyond the ones it names. Each key type is admitted with length 0, which
// is how OpenBAO spells a type of one size such as ed25519.
func sshRoleArgs(namespace pulumi.StringPtrInput, backend pulumi.StringInput, role *model.SSHRole) *vaultssh.SecretBackendRoleArgs {
	// Validate has parsed both already.
	ttl, _ := model.DurationSeconds(role.TTL)
	maxTTL, _ := model.DurationSeconds(role.MaxTTL)

	keys := vaultssh.SecretBackendRoleAllowedUserKeyConfigArray{}
	for _, keyType := range role.KeyTypes {
		keys = append(keys, vaultssh.SecretBackendRoleAllowedUserKeyConfigArgs{
			Type:    pulumi.String(keyType),
			Lengths: pulumi.ToIntArray([]int{0}),
		})
	}

	extensions := pulumi.StringMap{}
	for _, extension := range role.Extensions {
		extensions[extension] = pulumi.String("")
	}

	return &vaultssh.SecretBackendRoleArgs{
		Namespace:                 namespace,
		Backend:                   backend,
		Name:                      pulumi.String(role.Name),
		KeyType:                   pulumi.String("ca"),
		AllowUserCertificates:     pulumi.Bool(true),
		AllowHostCertificates:     pulumi.Bool(false),
		AllowBareDomains:          pulumi.Bool(false),
		AllowSubdomains:           pulumi.Bool(false),
		AllowEmptyPrincipals:      pulumi.Bool(false),
		AllowUserKeyIds:           pulumi.Bool(false),
		KeyIdFormat:               pulumi.String(role.KeyIDFormat),
		AllowedUsers:              pulumi.String(strings.Join(role.AllowedUsers, ",")),
		AllowedUsersTemplate:      pulumi.Bool(false),
		DefaultUser:               pulumi.String(role.DefaultUser),
		DefaultUserTemplate:       pulumi.Bool(false),
		AllowedUserKeyConfigs:     keys,
		AllowedExtensions:         pulumi.String(strings.Join(role.Extensions, ",")),
		DefaultExtensions:         extensions,
		DefaultExtensionsTemplate: pulumi.Bool(false),
		AllowedCriticalOptions:    pulumi.String(""),
		DefaultCriticalOptions:    pulumi.StringMap{},
		Ttl:                       pulumi.String(strconv.Itoa(ttl)),
		MaxTtl:                    pulumi.String(strconv.Itoa(maxTTL)),
	}
}
