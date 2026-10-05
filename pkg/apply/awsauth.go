package apply

import (
	"encoding/json"
	"fmt"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	vaultaws "github.com/pulumi/pulumi-vault/sdk/v7/go/vault/aws"
	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault/generic"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/secrets/pkg/model"
)

// awsAuthType is the one auth type this backend is ever mounted or
// configured as; model.AWSAuthMount supports IAM logins only.
const awsAuthType = "aws"

// awsAuthMount registers one AWS IAM auth backend: the mount itself (an
// ordinary `vault.AuthBackend`, or -- when desired.PluginVersion pins a
// catalog version -- the generic `sys/auth/<path>` endpoint
// awsAuthMountVersioned builds instead, since pulumi-vault v7's
// AuthBackend has no pluginVersion input anywhere, not even in its tune
// block), its client configuration (the server-id header every login's
// signed request must carry), and its roles.
//
// Unlike door(), a role here grants its TokenPolicies directly and gets no
// accessor-based identity group: an AWS login authenticates a host, not a
// person (model.AWSAuthMount's own doc comment).
func (a *applier) awsAuthMount(s *scope, desired *model.AWSAuthMount, policies map[string]*vault.Policy) error {
	var (
		mountPath  pulumi.StringInput
		mountWaits []pulumi.Resource
	)

	if desired.PluginVersion != "" {
		endpoint, err := a.awsAuthMountVersioned(s, desired)
		if err != nil {
			return err
		}

		// The Endpoint's own Path output carries the full
		// "sys/auth/<path>" it was written to, not the mount path the
		// client configuration and every role below need -- that is
		// desired.Path itself, a plain string with no resource of its
		// own to derive it from (generic.NewEndpoint's `Path` argument
		// above only ever fed IN a string built from it).
		mountPath = pulumi.String(desired.Path)
		mountWaits = []pulumi.Resource{endpoint}
	} else {
		args := &vault.AuthBackendArgs{
			Namespace: s.arg,
			Path:      pulumi.String(desired.Path),
			Type:      pulumi.String(awsAuthType),
		}

		if desired.Description != "" {
			args.Description = pulumi.String(desired.Description)
		}

		backend, err := vault.NewAuthBackend(a.c, a.name(s.label+"-auth-"+desired.Path), args,
			a.pluginDependency(s.inside, "auth", awsAuthType)...)
		if err != nil {
			return fmt.Errorf("%s aws auth %s: %w", s.label, desired.Path, err)
		}

		mountPath = backend.Path
		mountWaits = []pulumi.Resource{backend}
	}

	if _, err := vaultaws.NewAuthBackendClient(a.c, a.name(s.label+"-auth-"+desired.Path+"-client"), &vaultaws.AuthBackendClientArgs{
		Namespace:              s.arg,
		Backend:                mountPath,
		IamServerIdHeaderValue: pulumi.String(desired.IAMServerIDHeaderValue),
	}, options(s.inside, pulumi.DependsOn(mountWaits))...); err != nil {
		return fmt.Errorf("%s aws auth %s client: %w", s.label, desired.Path, err)
	}

	for i := range desired.Roles {
		if err := a.awsAuthRole(s, desired.Path, mountPath, mountWaits, &desired.Roles[i], policies); err != nil {
			return err
		}
	}

	return nil
}

// awsAuthMountVersioned mounts one AWS auth backend at a PINNED plugin
// version, through the provider's generic `sys/auth/<path>` endpoint
// (`generic.NewEndpoint`): pulumi-vault v7's `vault.AuthBackend` has no
// `pluginVersion` input, so it can only ever create the unversioned kind
// of mount -- which, against a catalog that holds this plugin only as a
// VERSIONED entry (model.AWSAuthMount.PluginVersion's own doc comment),
// OpenBAO refuses with "plugin not found in the catalog".
//
// DisableRead is true: `sys/auth/<path>` is OpenBAO's mount-and-tune
// endpoint, and a GET against it does not return the shape this resource
// wrote (a raw JSON body of `type`/`description`/`plugin_version`) -- it
// returns the mount's tuned configuration instead, in a different shape
// entirely, which the generic provider would then read as permanent
// drift, forever. DisableDelete stays false: `DELETE sys/auth/<path>` is
// exactly how OpenBAO disables (unmounts) an auth backend, the same
// effect a removal from the desired state has on any other mount here, so
// leaving delete enabled is what makes that removal actually take effect
// rather than silently stop managing an auth backend still live in the
// catalog.
func (a *applier) awsAuthMountVersioned(s *scope, desired *model.AWSAuthMount) (*generic.Endpoint, error) {
	body := struct {
		Type          string `json:"type"`
		Description   string `json:"description,omitempty"`
		PluginVersion string `json:"plugin_version"`
	}{
		Type:          awsAuthType,
		Description:   desired.Description,
		PluginVersion: desired.PluginVersion,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%s aws auth %s: encode mount body: %w", s.label, desired.Path, err)
	}

	args := &generic.EndpointArgs{
		Namespace: s.arg,
		Path:      pulumi.String("sys/auth/" + desired.Path),
		DataJson:  pulumi.String(data),
		// Every field above is written or nothing here is; a partial
		// write that OpenBAO rejected outright would leave no mount to
		// read unevenly in the first place, and DisableRead below means
		// nothing here is ever read back to compare against it anyway.
		IgnoreAbsentFields: pulumi.Bool(true),
		DisableRead:        pulumi.Bool(true),
		DisableDelete:      pulumi.Bool(false),
	}

	endpoint, err := generic.NewEndpoint(a.c, a.name(s.label+"-auth-"+desired.Path), args,
		a.pluginDependency(s.inside, "auth", awsAuthType)...)
	if err != nil {
		return nil, fmt.Errorf("%s aws auth %s: %w", s.label, desired.Path, err)
	}

	return endpoint, nil
}

// awsAuthRole registers one `iam`-type role: the auth type this model
// supports exclusively (model.AWSAuthMount's doc comment), so it is never
// read from the desired state.
//
// mountWaits is the mount's own resource (the AuthBackend, or the
// versioned Endpoint) to depend on explicitly: a plain mountPath string
// carries no implicit Pulumi dependency of its own the way an unversioned
// mount's backend.Path output would.
func (a *applier) awsAuthRole(
	s *scope, mount string, mountPath pulumi.StringInput, mountWaits []pulumi.Resource,
	role *model.AWSAuthRole, policies map[string]*vault.Policy,
) error {
	ttl, err := model.DurationSeconds(role.TTL)
	if err != nil {
		return fmt.Errorf("%s aws role %s/%s: %w", s.label, mount, role.Name, err)
	}

	maxTTL, err := model.DurationSeconds(role.MaxTTL)
	if err != nil {
		return fmt.Errorf("%s aws role %s/%s: %w", s.label, mount, role.Name, err)
	}

	args := &vaultaws.AuthBackendRoleArgs{
		Namespace:             s.arg,
		Backend:               mountPath,
		Role:                  pulumi.String(role.Name),
		AuthType:              pulumi.String("iam"),
		BoundIamPrincipalArns: pulumi.ToStringArray(role.BoundIAMPrincipalARNs),
		ResolveAwsUniqueIds:   pulumi.Bool(role.ResolveAWSUniqueIDs),
		TokenPolicies:         pulumi.ToStringArray(role.Policies),
		TokenTtl:              pulumi.Int(ttl),
		TokenMaxTtl:           pulumi.Int(maxTTL),
	}

	// A policy this namespace does not declare is referenced by name
	// only, with nothing to wait for -- the same rule role() (namespace.go)
	// applies to a JWT role's policies.
	waits := append([]pulumi.Resource{}, mountWaits...)

	for _, name := range role.Policies {
		if policy := policies[name]; policy != nil {
			waits = append(waits, policy)
		}
	}

	if _, err := vaultaws.NewAuthBackendRole(a.c, a.name(s.label+"-role-"+mount+"-"+role.Name), args,
		options(s.inside, pulumi.DependsOn(waits))...); err != nil {
		return fmt.Errorf("%s aws role %s/%s: %w", s.label, mount, role.Name, err)
	}

	return nil
}
