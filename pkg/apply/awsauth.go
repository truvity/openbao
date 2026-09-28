package apply

import (
	"fmt"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	vaultaws "github.com/pulumi/pulumi-vault/sdk/v7/go/vault/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/openbao/pkg/model"
)

// awsAuthType is the one auth type this backend is ever mounted or
// configured as; model.AWSAuthMount supports IAM logins only.
const awsAuthType = "aws"

// awsAuthMount registers one AWS IAM auth backend: the generic auth mount
// (there is no `aws.NewAuthBackend` -- the provider mounts every auth
// method through `vault.NewAuthBackend` and configures the plugin-specific
// pieces with a resource of its own, the way jwt.NewAuthBackend's mount
// and door() above configure a JWT/OIDC one differently), its client
// configuration (the server-id header every login's signed request must
// carry), and its roles.
//
// Unlike door(), a role here grants its TokenPolicies directly and gets no
// accessor-based identity group: an AWS login authenticates a host, not a
// person (model.AWSAuthMount's own doc comment).
func (a *applier) awsAuthMount(s *scope, desired *model.AWSAuthMount, policies map[string]*vault.Policy) error {
	args := &vault.AuthBackendArgs{
		Namespace: s.arg,
		Path:      pulumi.String(desired.Path),
		Type:      pulumi.String(awsAuthType),
	}

	if desired.Description != "" {
		args.Description = pulumi.String(desired.Description)
	}

	backend, err := vault.NewAuthBackend(a.c, a.name(s.label+"-auth-"+desired.Path), args, s.inside...)
	if err != nil {
		return fmt.Errorf("%s aws auth %s: %w", s.label, desired.Path, err)
	}

	if _, err := vaultaws.NewAuthBackendClient(a.c, a.name(s.label+"-auth-"+desired.Path+"-client"), &vaultaws.AuthBackendClientArgs{
		Namespace:              s.arg,
		Backend:                backend.Path,
		IamServerIdHeaderValue: pulumi.String(desired.IAMServerIDHeaderValue),
	}, options(s.inside, pulumi.DependsOn([]pulumi.Resource{backend}))...); err != nil {
		return fmt.Errorf("%s aws auth %s client: %w", s.label, desired.Path, err)
	}

	for i := range desired.Roles {
		if err := a.awsAuthRole(s, desired.Path, backend, &desired.Roles[i], policies); err != nil {
			return err
		}
	}

	return nil
}

// awsAuthRole registers one `iam`-type role: the auth type this model
// supports exclusively (model.AWSAuthMount's doc comment), so it is never
// read from the desired state.
func (a *applier) awsAuthRole(
	s *scope, mount string, backend *vault.AuthBackend, role *model.AWSAuthRole, policies map[string]*vault.Policy,
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
		Backend:               backend.Path,
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
	var waits []pulumi.Resource

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
