package apply

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault/identity"
	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault/jwt"
	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault/kv"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/openbao/pkg/model"
)

type (
	// applier holds one Deploy's state: what is registered so far, by the
	// references later resources depend on.
	applier struct {
		c        *pulumi.Context
		desired  *model.Desired
		opts     Options
		provider *vault.Provider
		result   *Result
		mounts   map[MountRef]*pkiMount
		issuers  map[model.IssuerRef]*pkiIssuer
		// registeredPlugins are the plugin catalog entries plugins() has
		// registered so far, keyed "<category>/<name>" (a mount's
		// OpenBAO type is its catalog Name; category is Plugin.Type,
		// "auth" or "secret"). pluginDependency reads this to make a
		// mount of a plugin's type wait for its registration -- Deploy
		// calls plugins() before a single namespace is, but that only
		// orders THIS PROGRAM; Pulumi itself creates resources with no
		// edge between them in parallel, so the wait must be an
		// explicit DependsOn, or a fresh apply can create the mount
		// before the registration and reproduce the same "plugin not
		// found in the catalog" error this model exists to prevent.
		registeredPlugins map[string]*vault.Plugin
	}

	// scope is one namespace being registered: its label, its `namespace`
	// argument (nil in root), and the options every resource inside it
	// takes.
	scope struct {
		namespace *model.Namespace
		label     string
		arg       pulumi.StringPtrInput
		// created is the namespace resource, nil (an untyped nil, so it
		// drops out of a dependency list) in root.
		created pulumi.Resource
		// base is the provider and the caller's options; inside adds the
		// dependency on the namespace itself.
		base   []pulumi.ResourceOption
		inside []pulumi.ResourceOption
	}
)

func newApplier(c *pulumi.Context, desired *model.Desired, opts Options) (*applier, error) {
	if err := checkInputs(desired, &opts); err != nil {
		return nil, err
	}

	return &applier{
		c:       c,
		desired: desired,
		opts:    opts,
		result: &Result{
			Certificates:        map[string]pulumi.StringOutput{},
			CertificateRequests: map[string]pulumi.StringOutput{},
			SSHCAPublicKeys:     map[MountRef]pulumi.StringOutput{},
			SSHHostCAPublicKeys: map[MountRef]pulumi.StringOutput{},
		},
		mounts:            map[MountRef]*pkiMount{},
		issuers:           map[model.IssuerRef]*pkiIssuer{},
		registeredPlugins: map[string]*vault.Plugin{},
	}, nil
}

// name applies the caller's Rename to a logical name.
func (a *applier) name(logical string) string {
	if a.opts.Rename == nil {
		return logical
	}

	return a.opts.Rename(logical)
}

// options is a fresh copy of the given options plus the extras, so no two
// resources ever share a backing array.
func options(base []pulumi.ResourceOption, extra ...pulumi.ResourceOption) []pulumi.ResourceOption {
	out := make([]pulumi.ResourceOption, 0, len(base)+len(extra))
	out = append(out, base...)

	return append(out, extra...)
}

// dependsOn is a DependsOn option, or nothing for no dependency.
func dependsOn(resources ...pulumi.Resource) []pulumi.ResourceOption {
	var kept []pulumi.Resource

	for _, resource := range resources {
		if resource != nil {
			kept = append(kept, resource)
		}
	}

	if len(kept) == 0 {
		return nil
	}

	return []pulumi.ResourceOption{pulumi.DependsOn(kept)}
}

// namespace registers one namespace and everything in it.
func (a *applier) namespace(namespace *model.Namespace) error {
	s := &scope{namespace: namespace, label: namespace.Label()}
	s.base = options(a.opts.ResourceOptions, pulumi.Provider(a.provider))
	s.inside = s.base

	if namespace.Name != "" {
		created, err := vault.NewNamespace(a.c, a.name("ns-"+namespace.Name), &vault.NamespaceArgs{
			Path: pulumi.String(namespace.Name),
		}, s.base...)
		if err != nil {
			return fmt.Errorf("namespace %s: %w", namespace.Name, err)
		}

		s.created = created
		s.arg = pulumi.String(namespace.Name)
		s.inside = options(s.base, pulumi.DependsOn([]pulumi.Resource{created}))
		a.result.Namespaces = append(a.result.Namespaces, namespace.Name)
	}

	for i := range namespace.PKI {
		if err := a.pkiMount(s, &namespace.PKI[i]); err != nil {
			return err
		}
	}

	// Projects nest below this namespace's OWN mounts, never before them: a
	// project's issuing CA is signed by an issuer just registered above
	// (model.Namespace.validateProjects already refused any other signer).
	for i := range namespace.Projects {
		if err := a.projectNamespace(s, &namespace.Projects[i]); err != nil {
			return err
		}
	}

	for i := range namespace.KV {
		if err := a.kvMount(s, &namespace.KV[i]); err != nil {
			return err
		}
	}

	policies := map[string]*vault.Policy{}

	for i := range namespace.Policies {
		policy := &namespace.Policies[i]

		created, err := vault.NewPolicy(a.c, a.name(s.label+"-policy-"+resourceName(policy.Name)), &vault.PolicyArgs{
			Namespace: s.arg,
			Name:      pulumi.String(policy.Name),
			Policy:    pulumi.String(policy.HCL()),
		}, s.inside...)
		if err != nil {
			return fmt.Errorf("%s policy %s: %w", s.label, policy.Name, err)
		}

		policies[policy.Name] = created
	}

	accessors := map[string]pulumi.StringOutput{}

	for i := range namespace.Auth {
		accessor, err := a.door(s, &namespace.Auth[i], policies)
		if err != nil {
			return err
		}

		accessors[namespace.Auth[i].Path] = accessor
	}

	// AWS auth mounts grant policies directly (awsAuthMount's doc
	// comment): no accessor, no group alias, so they register after the
	// JWT doors but need no accessors map entry.
	for i := range namespace.AWSAuth {
		if err := a.awsAuthMount(s, &namespace.AWSAuth[i], policies); err != nil {
			return err
		}
	}

	for i := range namespace.Groups {
		if err := a.group(s, &namespace.Groups[i], accessors, policies); err != nil {
			return err
		}
	}

	for i := range namespace.SSH {
		if err := a.sshMount(s, &namespace.SSH[i]); err != nil {
			return err
		}
	}

	for i := range namespace.SSHHost {
		if err := a.sshHostMount(s, &namespace.SSHHost[i]); err != nil {
			return err
		}
	}

	for i := range namespace.PKI {
		if err := a.credentialRoles(s, &namespace.PKI[i], accessors); err != nil {
			return err
		}
	}

	return nil
}

// kvMount registers a KV v2 mount and its restore canary.
func (a *applier) kvMount(s *scope, desired *model.KVMount) error {
	args := &vault.MountArgs{
		Namespace: s.arg,
		Path:      pulumi.String(desired.Path),
		Type:      pulumi.String("kv"),
		Options:   pulumi.StringMap{"version": pulumi.String("2")},
	}

	if desired.Description != "" {
		args.Description = pulumi.String(desired.Description)
	}

	mount, err := vault.NewMount(a.c, a.name(mountName(s, desired.Path)), args, s.inside...)
	if err != nil {
		return fmt.Errorf("%s kv %s: %w", s.label, desired.Path, err)
	}

	if desired.Canary == "" {
		return nil
	}

	// Nothing about the canary is secret; it exists so a restored
	// snapshot can prove it decrypts data in every namespace.
	data, err := json.Marshal(map[string]string{"namespace": s.namespace.Name})
	if err != nil {
		return fmt.Errorf("%s canary: %w", s.label, err)
	}

	if _, err := kv.NewSecretV2(a.c, a.name(s.label+"-"+desired.Canary), &kv.SecretV2Args{
		Namespace: s.arg,
		Mount:     mount.Path,
		Name:      pulumi.String(desired.Canary),
		DataJson:  pulumi.String(string(data)),
	}, options(s.base, pulumi.DependsOn([]pulumi.Resource{mount}))...); err != nil {
		return fmt.Errorf("%s canary: %w", s.label, err)
	}

	return nil
}

// door registers one auth mount and its roles, and returns the mount's
// accessor for the group aliases and the credential roles.
func (a *applier) door(s *scope, mount *model.JWTMount, policies map[string]*vault.Policy) (pulumi.StringOutput, error) {
	// authType is model.MethodJWT or model.MethodOIDC as a plain string,
	// kept alongside args.Type (a pulumi.StringInput) so pluginDependency
	// below can look it up -- neither is ever a plugin's name today (both
	// are OpenBAO built-ins), but the lookup is generic over any type a
	// future Desired.Plugins entry might declare.
	authType := model.MethodJWT

	args := &jwt.AuthBackendArgs{
		Namespace:        s.arg,
		Path:             pulumi.String(mount.Path),
		Type:             pulumi.String(authType),
		OidcDiscoveryUrl: pulumi.String(mount.DiscoveryURL),
		BoundIssuer:      pulumi.String(mount.DiscoveryURL),
		// The plugin's own default is RS256 alone for an oidc role ("all"
		// for a jwt role); state the algorithms explicitly so an ES256 or
		// ES384 issuer is not refused on a mount this library applies.
		JwtSupportedAlgs: pulumi.ToStringArray(mount.Algorithms()),
	}

	if mount.Description != "" {
		args.Description = pulumi.String(mount.Description)
	}

	if mount.Type == model.MethodOIDC {
		authType = model.MethodOIDC
		args.Type = pulumi.String(authType)
		args.OidcClientId = pulumi.String(mount.ClientID)
		args.OidcClientSecret = a.opts.OIDCClientSecrets[mount.ClientID]
		args.DefaultRole = pulumi.String(mount.DefaultRole)
		args.NamespaceInState = pulumi.Bool(true)
		args.Tune = &jwt.AuthBackendTuneArgs{ListingVisibility: pulumi.String("unauth")}
	}

	backend, err := jwt.NewAuthBackend(a.c, a.name(s.label+"-auth-"+mount.Path), args,
		a.pluginDependency(s.inside, "auth", authType)...)
	if err != nil {
		return pulumi.StringOutput{}, fmt.Errorf("%s auth %s: %w", s.label, mount.Path, err)
	}

	for i := range mount.Roles {
		if err := a.role(s, mount.Path, backend, &mount.Roles[i], policies); err != nil {
			return pulumi.StringOutput{}, err
		}
	}

	return backend.Accessor, nil
}

func (a *applier) role(s *scope, mount string, backend *jwt.AuthBackend, role *model.Role, policies map[string]*vault.Policy) error {
	ttl, err := model.DurationSeconds(role.TTL)
	if err != nil {
		return fmt.Errorf("%s role %s/%s: %w", s.label, mount, role.Name, err)
	}

	roleType := model.MethodJWT
	if role.Type != "" {
		roleType = role.Type
	}

	args := &jwt.AuthBackendRoleArgs{
		Namespace:      s.arg,
		Backend:        backend.Path,
		RoleName:       pulumi.String(role.Name),
		RoleType:       pulumi.String(roleType),
		BoundAudiences: pulumi.ToStringArray(role.BoundAudiences),
		UserClaim:      pulumi.String(role.UserClaim),
		TokenPolicies:  pulumi.ToStringArray(role.Policies),
		TokenTtl:       pulumi.Int(ttl),
		TokenMaxTtl:    pulumi.Int(ttl),
	}

	if role.BoundSubject != "" {
		args.BoundSubject = pulumi.String(role.BoundSubject)
	}

	if role.GroupsClaim != "" {
		args.GroupsClaim = pulumi.String(role.GroupsClaim)
	}

	if len(role.ClaimMappings) > 0 {
		args.ClaimMappings = pulumi.ToStringMap(role.ClaimMappings)
	}

	if len(role.AllowedRedirectURIs) > 0 {
		args.AllowedRedirectUris = pulumi.ToStringArray(role.AllowedRedirectURIs)
	}

	if len(role.OIDCScopes) > 0 {
		args.OidcScopes = pulumi.ToStringArray(role.OIDCScopes)
	}

	// A policy this namespace does not declare (the bootstrap's, say) is
	// referenced by name only, with nothing to wait for.
	var waits []pulumi.Resource

	for _, name := range role.Policies {
		if policy := policies[name]; policy != nil {
			waits = append(waits, policy)
		}
	}

	if _, err := jwt.NewAuthBackendRole(a.c, a.name(s.label+"-role-"+mount+"-"+role.Name), args,
		options(s.inside, pulumi.DependsOn(waits))...); err != nil {
		return fmt.Errorf("%s role %s/%s: %w", s.label, mount, role.Name, err)
	}

	return nil
}

// group registers one group's identity group per door, each aliased on that
// door's mount by the group's name and carrying the same policies. The
// primary door's identity group and alias keep the bare names.
func (a *applier) group(
	s *scope, group *model.Group, accessors map[string]pulumi.StringOutput, policies map[string]*vault.Policy,
) error {
	var waits []pulumi.Resource

	for _, name := range group.Policies {
		if policy := policies[name]; policy != nil {
			waits = append(waits, policy)
		}
	}

	identitySettings := a.desired.Identity

	for _, door := range group.Doors {
		accessor, ok := accessors[door]
		if !ok {
			return fmt.Errorf("%s group %s: door %s is no auth mount in this namespace", s.label, group.Name, door)
		}

		suffix := ""
		if door != identitySettings.PrimaryDoor {
			suffix = "-" + door
		}

		groupArgs := &identity.GroupArgs{
			Namespace: s.arg,
			Name:      pulumi.String(identitySettings.GroupName(group.Name, door)),
			Type:      pulumi.String("external"),
			Policies:  pulumi.ToStringArray(group.Policies),
		}

		if metadata := identitySettings.GroupMetadata(door); len(metadata) > 0 {
			groupArgs.Metadata = pulumi.ToStringMap(metadata)
		}

		created, err := identity.NewGroup(a.c, a.name(s.label+"-group-"+resourceName(group.Name)+suffix), groupArgs,
			options(s.inside, pulumi.DependsOn(waits))...)
		if err != nil {
			return fmt.Errorf("%s group %s: %w", s.label, identitySettings.GroupName(group.Name, door), err)
		}

		if _, err := identity.NewGroupAlias(a.c, a.name(s.label+"-alias-"+resourceName(group.Name)+suffix), &identity.GroupAliasArgs{
			Namespace:     s.arg,
			Name:          pulumi.String(group.Name),
			MountAccessor: accessor,
			CanonicalId:   created.ID().ToStringOutput(),
		}, s.inside...); err != nil {
			return fmt.Errorf("%s group alias %s on %s: %w", s.label, group.Name, door, err)
		}
	}

	return nil
}

// mountName is a secrets engine's logical name: its path in root, and
// `<namespace>-<path>` in a namespace -- `<environment>-<project>-<path>`
// in a project, since s.namespace.Name there is the real, slash-joined
// OpenBAO namespace path (`<environment>/<project>`), and a logical name
// never carries the `/` a URN segment would parse.
func mountName(s *scope, path string) string {
	return mountLogicalName(s.namespace.Name, path)
}

// mountLogicalName is [mountName] for a namespace given by its OpenBAO
// path ("" for root), so [BootstrapEnvironmentCA] registers the mount
// under exactly the name [Deploy] will.
func mountLogicalName(namespace, path string) string {
	if namespace == "" {
		return path
	}

	return strings.ReplaceAll(namespace, "/", "-") + "-" + path
}

// resourceName makes a group or policy name safe inside a Pulumi resource
// name, where `:` separates URN parts.
func resourceName(name string) string {
	return strings.ReplaceAll(name, ":", "-")
}
