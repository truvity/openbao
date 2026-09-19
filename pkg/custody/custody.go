// Package custody provisions the AWS custody of a KMS-rooted private PKI:
// per root generation, a multi-region ECC P-384 SIGN_VERIFY key and its
// replica, protected and retained; two IAM roles (one administers the key
// and can neither sign nor schedule its deletion, one reads and signs
// during a ceremony); and a Sign alarm in each custody region, because
// after the ceremony every signature by a root key is an incident.
//
// Certificate creation is deliberately not here. A root signature is an
// explicit operator ceremony (pkg/ceremony, `openbaoctl pki`) run after
// this has been deployed.
//
// Deploy registers its resources directly on the caller's Pulumi context,
// under whatever parent the caller passes, rather than inside a component
// resource of its own. A wrapper type would put itself into every child's
// URN, so adopting hand-written custody would replace protected, retained
// KMS keys; registering directly keeps the adoption preview empty.
package custody

import (
	"fmt"
	"slices"

	awspulumi "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/kms"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	// DefaultPartition is the AWS partition every ARN is composed in.
	DefaultPartition = "aws"
	// DefaultAliasPrefix names each generation's key alias:
	// <prefix><generation ID>, identical in both regions.
	DefaultAliasPrefix = "alias/private-pki/root/"
	// DefaultSignAlertPrefix names each generation's topic, rule and
	// alarm: <prefix><generation ID>.
	DefaultSignAlertPrefix = "private-pki-root-sign-"
	// DefaultDescriptionPrefix starts each key's description.
	DefaultDescriptionPrefix = "Private PKI root"
	// DefaultRolesProviderName is the Pulumi name of the provider the roles
	// are created with (as "provider/aws/<name>").
	DefaultRolesProviderName = "private-pki-root-primary"
	// DefaultDeletionWindowDays is the longest window KMS allows: a
	// scheduled deletion of a root key should be as recoverable as it gets.
	DefaultDeletionWindowDays = 30

	roleMaxSessionSeconds = 3600
	providerNamePrefix    = "provider/aws/"
)

type (
	// Args is the custody of every root generation in one AWS account.
	Args struct {
		// AccountID is the AWS account the keys and roles live in.
		AccountID string
		// Partition defaults to DefaultPartition.
		Partition string
		// Profile is the AWS shared-config profile each provider uses;
		// empty for the provider's default credential chain.
		Profile string
		// TrustedPrincipalARNPattern is an ArnLike pattern for the human
		// administrators (typically an SSO permission-set role) allowed to
		// assume both roles and to administer the keys directly.
		TrustedPrincipalARNPattern string
		// AdminRoleName and CeremonyRoleName name the two roles.
		AdminRoleName    string
		CeremonyRoleName string
		// PermissionsBoundaryPolicyName is a customer-managed policy in the
		// same account attached to both roles as their boundary; empty for
		// none.
		PermissionsBoundaryPolicyName string
		// Generations are the root generations, oldest first. Rotation is
		// additive: an old generation stays managed and protected through
		// its overlap and retirement.
		Generations []Generation
		// Notify are the e-mail addresses told of every Sign. Each
		// subscription is confirmed by hand once.
		Notify []string

		// AliasPrefix, SignAlertPrefix, DescriptionPrefix and
		// RolesProviderName default to the Default* constants.
		AliasPrefix       string
		SignAlertPrefix   string
		DescriptionPrefix string
		RolesProviderName string
		// DeletionWindowDays defaults to DefaultDeletionWindowDays.
		DeletionWindowDays int
		// Tags returns the tags for one group of resources; nil tags
		// nothing.
		Tags func(TagScope) map[string]string
	}

	// Generation is one root generation's key placement.
	Generation struct {
		// ID names the generation (and its key, alias and alarm).
		ID string
		// Region holds the multi-region primary; ReplicaRegion the
		// disaster-recovery replica. They must differ.
		Region        string
		ReplicaRegion string
	}

	// TagScope says which resources a Tags call is for.
	TagScope struct {
		Kind TagKind
		// Generation is empty for TagRoles.
		Generation string
	}

	// TagKind is a group of resources that share tags.
	TagKind string

	// Custody is what Deploy created, for the caller's exports.
	Custody struct {
		AdminRole    *iam.Role
		CeremonyRole *iam.Role
		// Generations are in the order of Args.Generations.
		Generations []GenerationKeys
	}

	// GenerationKeys is one generation's key pair.
	GenerationKeys struct {
		ID            string
		Alias         string
		Region        string
		ReplicaRegion string
		Key           *kms.Key
		Replica       *kms.ReplicaKey
	}
)

const (
	// TagRoles tags the two IAM roles.
	TagRoles TagKind = "roles"
	// TagKey tags one generation's primary and replica key.
	TagKey TagKind = "key"
	// TagSignAlert tags one generation's topics, rules and alarms.
	TagSignAlert TagKind = "sign-alert"
)

// Deploy creates the custody for every generation. opts are appended to
// every resource it registers (for example pulumi.Parent).
func Deploy(ctx *pulumi.Context, args Args, opts ...pulumi.ResourceOption) (*Custody, error) {
	args = args.withDefaults()
	if err := args.validate(); err != nil {
		return nil, err
	}

	rolesProvider, err := args.provider(ctx, args.RolesProviderName, args.Generations[0].Region, opts)
	if err != nil {
		return nil, err
	}

	adminRole, ceremonyRole, err := deployRoles(ctx, args, rolesProvider, opts)
	if err != nil {
		return nil, err
	}

	custody := &Custody{AdminRole: adminRole, CeremonyRole: ceremonyRole}
	for _, generation := range args.Generations {
		provider, err := args.provider(ctx, generation.ID+"-primary", generation.Region, opts)
		if err != nil {
			return nil, err
		}
		replicaProvider, err := args.provider(ctx, generation.ID+"-replica", generation.ReplicaRegion, opts)
		if err != nil {
			return nil, err
		}

		keys, err := deployGeneration(ctx, args, generation, adminRole.Arn, ceremonyRole.Arn, provider, replicaProvider, opts)
		if err != nil {
			return nil, err
		}
		custody.Generations = append(custody.Generations, *keys)
	}
	return custody, nil
}

func (a Args) withDefaults() Args {
	if a.Partition == "" {
		a.Partition = DefaultPartition
	}
	if a.AliasPrefix == "" {
		a.AliasPrefix = DefaultAliasPrefix
	}
	if a.SignAlertPrefix == "" {
		a.SignAlertPrefix = DefaultSignAlertPrefix
	}
	if a.DescriptionPrefix == "" {
		a.DescriptionPrefix = DefaultDescriptionPrefix
	}
	if a.RolesProviderName == "" {
		a.RolesProviderName = DefaultRolesProviderName
	}
	if a.DeletionWindowDays == 0 {
		a.DeletionWindowDays = DefaultDeletionWindowDays
	}
	return a
}

func (a Args) validate() error {
	if a.AccountID == "" || a.TrustedPrincipalARNPattern == "" {
		return fmt.Errorf("custody requires an account ID and a trusted principal ARN pattern")
	}
	if a.AdminRoleName == "" || a.CeremonyRoleName == "" || a.AdminRoleName == a.CeremonyRoleName {
		return fmt.Errorf("custody requires two distinct role names")
	}
	if len(a.Generations) == 0 {
		return fmt.Errorf("custody requires at least one root generation")
	}
	if a.DeletionWindowDays < 7 || a.DeletionWindowDays > 30 {
		return fmt.Errorf("KMS deletion window must be 7 to 30 days, got %d", a.DeletionWindowDays)
	}
	seen := map[string]bool{}
	for _, generation := range a.Generations {
		if generation.ID == "" || seen[generation.ID] {
			return fmt.Errorf("root generation IDs must be present and unique, got %q", generation.ID)
		}
		seen[generation.ID] = true
		if generation.Region == "" || generation.ReplicaRegion == "" || generation.Region == generation.ReplicaRegion {
			return fmt.Errorf("root generation %s needs two different regions, got %q and %q",
				generation.ID, generation.Region, generation.ReplicaRegion)
		}
	}
	if slices.Contains(a.Notify, "") {
		return fmt.Errorf("an empty sign-alert address")
	}
	return nil
}

func (a Args) provider(ctx *pulumi.Context, name, region string, opts []pulumi.ResourceOption) (*awspulumi.Provider, error) {
	providerArgs := &awspulumi.ProviderArgs{
		Region:            pulumi.String(region),
		AllowedAccountIds: pulumi.StringArray{pulumi.String(a.AccountID)},
	}
	if a.Profile != "" {
		providerArgs.Profile = pulumi.String(a.Profile)
	}
	provider, err := awspulumi.NewProvider(ctx, providerNamePrefix+name, providerArgs, opts...)
	if err != nil {
		return nil, fmt.Errorf("create AWS provider %s: %w", name, err)
	}
	return provider, nil
}

func (a Args) tags(scope TagScope) pulumi.StringMapInput {
	if a.Tags == nil {
		return nil
	}
	return pulumi.ToStringMap(a.Tags(scope))
}

func deployRoles(ctx *pulumi.Context, args Args, provider *awspulumi.Provider, extra []pulumi.ResourceOption) (*iam.Role, *iam.Role, error) {
	trust, err := roleTrustPolicy(args.Partition, args.AccountID, args.TrustedPrincipalARNPattern)
	if err != nil {
		return nil, nil, err
	}
	var boundary pulumi.StringPtrInput
	if args.PermissionsBoundaryPolicyName != "" {
		boundary = pulumi.String(arn(args.Partition, "iam", "", args.AccountID, "policy/"+args.PermissionsBoundaryPolicyName))
	}
	tags := args.tags(TagScope{Kind: TagRoles})
	opts := append([]pulumi.ResourceOption{pulumi.Provider(provider), pulumi.Protect(true)}, extra...)

	admin, err := iam.NewRole(ctx, args.AdminRoleName, &iam.RoleArgs{
		Name:                pulumi.String(args.AdminRoleName),
		Description:         pulumi.String("Administer protected private PKI root KMS keys; cannot sign or schedule deletion"),
		AssumeRolePolicy:    pulumi.String(trust),
		PermissionsBoundary: boundary,
		MaxSessionDuration:  pulumi.Int(roleMaxSessionSeconds),
		Tags:                tags,
	}, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("create root admin role: %w", err)
	}

	ceremony, err := iam.NewRole(ctx, args.CeremonyRoleName, &iam.RoleArgs{
		Name:                pulumi.String(args.CeremonyRoleName),
		Description:         pulumi.String("Read and sign with private PKI root KMS keys during an explicit ceremony"),
		AssumeRolePolicy:    pulumi.String(trust),
		PermissionsBoundary: boundary,
		MaxSessionDuration:  pulumi.Int(roleMaxSessionSeconds),
		Tags:                tags,
	}, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("create root ceremony role: %w", err)
	}
	return admin, ceremony, nil
}

func deployGeneration(
	ctx *pulumi.Context,
	args Args,
	generation Generation,
	adminRoleARN, ceremonyRoleARN pulumi.StringOutput,
	provider, replicaProvider *awspulumi.Provider,
	extra []pulumi.ResourceOption,
) (*GenerationKeys, error) {
	policy := pulumi.All(adminRoleARN, ceremonyRoleARN).ApplyT(func(values []any) (string, error) {
		return keyPolicy(args.Partition, args.AccountID, args.TrustedPrincipalARNPattern, values[0].(string), values[1].(string))
	}).(pulumi.StringOutput)
	tags := args.tags(TagScope{Kind: TagKey, Generation: generation.ID})
	with := func(base ...pulumi.ResourceOption) []pulumi.ResourceOption { return append(base, extra...) }

	key, err := kms.NewKey(ctx, generation.ID, &kms.KeyArgs{
		Description:           pulumi.String(args.DescriptionPrefix + " " + generation.ID + " (multi-region primary)"),
		CustomerMasterKeySpec: pulumi.String("ECC_NIST_P384"),
		KeyUsage:              pulumi.String("SIGN_VERIFY"),
		MultiRegion:           pulumi.Bool(true),
		DeletionWindowInDays:  pulumi.Int(args.DeletionWindowDays),
		Policy:                policy,
		Tags:                  tags,
	}, with(pulumi.Provider(provider), pulumi.Protect(true), pulumi.RetainOnDelete(true))...)
	if err != nil {
		return nil, fmt.Errorf("create root key %s: %w", generation.ID, err)
	}

	alias := args.AliasPrefix + generation.ID
	if _, err := kms.NewAlias(ctx, generation.ID+"-alias", &kms.AliasArgs{
		Name:        pulumi.String(alias),
		TargetKeyId: key.KeyId,
	}, with(pulumi.Provider(provider), pulumi.Protect(true))...); err != nil {
		return nil, fmt.Errorf("create root key alias %s: %w", generation.ID, err)
	}

	replica, err := kms.NewReplicaKey(ctx, generation.ID+"-replica", &kms.ReplicaKeyArgs{
		PrimaryKeyArn:        key.Arn,
		Description:          pulumi.String(args.DescriptionPrefix + " " + generation.ID + " (DR replica)"),
		DeletionWindowInDays: pulumi.Int(args.DeletionWindowDays),
		Policy:               policy,
		Tags:                 tags,
	}, with(pulumi.Provider(replicaProvider), pulumi.Protect(true), pulumi.RetainOnDelete(true))...)
	if err != nil {
		return nil, fmt.Errorf("create root replica %s: %w", generation.ID, err)
	}

	if _, err := kms.NewAlias(ctx, generation.ID+"-replica-alias", &kms.AliasArgs{
		Name:        pulumi.String(alias),
		TargetKeyId: replica.KeyId,
	}, with(pulumi.Provider(replicaProvider), pulumi.Protect(true))...); err != nil {
		return nil, fmt.Errorf("create root replica alias %s: %w", generation.ID, err)
	}

	// Both regions, separately: the primary and the replica are one
	// multi-region key, and a Sign with either is the same incident, but
	// CloudTrail, EventBridge and CloudWatch are regional and an alarm in
	// one region sees nothing of the other.
	for _, scope := range []signAlertScope{
		{generation: generation.ID, region: generation.Region, alias: alias, keyARN: key.Arn, keyID: key.KeyId, provider: provider},
		{generation: generation.ID, region: generation.ReplicaRegion, alias: alias, keyARN: replica.Arn, keyID: replica.KeyId, provider: replicaProvider},
	} {
		if err := deploySignAlerts(ctx, args, scope, extra); err != nil {
			return nil, err
		}
	}

	return &GenerationKeys{
		ID:            generation.ID,
		Alias:         alias,
		Region:        generation.Region,
		ReplicaRegion: generation.ReplicaRegion,
		Key:           key,
		Replica:       replica,
	}, nil
}
