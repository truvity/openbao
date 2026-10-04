package awsserver

import (
	"errors"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/kms"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type (
	// UnsealKeyArgs configures NewUnsealKey.
	UnsealKeyArgs struct {
		// Name is the logical-name stem: the key is "<Name>", its alias
		// "<Name>-alias", the replica "<Name>-replica" and the replica's
		// alias "<Name>-replica-alias".
		Name string
		// AliasName is the alias both regions carry ("alias/...").
		AliasName string
		// Description and ReplicaDescription describe the two keys.
		Description        string
		ReplicaDescription string
		// Tags are put on both keys.
		Tags map[string]string
		// Provider is the AWS provider of the key's region, ReplicaProvider
		// of the replica's. Both are required: nothing falls back to a
		// default provider.
		Provider        pulumi.ProviderResource
		ReplicaProvider pulumi.ProviderResource
	}

	// UnsealKey is the multi-region key the awskms seal uses.
	UnsealKey struct {
		Key          *kms.Key
		Alias        *kms.Alias
		ReplicaKey   *kms.ReplicaKey
		ReplicaAlias *kms.Alias
	}
)

// NewUnsealKey registers the auto-unseal key: a multi-region key with
// rotation on, an alias, a replica in the second region, and the replica's
// alias. The two keys carry Protect and RetainOnDelete unless the hook says
// otherwise (the key that seals every secret is never destroyed by Pulumi).
//
// It registers its resources directly, under whatever parent the hook
// gives, not inside a component of its own: a wrapper type would put itself
// into every child's URN and adopting existing state would then replace the
// key.
func NewUnsealKey(ctx *pulumi.Context, args UnsealKeyArgs, options ...Option) (*UnsealKey, error) {
	var errs []error

	for field, v := range map[string]string{"Name": args.Name, "AliasName": args.AliasName} {
		if v == "" {
			errs = append(errs, fmt.Errorf("args: %s is empty", field))
		}
	}

	if args.Provider == nil || args.ReplicaProvider == nil {
		errs = append(errs, errors.New("args: Provider and ReplicaProvider are required"))
	}

	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("awsserver: unseal key: %w", err)
	}

	s := newSettings(options)
	tags := pulumi.ToStringMap(args.Tags)
	out := &UnsealKey{}

	var err error

	out.Key, err = kms.NewKey(ctx, args.Name, &kms.KeyArgs{
		Description:       pulumi.String(args.Description),
		MultiRegion:       pulumi.Bool(true),
		EnableKeyRotation: pulumi.Bool(true),
		Tags:              tags,
	}, s.opts(KindKMSKey, args.Name, append(guarded(), pulumi.Provider(args.Provider))...)...)
	if err != nil {
		return nil, fmt.Errorf("unseal key: %w", err)
	}

	name := args.Name + "-alias"

	out.Alias, err = kms.NewAlias(ctx, name, &kms.AliasArgs{
		Name:        pulumi.String(args.AliasName),
		TargetKeyId: out.Key.KeyId,
	}, s.opts(KindKMSAlias, name, pulumi.Provider(args.Provider))...)
	if err != nil {
		return nil, fmt.Errorf("unseal key alias: %w", err)
	}

	name = args.Name + "-replica"

	out.ReplicaKey, err = kms.NewReplicaKey(ctx, name, &kms.ReplicaKeyArgs{
		PrimaryKeyArn: out.Key.Arn,
		Description:   pulumi.String(args.ReplicaDescription),
		Tags:          tags,
	}, s.opts(KindKMSReplicaKey, name, append(guarded(), pulumi.Provider(args.ReplicaProvider))...)...)
	if err != nil {
		return nil, fmt.Errorf("unseal key replica: %w", err)
	}

	name = args.Name + "-replica-alias"

	out.ReplicaAlias, err = kms.NewAlias(ctx, name, &kms.AliasArgs{
		Name:        pulumi.String(args.AliasName),
		TargetKeyId: out.ReplicaKey.KeyId,
	}, s.opts(KindKMSAlias, name, pulumi.Provider(args.ReplicaProvider))...)
	if err != nil {
		return nil, fmt.Errorf("unseal key replica alias: %w", err)
	}

	return out, nil
}
