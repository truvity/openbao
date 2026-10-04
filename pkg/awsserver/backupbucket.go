package awsserver

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/kms"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// DefaultPartition is the AWS partition used in ARNs when
// BackupBucketArgs.Partition is empty.
const DefaultPartition = "aws"

type (
	// BackupReplica configures the same-account replica in another region.
	BackupReplica struct {
		// Provider is the AWS provider of the replica's region, in the
		// backup account. Required.
		Provider pulumi.ProviderResource
		// BucketName is the replica bucket's name.
		BucketName string
		// KeyDescription is the description of the replica's KMS key.
		KeyDescription string
		// RoleName is the name of the IAM role S3 assumes to replicate.
		RoleName string
		// RolePermissionsBoundary is that role's permissions boundary ARN;
		// nil sets none.
		RolePermissionsBoundary pulumi.StringInput
	}

	// BackupBucketArgs configures NewBackupBucket.
	BackupBucketArgs struct {
		// Provider is the AWS provider of the backup account and the
		// bucket's region. Required.
		Provider pulumi.ProviderResource
		// BucketName is the bucket's name and the stem of every child's
		// logical name.
		BucketName string
		// SourceAccountID is the account whose roles write the backups;
		// BackupAccountID the account the bucket lives in. Only principals
		// in the latter may delete an object version.
		SourceAccountID string
		BackupAccountID string
		// Partition defaults to DefaultPartition.
		Partition string
		// WriterRoleName is the role name, inside the source account, that
		// the bucket and key policies admit; it may be a glob.
		WriterRoleName string
		// WriterObjectActions replaces the object actions granted to the
		// writer; nil grants put, get, delete and the multipart pair.
		WriterObjectActions []string
		// ReaderRoleName is one more role in the source account, admitted
		// read-only; an exact name.
		ReaderRoleName string
		// ListerRoleNames may list the bucket and its replica and nothing
		// else; exact names.
		ListerRoleNames []string
		// KeyDescription describes the bucket's KMS key.
		KeyDescription string
		// Tags are put on the bucket.
		Tags map[string]string
		// LifecycleRules is the bucket's lifecycle; at least one rule.
		LifecycleRules s3.BucketLifecycleConfigurationV2RuleArray
		// ObjectLockDays, when above zero, creates the bucket (and the
		// replica) with Object Lock and a COMPLIANCE default retention of
		// that many days: nobody, the backup account included, can delete a
		// version inside the window.
		ObjectLockDays int
		// Replica, when set, replicates the bucket to another region.
		Replica *BackupReplica
	}

	// BackupBucket is the component: a versioned, encrypted, private
	// bucket for backups, with the key, the policies and, optionally, the
	// lock and the replica.
	BackupBucket struct {
		pulumi.ResourceState

		// BucketName and BucketARN are the bucket's, KMSKeyARN its key's.
		BucketName pulumi.StringOutput
		BucketARN  pulumi.StringOutput
		KMSKeyARN  pulumi.StringOutput
	}
)

func (a *BackupBucketArgs) partition() string {
	if a.Partition == "" {
		return DefaultPartition
	}

	return a.Partition
}

func (a *BackupBucketArgs) validate() error {
	var errs []error

	if a.Provider == nil {
		errs = append(errs, errors.New("args.Provider is nil"))
	}

	for field, v := range map[string]string{
		"BucketName": a.BucketName, "SourceAccountID": a.SourceAccountID, "BackupAccountID": a.BackupAccountID,
		"WriterRoleName": a.WriterRoleName, "KeyDescription": a.KeyDescription,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is empty", field))
		}
	}

	if len(a.LifecycleRules) == 0 {
		errs = append(errs, errors.New("LifecycleRules is empty"))
	}

	if a.ObjectLockDays < 0 {
		errs = append(errs, fmt.Errorf("ObjectLockDays is %d, want 0 or more", a.ObjectLockDays))
	}

	if strings.ContainsAny(a.ReaderRoleName, "*?") {
		errs = append(errs, fmt.Errorf("ReaderRoleName %q is a glob; it must be an exact name", a.ReaderRoleName))
	}

	for i, r := range a.ListerRoleNames {
		switch {
		case r == "":
			errs = append(errs, fmt.Errorf("ListerRoleNames[%d] is empty", i))
		case strings.ContainsAny(r, "*?"):
			errs = append(errs, fmt.Errorf("ListerRoleNames[%d] %q is a glob; it must be an exact name", i, r))
		}
	}

	if a.WriterObjectActions != nil && len(a.WriterObjectActions) == 0 {
		errs = append(errs, errors.New("WriterObjectActions is empty; leave it nil for the default set"))
	}

	if r := a.Replica; r != nil {
		if r.Provider == nil {
			errs = append(errs, errors.New("Replica.Provider is nil"))
		}

		for field, v := range map[string]string{
			"Replica.BucketName": r.BucketName, "Replica.KeyDescription": r.KeyDescription, "Replica.RoleName": r.RoleName,
		} {
			if v == "" {
				errs = append(errs, fmt.Errorf("%s is empty", field))
			}
		}

		if r.BucketName != "" && r.BucketName == a.BucketName {
			errs = append(errs, errors.New("Replica.BucketName equals BucketName"))
		}
	}

	return errors.Join(errs...)
}

// NewBackupBucket registers the component and its children. It registers
// nothing and returns an error when args are invalid.
//
// The KMS keys and the buckets carry Protect and RetainOnDelete unless the
// hook says otherwise: a preview that would delete one fails, and a
// destroy drops it from state instead of deleting it in the cloud.
func NewBackupBucket(ctx *pulumi.Context, args BackupBucketArgs, options ...Option) (*BackupBucket, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("awsserver: backup bucket %q: %w", args.BucketName, err)
	}

	s := newSettings(options)
	comp := &BackupBucket{}

	if err := ctx.RegisterComponentResource(KindBackupBucket, args.BucketName, comp,
		s.opts(KindBackupBucket, args.BucketName)...); err != nil {
		return nil, err
	}

	b := &bucketBuilder{ctx: ctx, s: s, comp: comp, args: &args}

	if err := b.primary(); err != nil {
		return nil, err
	}

	if args.Replica != nil {
		if err := b.replica(); err != nil {
			return nil, err
		}
	}

	comp.BucketName, comp.BucketARN, comp.KMSKeyARN = b.bucket.Bucket, b.bucket.Arn, b.key.Arn

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{
		"bucketName": comp.BucketName,
		"bucketArn":  comp.BucketARN,
		"kmsKeyArn":  comp.KMSKeyARN,
	}); err != nil {
		return nil, err
	}

	return comp, nil
}

type bucketBuilder struct {
	ctx  *pulumi.Context
	s    *settings
	comp *BackupBucket
	args *BackupBucketArgs

	bucket *s3.Bucket
	key    *kms.Key
}

// opts is what a primary-region child registers with.
func (b *bucketBuilder) opts(kind, name string, extra ...pulumi.ResourceOption) []pulumi.ResourceOption {
	return b.s.opts(kind, name, append([]pulumi.ResourceOption{pulumi.Parent(b.comp), pulumi.Provider(b.args.Provider)}, extra...)...)
}

// replicaOpts is what a replica-region child registers with.
func (b *bucketBuilder) replicaOpts(kind, name string, extra ...pulumi.ResourceOption) []pulumi.ResourceOption {
	return b.s.opts(kind, name, append([]pulumi.ResourceOption{pulumi.Parent(b.comp), pulumi.Provider(b.args.Replica.Provider)}, extra...)...)
}

func (b *bucketBuilder) primary() error {
	a := b.args
	name := a.BucketName
	part := a.partition()

	n := name + "-kms"

	key, err := kms.NewKey(b.ctx, n, &kms.KeyArgs{
		Description:       pulumi.String(a.KeyDescription),
		EnableKeyRotation: pulumi.Bool(true),
		Policy:            pulumi.String(buildKeyPolicy(part, a.SourceAccountID, a.BackupAccountID, a.WriterRoleName, a.ReaderRoleName)),
	}, b.opts(KindKMSKey, n, guarded()...)...)
	if err != nil {
		return fmt.Errorf("awsserver: create KMS key: %w", err)
	}

	b.key = key

	n = name + "-kms-alias"

	if _, err := kms.NewAlias(b.ctx, n, &kms.AliasArgs{
		Name:        pulumi.String("alias/" + name),
		TargetKeyId: key.KeyId,
	}, b.opts(KindKMSAlias, n)...); err != nil {
		return fmt.Errorf("awsserver: create KMS alias: %w", err)
	}

	bucketArgs := &s3.BucketArgs{
		Bucket: pulumi.String(name),
		Tags:   pulumi.ToStringMap(a.Tags),
	}
	if a.ObjectLockDays > 0 {
		bucketArgs.ObjectLockEnabled = pulumi.Bool(true)
	}

	bucket, err := s3.NewBucket(b.ctx, name, bucketArgs, b.opts(KindS3Bucket, name, guarded()...)...)
	if err != nil {
		return fmt.Errorf("awsserver: create backup bucket: %w", err)
	}

	b.bucket = bucket

	n = name + "-versioning"

	if _, err := s3.NewBucketVersioningV2(b.ctx, n, &s3.BucketVersioningV2Args{
		Bucket: bucket.ID(),
		VersioningConfiguration: &s3.BucketVersioningV2VersioningConfigurationArgs{
			Status: pulumi.String("Enabled"),
		},
	}, b.opts(KindS3Versioning, n)...); err != nil {
		return fmt.Errorf("awsserver: enable bucket versioning: %w", err)
	}

	n = name + "-encryption"

	if _, err := s3.NewBucketServerSideEncryptionConfigurationV2(b.ctx, n, &s3.BucketServerSideEncryptionConfigurationV2Args{
		Bucket: bucket.ID(),
		Rules: s3.BucketServerSideEncryptionConfigurationV2RuleArray{
			&s3.BucketServerSideEncryptionConfigurationV2RuleArgs{
				ApplyServerSideEncryptionByDefault: &s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs{
					SseAlgorithm:   pulumi.String("aws:kms"),
					KmsMasterKeyId: key.Arn,
				},
			},
		},
	}, b.opts(KindS3Encryption, n)...); err != nil {
		return fmt.Errorf("awsserver: configure bucket encryption: %w", err)
	}

	n = name + "-lifecycle"

	if _, err := s3.NewBucketLifecycleConfigurationV2(b.ctx, n, &s3.BucketLifecycleConfigurationV2Args{
		Bucket: bucket.ID(),
		Rules:  a.LifecycleRules,
	}, b.opts(KindS3Lifecycle, n)...); err != nil {
		return fmt.Errorf("awsserver: configure bucket lifecycle: %w", err)
	}

	if a.ObjectLockDays > 0 {
		n = name + "-object-lock"

		if _, err := s3.NewBucketObjectLockConfigurationV2(b.ctx, n, &s3.BucketObjectLockConfigurationV2Args{
			Bucket: bucket.ID(),
			Rule: &s3.BucketObjectLockConfigurationV2RuleArgs{
				DefaultRetention: &s3.BucketObjectLockConfigurationV2RuleDefaultRetentionArgs{
					Mode: pulumi.String("COMPLIANCE"),
					Days: pulumi.Int(a.ObjectLockDays),
				},
			},
		}, b.opts(KindS3ObjectLock, n)...); err != nil {
			return fmt.Errorf("awsserver: configure object lock: %w", err)
		}
	}

	n = name + "-public-access"

	if _, err := s3.NewBucketPublicAccessBlock(b.ctx, n, blockPublicAccess(bucket.ID()), b.opts(KindS3PublicAccessBlock, n)...); err != nil {
		return fmt.Errorf("awsserver: configure bucket public access block: %w", err)
	}

	policy := buildBucketPolicy(bucketPolicyParams{
		Partition:       part,
		BucketName:      name,
		SourceAccountID: a.SourceAccountID,
		BackupAccountID: a.BackupAccountID,
		WriterRole:      a.WriterRoleName,
		ReaderRole:      a.ReaderRoleName,
		ListerRoles:     a.ListerRoleNames,
		ObjectActions:   a.WriterObjectActions,
	})

	n = name + "-policy"

	if _, err := s3.NewBucketPolicy(b.ctx, n, &s3.BucketPolicyArgs{
		Bucket: bucket.ID(),
		Policy: pulumi.String(policy),
	}, b.opts(KindS3BucketPolicy, n)...); err != nil {
		return fmt.Errorf("awsserver: attach bucket policy: %w", err)
	}

	return nil
}

func blockPublicAccess(bucket pulumi.StringInput) *s3.BucketPublicAccessBlockArgs {
	return &s3.BucketPublicAccessBlockArgs{
		Bucket:                bucket,
		BlockPublicAcls:       pulumi.Bool(true),
		IgnorePublicAcls:      pulumi.Bool(true),
		BlockPublicPolicy:     pulumi.Bool(true),
		RestrictPublicBuckets: pulumi.Bool(true),
	}
}

// replica builds the same-account copy: its own key, bucket, versioning,
// public access block, a policy when something may list it, the
// replication role and its policy, and the replication configuration on the
// primary.
func (b *bucketBuilder) replica() error {
	a := b.args
	r := a.Replica
	name := a.BucketName
	rname := r.BucketName
	part := a.partition()

	n := rname + "-kms"

	replicaKey, err := kms.NewKey(b.ctx, n, &kms.KeyArgs{
		Description:       pulumi.String(r.KeyDescription),
		EnableKeyRotation: pulumi.Bool(true),
	}, b.replicaOpts(KindKMSKey, n, guarded()...)...)
	if err != nil {
		return fmt.Errorf("awsserver: create replica KMS key: %w", err)
	}

	replicaArgs := &s3.BucketV2Args{Bucket: pulumi.String(rname)}
	if a.ObjectLockDays > 0 {
		// Replicating locked objects requires Object Lock on the destination.
		replicaArgs.ObjectLockEnabled = pulumi.Bool(true)
	}

	replica, err := s3.NewBucketV2(b.ctx, rname, replicaArgs, b.replicaOpts(KindS3BucketV2, rname, guarded()...)...)
	if err != nil {
		return fmt.Errorf("awsserver: create replica bucket: %w", err)
	}

	n = rname + "-versioning"

	if _, err := s3.NewBucketVersioningV2(b.ctx, n, &s3.BucketVersioningV2Args{
		Bucket: replica.ID(),
		VersioningConfiguration: &s3.BucketVersioningV2VersioningConfigurationArgs{
			Status: pulumi.String("Enabled"),
		},
	}, b.replicaOpts(KindS3Versioning, n)...); err != nil {
		return fmt.Errorf("awsserver: replica versioning: %w", err)
	}

	n = rname + "-public-access"

	if _, err := s3.NewBucketPublicAccessBlock(b.ctx, n, blockPublicAccess(replica.ID()), b.replicaOpts(KindS3PublicAccessBlock, n)...); err != nil {
		return fmt.Errorf("awsserver: replica public access block: %w", err)
	}

	// A resource policy on the replica only when something in the source
	// account is meant to list it. It carries the delete-version deny, so
	// the replica's immutability reads the same as the primary's.
	if len(a.ListerRoleNames) > 0 {
		doc, err := buildReplicaPolicy(part, rname, a.SourceAccountID, a.BackupAccountID, a.ListerRoleNames)
		if err != nil {
			return fmt.Errorf("awsserver: marshal replica bucket policy: %w", err)
		}

		n = rname + "-policy"

		if _, err := s3.NewBucketPolicy(b.ctx, n, &s3.BucketPolicyArgs{
			Bucket: replica.ID(),
			Policy: pulumi.String(doc),
		}, b.replicaOpts(KindS3BucketPolicy, n)...); err != nil {
			return fmt.Errorf("awsserver: attach replica bucket policy: %w", err)
		}
	}

	roleArgs := &iam.RoleArgs{
		Name:             pulumi.String(r.RoleName),
		AssumeRolePolicy: pulumi.String(replicationTrust),
	}
	if r.RolePermissionsBoundary != nil {
		roleArgs.PermissionsBoundary = r.RolePermissionsBoundary
	}

	n = name + "-replication-role"

	role, err := iam.NewRole(b.ctx, n, roleArgs, b.opts(KindIAMRole, n)...)
	if err != nil {
		return fmt.Errorf("awsserver: replication role: %w", err)
	}

	policy := pulumi.All(b.bucket.Arn, replica.Arn, b.key.Arn, replicaKey.Arn).ApplyT(func(vs []any) (string, error) {
		return buildReplicationPolicy(vs[0].(string), vs[1].(string), vs[2].(string), vs[3].(string), a.ObjectLockDays > 0)
	}).(pulumi.StringOutput)

	n = name + "-replication-policy"

	if _, err := iam.NewRolePolicy(b.ctx, n, &iam.RolePolicyArgs{
		Role:   role.Name,
		Policy: policy,
	}, b.opts(KindIAMRolePolicy, n)...); err != nil {
		return fmt.Errorf("awsserver: replication policy: %w", err)
	}

	n = name + "-replication"

	if _, err := s3.NewBucketReplicationConfig(b.ctx, n, &s3.BucketReplicationConfigArgs{
		Bucket: b.bucket.ID(),
		Role:   role.Arn,
		Rules: s3.BucketReplicationConfigRuleArray{
			&s3.BucketReplicationConfigRuleArgs{
				Id:     pulumi.String("crr"),
				Status: pulumi.String("Enabled"),
				Filter: &s3.BucketReplicationConfigRuleFilterArgs{Prefix: pulumi.String("")},
				DeleteMarkerReplication: &s3.BucketReplicationConfigRuleDeleteMarkerReplicationArgs{
					Status: pulumi.String("Enabled"),
				},
				SourceSelectionCriteria: &s3.BucketReplicationConfigRuleSourceSelectionCriteriaArgs{
					SseKmsEncryptedObjects: &s3.BucketReplicationConfigRuleSourceSelectionCriteriaSseKmsEncryptedObjectsArgs{
						Status: pulumi.String("Enabled"),
					},
				},
				Destination: &s3.BucketReplicationConfigRuleDestinationArgs{
					Bucket:       replica.Arn,
					StorageClass: pulumi.String("STANDARD_IA"),
					EncryptionConfiguration: &s3.BucketReplicationConfigRuleDestinationEncryptionConfigurationArgs{
						ReplicaKmsKeyId: replicaKey.Arn,
					},
				},
			},
		},
	}, b.opts(KindS3ReplicationConfig, n)...); err != nil {
		return fmt.Errorf("awsserver: replication config: %w", err)
	}

	return nil
}
