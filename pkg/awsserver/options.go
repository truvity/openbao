package awsserver

import "github.com/pulumi/pulumi/sdk/v3/go/pulumi"

// ResourceOptionsFunc returns extra Pulumi resource options for one child.
// kind is the child's Pulumi type token (for example "aws:kms/key:Key") and
// logicalName its Pulumi logical name; both are tabulated in docs/awsserver.md
// and pinned by this package's tests, because together with the parent they
// are the child's URN and so the contract for adopting existing state.
type ResourceOptionsFunc func(kind, logicalName string) []pulumi.ResourceOption

// Option configures a constructor of this package.
type Option func(*settings)

type settings struct {
	hook ResourceOptionsFunc
}

// WithResourceOptions registers a hook that is asked for options for EVERY
// resource a constructor registers, component resources included. What it
// returns is appended after the library's own options, so it can add
// pulumi.Aliases (to adopt state created by other code), pulumi.Parent,
// pulumi.IgnoreChanges, and override the defaults (pulumi.Protect(false),
// pulumi.RetainOnDelete(false)): the last option of a kind wins, and
// aliases accumulate.
//
// A second call replaces the first.
func WithResourceOptions(f ResourceOptionsFunc) Option {
	return func(s *settings) { s.hook = f }
}

func newSettings(opts []Option) *settings {
	s := &settings{}
	for _, o := range opts {
		if o != nil {
			o(s)
		}
	}

	return s
}

// opts is what a child registers with: the library's options, then the
// hook's.
func (s *settings) opts(kind, name string, base ...pulumi.ResourceOption) []pulumi.ResourceOption {
	out := append([]pulumi.ResourceOption{}, base...)
	if s.hook != nil {
		out = append(out, s.hook(kind, name)...)
	}

	return out
}

// Pulumi type tokens of the children. They are the "kind" the hook receives.
const (
	KindKMSKey                 = "aws:kms/key:Key"
	KindKMSReplicaKey          = "aws:kms/replicaKey:ReplicaKey"
	KindKMSAlias               = "aws:kms/alias:Alias"
	KindIAMRole                = "aws:iam/role:Role"
	KindIAMRolePolicy          = "aws:iam/rolePolicy:RolePolicy"
	KindPodIdentityAssociation = "aws:eks/podIdentityAssociation:PodIdentityAssociation"
	KindSNSTopic               = "aws:sns/topic:Topic"
	KindSNSTopicSubscription   = "aws:sns/topicSubscription:TopicSubscription"
	KindRoute53Record          = "aws:route53/record:Record"
	KindS3Bucket               = "aws:s3/bucket:Bucket"
	KindS3BucketV2             = "aws:s3/bucketV2:BucketV2"
	KindS3Versioning           = "aws:s3/bucketVersioningV2:BucketVersioningV2"
	KindS3Encryption           = "aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2"
	KindS3Lifecycle            = "aws:s3/bucketLifecycleConfigurationV2:BucketLifecycleConfigurationV2"
	KindS3ObjectLock           = "aws:s3/bucketObjectLockConfigurationV2:BucketObjectLockConfigurationV2"
	KindS3PublicAccessBlock    = "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock"
	KindS3BucketPolicy         = "aws:s3/bucketPolicy:BucketPolicy"
	KindS3ReplicationConfig    = "aws:s3/bucketReplicationConfig:BucketReplicationConfig"

	// KindPodRole and KindBackupBucket are the component resources.
	KindPodRole      = "truvity:openbao/aws:PodRole"
	KindBackupBucket = "truvity:openbao/aws:BackupBucket"
)

// guarded is what a key or a bucket always carries unless the hook says
// otherwise: protected from a destroying preview, and dropped from state
// instead of deleted in the cloud.
func guarded() []pulumi.ResourceOption {
	return []pulumi.ResourceOption{pulumi.Protect(true), pulumi.RetainOnDelete(true)}
}
