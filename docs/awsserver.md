# The server's AWS resources

`pkg/awsserver` is a Pulumi Go module that creates what an OpenBAO server and
its jobs need from AWS: the auto-unseal key, the Pod Identity roles, the alert
topics, the Raft snapshot bucket and the server's endpoint record. Every
particular (names, accounts, regions, clusters, service accounts, addresses)
is an argument.

```go
import "github.com/truvity/secrets/pkg/awsserver"

key, err := awsserver.NewUnsealKey(ctx, awsserver.UnsealKeyArgs{
    Name:               "unseal",
    AliasName:          "alias/openbao-unseal",
    Description:        "OpenBAO auto-unseal, multi-region primary",
    ReplicaDescription: "OpenBAO auto-unseal, replica",
    Provider:           primary,
    ReplicaProvider:    secondary,
})

_, err = awsserver.NewPodRole(ctx, awsserver.PodRoleArgs{
    Name:            "openbao-unseal",
    Provider:        primary,
    ClusterName:     pulumi.String("example-cluster"),
    ClusterARN:      "arn:aws:eks:eu-example-1:111122223333:cluster/example-cluster",
    AccountID:       "111122223333",
    Namespace:       "openbao",
    ServiceAccounts: []string{"openbao"},
    PolicyName:      "openbao-unseal",
    Policy: pulumi.All(key.Key.Arn, key.ReplicaKey.Arn).ApplyT(func(a []any) (string, error) {
        return awsserver.UnsealPolicy(a[0].(string), a[1].(string))
    }).(pulumi.StringOutput),
})
```

## The whole server

`NewServer` composes the constructors into a server's whole AWS side and
exports what the server's charts read:

| Piece | Output |
|---|---|
| the auto-unseal key, its replica and aliases, and the unseal role | `unsealKeyArn`, `unsealReplicaKeyArn`, `unsealKeyAlias`, `unsealRoleArn` |
| the snapshot and restore-check roles, once `Backups` is given | `snapshotRoleArn`, `snapshotBucket`, `restoreCheckRoleArn` |
| the watches' topic and its four roles (snapshot age, job success, root generation, plugin catalog), once `Backups` is given | `watchTopicArn`, `snapshotAgeRoleArn`, `jobSuccessRoleArn`, `rootGenerationRoleArn`, `pluginCatalogRoleArn` |
| the certificate-expiry topic and its role | `tlsExpiryTopicArn`, `tlsExpiryRoleArn` |
| the endpoint record, once `Endpoint` is given | `loadBalancerDns`; `endpoint` always |

Each role is bound to one ServiceAccount in the server's namespace, with the
least-privilege policy for its job. What another control plane creates (the
snapshot bucket, the load balancer) is optional: until it exists the
dependent pieces are skipped with a warning, and a re-run completes them.

`WithLegacyParent(ctx, type)` adopts roles created under another component
type, named after each role: every role, inline policy and association
carries an alias to the URN it has in state.

## The alias contract

A resource's Pulumi URN is its type, its logical name and its parents. The
type and the logical name of every resource below are API: the tests pin
them, and a change is a breaking change to every caller that adopted
existing state. `<N>` is the `Name` (or `BucketName`) argument; `<R>` is
`Replica.BucketName`.

| Constructor | Kind (Pulumi type) | Logical name | Parent | Protect and retain |
|---|---|---|---|---|
| `NewUnsealKey` | `aws:kms/key:Key` | `<N>` | caller's | yes |
| | `aws:kms/alias:Alias` | `<N>-alias` | caller's | no |
| | `aws:kms/replicaKey:ReplicaKey` | `<N>-replica` | caller's | yes |
| | `aws:kms/alias:Alias` | `<N>-replica-alias` | caller's | no |
| `NewPodRole` | `truvity:openbao/aws:PodRole` (component) | `<N>` | caller's | no |
| | `aws:iam/role:Role` | `<N>` | the component | no |
| | `aws:iam/rolePolicy:RolePolicy` | `<N>-policy` | the component | no |
| | `aws:eks/podIdentityAssociation:PodIdentityAssociation` | `<N>-pia` (one service account) or `<N>-pia-<service account>` | the component | no |
| `NewAlertTopic` | `aws:sns/topic:Topic` | `<N>-topic` | caller's | no |
| | `aws:sns/topicSubscription:TopicSubscription` | `<N>-subscription-<SubscriptionSlug(email)>` | caller's | no |
| `NewEndpointRecord` | `aws:route53/record:Record` | `Name` | caller's | no |
| `NewBackupBucket` | `truvity:openbao/aws:BackupBucket` (component) | `<N>` | caller's | no |
| | `aws:kms/key:Key` | `<N>-kms` | the component | yes |
| | `aws:kms/alias:Alias` | `<N>-kms-alias` | the component | no |
| | `aws:s3/bucket:Bucket` | `<N>` | the component | yes |
| | `aws:s3/bucketVersioningV2:BucketVersioningV2` | `<N>-versioning` | the component | no |
| | `aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2` | `<N>-encryption` | the component | no |
| | `aws:s3/bucketLifecycleConfigurationV2:BucketLifecycleConfigurationV2` | `<N>-lifecycle` | the component | no |
| | `aws:s3/bucketObjectLockConfigurationV2:BucketObjectLockConfigurationV2` (`ObjectLockDays` > 0) | `<N>-object-lock` | the component | no |
| | `aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock` | `<N>-public-access` | the component | no |
| | `aws:s3/bucketPolicy:BucketPolicy` | `<N>-policy` | the component | no |
| | `aws:kms/key:Key` (`Replica` set) | `<R>-kms` | the component | yes |
| | `aws:s3/bucketV2:BucketV2` (`Replica` set) | `<R>` | the component | yes |
| | `aws:s3/bucketVersioningV2:BucketVersioningV2` (`Replica` set) | `<R>-versioning` | the component | no |
| | `aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock` (`Replica` set) | `<R>-public-access` | the component | no |
| | `aws:s3/bucketPolicy:BucketPolicy` (`Replica` set and `ListerRoleNames`) | `<R>-policy` | the component | no |
| | `aws:iam/role:Role` (`Replica` set) | `<N>-replication-role` | the component | no |
| | `aws:iam/rolePolicy:RolePolicy` (`Replica` set) | `<N>-replication-policy` | the component | no |
| | `aws:s3/bucketReplicationConfig:BucketReplicationConfig` (`Replica` set) | `<N>-replication` | the component | no |

The primary bucket is an `aws:s3/bucket:Bucket` and the replica an
`aws:s3/bucketV2:BucketV2`; both are the same S3 resource and the SDK
aliases the two types to each other, but a state records one of them, so the
split is part of the contract too.

The unseal key, the alert topics and the endpoint record are registered
directly because wrapping them in a component of this package would put its
type into their URNs and make a caller's first preview a replacement of the
key. The pod roles and the bucket are components, and the components are
resources too: a caller adopting a role that was a child of another
component aliases the new component as well.

## Hooks

Every constructor takes options; `WithResourceOptions` is the one that
matters for adoption:

```go
awsserver.WithResourceOptions(func(kind, logicalName string) []pulumi.ResourceOption {
    // kind is the Pulumi type from the table, logicalName the name from it.
    return []pulumi.ResourceOption{pulumi.Aliases(oldURN(kind, logicalName))}
})
```

The hook is called once per resource, components included, and what it
returns is appended after the library's own options, so it can add aliases,
a parent or `IgnoreChanges`, and override a default (`pulumi.Protect(false)`
to retire a key).

## Order of adoption

1. Run `pulumi preview` with the aliases in place and read it: every
   resource must be `same`, and nothing may be a create, a delete or a
   replace.
2. A preview that proposes to delete or replace a key or a bucket is a
   logical-name or parent mismatch. Stop and fix the alias; never apply it.
3. Apply from an up-to-date checkout, then refresh-preview.
