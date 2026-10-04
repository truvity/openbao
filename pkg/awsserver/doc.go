// Package awsserver provisions what an OpenBAO server needs from AWS as
// Pulumi Go resources, from caller inputs alone: nothing here names a
// cluster, an account, a region, a bucket or an e-mail address.
//
//   - NewUnsealKey: the multi-region key the awskms seal uses, its replica
//     in a second region and an alias in each;
//   - NewPodRole: one EKS Pod Identity role (the IAM role, an inline policy
//     and the association with the server's or a job's ServiceAccount);
//   - UnsealPolicy, SnapshotPolicy, RestoreCheckPolicy, SnapshotAgePolicy
//     and PublishOnlyPolicy: the least-privilege policy documents of the
//     roles the server and its jobs use;
//   - NewAlertTopic: an SNS topic and e-mail subscriptions for the alerts
//     the charts' watches publish;
//   - NewBackupBucket: the Raft snapshot bucket (versioned, KMS-encrypted,
//     private, Object Lock COMPLIANCE, cross-region replication) with its
//     key, resource policies and replica, for a source account whose roles
//     write, read and list it;
//   - NewEndpointRecord: the CNAME to the server's load balancer.
//
// # Adopting existing state
//
// A Pulumi resource's identity is its URN: type, logical name and the chain
// of parents. A change to any of them is a delete and a create, which for a
// key or a bucket that holds data nobody can recover is not acceptable. So
// the type and the logical name of every resource are part of this
// package's contract (docs/awsserver.md tabulates them and the tests pin
// them), and every constructor takes WithResourceOptions: a hook that is
// asked for options for every resource it registers. A caller that already
// has the resources in its state returns pulumi.Aliases from the hook,
// naming the URN each resource has today, and the first preview is empty.
//
// The unseal key, the alert topics and the endpoint record are registered
// directly, under whatever parent the hook gives. The pod roles and the
// backup bucket are components, because each has children that share a
// life cycle.
//
// # Defaults
//
// The KMS keys and the buckets carry pulumi.Protect(true) and
// pulumi.RetainOnDelete(true). The hook's options come last, so a caller
// retiring one passes pulumi.Protect(false) for it.
package awsserver
