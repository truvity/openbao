package awsserver

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type (
	// ServerArgs configures NewServer: the whole AWS side of one OpenBAO
	// server on EKS.
	ServerArgs struct {
		// Cluster is the EKS cluster the server runs on, and Namespace the
		// server's namespace there.
		Cluster   Cluster
		Namespace string
		// Provider is the AWS provider of the cluster's account and region,
		// ReplicaProvider of the disaster-recovery region.
		Provider        pulumi.ProviderResource
		ReplicaProvider pulumi.ProviderResource
		// Unseal is the auto-unseal key (NewUnsealKey); its Provider and
		// ReplicaProvider are filled from the above.
		Unseal UnsealKeyArgs
		// Roles are the server's Pod Identity roles.
		Roles ServerRoles
		// Backups are where the snapshots are kept. Nil skips the snapshot
		// and restore-check roles and the watches until the backup storage
		// exists: a re-run completes them.
		Backups *ServerBackups
		// TLSExpiry and Watches are the two alert topics: the server
		// certificate's expiry, and the watches over snapshots, jobs, root
		// generation and the plugin catalog. Their Emails and Provider are
		// filled from Emails and Provider.
		TLSExpiry AlertTopicArgs
		Watches   AlertTopicArgs
		// Emails subscribe to both topics.
		Emails []string
		// Endpoint is the server's private DNS record. Nil skips it until
		// the load balancer exists: a re-run completes it.
		Endpoint *EndpointRecordArgs
		// EndpointName is exported as the server's address, record or not.
		EndpointName string
		// Logger records what is skipped; nil is slog.Default.
		Logger *slog.Logger
	}

	// Cluster is the EKS cluster a Pod Identity role is bound to.
	Cluster struct {
		Name                string
		ARN                 string
		AccountID           string
		Region              string
		PermissionsBoundary string
	}

	// ServerRoles are the Pod Identity roles, one per job, each bound to one
	// ServiceAccount in the server's namespace.
	ServerRoles struct {
		Unseal         ServerRole
		Snapshot       ServerRole
		RestoreCheck   ServerRole
		TLSExpiry      ServerRole
		SnapshotAge    ServerRole
		JobSuccess     ServerRole
		RootGeneration ServerRole
		PluginCatalog  ServerRole
	}

	// ServerRole is one role's name and the ServiceAccount that assumes it.
	ServerRole struct {
		Name           string
		ServiceAccount string
	}

	// ServerBackups is the snapshot storage (NewBackupBucket's outputs).
	ServerBackups struct {
		BucketName string
		BucketARN  string
		KeyARN     string
		// ReplicaBucketARN is the replica's, which the snapshot-age watch
		// lists beside the primary.
		ReplicaBucketARN string
		// SnapshotPrefix holds the snapshots; WeeklyPrefix the weekly copies.
		SnapshotPrefix string
		WeeklyPrefix   string
	}

	// Server is what NewServer registered.
	Server struct {
		Unseal *UnsealKey
	}
)

// NewServer registers the AWS side of one OpenBAO server and exports what
// the server's charts read: the unseal key and its role, the snapshot and
// restore-check roles, the two alert topics and the roles that publish to
// them, and the endpoint record. Every role's policy is least privilege
// (policies.go); every resource name is this package's, and options apply
// to all of them (WithResourceOptions).
func NewServer(ctx *pulumi.Context, args ServerArgs, options ...Option) (*Server, error) {
	logger := args.Logger
	if logger == nil {
		logger = slog.Default()
	}

	unseal := args.Unseal
	unseal.Provider, unseal.ReplicaProvider = args.Provider, args.ReplicaProvider

	key, err := NewUnsealKey(ctx, unseal, options...)
	if err != nil {
		return nil, err
	}

	keyARN, replicaARN := key.Key.Arn, key.ReplicaKey.Arn

	unsealRole, err := args.role(ctx, args.Roles.Unseal, "openbao-unseal", pulumi.All(keyARN, replicaARN).ApplyT(func(arns []any) (string, error) {
		return UnsealPolicy(arns[0].(string), arns[1].(string))
	}).(pulumi.StringOutput), options)
	if err != nil {
		return nil, err
	}

	ctx.Export("unsealKeyArn", keyARN)
	ctx.Export("unsealReplicaKeyArn", replicaARN)
	ctx.Export("unsealKeyAlias", pulumi.String(unseal.AliasName))
	ctx.Export("unsealRoleArn", unsealRole.RoleARN)
	ctx.Export("endpoint", pulumi.String(args.EndpointName))

	if args.Backups == nil {
		logger.WarnContext(ctx.Context(), "backup storage not deployed yet; skipping the snapshot and restore-check roles and the watches")
	} else if err := args.backups(ctx, replicaARN, options); err != nil {
		return nil, err
	}

	if err := args.tlsExpiry(ctx, options); err != nil {
		return nil, err
	}

	if args.Endpoint == nil {
		logger.WarnContext(ctx.Context(), "load balancer not found yet; skipping the endpoint record", slog.String("record", args.EndpointName))

		return &Server{Unseal: key}, nil
	}

	endpoint := *args.Endpoint
	endpoint.Provider = args.Provider

	if _, err := NewEndpointRecord(ctx, endpoint, options...); err != nil {
		return nil, fmt.Errorf("endpoint record: %w", err)
	}

	ctx.Export("loadBalancerDns", pulumi.String(endpoint.Target))

	return &Server{Unseal: key}, nil
}

// role is one of the server's Pod Identity roles: the Pod Identity service,
// this cluster, the server's namespace and exactly one ServiceAccount.
func (a *ServerArgs) role(ctx *pulumi.Context, role ServerRole, policyName string, policy pulumi.StringInput, options []Option) (*PodRole, error) {
	return NewPodRole(ctx, PodRoleArgs{
		Name:                role.Name,
		Provider:            a.Provider,
		ClusterName:         pulumi.String(a.Cluster.Name),
		ClusterARN:          a.Cluster.ARN,
		AccountID:           a.Cluster.AccountID,
		Region:              a.Cluster.Region,
		Namespace:           a.Namespace,
		ServiceAccounts:     []string{role.ServiceAccount},
		PermissionsBoundary: a.Cluster.PermissionsBoundary,
		PolicyName:          policyName,
		Policy:              policy,
	}, options...)
}

// backups are the snapshot job's and the restore check's roles, and the
// watches, which are told where the backups are.
func (a *ServerArgs) backups(ctx *pulumi.Context, replicaARN pulumi.StringOutput, options []Option) error {
	backups := a.Backups

	policy, err := SnapshotPolicy(backups.BucketARN, backups.KeyARN, backups.SnapshotPrefix, backups.WeeklyPrefix)
	if err != nil {
		return err
	}

	snapshot, err := a.role(ctx, a.Roles.Snapshot, "openbao-snapshot", pulumi.String(policy), options)
	if err != nil {
		return err
	}

	ctx.Export("snapshotRoleArn", snapshot.RoleARN)
	ctx.Export("snapshotBucket", pulumi.String(backups.BucketName))

	check, err := a.role(ctx, a.Roles.RestoreCheck, "openbao-restore-check", replicaARN.ApplyT(func(replica string) (string, error) {
		return RestoreCheckPolicy(backups.BucketARN, backups.KeyARN, replica, backups.SnapshotPrefix)
	}).(pulumi.StringOutput), options)
	if err != nil {
		return err
	}

	ctx.Export("restoreCheckRoleArn", check.RoleARN)

	return a.watches(ctx, options)
}

// watches is the AWS half of the four watches: one topic for all of them,
// since the audience is the same and every subscription is one more thing
// to keep confirmed, and a role each. The snapshot-age watch lists both
// stores and reads no object; the other three need only the alert.
func (a *ServerArgs) watches(ctx *pulumi.Context, options []Option) error {
	args := a.Watches
	args.Emails, args.Provider = a.Emails, a.Provider

	alert, err := NewAlertTopic(ctx, args, options...)
	if err != nil {
		return err
	}

	topic := alert.Topic.Arn
	backups := a.Backups

	age, err := a.role(ctx, a.Roles.SnapshotAge, "openbao-snapshot-age", topic.ApplyT(func(arn string) (string, error) {
		return SnapshotAgePolicy(arn, backups.SnapshotPrefix, backups.BucketARN, backups.ReplicaBucketARN)
	}).(pulumi.StringOutput), options)
	if err != nil {
		return err
	}

	ctx.Export("watchTopicArn", topic)
	ctx.Export("snapshotAgeRoleArn", age.RoleARN)

	for _, publisher := range []struct {
		role   ServerRole
		policy string
		sid    string
		output string
	}{
		{a.Roles.JobSuccess, "openbao-job-success", "PublishOpenBAOJobSuccess", "jobSuccessRoleArn"},
		{a.Roles.RootGeneration, "openbao-root-generation", "PublishOpenBAORootGeneration", "rootGenerationRoleArn"},
		{a.Roles.PluginCatalog, "openbao-plugin-catalog", "PublishOpenBAOPluginCatalog", "pluginCatalogRoleArn"},
	} {
		role, err := a.role(ctx, publisher.role, publisher.policy, publishOnly(topic, publisher.sid), options)
		if err != nil {
			return err
		}

		ctx.Export(publisher.output, role.RoleARN)
	}

	return nil
}

// tlsExpiry is the AWS half of the alert before the server's certificate
// ends: a topic, and a role that may publish to it and do nothing else.
func (a *ServerArgs) tlsExpiry(ctx *pulumi.Context, options []Option) error {
	args := a.TLSExpiry
	args.Emails, args.Provider = a.Emails, a.Provider

	alert, err := NewAlertTopic(ctx, args, options...)
	if err != nil {
		return err
	}

	role, err := a.role(ctx, a.Roles.TLSExpiry, "openbao-tls-expiry", publishOnly(alert.Topic.Arn, "PublishOpenBAOTLSExpiry"), options)
	if err != nil {
		return err
	}

	ctx.Export("tlsExpiryTopicArn", alert.Topic.Arn)
	ctx.Export("tlsExpiryRoleArn", role.RoleARN)

	return nil
}

func publishOnly(topicARN pulumi.StringOutput, sid string) pulumi.StringOutput {
	return topicARN.ApplyT(func(arn string) (string, error) {
		return PublishOnlyPolicy(sid, arn)
	}).(pulumi.StringOutput)
}

// WithLegacyParent adopts roles created as children of another component
// type before they moved onto [NewPodRole]: each PodRole, IAM role, inline
// policy and association carries an alias to the URN it has in state, under
// a component of legacyType named after the role (the policy "<role>-policy"
// and the association "<role>-pia" under the role's component). Without the
// aliases the preview would replace every role.
func WithLegacyParent(ctx *pulumi.Context, legacyType string) Option {
	return WithResourceOptions(func(kind, name string) []pulumi.ResourceOption {
		var parent string

		switch kind {
		case KindPodRole:
			return []pulumi.ResourceOption{pulumi.Aliases([]pulumi.Alias{{
				Type: pulumi.String(legacyType), Name: pulumi.String(name), NoParent: pulumi.Bool(true),
			}})}
		case KindIAMRole:
			parent = name
		case KindIAMRolePolicy:
			parent = strings.TrimSuffix(name, "-policy")
		case KindPodIdentityAssociation:
			parent = strings.TrimSuffix(name, "-pia")
		default:
			return nil
		}

		return []pulumi.ResourceOption{pulumi.Aliases([]pulumi.Alias{{
			Type: pulumi.String(kind), Name: pulumi.String(name),
			ParentURN: pulumi.CreateURN(pulumi.String(parent), pulumi.String(legacyType), nil, pulumi.String(ctx.Project()), pulumi.String(ctx.Stack())),
		}})}
	})
}
