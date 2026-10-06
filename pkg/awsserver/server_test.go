package awsserver

import (
	"log/slog"
	"slices"
	"sort"
	"testing"

	awspulumi "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serverArgs is a server's whole AWS side with every particular a
// placeholder; backups and endpoint say whether those exist yet.
func serverArgs(ctx *pulumi.Context, backups, endpoint bool) (ServerArgs, error) {
	primary, err := awspulumi.NewProvider(ctx, "primary", &awspulumi.ProviderArgs{Region: pulumi.String("region-a")})
	if err != nil {
		return ServerArgs{}, err
	}

	dr, err := awspulumi.NewProvider(ctx, "dr", &awspulumi.ProviderArgs{Region: pulumi.String("region-b")})
	if err != nil {
		return ServerArgs{}, err
	}

	role := func(name string) ServerRole { return ServerRole{Name: "example-" + name, ServiceAccount: name} }

	args := ServerArgs{
		Cluster: Cluster{
			Name: "example", ARN: "arn:aws:eks:region-a:" + testSource + ":cluster/example", AccountID: testSource, Region: "region-a",
			PermissionsBoundary: "arn:aws:iam::" + testSource + ":policy/boundary",
		},
		Namespace: "openbao", Provider: primary, ReplicaProvider: dr,
		Unseal: UnsealKeyArgs{Name: "openbao-unseal", AliasName: "alias/example-unseal", Description: "unseal", ReplicaDescription: "unseal replica"},
		Roles: ServerRoles{
			Unseal: role("unseal"), Snapshot: role("snapshot"), RestoreCheck: role("restore-check"), TLSExpiry: role("tls-expiry"),
			SnapshotAge: role("snapshot-age"), JobSuccess: role("job-success"), RootGeneration: role("root-generation"), PluginCatalog: role("plugin-catalog"),
		},
		TLSExpiry:    AlertTopicArgs{Name: "openbao-tls-expiry", TopicName: "example-tls-expiry", DisplayName: "expiry"},
		Watches:      AlertTopicArgs{Name: "openbao-watches", TopicName: "example-watches", DisplayName: "watches"},
		Emails:       []string{"security@example.org"},
		EndpointName: "openbao.example.internal",
		Logger:       slog.New(slog.DiscardHandler),
	}

	if backups {
		args.Backups = &ServerBackups{
			BucketName: testBucket, BucketARN: "arn:aws:s3:::" + testBucket, KeyARN: "arn:aws:kms:region-a:" + testBackup + ":key/backup",
			ReplicaBucketARN: "arn:aws:s3:::" + testReplica, SnapshotPrefix: "snapshots/", WeeklyPrefix: "weekly/",
		}
	}

	if endpoint {
		args.Endpoint = &EndpointRecordArgs{Name: "openbao-endpoint", ZoneID: "Z0EXAMPLE", Record: "openbao.example.internal", Target: "nlb.example", TTL: 60}
	}

	return args, nil
}

func runServer(t *testing.T, backups, endpoint bool, options ...func(*pulumi.Context) Option) *recorder {
	t.Helper()

	r := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args, err := serverArgs(ctx, backups, endpoint)
		if err != nil {
			return err
		}

		var opts []Option
		for _, option := range options {
			opts = append(opts, option(ctx))
		}

		_, err = NewServer(ctx, args, opts...)

		return err
	}, pulumi.WithMocks("example", "openbao", r))
	require.NoError(t, err)

	return r
}

func namesOf(r *recorder, kind string) []string {
	var out []string

	for _, rec := range r.all {
		if rec.Type == kind {
			out = append(out, rec.Name)
		}
	}

	sort.Strings(out)

	return out
}

// The whole server: the unseal key and replica, eight roles, two topics, the
// endpoint record.
func TestServerRegistersEveryPiece(t *testing.T) {
	r := runServer(t, true, true)

	assert.Equal(t, []string{
		"example-job-success", "example-plugin-catalog", "example-restore-check", "example-root-generation",
		"example-snapshot", "example-snapshot-age", "example-tls-expiry", "example-unseal",
	}, namesOf(r, KindIAMRole))
	assert.Equal(t, []string{"openbao-tls-expiry-topic", "openbao-watches-topic"}, namesOf(r, KindSNSTopic))
	assert.Equal(t, []string{"openbao-unseal"}, namesOf(r, KindKMSKey))
	assert.Equal(t, []string{"openbao-endpoint"}, namesOf(r, KindRoute53Record))

	for _, rec := range r.all {
		if rec.Type == KindIAMRolePolicy {
			assert.NotEmpty(t, rec.Inputs["policy"], rec.Name)
		}
	}
}

// What another control plane creates is skipped until it exists: the
// backups' roles and the watches, and the endpoint record.
func TestServerSkipsWhatIsNotThereYet(t *testing.T) {
	r := runServer(t, false, false)

	assert.Equal(t, []string{"example-tls-expiry", "example-unseal"}, namesOf(r, KindIAMRole))
	assert.Equal(t, []string{"openbao-tls-expiry-topic"}, namesOf(r, KindSNSTopic))
	assert.Empty(t, namesOf(r, KindRoute53Record))
}

// WithLegacyParent aliases every role's pieces to the URNs they have under
// the component type they were created with.
func TestServerAdoptsRolesFromALegacyParent(t *testing.T) {
	r := runServer(t, true, true, func(ctx *pulumi.Context) Option { return WithLegacyParent(ctx, "example:legacy:Role") })

	for _, rec := range r.all {
		switch rec.Type {
		case KindPodRole, KindIAMRole, KindIAMRolePolicy, KindPodIdentityAssociation:
			assert.True(t, slices.Contains(rec.Aliases, rec.Name), "%s %s carries no alias: %v", rec.Type, rec.Name, rec.Aliases)
		case KindKMSKey, KindSNSTopic:
			assert.Empty(t, rec.Aliases, rec.Name)
		}
	}
}
