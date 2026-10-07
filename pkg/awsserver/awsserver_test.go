package awsserver

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"testing"

	awspulumi "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSource  = "111122223333"
	testBackup  = "444455556666"
	testBucket  = "example-openbao-111122223333-region-a"
	testReplica = testBucket + "-replica"
)

type (
	recorded struct {
		Type, Name, Parent string
		Inputs             resource.PropertyMap
		Protect, Retain    bool
		Aliases            []string
		Provider           string
	}

	recorder struct {
		mu  sync.Mutex
		all []recorded
	}
)

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	rec := recorded{Type: args.TypeToken, Name: args.Name, Inputs: args.Inputs}

	if rpc := args.RegisterRPC; rpc != nil {
		rec.Parent = rpc.GetParent()
		rec.Protect = rpc.GetProtect()
		rec.Retain = rpc.GetRetainOnDelete()
		rec.Provider = rpc.GetProvider()

		for _, a := range rpc.GetAliases() {
			if spec := a.GetSpec(); spec != nil {
				rec.Aliases = append(rec.Aliases, spec.GetName())
			}
		}
	}

	r.mu.Lock()
	r.all = append(r.all, rec)
	r.mu.Unlock()

	state := args.Inputs.Copy()
	state["arn"] = resource.NewProperty("arn:aws:mock:::" + args.Name)
	state["keyId"] = resource.NewProperty("key-" + args.Name)

	return args.Name + "-id", state, nil
}

func (r *recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

// fixture is a server's AWS side, with every particular a placeholder.
func fixture(ctx *pulumi.Context, options ...Option) error {
	primary, err := awspulumi.NewProvider(ctx, "primary", &awspulumi.ProviderArgs{Region: pulumi.String("region-a")})
	if err != nil {
		return err
	}

	dr, err := awspulumi.NewProvider(ctx, "dr", &awspulumi.ProviderArgs{Region: pulumi.String("region-b")})
	if err != nil {
		return err
	}

	key, err := NewUnsealKey(ctx, UnsealKeyArgs{
		Name:               "example-unseal",
		AliasName:          "alias/example-unseal",
		Description:        "auto-unseal, multi-region primary",
		ReplicaDescription: "auto-unseal, replica in region-b",
		Tags:               map[string]string{"owner": "infra"},
		Provider:           primary,
		ReplicaProvider:    dr,
	}, options...)
	if err != nil {
		return err
	}

	for _, spec := range []struct {
		name, sa, policyName string
		policy               pulumi.StringInput
	}{
		{"example-unseal-role", "server", "unseal", pulumi.All(key.Key.Arn, key.ReplicaKey.Arn).ApplyT(func(a []any) (string, error) {
			return UnsealPolicy(a[0].(string), a[1].(string))
		}).(pulumi.StringOutput)},
		{"example-snapshot-role", "snapshot", "snapshot", pulumi.String(`{"Version":"2012-10-17","Statement":[]}`)},
	} {
		if _, err := NewPodRole(ctx, PodRoleArgs{
			Name:                spec.name,
			Provider:            primary,
			ClusterName:         pulumi.String("example-cluster"),
			ClusterARN:          "arn:aws:eks:region-a:" + testSource + ":cluster/example-cluster",
			AccountID:           testSource,
			Region:              "region-a",
			Namespace:           "example-ns",
			ServiceAccounts:     []string{spec.sa},
			PermissionsBoundary: "arn:aws:iam::" + testSource + ":policy/example-boundary",
			PolicyName:          spec.policyName,
			Policy:              spec.policy,
		}, options...); err != nil {
			return err
		}
	}

	if _, err := NewAlertTopic(ctx, AlertTopicArgs{
		Name:        "example-watches",
		TopicName:   "example-watches",
		DisplayName: "Example watches",
		Tags:        map[string]string{"owner": "infra"},
		Emails:      []string{"Ops.Team@example.com", "second@example.com"},
		Provider:    primary,
	}, options...); err != nil {
		return err
	}

	if _, err := NewBackupBucket(ctx, BackupBucketArgs{
		Provider:        primary,
		BucketName:      testBucket,
		SourceAccountID: testSource,
		BackupAccountID: testBackup,
		WriterRoleName:  "example-snapshot-role",
		ReaderRoleName:  "example-restore-role",
		ListerRoleNames: []string{"example-age-role"},
		KeyDescription:  "example snapshots " + testBucket,
		Tags:            map[string]string{"owner": "infra"},
		ObjectLockDays:  30,
		LifecycleRules: s3.BucketLifecycleConfigurationV2RuleArray{&s3.BucketLifecycleConfigurationV2RuleArgs{
			Id:     pulumi.String("all"),
			Status: pulumi.String("Enabled"),
		}},
		Replica: &BackupReplica{
			Provider:                dr,
			BucketName:              testReplica,
			KeyDescription:          "example snapshots replica",
			RoleName:                testBucket + "-replication",
			RolePermissionsBoundary: pulumi.String("arn:aws:iam::" + testBackup + ":policy/example-boundary"),
		},
	}, options...); err != nil {
		return err
	}

	_, err = NewEndpointRecord(ctx, EndpointRecordArgs{
		Name: "example-endpoint", ZoneID: "Z0EXAMPLE", Record: "bao.example.test", Target: "lb.example.test", Provider: primary,
	}, options...)

	return err
}

func run(t *testing.T, options ...Option) []recorded {
	t.Helper()

	rec := &recorder{}
	require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error { return fixture(ctx, options...) }, pulumi.WithMocks("example", "stack", rec)))

	var out []recorded

	for _, r := range rec.all {
		if !strings.HasPrefix(r.Type, "pulumi:providers:") {
			out = append(out, r)
		}
	}

	return out
}

func names(rs []recorded) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Type+" "+r.Name)
	}

	sort.Strings(out)

	return out
}

func byKey(rs []recorded) map[string]recorded {
	out := map[string]recorded{}
	for _, r := range rs {
		out[r.Type+" "+r.Name] = r
	}

	return out
}

// The alias contract: kind and logical name of every resource the fixture
// registers. docs/awsserver.md tabulates the same.
func TestResourceSetAndLogicalNames(t *testing.T) {
	want := []string{
		"aws:eks/podIdentityAssociation:PodIdentityAssociation example-snapshot-role-pia",
		"aws:eks/podIdentityAssociation:PodIdentityAssociation example-unseal-role-pia",
		"aws:iam/role:Role " + testBucket + "-replication-role",
		"aws:iam/role:Role example-snapshot-role",
		"aws:iam/role:Role example-unseal-role",
		"aws:iam/rolePolicy:RolePolicy " + testBucket + "-replication-policy",
		"aws:iam/rolePolicy:RolePolicy example-snapshot-role-policy",
		"aws:iam/rolePolicy:RolePolicy example-unseal-role-policy",
		"aws:kms/alias:Alias example-unseal-alias",
		"aws:kms/alias:Alias example-unseal-replica-alias",
		"aws:kms/alias:Alias " + testBucket + "-kms-alias",
		"aws:kms/key:Key example-unseal",
		"aws:kms/key:Key " + testBucket + "-kms",
		"aws:kms/key:Key " + testReplica + "-kms",
		"aws:kms/replicaKey:ReplicaKey example-unseal-replica",
		"aws:route53/record:Record example-endpoint",
		"aws:s3/bucket:Bucket " + testBucket,
		"aws:s3/bucketLifecycleConfigurationV2:BucketLifecycleConfigurationV2 " + testBucket + "-lifecycle",
		"aws:s3/bucketObjectLockConfigurationV2:BucketObjectLockConfigurationV2 " + testBucket + "-object-lock",
		"aws:s3/bucketPolicy:BucketPolicy " + testBucket + "-policy",
		"aws:s3/bucketPolicy:BucketPolicy " + testReplica + "-policy",
		"aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock " + testBucket + "-public-access",
		"aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock " + testReplica + "-public-access",
		"aws:s3/bucketReplicationConfig:BucketReplicationConfig " + testBucket + "-replication",
		"aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2 " + testBucket + "-encryption",
		"aws:s3/bucketV2:BucketV2 " + testReplica,
		"aws:s3/bucketVersioningV2:BucketVersioningV2 " + testBucket + "-versioning",
		"aws:s3/bucketVersioningV2:BucketVersioningV2 " + testReplica + "-versioning",
		"aws:sns/topic:Topic example-watches-topic",
		"aws:sns/topicSubscription:TopicSubscription example-watches-subscription-ops-team-at-example-com",
		"aws:sns/topicSubscription:TopicSubscription example-watches-subscription-second-at-example-com",
		"truvity:openbao/aws:BackupBucket " + testBucket,
		"truvity:openbao/aws:PodRole example-snapshot-role",
		"truvity:openbao/aws:PodRole example-unseal-role",
	}
	sort.Strings(want)

	got := run(t)
	assert.Equal(t, want, names(got))

	// Every resource of a component is its child; the rest are top level.
	parents := map[string]string{}
	for _, r := range got {
		parents[r.Type+" "+r.Name] = r.Parent
	}

	assert.Contains(t, parents["aws:iam/role:Role example-unseal-role"], "PodRole::example-unseal-role")
	assert.Contains(t, parents["aws:s3/bucket:Bucket "+testBucket], "BackupBucket::"+testBucket)
	assert.Contains(t, parents["aws:iam/role:Role "+testBucket+"-replication-role"], "BackupBucket::"+testBucket)
	assert.Contains(t, parents["aws:kms/key:Key example-unseal"], "pulumi:pulumi:Stack", "the unseal key is registered directly, with no wrapper in its URN")
	assert.Contains(t, parents["aws:sns/topic:Topic example-watches-topic"], "pulumi:pulumi:Stack")
	assert.Contains(t, parents["aws:route53/record:Record example-endpoint"], "pulumi:pulumi:Stack")
}

func TestPropertiesOfTheFixture(t *testing.T) {
	got := byKey(run(t))
	in := func(key string) resource.PropertyMap { return got[key].Inputs }

	key := in("aws:kms/key:Key example-unseal")
	assert.True(t, key["multiRegion"].BoolValue())
	assert.True(t, key["enableKeyRotation"].BoolValue())
	assert.Equal(t, "auto-unseal, multi-region primary", key["description"].StringValue())

	assert.Equal(t, "alias/example-unseal", in("aws:kms/alias:Alias example-unseal-alias")["name"].StringValue())
	assert.Equal(t, "alias/example-unseal", in("aws:kms/alias:Alias example-unseal-replica-alias")["name"].StringValue())

	role := in("aws:iam/role:Role example-unseal-role")
	assert.Equal(t, "example-unseal-role", role["name"].StringValue())
	assert.Equal(t, "arn:aws:iam::"+testSource+":policy/example-boundary", role["permissionsBoundary"].StringValue())

	var trust map[string]any
	require.NoError(t, json.Unmarshal([]byte(role["assumeRolePolicy"].StringValue()), &trust))

	cond := trust["Statement"].([]any)[0].(map[string]any)["Condition"].(map[string]any)
	assert.Equal(t, map[string]any{
		"aws:SourceAccount":                         testSource,
		"aws:RequestTag/kubernetes-namespace":       "example-ns",
		"aws:RequestTag/kubernetes-service-account": "server",
	}, cond["StringEquals"])
	assert.Equal(t, map[string]any{"aws:SourceArn": "arn:aws:eks:region-a:" + testSource + ":cluster/example-cluster"}, cond["ArnEquals"])

	pia := in("aws:eks/podIdentityAssociation:PodIdentityAssociation example-unseal-role-pia")
	assert.Equal(t, "example-ns", pia["namespace"].StringValue())
	assert.Equal(t, "server", pia["serviceAccount"].StringValue())
	assert.Equal(t, "region-a", pia["region"].StringValue())

	assert.Equal(t, "example-watches", in("aws:sns/topic:Topic example-watches-topic")["name"].StringValue())

	sub := in("aws:sns/topicSubscription:TopicSubscription example-watches-subscription-ops-team-at-example-com")
	assert.Equal(t, "email", sub["protocol"].StringValue())
	assert.Equal(t, "Ops.Team@example.com", sub["endpoint"].StringValue())

	bucket := in("aws:s3/bucket:Bucket " + testBucket)
	assert.True(t, bucket["objectLockEnabled"].BoolValue())
	assert.True(t, in("aws:s3/bucketV2:BucketV2 " + testReplica)["objectLockEnabled"].BoolValue(),
		"a locked bucket replicates into a locked bucket")

	lock := in("aws:s3/bucketObjectLockConfigurationV2:BucketObjectLockConfigurationV2 " + testBucket + "-object-lock")
	retention := lock["rule"].ObjectValue()["defaultRetention"].ObjectValue()
	assert.Equal(t, "COMPLIANCE", retention["mode"].StringValue())
	assert.EqualValues(t, 30, retention["days"].NumberValue())

	record := in("aws:route53/record:Record example-endpoint")
	assert.Equal(t, "CNAME", record["type"].StringValue())
	assert.EqualValues(t, DefaultEndpointTTL, record["ttl"].NumberValue())

	repl := in("aws:s3/bucketReplicationConfig:BucketReplicationConfig " + testBucket + "-replication")
	rule := repl["rules"].ArrayValue()[0].ObjectValue()
	assert.Equal(t, "crr", rule["id"].StringValue())
	assert.Equal(t, "STANDARD_IA", rule["destination"].ObjectValue()["storageClass"].StringValue())

	// The bucket policy names the writer by glob-capable StringLike, the
	// reader and the lister by exact role ARN.
	policy := in("aws:s3/bucketPolicy:BucketPolicy " + testBucket + "-policy")["policy"].StringValue()
	assert.Contains(t, policy, "arn:aws:iam::"+testSource+":role/example-snapshot-role")
	assert.Contains(t, policy, "AllowReaderGetObject")
	assert.Contains(t, policy, "AllowListerListBucketExampleAgeRole")
	assert.Contains(t, policy, "DenyDeleteObjectVersionFromExternalAccount")
}

// The two providers are used where they belong: the replica key, its alias
// and the replica bucket live in the second region.
func TestProvidersFollowTheRegions(t *testing.T) {
	got := byKey(run(t))

	primary := got["aws:kms/key:Key example-unseal"].Provider
	replica := got["aws:kms/replicaKey:ReplicaKey example-unseal-replica"].Provider
	require.NotEmpty(t, primary)
	require.NotEmpty(t, replica)
	assert.NotEqual(t, primary, replica)
	assert.Equal(t, replica, got["aws:kms/alias:Alias example-unseal-replica-alias"].Provider)
	assert.Equal(t, replica, got["aws:s3/bucketV2:BucketV2 "+testReplica].Provider)
	assert.Equal(t, replica, got["aws:kms/key:Key "+testReplica+"-kms"].Provider)
	assert.Equal(t, primary, got["aws:s3/bucket:Bucket "+testBucket].Provider)
	assert.Equal(t, primary, got["aws:iam/role:Role "+testBucket+"-replication-role"].Provider)
}

// The hook is asked about, and its options are applied to, every resource
// registered: leaves and components alike.
func TestHookIsAppliedToEveryChild(t *testing.T) {
	var (
		mu    sync.Mutex
		asked = map[string]int{}
	)

	hook := WithResourceOptions(func(kind, logicalName string) []pulumi.ResourceOption {
		mu.Lock()
		asked[kind+" "+logicalName]++
		mu.Unlock()

		return []pulumi.ResourceOption{pulumi.Aliases([]pulumi.Alias{{Name: pulumi.String("legacy-" + logicalName)}})}
	})

	got := run(t, hook)
	require.NotEmpty(t, got)

	for _, r := range got {
		key := r.Type + " " + r.Name
		assert.Equal(t, 1, asked[key], "the hook is asked exactly once for %s", key)
		assert.Contains(t, r.Aliases, "legacy-"+r.Name, "the hook's alias reaches %s", key)
	}

	assert.Len(t, asked, len(got), "the hook is asked about nothing the program does not register")
}

// Protect and RetainOnDelete are on every key and bucket by default and on
// nothing else.
func TestKeysAndBucketsAreProtectedByDefault(t *testing.T) {
	guarded := map[string]bool{
		"aws:kms/key:Key example-unseal":                       true,
		"aws:kms/replicaKey:ReplicaKey example-unseal-replica": true,
		"aws:kms/key:Key " + testBucket + "-kms":               true,
		"aws:kms/key:Key " + testReplica + "-kms":              true,
		"aws:s3/bucket:Bucket " + testBucket:                   true,
		"aws:s3/bucketV2:BucketV2 " + testReplica:              true,
	}

	for _, r := range run(t) {
		key := r.Type + " " + r.Name
		assert.Equal(t, guarded[key], r.Protect, "protect on %s", key)
		assert.Equal(t, guarded[key], r.Retain, "retainOnDelete on %s", key)
	}
}

// A caller can lift the defaults: the hook's options come last and win.
func TestHookOverridesTheDefaults(t *testing.T) {
	got := run(t, WithResourceOptions(func(kind, _ string) []pulumi.ResourceOption {
		if kind == KindKMSKey {
			return []pulumi.ResourceOption{pulumi.Protect(false), pulumi.RetainOnDelete(false)}
		}

		return nil
	}))

	byk := byKey(got)
	assert.False(t, byk["aws:kms/key:Key example-unseal"].Protect)
	assert.False(t, byk["aws:kms/key:Key example-unseal"].Retain)
	assert.True(t, byk["aws:s3/bucket:Bucket "+testBucket].Protect)
	assert.True(t, byk["aws:kms/replicaKey:ReplicaKey example-unseal-replica"].Protect)
}

func TestInvalidArgsRegisterNothing(t *testing.T) {
	rec := &recorder{}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := awspulumi.NewProvider(ctx, "p", &awspulumi.ProviderArgs{})
		if err != nil {
			return err
		}

		_, err = NewPodRole(ctx, PodRoleArgs{Name: "r", Provider: p})
		require.Error(t, err)

		_, err = NewBackupBucket(ctx, BackupBucketArgs{Provider: p, BucketName: "b"})
		require.Error(t, err)

		_, err = NewUnsealKey(ctx, UnsealKeyArgs{Name: "k"})
		require.Error(t, err)

		return nil
	}, pulumi.WithMocks("example", "stack", rec))
	require.NoError(t, err)

	for _, r := range rec.all {
		assert.True(t, strings.HasPrefix(r.Type, "pulumi:providers:"), "registered %s", r.Type)
	}
}

func TestSubscriptionSlug(t *testing.T) {
	assert.Equal(t, "ops-team-at-example-com", SubscriptionSlug("Ops.Team@Example.com"))
}

func TestPolicies(t *testing.T) {
	unseal, err := UnsealPolicy("key-arn", "replica-arn")
	require.NoError(t, err)
	assert.JSONEq(t, `{"Version":"2012-10-17","Statement":[{"Sid":"OpenBAOAutoUnseal","Effect":"Allow",
		"Action":["kms:Encrypt","kms:Decrypt","kms:DescribeKey"],"Resource":["key-arn","replica-arn"]}]}`, unseal)

	snapshot, err := SnapshotPolicy("arn:aws:s3:::b", "key-arn", "raft/", "weekly/")
	require.NoError(t, err)
	assert.Contains(t, snapshot, `"arn:aws:s3:::b/raft/*","arn:aws:s3:::b/weekly/*"`)

	for _, forbidden := range []string{"s3:GetObject", "s3:ListBucket", "s3:DeleteObject"} {
		assert.NotContains(t, snapshot, `"`+forbidden+`"`)
	}
	// A multipart upload into an SSE-KMS bucket needs kms:Decrypt.
	assert.Contains(t, snapshot, `"kms:Decrypt"`)

	restore, err := RestoreCheckPolicy("arn:aws:s3:::b", "backup-key", "replica-key", "raft/")
	require.NoError(t, err)

	for _, forbidden := range []string{"s3:PutObject", "s3:DeleteObject", "kms:GenerateDataKey", "weekly/"} {
		assert.NotContains(t, restore, forbidden)
	}

	age, err := SnapshotAgePolicy("topic", "raft/", "arn:aws:s3:::b", "arn:aws:s3:::b-replica")
	require.NoError(t, err)
	assert.Contains(t, age, `"Resource":["arn:aws:s3:::b","arn:aws:s3:::b-replica"]`)
	assert.Contains(t, age, `"s3:prefix":"raft/*"`)
	assert.NotContains(t, age, "b/*")

	publish, err := PublishOnlyPolicy("PublishExample", "topic")
	require.NoError(t, err)
	assert.JSONEq(t, `{"Version":"2012-10-17","Statement":[{"Sid":"PublishExample","Effect":"Allow",
		"Action":["sns:Publish"],"Resource":["topic"]}]}`, publish)
}

func TestSeveralServiceAccountsNameTheirAssociations(t *testing.T) {
	rec := &recorder{}
	require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := awspulumi.NewProvider(ctx, "p", &awspulumi.ProviderArgs{})
		if err != nil {
			return err
		}

		_, err = NewPodRole(ctx, PodRoleArgs{
			Name: "r", Provider: p, ClusterName: pulumi.String("c"), ClusterARN: "arn", AccountID: testSource,
			Namespace: "ns", ServiceAccounts: []string{"a", "b"}, PolicyName: "p", Policy: pulumi.String("{}"),
		})

		return err
	}, pulumi.WithMocks("example", "stack", rec)))

	got := byKey(rec.all)
	assert.Contains(t, got, "aws:eks/podIdentityAssociation:PodIdentityAssociation r-pia-a")
	assert.Contains(t, got, "aws:eks/podIdentityAssociation:PodIdentityAssociation r-pia-b")
	assert.Contains(t, got["aws:iam/role:Role r"].Inputs["assumeRolePolicy"].StringValue(), `["a","b"]`)
}
