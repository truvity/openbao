package esoaws

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	awspulumi "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AWS's documented placeholder accounts: the cluster's and the parameters'.
const (
	clusterAccount = "111122223333"
	sourceAccount  = "444455556666"
	region         = "eu-example-1"
	clusterARN     = "arn:aws:eks:" + region + ":" + clusterAccount + ":cluster/a"
	esoRole        = "arn:aws:iam::" + clusterAccount + ":role/a-external-secrets"
	keyARN         = "arn:aws:kms:" + region + ":" + sourceAccount + ":key/1234abcd-12ab-34cd-56ef-1234567890ab"
	issuerB        = "https://oidc.b.example.com"
	issuerC        = "https://issuer.example.com/clusters/c"
	providerC      = "arn:aws:iam::" + sourceAccount + ":oidc-provider/issuer.example.com/clusters/c"
)

type (
	recorded struct {
		Type, Name, Parent, Provider string
		Inputs                       resource.PropertyMap
	}

	recorder struct {
		mu  sync.Mutex
		all []recorded
	}
)

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	rec := recorded{Type: args.TypeToken, Name: args.Name, Inputs: args.Inputs}
	if rpc := args.RegisterRPC; rpc != nil {
		rec.Parent, rec.Provider = rpc.GetParent(), rpc.GetProvider()
	}

	r.mu.Lock()
	r.all = append(r.all, rec)
	r.mu.Unlock()

	state := args.Inputs.Copy()
	switch args.TypeToken {
	case KindIAMRole:
		state["arn"] = resource.NewProperty("arn:aws:iam::mock:role/" + args.Name)
	case KindOIDCProvider:
		state["arn"] = resource.NewProperty("arn:aws:iam::mock:oidc-provider/" + args.Name)
	}

	return args.Name + "-id", state, nil
}

func (r *recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

func clusterArgs(p pulumi.ProviderResource) ClusterIdentityArgs {
	return ClusterIdentityArgs{
		Mode:                PodIdentityMode,
		Name:                "a-external-secrets",
		Provider:            p,
		ClusterName:         pulumi.String("a"),
		ClusterARN:          clusterARN,
		AccountID:           clusterAccount,
		Region:              region,
		SourceRoles:         []string{"arn:aws:iam::" + sourceAccount + ":role/a-app-config", "arn:aws:iam::" + sourceAccount + ":role/a-app-credentials"},
		PermissionsBoundary: "arn:aws:iam::" + clusterAccount + ":policy/example-boundary",
		Tags:                map[string]string{"owner": "platform"},
	}
}

// Three clusters: a on Pod Identity, b on web identity with a provider the
// component creates, c on web identity with a provider that exists.
func clusters() []Cluster {
	return []Cluster{
		{Name: "a", Mode: PodIdentityMode, PodIdentity: &PodIdentity{RoleARN: esoRole}},
		{Name: "b", Mode: WebIdentityMode, WebIdentity: &WebIdentity{IssuerURL: issuerB}},
		{Name: "c", Mode: WebIdentityMode, WebIdentity: &WebIdentity{IssuerURL: issuerC, ProviderARN: providerC, Audience: "example-audience"}},
	}
}

func grants() []Grant {
	return []Grant{
		{
			Name:       "a-app-config",
			Cluster:    "a",
			Parameters: []string{"/app/config/", "/shared/endpoint", "standalone"},
		},
		{
			Name:    "a-app-credentials",
			Cluster: "a",
			Parameters: []string{
				"arn:aws:ssm:" + region + ":" + sourceAccount + ":parameter/app/credentials/",
				"/app/token",
			},
			KMSKeyARN: keyARN,
		},
		{
			Name:           "b-app-config",
			Cluster:        "b",
			ServiceAccount: &ServiceAccount{Name: "eso-b-app-config"},
			Parameters:     []string{"/app/config/"},
		},
		{
			Name:           "c-app-config",
			Cluster:        "c",
			ServiceAccount: &ServiceAccount{Namespace: "eso", Name: "c-app-config"},
			Parameters:     []string{"/app/config/"},
		},
	}
}

func readersArgs(p pulumi.ProviderResource) ReadersArgs {
	return ReadersArgs{
		Name:                "a-parameter-readers",
		Provider:            p,
		AccountID:           sourceAccount,
		Region:              region,
		Clusters:            clusters(),
		Grants:              grants(),
		PermissionsBoundary: "arn:aws:iam::" + sourceAccount + ":policy/example-boundary",
		Tags:                map[string]string{"owner": "platform"},
	}
}

type outputs struct {
	clusterRoleARN string
	readerARNs     map[string]string
	providerARNs   map[string]string
}

func run(t *testing.T) ([]recorded, outputs) {
	t.Helper()

	var (
		rec = &recorder{}
		out = outputs{readerARNs: map[string]string{}, providerARNs: map[string]string{}}
		mu  sync.Mutex
		wg  sync.WaitGroup
	)

	require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error {
		cluster, err := awspulumi.NewProvider(ctx, "cluster", &awspulumi.ProviderArgs{Region: pulumi.String(region)})
		if err != nil {
			return err
		}

		source, err := awspulumi.NewProvider(ctx, "source", &awspulumi.ProviderArgs{Region: pulumi.String(region)})
		if err != nil {
			return err
		}

		id, err := NewClusterIdentity(ctx, clusterArgs(cluster))
		if err != nil {
			return err
		}

		readers, err := NewReaders(ctx, readersArgs(source))
		if err != nil {
			return err
		}

		wg.Add(1 + len(readers.RoleARNs) + len(readers.OIDCProviderARNs))
		id.RoleARN.ApplyT(func(s string) string {
			out.clusterRoleARN = s
			wg.Done()

			return s
		})

		for name, arn := range readers.RoleARNs {
			arn.ApplyT(func(s string) string {
				mu.Lock()
				out.readerARNs[name] = s
				mu.Unlock()
				wg.Done()

				return s
			})
		}

		for name, arn := range readers.OIDCProviderARNs {
			arn.ApplyT(func(s string) string {
				mu.Lock()
				out.providerARNs[name] = s
				mu.Unlock()
				wg.Done()

				return s
			})
		}

		return nil
	}, pulumi.WithMocks("example", "stack", rec)))

	wg.Wait()

	var got []recorded

	for _, r := range rec.all {
		if !strings.HasPrefix(r.Type, "pulumi:providers:") {
			got = append(got, r)
		}
	}

	return got, out
}

func byKey(rs []recorded) map[string]recorded {
	out := map[string]recorded{}
	for _, r := range rs {
		out[r.Type+" "+r.Name] = r
	}

	return out
}

// The URN contract: kind, logical name and parent of everything registered.
func TestResourceSetAndLogicalNames(t *testing.T) {
	got, _ := run(t)

	want := map[string]string{
		KindClusterIdentity + " a-external-secrets":            "pulumi:pulumi:Stack",
		KindIAMRole + " a-external-secrets":                    "ClusterIdentity::a-external-secrets",
		KindIAMRolePolicy + " a-external-secrets-policy":       "ClusterIdentity::a-external-secrets",
		KindPodIdentityAssociation + " a-external-secrets-pia": "ClusterIdentity::a-external-secrets",
		KindReaders + " a-parameter-readers":                   "pulumi:pulumi:Stack",
		KindIAMRole + " a-app-config":                          "Readers::a-parameter-readers",
		KindIAMRolePolicy + " a-app-config-policy":             "Readers::a-parameter-readers",
		KindIAMRole + " a-app-credentials":                     "Readers::a-parameter-readers",
		KindIAMRolePolicy + " a-app-credentials-policy":        "Readers::a-parameter-readers",
		KindIAMRole + " b-app-config":                          "Readers::a-parameter-readers",
		KindIAMRolePolicy + " b-app-config-policy":             "Readers::a-parameter-readers",
		KindIAMRole + " c-app-config":                          "Readers::a-parameter-readers",
		KindIAMRolePolicy + " c-app-config-policy":             "Readers::a-parameter-readers",
		// Only b's provider is created: c names an existing one.
		KindOIDCProvider + " a-parameter-readers-b-oidc": "Readers::a-parameter-readers",
	}

	var names []string

	for _, r := range got {
		key := r.Type + " " + r.Name
		names = append(names, key)

		if parent, ok := want[key]; ok {
			assert.Contains(t, r.Parent, parent, "parent of %s", key)
		}
	}

	wantNames := make([]string, 0, len(want))
	for k := range want {
		wantNames = append(wantNames, k)
	}

	sort.Strings(names)
	sort.Strings(wantNames)
	assert.Equal(t, wantNames, names)
}

func TestProvidersFollowTheAccounts(t *testing.T) {
	got := byKey(func() []recorded { r, _ := run(t); return r }())

	cluster := got[KindIAMRole+" a-external-secrets"].Provider
	source := got[KindIAMRole+" a-app-config"].Provider

	assert.Contains(t, cluster, "::cluster::")
	assert.Contains(t, source, "::source::")
	assert.Equal(t, cluster, got[KindPodIdentityAssociation+" a-external-secrets-pia"].Provider)
	assert.Equal(t, source, got[KindIAMRolePolicy+" a-app-credentials-policy"].Provider)
}

func TestTheClusterIdentity(t *testing.T) {
	got, out := run(t)
	in := func(key string) resource.PropertyMap { return byKey(got)[key].Inputs }

	role := in(KindIAMRole + " a-external-secrets")
	assert.Equal(t, "a-external-secrets", role["name"].StringValue())
	assert.Equal(t, "arn:aws:iam::"+clusterAccount+":policy/example-boundary", role["permissionsBoundary"].StringValue())
	assert.Equal(t, "platform", role["tags"].ObjectValue()["owner"].StringValue())
	golden(t, "cluster-trust.json", role["assumeRolePolicy"].StringValue())

	policy := in(KindIAMRolePolicy + " a-external-secrets-policy")
	assert.Equal(t, ClusterPolicyName, policy["name"].StringValue())
	golden(t, "cluster-policy.json", policy["policy"].StringValue())

	// The defaults are the upstream chart's controller.
	pia := in(KindPodIdentityAssociation + " a-external-secrets-pia")
	assert.Equal(t, "a", pia["clusterName"].StringValue())
	assert.Equal(t, DefaultNamespace, pia["namespace"].StringValue())
	assert.Equal(t, DefaultServiceAccount, pia["serviceAccount"].StringValue())
	assert.Equal(t, region, pia["region"].StringValue())

	assert.Equal(t, "arn:aws:iam::mock:role/a-external-secrets", out.clusterRoleARN)
}

func TestTheReaders(t *testing.T) {
	got, out := run(t)
	in := func(key string) resource.PropertyMap { return byKey(got)[key].Inputs }

	for name, trust := range map[string]string{
		"a-app-config":      "reader-trust-pod-identity.json",
		"a-app-credentials": "reader-trust-pod-identity.json",
		"b-app-config":      "reader-trust-web-identity.json",
		"c-app-config":      "reader-trust-web-identity-existing.json",
	} {
		role := in(KindIAMRole + " " + name)
		assert.Equal(t, name, role["name"].StringValue())
		assert.Equal(t, "arn:aws:iam::"+sourceAccount+":policy/example-boundary", role["permissionsBoundary"].StringValue())
		golden(t, trust, role["assumeRolePolicy"].StringValue())

		policy := in(KindIAMRolePolicy + " " + name + "-policy")
		assert.Equal(t, name, policy["name"].StringValue())

		if strings.HasPrefix(name, "a-") {
			golden(t, name+".json", policy["policy"].StringValue())
		}
	}

	provider := in(KindOIDCProvider + " a-parameter-readers-b-oidc")
	assert.Equal(t, issuerB, provider["url"].StringValue())
	assert.Equal(t, []resource.PropertyValue{resource.NewProperty(DefaultAudience)}, provider["clientIdLists"].ArrayValue())
	assert.NotContains(t, provider, resource.PropertyKey("thumbprintLists"), "no thumbprints: IAM fetches them")
	assert.Equal(t, "platform", provider["tags"].ObjectValue()["owner"].StringValue())

	assert.Equal(t, map[string]string{
		"a-app-config":      "arn:aws:iam::mock:role/a-app-config",
		"a-app-credentials": "arn:aws:iam::mock:role/a-app-credentials",
		"b-app-config":      "arn:aws:iam::mock:role/b-app-config",
		"c-app-config":      "arn:aws:iam::mock:role/c-app-config",
	}, out.readerARNs)
	assert.Equal(t, map[string]string{
		"b": "arn:aws:iam::mock:oidc-provider/a-parameter-readers-b-oidc",
		"c": providerC,
	}, out.providerARNs, "a PodIdentity cluster has no provider")
}

// A role trusting a provider the component creates waits for it; IAM
// refuses a trust in a principal that does not exist yet.
func TestWebIdentityRolesWaitForTheirProvider(t *testing.T) {
	rec := &recorder{}
	deps := map[string][]string{}

	require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := awspulumi.NewProvider(ctx, "source", &awspulumi.ProviderArgs{})
		if err != nil {
			return err
		}

		_, err = NewReaders(ctx, readersArgs(p))

		return err
	}, pulumi.WithMocks("example", "stack", &depRecorder{recorder: rec, deps: deps})))

	assert.Contains(t, strings.Join(deps["b-app-config"], " "), "a-parameter-readers-b-oidc")
	assert.Empty(t, deps["a-app-config"])
	assert.Empty(t, deps["c-app-config"], "an existing provider is not a resource of this program")
}

type depRecorder struct {
	*recorder
	mu   sync.Mutex
	deps map[string][]string
}

func (r *depRecorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	if rpc := args.RegisterRPC; rpc != nil && args.TypeToken == KindIAMRole {
		r.mu.Lock()
		r.deps[args.Name] = rpc.GetDependencies()
		r.mu.Unlock()
	}

	return r.recorder.NewResource(args)
}

// What each policy grants, said in words rather than read off a golden.
func TestReaderPolicyIsLeastPrivilege(t *testing.T) {
	args := readersArgs(nil)

	exact, err := ReaderPolicy(args, Grant{Name: "r", Cluster: "a", Parameters: []string{"/app/token"}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"Version":"2012-10-17","Statement":[{"Sid":"ReadParameters","Effect":"Allow",
		"Action":["ssm:GetParameter","ssm:GetParameters"],
		"Resource":["arn:aws:ssm:`+region+`:`+sourceAccount+`:parameter/app/token"]}]}`, exact,
		"an exact grant: no GetParametersByPath, no wildcard, no KMS")

	prefix, err := ReaderPolicy(args, Grant{Name: "r", Cluster: "a", Parameters: []string{"/app/config/"}})
	require.NoError(t, err)
	assert.Contains(t, prefix, `"ssm:GetParametersByPath"`)
	assert.Contains(t, prefix, `"arn:aws:ssm:`+region+`:`+sourceAccount+`:parameter/app/config","arn:aws:ssm:`+region+`:`+sourceAccount+`:parameter/app/config/*"`)
	assert.NotContains(t, prefix, "kms:")

	for _, forbidden := range []string{"ssm:PutParameter", "ssm:DeleteParameter", "ssm:DescribeParameters", `"*"`, "parameter/*"} {
		assert.NotContains(t, prefix, forbidden)
	}

	withKey, err := ReaderPolicy(args, Grant{Name: "r", Cluster: "a", Parameters: []string{"/app/token"}, KMSKeyARN: keyARN})
	require.NoError(t, err)
	assert.Contains(t, withKey, `"kms:ViaService":"ssm.`+region+`.amazonaws.com"`)
	assert.Contains(t, withKey, `"kms:EncryptionContext:PARAMETER_ARN":["arn:aws:ssm:`+region+`:`+sourceAccount+`:parameter/app/token"]`)

	china := args
	china.Partition, china.Region, china.AccountID = "aws-cn", "cn-example-1", sourceAccount
	cn, err := ReaderPolicy(china, Grant{
		Name: "r", Cluster: "a", Parameters: []string{"/app/token"},
		KMSKeyARN: "arn:aws-cn:kms:cn-example-1:" + sourceAccount + ":key/k",
	})
	require.NoError(t, err)
	assert.Contains(t, cn, `"ssm.cn-example-1.amazonaws.com.cn"`)
	assert.Contains(t, cn, `"arn:aws-cn:ssm:cn-example-1:`+sourceAccount+`:parameter/app/token"`)
}

func TestReaderTrustFollowsTheClustersMode(t *testing.T) {
	args := readersArgs(nil)

	pod, err := ReaderTrustPolicy(args, args.Grants[0])
	require.NoError(t, err)
	assert.JSONEq(t, `{"Version":"2012-10-17","Statement":[{"Sid":"ExternalSecretsOperator","Effect":"Allow",
		"Principal":{"AWS":"`+esoRole+`"},"Action":["sts:AssumeRole","sts:TagSession"],
		"Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["eks-cluster-arn","eks-cluster-name",
		"kubernetes-namespace","kubernetes-service-account","kubernetes-pod-name","kubernetes-pod-uid"]}}}]}`, pod,
		"exactly the cluster's role, and no tag keys but Pod Identity's")

	web, err := ReaderTrustPolicy(args, args.Grants[2])
	require.NoError(t, err)
	assert.JSONEq(t, `{"Version":"2012-10-17","Statement":[{"Sid":"ExternalSecretsOperator","Effect":"Allow",
		"Principal":{"Federated":"arn:aws:iam::`+sourceAccount+`:oidc-provider/oidc.b.example.com"},
		"Action":["sts:AssumeRoleWithWebIdentity"],
		"Condition":{"StringEquals":{
			"oidc.b.example.com:sub":"system:serviceaccount:external-secrets:eso-b-app-config",
			"oidc.b.example.com:aud":"sts.amazonaws.com"}}}]}`, web,
		"one ServiceAccount's tokens, from the cluster's issuer, for the cluster's audience; no TagSession")

	existing, err := ReaderTrustPolicy(args, args.Grants[3])
	require.NoError(t, err)
	assert.Contains(t, existing, `"Federated":"`+providerC+`"`)
	assert.Contains(t, existing, `"issuer.example.com/clusters/c:sub":"system:serviceaccount:eso:c-app-config"`)
	assert.Contains(t, existing, `"issuer.example.com/clusters/c:aud":"example-audience"`)
}

func TestParameterEntries(t *testing.T) {
	args := readersArgs(nil).withDefaults()

	for entry, want := range map[string]parameter{
		"/app/token":   {resource: "app/token"},
		"token":        {resource: "token"},
		"/app/config/": {resource: "app/config/", prefix: true},
		"/a.b/c_d-e":   {resource: "a.b/c_d-e"},
		"arn:aws:ssm:" + region + ":" + sourceAccount + ":parameter/app/token":   {resource: "app/token"},
		"arn:aws:ssm:" + region + ":" + sourceAccount + ":parameter/app/config/": {resource: "app/config/", prefix: true},
	} {
		got, err := args.parseParameter(entry)
		require.NoError(t, err, entry)
		assert.Equal(t, want, got, entry)
	}

	for entry, why := range map[string]string{
		"":             "empty entry",
		"/":            "every parameter in the account",
		"//":           "every parameter in the account",
		"/app/*":       "no wildcards",
		"/app/to?en":   "no wildcards",
		"*":            "no wildcards",
		"app/token":    `starts with "/"`,
		"app/":         `starts with "/"`,
		"//app":        "empty path segment",
		"/app//token":  "empty path segment",
		"/app/to ken":  "not a parameter name",
		"/app/token\n": "not a parameter name",
		"arn:aws:ssm:" + region + ":" + clusterAccount + ":parameter/app/token": "not in this source's account and region",
		"arn:aws:ssm:eu-example-2:" + sourceAccount + ":parameter/app/token":    "not in this source's account and region",
		"arn:aws-cn:ssm:" + region + ":" + sourceAccount + ":parameter/app/x":   "not in this source's account and region",
		"arn:aws:ssm:" + region + ":" + sourceAccount + ":document/app":         "not an SSM parameter ARN",
		"arn:aws:secretsmanager:" + region + ":" + sourceAccount + ":secret:x":  "not an SSM parameter ARN",
		"arn:aws:ssm:" + region + ":" + sourceAccount + ":parameter/":           "every parameter in the account",
		"arn:aws:ssm:" + region + ":" + sourceAccount + ":parameter/app/*":      "no wildcards",
		"arn:nope": "is not an ARN",
	} {
		_, err := args.parseParameter(entry)
		require.Error(t, err, "%q must be refused", entry)
		assert.Contains(t, err.Error(), why, entry)
	}
}

func TestGrantRefusals(t *testing.T) {
	valid := Grant{Name: "r", Cluster: "a", Parameters: []string{"/app/token"}}

	for name, tc := range map[string]struct {
		edit func(*Grant)
		why  string
	}{
		"no parameters": {func(g *Grant) { g.Parameters = nil }, "Parameters is empty"},
		"twice":         {func(g *Grant) { g.Parameters = []string{"/a", "/a"} }, "listed twice"},
		"name and its arn": {func(g *Grant) {
			g.Parameters = []string{"/a", "arn:aws:ssm:" + region + ":" + sourceAccount + ":parameter/a"}
		}, "listed twice"},
		"under a prefix":      {func(g *Grant) { g.Parameters = []string{"/a/", "/a/b"} }, `covered by the prefix "/a/"`},
		"prefix after":        {func(g *Grant) { g.Parameters = []string{"/a/b/c", "/a/"} }, "covers"},
		"nested prefixes":     {func(g *Grant) { g.Parameters = []string{"/a/", "/a/b/"} }, "covered by the prefix"},
		"bad role name":       {func(g *Grant) { g.Name = "has space" }, "not an IAM role name"},
		"long role name":      {func(g *Grant) { g.Name = strings.Repeat("r", 65) }, "not an IAM role name"},
		"key alias":           {func(g *Grant) { g.KMSKeyARN = "arn:aws:kms:" + region + ":" + sourceAccount + ":alias/aws/ssm" }, "not a KMS key ARN"},
		"key wildcard":        {func(g *Grant) { g.KMSKeyARN = "arn:aws:kms:" + region + ":" + sourceAccount + ":key/*" }, "not a KMS key ARN"},
		"key in other region": {func(g *Grant) { g.KMSKeyARN = "arn:aws:kms:eu-example-2:" + sourceAccount + ":key/k" }, "region"},
		"key not an arn":      {func(g *Grant) { g.KMSKeyARN = "1234abcd" }, "not an ARN"},
		"too large": {func(g *Grant) {
			g.Parameters = nil
			for i := range 200 {
				g.Parameters = append(g.Parameters, fmt.Sprintf("/app/a-rather-long-parameter-name-%03d", i))
			}
		}, "over IAM's 10240"},
	} {
		t.Run(name, func(t *testing.T) {
			g := valid
			g.Parameters = append([]string(nil), valid.Parameters...)
			tc.edit(&g)

			_, err := ReaderPolicy(readersArgs(nil), g)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.why)
		})
	}

	// A key in another account is allowed: its key policy decides.
	g := valid
	g.KMSKeyARN = "arn:aws:kms:" + region + ":" + clusterAccount + ":key/k"
	_, err := ReaderPolicy(readersArgs(nil), g)
	require.NoError(t, err)
}

// The trust's half of a grant: its cluster, and the ServiceAccount the
// cluster's mode requires or refuses.
func TestTrustRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*ReadersArgs)
		why  string
	}{
		"unknown cluster": {func(a *ReadersArgs) { a.Grants[0].Cluster = "z" }, `grant.Cluster "z" is not in args.Clusters`},
		"no cluster":      {func(a *ReadersArgs) { a.Grants[0].Cluster = "" }, `grant.Cluster "" is not in args.Clusters`},
		"ServiceAccount on a PodIdentity cluster": {func(a *ReadersArgs) {
			a.Grants[0].ServiceAccount = &ServiceAccount{Name: "x"}
		}, "a WebIdentity grant on a PodIdentity cluster"},
		"no ServiceAccount on a WebIdentity cluster": {func(a *ReadersArgs) { a.Grants[2].ServiceAccount = nil }, "grant.ServiceAccount is required"},
		"bad ServiceAccount name": {func(a *ReadersArgs) {
			a.Grants[2].ServiceAccount = &ServiceAccount{Name: "Not_A_Name"}
		}, "not a Kubernetes ServiceAccount name"},
		"bad namespace": {func(a *ReadersArgs) {
			a.Grants[2].ServiceAccount = &ServiceAccount{Namespace: "a.b", Name: "x"}
		}, "not a Kubernetes namespace name"},
		"both modes' settings": {func(a *ReadersArgs) {
			a.Clusters[0].WebIdentity = &WebIdentity{IssuerURL: "https://other.example.com"}
		}, "mutually exclusive"},
		"no mode":                {func(a *ReadersArgs) { a.Clusters[0].Mode = "" }, "there is no default"},
		"unknown mode":           {func(a *ReadersArgs) { a.Clusters[0].Mode = "IRSA" }, `"IRSA" is not an identity mode`},
		"mode without settings":  {func(a *ReadersArgs) { a.Clusters[0].PodIdentity = nil }, "Mode is PodIdentity but PodIdentity is not set"},
		"web settings, pod mode": {func(a *ReadersArgs) { a.Clusters[1].Mode = PodIdentityMode }, "Mode is PodIdentity but PodIdentity is not set"},
		"pod settings, web mode": {func(a *ReadersArgs) {
			a.Clusters[0] = Cluster{Name: "a", Mode: WebIdentityMode, PodIdentity: &PodIdentity{RoleARN: esoRole}}
		}, "Mode is WebIdentity but WebIdentity is not set"},
		"wildcard principal": {func(a *ReadersArgs) {
			a.Clusters[0].PodIdentity.RoleARN = "arn:aws:iam::" + clusterAccount + ":role/eso-*"
		}, "no wildcards"},
		"user principal": {func(a *ReadersArgs) {
			a.Clusters[0].PodIdentity.RoleARN = "arn:aws:iam::" + clusterAccount + ":user/someone"
		}, "not a role ARN"},
		"account principal": {func(a *ReadersArgs) { a.Clusters[0].PodIdentity.RoleARN = "arn:aws:iam::" + clusterAccount + ":root" }, "not a role ARN"},
		"other partition": {func(a *ReadersArgs) {
			a.Clusters[0].PodIdentity.RoleARN = "arn:aws-cn:iam::" + clusterAccount + ":role/eso"
		}, "not in partition aws"},
		"http issuer":       {func(a *ReadersArgs) { a.Clusters[1].WebIdentity.IssuerURL = "http://oidc.b.example.com" }, "an issuer is an https URL"},
		"slash issuer":      {func(a *ReadersArgs) { a.Clusters[1].WebIdentity.IssuerURL = issuerB + "/" }, "no trailing slash"},
		"port issuer":       {func(a *ReadersArgs) { a.Clusters[1].WebIdentity.IssuerURL = "https://oidc.b.example.com:8443" }, "no port"},
		"upper-case issuer": {func(a *ReadersArgs) { a.Clusters[1].WebIdentity.IssuerURL = "https://OIDC.b.example.com" }, "write the host in lower case"},
		"query issuer":      {func(a *ReadersArgs) { a.Clusters[1].WebIdentity.IssuerURL = issuerB + "?x=1" }, "no query"},
		"wildcard audience": {func(a *ReadersArgs) { a.Clusters[1].WebIdentity.Audience = "*" }, "empty or a pattern"},
		"provider of another issuer": {func(a *ReadersArgs) {
			a.Clusters[2].WebIdentity.ProviderARN = "arn:aws:iam::" + sourceAccount + ":oidc-provider/oidc.b.example.com"
		}, "is not this account's provider for"},
		"provider in another account": {func(a *ReadersArgs) {
			a.Clusters[2].WebIdentity.ProviderARN = "arn:aws:iam::" + clusterAccount + ":oidc-provider/issuer.example.com/clusters/c"
		}, "is not this account's provider for"},
		"thumbprints with an existing provider": {func(a *ReadersArgs) {
			a.Clusters[2].WebIdentity.Thumbprints = []string{strings.Repeat("a", 40)}
		}, "an existing one keeps its own"},
		"bad thumbprint": {func(a *ReadersArgs) { a.Clusters[1].WebIdentity.Thumbprints = []string{"abc"} }, "not a SHA-1 thumbprint"},
	} {
		t.Run(name, func(t *testing.T) {
			args := readersArgs(nil)
			args.Clusters = clusters()
			args.Grants = grants()
			tc.edit(&args)

			var errs []string

			for _, g := range args.Grants {
				if _, err := ReaderTrustPolicy(args, g); err != nil {
					errs = append(errs, err.Error())
				}
			}

			require.NotEmpty(t, errs)
			assert.Contains(t, strings.Join(errs, "\n"), tc.why)
		})
	}
}

func TestSourceRoleRefusals(t *testing.T) {
	for role, why := range map[string]string{
		"arn:aws:iam::" + sourceAccount + ":role/*":                          "no wildcards",
		"arn:aws:iam::" + sourceAccount + ":role/eso-reader-*":               "no wildcards",
		"arn:aws:iam::" + sourceAccount + ":role/path/*":                     "no wildcards",
		"arn:aws:iam::" + sourceAccount + ":role/a?":                         "no wildcards",
		"arn:aws:iam::" + sourceAccount + ":role//a":                         "empty path segment",
		"arn:aws:iam::*:role/eso":                                            "12-digit",
		"arn:*:iam::" + sourceAccount + ":role/eso":                          "partition",
		"arn:aws:iam::" + sourceAccount + ":user/eso":                        "not a role ARN",
		"arn:aws:sts::" + sourceAccount + ":role/eso":                        "not an IAM ARN",
		"arn:aws:iam:" + region + ":" + sourceAccount + ":role/eso":          "has no region",
		"arn:aws:iam::" + sourceAccount + ":role/":                           "not a role ARN",
		"arn:aws:iam::" + sourceAccount + ":role/path/":                      "role name",
		"arn:aws:iam::" + sourceAccount + ":role/" + strings.Repeat("r", 65): "role name",
	} {
		_, err := parseRoleARN(role)
		require.Error(t, err, "%q must be refused", role)
		assert.Contains(t, err.Error(), why, role)
	}

	for _, role := range []string{
		"arn:aws:iam::" + sourceAccount + ":role/eso",
		"arn:aws:iam::" + sourceAccount + ":role/path/to/eso",
		"arn:aws-cn:iam::" + sourceAccount + ":role/eso",
	} {
		_, err := parseRoleARN(role)
		require.NoError(t, err, role)
	}
}

// Invalid arguments register nothing at all, and say what is wrong.
func TestInvalidArgsRegisterNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		build func(ctx *pulumi.Context, p pulumi.ProviderResource) error
		why   string
	}{
		"cluster without source roles": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := clusterArgs(p)
			a.SourceRoles = nil
			_, err := NewClusterIdentity(ctx, a)

			return err
		}, "SourceRoles is empty"},
		"cluster with a duplicate source role": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := clusterArgs(p)
			a.SourceRoles = append(a.SourceRoles, a.SourceRoles[0])
			_, err := NewClusterIdentity(ctx, a)

			return err
		}, "duplicate"},
		"cluster in another account": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := clusterArgs(p)
			a.AccountID = sourceAccount
			_, err := NewClusterIdentity(ctx, a)

			return err
		}, "is not in AccountID"},
		"cluster in another region": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := clusterArgs(p)
			a.Region = "eu-example-2"
			_, err := NewClusterIdentity(ctx, a)

			return err
		}, "is not in Region"},
		"cluster ARN not a cluster": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := clusterArgs(p)
			a.ClusterARN = esoRole
			_, err := NewClusterIdentity(ctx, a)

			return err
		}, "not an EKS cluster ARN"},
		"cluster without a mode": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := clusterArgs(p)
			a.Mode = ""
			_, err := NewClusterIdentity(ctx, a)

			return err
		}, "args.Mode is empty"},
		"cluster in WebIdentity mode": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := clusterArgs(p)
			a.Mode = WebIdentityMode
			_, err := NewClusterIdentity(ctx, a)

			return err
		}, "no identity of its own in AWS"},
		"cluster without a provider": {func(ctx *pulumi.Context, _ pulumi.ProviderResource) error {
			_, err := NewClusterIdentity(ctx, clusterArgs(nil))

			return err
		}, "Provider is nil"},
		"cluster with a bad boundary": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := clusterArgs(p)
			a.PermissionsBoundary = "boundary"
			_, err := NewClusterIdentity(ctx, a)

			return err
		}, "PermissionsBoundary"},
		"readers without grants": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := readersArgs(p)
			a.Grants = nil
			_, err := NewReaders(ctx, a)

			return err
		}, "Grants is empty"},
		"readers with a duplicate grant": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := readersArgs(p)
			a.Grants = append(a.Grants, a.Grants[0])
			_, err := NewReaders(ctx, a)

			return err
		}, `duplicate name "a-app-config"`},
		"readers without an account": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := readersArgs(p)
			a.AccountID = ""
			_, err := NewReaders(ctx, a)

			return err
		}, "AccountID"},
		"readers without a region": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := readersArgs(p)
			a.Region = ""
			_, err := NewReaders(ctx, a)

			return err
		}, "Region"},
		"readers with one bad grant": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := readersArgs(p)
			a.Grants[1].Parameters = []string{"/"}
			_, err := NewReaders(ctx, a)

			return err
		}, "Grants[1] (a-app-credentials)"},
		"readers with an unused cluster": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := readersArgs(p)
			a.Clusters = append(a.Clusters, Cluster{Name: "d", Mode: PodIdentityMode, PodIdentity: &PodIdentity{RoleARN: esoRole}})
			_, err := NewReaders(ctx, a)

			return err
		}, `no grant names cluster "d"`},
		"readers with a duplicate cluster": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := readersArgs(p)
			a.Clusters = append(a.Clusters, a.Clusters[0])
			_, err := NewReaders(ctx, a)

			return err
		}, `duplicate name "a"`},
		"readers with one issuer twice": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := readersArgs(p)
			a.Clusters = append(a.Clusters, Cluster{Name: "d", Mode: WebIdentityMode, WebIdentity: &WebIdentity{IssuerURL: issuerB}})
			a.Grants = append(a.Grants, Grant{Name: "d", Cluster: "d", ServiceAccount: &ServiceAccount{Name: "d"}, Parameters: []string{"/d"}})
			_, err := NewReaders(ctx, a)

			return err
		}, "IAM registers one provider per issuer"},
		"readers with one ServiceAccount for two grants": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := readersArgs(p)
			a.Grants = append(a.Grants, Grant{
				Name: "b-other", Cluster: "b", ServiceAccount: &ServiceAccount{Namespace: DefaultNamespace, Name: "eso-b-app-config"}, Parameters: []string{"/other"},
			})
			_, err := NewReaders(ctx, a)

			return err
		}, "is grant b-app-config's already"},
		"cluster with a pattern source role": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := clusterArgs(p)
			a.SourceRoles = []string{"arn:aws:iam::" + sourceAccount + ":role/eso-reader-*"}
			_, err := NewClusterIdentity(ctx, a)

			return err
		}, "no wildcards"},
		"cluster with a source role in another partition": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := clusterArgs(p)
			a.SourceRoles = []string{"arn:aws-cn:iam::" + sourceAccount + ":role/eso"}
			_, err := NewClusterIdentity(ctx, a)

			return err
		}, "not in the cluster's partition"},
		"cluster with too many source roles": {func(ctx *pulumi.Context, p pulumi.ProviderResource) error {
			a := clusterArgs(p)
			a.SourceRoles = nil
			for i := range 300 {
				a.SourceRoles = append(a.SourceRoles, fmt.Sprintf("arn:aws:iam::%s:role/reader-%03d", sourceAccount, i))
			}
			_, err := NewClusterIdentity(ctx, a)

			return err
		}, "over IAM's 10240"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}
			require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error {
				p, err := awspulumi.NewProvider(ctx, "p", &awspulumi.ProviderArgs{})
				if err != nil {
					return err
				}

				err = tc.build(ctx, p)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.why)

				return nil
			}, pulumi.WithMocks("example", "stack", rec)))

			for _, r := range rec.all {
				assert.True(t, strings.HasPrefix(r.Type, "pulumi:providers:"), "registered %s", r.Type)
			}
		})
	}
}

// golden holds a policy document, indented, to testdata/<name>: what a
// reviewer reads when a policy changes. UPDATE_GOLDEN=1 rewrites it.
func golden(t *testing.T, name, doc string) {
	t.Helper()

	var got bytes.Buffer
	require.NoError(t, json.Indent(&got, []byte(doc), "", "  "))
	got.WriteByte('\n')

	path := filepath.Join("testdata", name)

	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(path, got.Bytes(), 0o644))

		return
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err, "UPDATE_GOLDEN=1 writes it")
	require.Equal(t, string(want), got.String(), "%s differs; review it and rerun with UPDATE_GOLDEN=1", path)
}
