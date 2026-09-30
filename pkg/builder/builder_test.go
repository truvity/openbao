package builder_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/openbao/pkg/builder"
	"github.com/truvity/openbao/pkg/model"
)

// example is the authored contract of a small estate (testdata/spec.yaml),
// built.
func example(t *testing.T) (*builder.Spec, *builder.Built) {
	t.Helper()

	file, err := os.Open("testdata/spec.yaml")
	require.NoError(t, err)

	t.Cleanup(func() { _ = file.Close() })

	spec, err := builder.Load(file)
	require.NoError(t, err)

	built, err := spec.Build()
	require.NoError(t, err)

	return spec, built
}

// TestGoldenDesiredState holds the whole desired state the example spec
// derives to testdata/desired.yaml: what a reviewer reads when a spec
// changes. UPDATE_GOLDEN=1 rewrites it.
func TestGoldenDesiredState(t *testing.T) {
	_, built := example(t)

	var got bytes.Buffer

	encoder := yaml.NewEncoder(&got)
	encoder.SetIndent(2)
	require.NoError(t, encoder.Encode(built.Model))

	const golden = "testdata/desired.yaml"

	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.WriteFile(golden, got.Bytes(), 0o644))

		return
	}

	want, err := os.ReadFile(golden)
	require.NoError(t, err, "UPDATE_GOLDEN=1 writes it")
	require.Equal(t, string(want), got.String(), "the derived state differs from %s; review it and rerun with UPDATE_GOLDEN=1", golden)
}

func TestTheExampleIsAValidDesiredState(t *testing.T) {
	_, built := example(t)

	require.NoError(t, built.Model.Validate())
	require.Len(t, built.Environments, len(built.Model.Namespaces))

	// The two views share nothing: editing one leaves the other alone.
	built.Environments[0].Policies[0].Name = "edited"
	assert.NotEqual(t, "edited", built.Model.Namespaces[0].Policies[0].Name)
}

func namespaceOf(t *testing.T, built *builder.Built, name string) model.Namespace {
	t.Helper()

	for i := range built.Model.Namespaces {
		if built.Model.Namespaces[i].Name == name {
			return built.Model.Namespaces[i]
		}
	}

	t.Fatalf("no namespace %q", name)

	return model.Namespace{}
}

func policyOf(t *testing.T, namespace model.Namespace, name string) model.Policy {
	t.Helper()

	for _, policy := range namespace.Policies {
		if policy.Name == name {
			return policy
		}
	}

	t.Fatalf("namespace %q has no policy %q", namespace.Name, name)

	return model.Policy{}
}

func paths(rules []model.Rule) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.Path)
	}

	return out
}

// A policy and a group's policies are sorted by name, and the host logins'
// policies follow them in declaration order.
func TestPoliciesAreSortedAndHostLoginsFollow(t *testing.T) {
	_, built := example(t)
	dev := namespaceOf(t, built, "dev")

	names := make([]string, 0, len(dev.Policies))
	for _, policy := range dev.Policies {
		names = append(names, policy.Name)
	}

	assert.Equal(t, "edge-host-sign", names[len(names)-1], "the host login's policy follows the sorted ones")
	assert.IsIncreasing(t, names[:len(names)-1])

	groups := make([]string, 0, len(dev.Groups))
	for _, group := range dev.Groups {
		groups = append(groups, group.Name)
	}

	assert.IsIncreasing(t, groups)
}

// The environment's authors, and only they, reach a project through the
// namespace it has, and reach one without a namespace through the shared
// mount.
func TestSecretsFollowTheProjectsNamespace(t *testing.T) {
	_, built := example(t)
	dev := namespaceOf(t, built, "dev")

	assert.Equal(t,
		[]string{"billing/kv/data/*", "billing/kv/metadata/*"},
		paths(policyOf(t, dev, "dev:billing:deployer").Rules), "a project with a namespace is reached through it")
	assert.Equal(t,
		[]string{"kv/data/search/*", "kv/metadata/search/*"},
		paths(policyOf(t, dev, "dev:search:viewer").Rules), "a project without one keeps its prefix in the shared mount")

	// The writer reaches everything: the shared mount, then each project's
	// own.
	assert.Equal(t,
		[]string{"kv/data/*", "kv/metadata/*", "billing/kv/data/*", "billing/kv/metadata/*"},
		paths(policyOf(t, dev, "dev:kv:writer").Rules))

	assert.Equal(t, []string{"kv/data/*", "kv/metadata/*"}, paths(policyOf(t, namespaceOf(t, built, "prod"), "prod:kv:writer").Rules))

	require.Len(t, dev.Projects, 1)
	assert.Equal(t, "billing", dev.Projects[0].Name)
}

// A group is admitted through both doors; a job's group through the first
// alone, since a job has no browser.
func TestGroupDoors(t *testing.T) {
	_, built := example(t)

	for _, group := range namespaceOf(t, built, "dev").Groups {
		assert.Equal(t, []string{"jwt-roster", "oidc"}, group.Doors, group.Name)
	}

	hub := namespaceOf(t, built, "hub")
	require.Len(t, hub.Groups, 2)

	for _, group := range hub.Groups {
		if group.Name == "hub:ci:release" {
			assert.Equal(t, []string{"jwt-roster"}, group.Doors)
			assert.Equal(t, []string{"hub:ci:deploy-key"}, group.Policies)
			assert.Equal(t, []string{"kv/data/ci/deploy-key"}, paths(policyOf(t, hub, "hub:ci:deploy-key").Rules))
		}
	}
}

// A workload's role carries its policy directly, on the mount of the cluster
// that mints its tokens, and a mount nobody logs in on is not declared.
func TestWorkloadsAndOptionalTrusts(t *testing.T) {
	_, built := example(t)

	dev := namespaceOf(t, built, "dev")

	var mounts []string
	for _, mount := range dev.Auth {
		mounts = append(mounts, mount.Path)
	}

	assert.Equal(t, []string{"jwt-dev", "jwt-hub", "jwt-roster", "oidc"}, mounts)

	var prod []string
	for _, mount := range namespaceOf(t, built, "prod").Auth {
		prod = append(prod, mount.Path)
	}

	assert.Equal(t, []string{"jwt-prod", "jwt-roster", "oidc"}, prod, "the hub's mount admits nobody in prod, so it is not there")

	runner := dev.Auth[0].Roles[1]
	assert.Equal(t, "runner", runner.Name)
	assert.Equal(t, "system:serviceaccount:runners:runner", runner.BoundSubject)
	assert.Equal(t, []string{"dev:ssh:user"}, runner.Policies)
	assert.Equal(t, []string{model.RosterAudience}, runner.BoundAudiences)
	assert.Equal(t, model.RosterUserClaim, runner.UserClaim)
	assert.Equal(t, "15m", runner.TTL)
}

// Each SSH user role signs for one account; a role that forces a command
// grants no extension and its policy denies critical_options.
func TestSSHRolesAndTheirPolicies(t *testing.T) {
	_, built := example(t)
	dev := namespaceOf(t, built, "dev")

	require.Len(t, dev.SSH, 1)
	require.Len(t, dev.SSH[0].Roles, 2)

	user, ci := dev.SSH[0].Roles[0], dev.SSH[0].Roles[1]
	assert.Equal(t, []string{"permit-pty"}, user.Extensions)
	assert.Empty(t, ci.Extensions)
	assert.Equal(t, "run-job --stdio", ci.ForceCommand)

	assert.Equal(t, []string{"ssh/sign/user"}, paths(policyOf(t, dev, "dev:ssh:user").Rules))

	forced := policyOf(t, dev, "dev:ssh:ci").Rules
	require.Len(t, forced, 1)
	assert.Equal(t, []string{"critical_options"}, forced[0].DeniedParameters)
	assert.Equal(t, []string{model.CapUpdate}, forced[0].Capabilities)

	require.Len(t, dev.SSHHost, 1)
	require.Len(t, dev.SSHHost[0].Roles, 2, "the declared role, then the host login's")
	assert.Equal(t, "builder", dev.SSHHost[0].Roles[0].Name)
	assert.True(t, dev.SSHHost[0].Roles[0].AllowBareDomains)

	edge := dev.SSHHost[0].Roles[1]
	assert.Equal(t, "edge", edge.Name)
	assert.Equal(t, []string{"edge.example.net"}, edge.AllowedDomains)
	assert.True(t, edge.AllowSubdomains)
	assert.False(t, edge.AllowBareDomains)
}

// A host login's role is bound to the fleet's instance role by its ARN's
// text, and lives as long as one signature needs.
func TestHostLogins(t *testing.T) {
	_, built := example(t)
	dev := namespaceOf(t, built, "dev")

	require.Len(t, dev.AWSAuth, 1)

	mount := dev.AWSAuth[0]
	assert.Equal(t, "aws", mount.Path)
	assert.Equal(t, "openbao-dev", mount.IAMServerIDHeaderValue)
	assert.Equal(t, "v0.1.1", mount.PluginVersion)
	require.Len(t, mount.Roles, 1)
	assert.Equal(t, []string{"arn:aws:iam::111122223333:role/dev-edge"}, mount.Roles[0].BoundIAMPrincipalARNs)
	assert.False(t, mount.Roles[0].ResolveAWSUniqueIDs)
	assert.Equal(t, "5m", mount.Roles[0].TTL)
	assert.Equal(t, "5m", mount.Roles[0].MaxTTL)
	assert.Equal(t, []string{"edge-host-sign"}, mount.Roles[0].Policies)
	assert.Equal(t, []string{"ssh-host/sign/edge"}, paths(policyOf(t, dev, "edge-host-sign").Rules))
}

// The root namespace holds the jobs' mount, the web UI's door and the
// operators-only mount; the operators' door is the bootstrap's.
func TestRoot(t *testing.T) {
	_, built := example(t)

	root := built.Model.Root

	var mounts []string
	for _, mount := range root.Auth {
		mounts = append(mounts, mount.Path)
	}

	assert.Equal(t, []string{"jwt-hub", "oidc"}, mounts)
	require.Len(t, root.KV, 1)
	assert.Equal(t, "kv-operator", root.KV[0].Path)

	require.Len(t, built.Model.Bootstrap.Auth, 1)
	assert.Equal(t, "jwt-roster", built.Model.Bootstrap.Auth[0].Path)
	assert.Equal(t, "15m", built.Model.Bootstrap.Auth[0].Roles[0].TTL)
	assert.Equal(t, []string{"operators"}, []string{built.Model.Bootstrap.Groups[0].Name})

	assert.Equal(t, []string{"operators"}, []string{built.RootUI.Groups[0].Name})
	assert.Equal(t, []string{"oidc"}, built.RootUI.Groups[0].Doors)

	check := policyOf(t, built.RootJobs, "restore-check")
	assert.Equal(t, []string{
		"sys/namespaces",
		"pki-root/cert/ca", "pki-root/issuer/example-root/json",
		"hub/kv/data/canary", "dev/kv/data/canary", "prod/kv/data/canary",
		"dev/pki/cert/ca", "dev/pki/issuer/example-dev/json", "dev/pki/issuer/example-dev-2/json",
	}, paths(check.Rules), "a stanza written twice is written once")

	assert.Equal(t, "builder example", built.Model.Identity.Metadata["source"])
	assert.Equal(t, "jwt-roster", built.Model.Identity.PrimaryDoor)
}

func specWith(t *testing.T, edit func(*builder.Spec)) error {
	t.Helper()

	spec, _ := example(t)
	edit(spec)

	_, err := spec.Build()

	return err
}

func TestBuildRefuses(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*builder.Spec)
		want string
	}{
		{"no issuer", func(s *builder.Spec) { s.Roster.Issuer = "" }, "no roster issuer"},
		{"no operators", func(s *builder.Spec) { s.Operators = "" }, "no operators group"},
		{"an environment declared twice", func(s *builder.Spec) { s.Environments = append(s.Environments, s.Environments[0]) }, "declared twice"},
		{"a mount with no issuer", func(s *builder.Spec) { s.Environments[1].Trusts[0].Issuer = "" }, "has no issuer"},
		{"a workload with no subject", func(s *builder.Spec) { s.Environments[1].Trusts[0].Workloads[0].Subject = "" }, "no role or no subject"},
		{
			"a workload naming a policy nobody declares",
			func(s *builder.Spec) { s.Environments[1].Trusts[0].Workloads[1].Policy = "dev:ssh:nobody" },
			"which nothing declares",
		},
		{"a workload with a role beyond the ceiling", func(s *builder.Spec) { s.Environments[1].SSH.Shape.UserMaxTTL = "2h" }, "credential ceiling"},
		{"an ssh role for root", func(s *builder.Spec) { s.Environments[1].SSH.User.Roles[0].Principal = "root" }, "root"},
		{"a host login with no host CA", func(s *builder.Spec) { s.Environments[1].SSH.Host = nil }, "no SSH host CA"},
		{"a host login with no mount", func(s *builder.Spec) { s.Environments[1].HostAuth = nil }, "no AWS auth mount"},
		{"a host login with no ARN", func(s *builder.Spec) { s.Environments[1].HostLogins[0].InstanceRoleARN = "" }, "no instance role ARN"},
		{"a secret inside a reserved prefix", func(s *builder.Spec) { s.Environments[0].Secrets[0].Path = "uploads/key" }, "inside uploader's prefix"},
		{"a secret with no key", func(s *builder.Spec) { s.Environments[0].Secrets[0].Path = "ci" }, "not <prefix>/<key>"},
		{"a grant with an unknown op", func(s *builder.Spec) { s.Environments[1].Grants[0].Access = builder.Access{{Op: "own"}} }, `op "own" is unknown`},
		{"a grant with no name", func(s *builder.Spec) { s.Environments[1].Grants[0].Name = "" }, "has no name"},
		{"a project with no KV mount", func(s *builder.Spec) { s.Environments[1].Projects[0].KV.Path = "" }, "no KV mount"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := specWith(t, test.edit)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.want)
		})
	}
}

func TestLoadRefusesWhatItDoesNotKnow(t *testing.T) {
	_, err := builder.Load(strings.NewReader("operators: ops\nbogus: 1\n"))
	require.Error(t, err)

	_, err = builder.Load(strings.NewReader("operators: a\n---\noperators: b\n"))
	require.Error(t, err)
}

// The plugins a spec names join the desired state as they are, validated.
func TestPluginsJoinTheDesiredState(t *testing.T) {
	spec, _ := example(t)

	plugin := model.Plugin{Type: "auth", Name: "example", Command: "auth-example", SHA256: strings.Repeat("ab", 32)}
	spec.Plugins = []model.Plugin{plugin}

	built, err := spec.Build()
	require.NoError(t, err)
	assert.Equal(t, []model.Plugin{plugin}, built.Model.Plugins)

	spec.Plugins[0].SHA256 = "not a checksum"
	_, err = spec.Build()
	require.Error(t, err)
}
