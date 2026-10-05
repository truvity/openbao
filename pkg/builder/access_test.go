package builder_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/builder"
	"github.com/truvity/secrets/pkg/model"
)

func rulesFor(t *testing.T, access builder.Access, projects ...builder.Project) []model.Rule {
	t.Helper()

	rules, err := access.Rules("kv", projects...)
	require.NoError(t, err)

	return rules
}

func TestKVClauses(t *testing.T) {
	read := rulesFor(t, builder.Access{builder.Read("app")})
	assert.Equal(t, []model.Rule{
		{Path: "kv/data/app/*", Capabilities: []string{"read"}},
		{Path: "kv/metadata/app/*", Capabilities: []string{"list", "read"}},
	}, read)

	write := rulesFor(t, builder.Access{builder.Write("")})
	assert.Equal(t, []model.Rule{
		{Path: "kv/data/*", Capabilities: []string{"create", "delete", "patch", "read", "update"}},
		{Path: "kv/metadata/*", Capabilities: []string{"delete", "list", "read"}},
	}, write)

	push := rulesFor(t, builder.Access{builder.Push("app")})
	assert.Equal(t, []model.Rule{
		{Path: "kv/data/app/*", Capabilities: []string{"create", "read", "update"}},
		{Path: "kv/metadata/app/*", Capabilities: []string{"create", "read", "update"}},
	}, push, "a push job reads, then writes: it never lists, patches or deletes")

	assert.Equal(t, []model.Rule{{Path: "kv/data/app/key", Capabilities: []string{"read"}}},
		rulesFor(t, builder.Access{builder.Key("app/key")}))
}

// A project's own namespace mount is the same grant, on another path.
func TestProjectClausesAreTheSharedMountsTwin(t *testing.T) {
	project := builder.Project{Name: "billing", KV: model.KVMount{Path: "kv"}}

	for _, write := range []bool{false, true} {
		shared := rulesFor(t, builder.Access{builder.Secrets("billing", write)})
		twin := rulesFor(t, builder.Access{builder.Secrets("billing", write)}, project)

		require.Len(t, twin, len(shared))

		for i := range shared {
			assert.Equal(t, shared[i].Capabilities, twin[i].Capabilities, "write=%v rule %d", write, i)
		}

		assert.Equal(t, "billing/kv/data/*", twin[0].Path)
		assert.Equal(t, "billing/kv/metadata/*", twin[1].Path)
		assert.Equal(t, "kv/data/billing/*", shared[0].Path)
	}
}

func TestSignClauses(t *testing.T) {
	assert.Equal(t, []model.Rule{{Path: "ssh/sign/user", Capabilities: []string{"update"}}},
		rulesFor(t, builder.Access{builder.Sign("ssh", "user")}))

	assert.Equal(t, []model.Rule{{Path: "ssh/sign/ci", Capabilities: []string{"update"}, DeniedParameters: []string{"critical_options"}}},
		rulesFor(t, builder.Access{builder.SignForced("ssh", "ci")}))
}

func TestSystemPathRules(t *testing.T) {
	assert.Equal(t, []string{"read", "sudo"}, builder.PluginCatalogRule("auth", "aws").Capabilities)
	assert.Equal(t, "sys/plugins/catalog/auth/aws", builder.PluginCatalogRule("auth", "aws").Path)
	assert.Equal(t, "sys/storage/raft/snapshot", builder.SnapshotRule().Path)
	assert.Equal(t, []string{"list"}, builder.NamespacesRule().Capabilities)
	assert.Equal(t, "sys/generate-root-token/attempt", builder.RootGenerationRule().Path)
}

func TestAccessRefusals(t *testing.T) {
	for _, test := range []struct {
		name   string
		access builder.Access
		want   string
	}{
		{"no op", builder.Access{{}}, "no op"},
		{"an unknown op", builder.Access{{Op: "own"}}, "unknown"},
		{"a key with no path", builder.Access{{Op: builder.OpKey}}, "no path"},
		{"a field the op ignores", builder.Access{{Op: builder.OpKey, Path: "a/b", Project: "x"}}, "does not read"},
		{"a sign with no role", builder.Access{{Op: builder.OpSign, Mount: "ssh"}}, "no role"},
		{"a project that is a path", builder.Access{builder.Secrets("a/b", false)}, "not one name"},
		{"a wildcard canary", builder.Access{builder.Canary("dev", "kv", "*")}, "not one secret path"},
		{"an empty rules clause", builder.Access{{Op: builder.OpRules}}, "no rule"},
		{
			"one path twice, differently",
			builder.Access{builder.Key("a"), builder.Rules(model.Rule{Path: "kv/data/a", Capabilities: []string{"update"}})},
			"twice with different capabilities",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.access.Rules("kv")
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.want)
		})
	}

	_, err := builder.Access{builder.Read("a")}.Rules("")
	require.Error(t, err, "a KV clause needs a KV mount")
}

// The same stanza twice is one stanza; the first is kept.
func TestAnExactRepeatIsDropped(t *testing.T) {
	rules := rulesFor(t, builder.Access{builder.Key("a"), builder.Key("a"), builder.Key("b")})
	assert.Equal(t, []string{"kv/data/a", "kv/data/b"}, []string{rules[0].Path, rules[1].Path})
}
