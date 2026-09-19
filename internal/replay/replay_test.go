package replay

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnakeCase(t *testing.T) {
	for from, to := range map[string]string{
		"allowedDomainsTemplate":        "allowed_domains_template",
		"oidcDiscoveryUrl":              "oidc_discovery_url",
		"basicConstraintsValidForNonCa": "basic_constraints_valid_for_non_ca",
		"ttl":                           "ttl",
	} {
		assert.Equal(t, to, snakeCase(from))
	}
}

// The path takes the inputs it names; the body gets the rest, snake-cased,
// and never the namespace, which travels as a header.
func TestPathFrom(t *testing.T) {
	path, body := pathFrom("{backend}/roles/{name}", map[string]any{
		"backend": "pki", "name": "db-client", "namespace": "dev", "keyBits": 384, "issuerRef": "example",
	})

	assert.Equal(t, "pki/roles/db-client", path)
	assert.Equal(t, map[string]any{"key_bits": 384, "issuer_ref": "example"}, body)
}

// A placeholder that is a prefix of another never matches inside it.
func TestSubstituteLongestFirst(t *testing.T) {
	values := map[string]string{"dev-auth-jwt#accessor": "short", "dev-auth-jwt-roster#accessor": "long"}

	got := substitute(map[string]any{"a": []any{"{{identity.entity.aliases.dev-auth-jwt-roster#accessor.name}}"}}, values)
	assert.Equal(t, map[string]any{"a": []any{"{{identity.entity.aliases.long.name}}"}}, got)
}

func TestOrdered(t *testing.T) {
	out, err := ordered([]Resource{
		{Name: "alias", DependsOn: []string{"group", "door"}},
		{Name: "group", DependsOn: []string{"ns"}},
		{Name: "door", DependsOn: []string{"ns"}},
		{Name: "ns"},
	})
	require.NoError(t, err)

	var names []string
	for _, r := range out {
		names = append(names, r.Name)
	}

	assert.Equal(t, []string{"ns", "group", "door", "alias"}, names)

	_, err = ordered([]Resource{{Name: "a", DependsOn: []string{"b"}}, {Name: "b", DependsOn: []string{"a"}}})
	require.ErrorContains(t, err, "wait for each other")
}
