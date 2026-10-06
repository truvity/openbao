package builder

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCISecretGrants(t *testing.T) {
	got, err := CISecretGrants(map[string][]string{
		"ci/goreleaser": {"b", "a"},
		"app/key-1":     {"a"},
	})
	require.NoError(t, err)
	assert.Equal(t, []SecretGrant{
		{Policy: "app-key-1", Path: "app/key-1", Groups: []string{"a"}},
		{Policy: "ci-goreleaser", Path: "ci/goreleaser", Groups: []string{"a", "b"}},
	}, got)
}

func TestCISecretGrantsRefuse(t *testing.T) {
	for want, paths := range map[string]map[string][]string{
		"not <prefix>/<key>":        {"goreleaser": {"g"}, "ci/dms/npm": {"g"}},
		"is not a path segment":     {"ci/*": {"g"}, "ci/..": {"g"}, "-ci/x": {"g"}},
		"grants nobody":             {"ci/x": {}},
		"may not derive one policy": {"ci-dms/npm": {"g"}, "ci/dms-npm": {"g"}},
	} {
		_, err := CISecretGrants(paths)
		require.ErrorContains(t, err, want)
	}
}
