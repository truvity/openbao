package ceremony

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadHierarchyResolvesSpecsAgainstTheFile(t *testing.T) {
	hierarchy, err := LoadHierarchy(filepath.Join("testdata", "hierarchy.yaml"))
	require.NoError(t, err)

	root, err := hierarchy.RootSpec()
	require.NoError(t, err)
	assert.Equal(t, fixtureRootSpec(), root)
	assert.Equal(t, filepath.Join("testdata", "roots", fixtureGeneration+".yaml"), hierarchy.Root.Artifact)

	for _, trustDomain := range []string{fixturePrivate, fixtureOrigin} {
		spec, err := hierarchy.Intermediate(trustDomain)
		require.NoError(t, err)
		assert.Equal(t, fixtureIntermediateSpec(trustDomain, filepath.Join("testdata", "roots")), spec,
			"the file and the in-code fixture must describe the same %s intermediate", trustDomain)
	}

	_, err = hierarchy.Intermediate("public")
	require.ErrorContains(t, err, "unknown trust domain")

	notBefore := time.Date(2026, 12, 12, 11, 0, 42, 0, time.UTC)
	emergency, err := hierarchy.EmergencyServerSpec(notBefore)
	require.NoError(t, err)
	assert.Equal(t, "openbao.example.internal", emergency.DNSName)
	assert.Equal(t, DefaultEmergencyServerLifetime, emergency.Lifetime)
	assert.Equal(t, notBefore, emergency.NotBefore)
	assert.Equal(t, hierarchy.Root.Artifact, emergency.RootArtifactPath)
}

func TestLoadHierarchyRefusals(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "hierarchy.yaml"))
	require.NoError(t, err)
	valid := string(raw)

	for name, mutate := range map[string]func(string) string{
		"an unknown key":     func(s string) string { return s + "bogusKey: 1\n" },
		"a bad lifetime":     func(s string) string { return strings.Replace(s, "lifetime: 175200h", "lifetime: twenty years", 1) },
		"a bad notBefore":    func(s string) string { return strings.Replace(s, `"2026-01-01T00:00:00Z"`, `"January"`, 1) },
		"an unbounded root":  func(s string) string { return strings.Replace(s, "maxPathLen: 3", "maxPathLen: -1", 1) },
		"a duplicate domain": func(s string) string { return strings.Replace(s, "trustDomain: origin", "trustDomain: private", 1) },
		"a wildcard emergency": func(s string) string {
			return strings.Replace(s, "dnsName: openbao.example.internal", `dnsName: "*.example.internal"`, 1)
		},
		"no root artifact": func(s string) string {
			return strings.Replace(s, "  artifact: roots/example-root-2026-01.yaml\n", "", 1)
		},
		"no intermediate artifact": func(s string) string {
			return strings.Replace(s, "    artifact: roots/example-root-2026-01-intermediate-origin.yaml\n", "", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hierarchy.yaml")
			require.NoError(t, os.WriteFile(path, []byte(mutate(valid)), 0o644))
			_, err := LoadHierarchy(path)
			require.Error(t, err)
		})
	}
}
