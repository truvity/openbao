package server_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/openbao/examples/server"
)

const (
	goldenPath   = "values.yaml"
	golden27Path = "values-2.7.yaml"
)

// The example is valid for both reference architectures, and values.yaml
// is what arm64 derives, byte for byte: the fragment a reader copies is
// the one the conformance test (conformance/server_preset_test.go) boots
// a real `bao server` from. UPDATE_GOLDEN=1 rewrites it.
func TestExampleGolden(t *testing.T) {
	require.NoError(t, server.Config("arm64").Validate())

	values, err := server.Values("arm64")
	require.NoError(t, err)

	checkGolden(t, goldenPath, values)
}

// values-2.7.yaml is the same for OpenBAO 2.7: the seal as a plugin, its
// init container and image volume. The 2.6 golden above is unchanged.
func TestExampleGolden27(t *testing.T) {
	require.NoError(t, server.Config27("arm64").Validate())

	values, err := server.Values27("arm64")
	require.NoError(t, err)

	checkGolden(t, golden27Path, values)
}

func checkGolden(t *testing.T, goldenPath string, values map[string]any) {
	t.Helper()

	var out bytes.Buffer

	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	require.NoError(t, encoder.Encode(values))

	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.WriteFile(goldenPath, out.Bytes(), 0o644))

		return
	}

	want, err := os.ReadFile(goldenPath)
	require.NoError(t, err)

	if !bytes.Equal(want, out.Bytes()) {
		t.Fatalf("%s is not what the example derives; review and rerun with UPDATE_GOLDEN=1", goldenPath)
	}
}

// TestExampleValidForBothReferenceArchitectures: the checksum map carries
// both, so the example itself never hides the mixed-arch mistake
// serverpreset.ResolveArch exists to catch upstream of it.
func TestExampleValidForBothReferenceArchitectures(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		require.NoError(t, server.Config(arch).Validate(), "arch %s", arch)
		require.NoError(t, server.Config27(arch).Validate(), "arch %s", arch)
	}
}
