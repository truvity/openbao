package roster_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/openbao/examples/roster"
)

const goldenPath = "desired.yaml"

// The example is valid, and desired.yaml is what it derives, byte for byte:
// the file a reader reviews is the state the conformance test applies.
// UPDATE_GOLDEN=1 rewrites it.
func TestExampleGolden(t *testing.T) {
	desired := roster.Desired(roster.Params{Issuer: "https://id.example.com", Address: "https://openbao.example.com"})
	require.NoError(t, desired.Validate())

	var out bytes.Buffer

	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	require.NoError(t, encoder.Encode(desired))

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
