// Package presets_test holds the values presets shipped under
// charts/openbao-consumers/presets to their shape: each is a YAML mapping
// that sets the keys its header promises. Whether the upstream chart accepts
// them is checked with `helm template` against that chart (docs/presets.md).
package presets_test

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestPresetsSetWhatTheyPromise(t *testing.T) {
	for name, keys := range map[string][]string{
		"cert-manager":     {"crds", "prometheus", "resources", "replicaCount", "podDisruptionBudget", "webhook", "cainjector"},
		"trust-manager":    {"defaultPackage", "app", "secretTargets", "resources", "replicaCount", "podDisruptionBudget"},
		"external-secrets": {"installCRDs", "serviceMonitor", "resources", "webhook", "certController"},
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "charts", "openbao-consumers", "presets", name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}

		var values map[string]any
		if err := yaml.Unmarshal(raw, &values); err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		for _, key := range keys {
			if _, ok := values[key]; !ok {
				t.Errorf("%s: no %q", name, key)
			}
		}
	}
}
