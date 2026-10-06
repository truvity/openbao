package presets_test

import (
	"testing"

	"github.com/truvity/secrets/charts/openbao-consumers/presets"
)

func TestEveryPresetLoads(t *testing.T) {
	t.Parallel()

	for _, name := range presets.Names() {
		values, err := presets.Values(name)
		if err != nil {
			t.Fatal(err)
		}

		if len(values) == 0 {
			t.Errorf("%s: empty", name)
		}
	}

	if _, err := presets.Values("nope"); err == nil {
		t.Error("an unknown preset loaded")
	}
}
