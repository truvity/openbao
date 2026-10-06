// Package presets ships the values presets of charts/openbao-consumers to Go
// consumers: the same files `-f` and Argo CD `valueFiles` read, versioned with
// the module. A consumer that composes an upstream chart's values in code
// (one source, the preset under its own values) reads them here instead of
// copying them.
package presets

import (
	"embed"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// The presets, by name.
const (
	CertManager     = "cert-manager"
	TrustManager    = "trust-manager"
	ExternalSecrets = "external-secrets"
)

//go:embed *.yaml
var files embed.FS

// Names lists every preset.
func Names() []string {
	return []string{CertManager, TrustManager, ExternalSecrets}
}

// Raw returns a preset's file as shipped.
func Raw(name string) ([]byte, error) {
	data, err := files.ReadFile(name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("preset %q: %w", name, err)
	}

	return data, nil
}

// Values returns a preset as a values map.
func Values(name string) (map[string]any, error) {
	data, err := Raw(name)
	if err != nil {
		return nil, err
	}

	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("preset %q: %w", name, err)
	}

	return values, nil
}
