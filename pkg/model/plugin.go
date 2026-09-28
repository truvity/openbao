package model

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// sha256Hex matches a lowercase hex SHA-256: exactly what OpenBAO's plugin
// catalog checks a registered binary's digest against.
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// pluginTypes are OpenBAO's three catalog types a plugin may register
// under. This model does not (yet) cover the separate KMS/seal-wrapper
// catalog, which uses its own mechanism.
var pluginTypes = []string{"auth", "secret", "database"}

// Plugin is one entry OpenBAO's plugin catalog needs before any namespace
// can enable it: the catalog sits above the namespace tree -- global, not
// per-environment -- so every Plugin here is applied exactly once, before
// a single [Namespace] is (the same ordering [Desired.Applied] documents
// for namespaces themselves).
//
// This model registers a plugin binary ALREADY PRESENT on every server
// node, under the server's own `plugin_directory`: Command names that
// file, and SHA256 is what OpenBAO checks it against at registration
// time. Placing the binary there is a separate concern this model does
// not own -- typically a declarative `plugin` block in the server's own
// HCL config (OpenBAO downloads and verifies an OCI image itself, from
// v2.5.0 on) or a manually provisioned image -- because a catalog entry
// for a binary that never arrives registers cleanly and only the first
// login against it fails; the two are reviewed and rolled out
// independently.
type Plugin struct {
	// Type is one of pluginTypes.
	Type string `yaml:"type"`
	// Name is the catalog name a mount is later enabled under (e.g.
	// "aws").
	Name string `yaml:"name"`
	// Command is the plugin's binary file name, relative to the server's
	// `plugin_directory`.
	Command string `yaml:"command"`
	// SHA256 is the lowercase hex SHA-256 of that binary.
	SHA256 string `yaml:"sha256"`
}

// Validate refuses a plugin whose type is none of pluginTypes, that has no
// name or command, or whose SHA256 is not exactly 64 lowercase hex
// characters -- the one shape OpenBAO's own catalog registration accepts.
func (p *Plugin) Validate() error {
	if !slices.Contains(pluginTypes, p.Type) {
		return fmt.Errorf("plugin %q has type %q, not one of %s", p.Name, p.Type, strings.Join(pluginTypes, ", "))
	}

	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("a %s plugin has no name", p.Type)
	}

	if strings.TrimSpace(p.Command) == "" {
		return fmt.Errorf("plugin %s/%s has no command", p.Type, p.Name)
	}

	if !sha256Hex.MatchString(p.SHA256) {
		return fmt.Errorf("plugin %s/%s has sha256 %q, which is not 64 lowercase hex characters", p.Type, p.Name, p.SHA256)
	}

	return nil
}
