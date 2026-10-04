// Package org is the library's worked example: one neutral organisation,
// built up in six capability levels (README.md), every level rendered and
// checked with no cluster and no cloud account.
//
// A level is a directory. The files in it are COMPLETE, not patches: level N
// lists everything level N needs, and a file a level does not change is not
// repeated (the nearest level below it that has the file supplies it). The
// tests prove the layering (every level contains the one below it) and the
// stand-alone claim (a level uses nothing from a level above it).
package org

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/openbao/examples/server"
	"github.com/truvity/openbao/pkg/builder"
	"github.com/truvity/openbao/pkg/model"
	"github.com/truvity/openbao/pkg/pki"
	"github.com/truvity/openbao/pkg/serverpreset"
)

// Files are the example's inputs and goldens.
//
//go:embed 0*/*.yaml
var Files embed.FS

// Names are the levels' directory names, by level.
var Names = [...]string{
	"00-server",
	"01-secrets",
	"02-ssh",
	"03-pki",
	"04-workload-identity",
	"05-enforcement",
}

// Arch is the one architecture the example resolves its server to.
const Arch = "arm64"

// Environments are the example's environments, with the facts a contract
// does not author: the DNS zone and the SPIFFE trust domain of each.
func Environments() []pki.Environment {
	return []pki.Environment{
		{Name: "dev", Zones: map[string]string{"internal": "dev.internal.example.org", "workload": "dev.internal.example.org"}},
		{Name: "prod", Zones: map[string]string{"internal": "prod.internal.example.org", "workload": "prod.internal.example.org"}},
	}
}

// Layer is one level, resolved.
type Layer struct {
	Level int
	Name  string
	// Server is the server preset: the Raft cluster, the seal and, from level
	// 2, the aws auth plugin.
	Server *serverpreset.Config
	// Spec is the authored, non-PKI contract; nil at level 0, which has no
	// desired state at all.
	Spec *builder.Spec
	// Contract is the private-PKI contract; nil below level 3.
	Contract *pki.Contract
	// Desired is the whole desired state: the spec built, and the contract's
	// PKI joined to it. Nil at level 0.
	Desired *model.Desired
}

// Source returns the file a level uses under name: its own, or the nearest
// level below it that has one. ok is false when there is none.
func Source(level int, name string) (path string, data []byte, ok bool) {
	for l := level; l >= 0; l-- {
		path = Names[l] + "/" + name

		data, err := fs.ReadFile(Files, path)
		if err == nil {
			return path, data, true
		}
	}

	return "", nil, false
}

// Own returns the file a level itself holds, nil if it holds none.
func Own(level int, name string) []byte {
	data, err := fs.ReadFile(Files, Names[level]+"/"+name)
	if err != nil {
		return nil
	}

	return data
}

// ServerConfig is the server preset at a level: the aws auth plugin
// (level 2, SSH host certificates) is the only thing that changes it.
func ServerConfig(level int) *serverpreset.Config {
	cfg := server.Config(Arch)
	if level < 2 {
		cfg.Plugins = nil
	}

	return cfg
}

// Load resolves a level.
func Load(level int) (*Layer, error) {
	if level < 0 || level >= len(Names) {
		return nil, fmt.Errorf("org: no level %d", level)
	}

	layer := &Layer{Level: level, Name: Names[level], Server: ServerConfig(level)}

	if _, raw, ok := Source(level, "spec.yaml"); ok {
		spec, err := builder.Load(strings.NewReader(string(raw)))
		if err != nil {
			return nil, err
		}

		layer.Spec = spec
	}

	if path, _, ok := Source(level, "contract.yaml"); ok {
		contract, err := pki.LoadFS(Files, path, "examples/org")
		if err != nil {
			return nil, err
		}

		layer.Contract = contract
	}

	if layer.Spec == nil {
		return layer, nil
	}

	built, err := layer.Spec.Build()
	if err != nil {
		return nil, fmt.Errorf("org: level %d: %w", level, err)
	}

	layer.Desired = built.Model

	if layer.Contract != nil {
		derivation, err := layer.Contract.Derive(Environments())
		if err != nil {
			return nil, fmt.Errorf("org: level %d: %w", level, err)
		}

		if err := derivation.Apply(layer.Desired); err != nil {
			return nil, fmt.Errorf("org: level %d: %w", level, err)
		}

		if err := layer.Desired.Validate(); err != nil {
			return nil, fmt.Errorf("org: level %d: %w", level, err)
		}
	}

	return layer, nil
}

// Marshal renders a value as the YAML the goldens hold.
func Marshal(v any) ([]byte, error) {
	var out strings.Builder

	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)

	if err := encoder.Encode(v); err != nil {
		return nil, err
	}

	return []byte(out.String()), nil
}
