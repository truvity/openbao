package serverpreset_test

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/openbao/pkg/serverpreset"
)

const (
	handWrittenValues = "testdata/gitops-shaped-server-values.yaml"
	handWrittenHCL    = "testdata/gitops-shaped-server.hcl"
	handWrittenPlugin = "plugin: the link the declarative download creates in plugin_directory\nfor the `plugin \"auth\" \"aws\"` block above."
)

// handWrittenConfig is the Config whose rendering the hand-written server
// above carries: three voters, the seal and the aws auth method as plugins,
// metrics on their own listener, the web UI, the audit device.
func handWrittenConfig() *serverpreset.Config {
	peers := make([]serverpreset.RaftPeer, 3)
	for i := range peers {
		peers[i] = serverpreset.RaftPeer{
			LeaderAPIAddr:       fmt.Sprintf("https://openbao-%d.openbao-internal:8200", i),
			LeaderCACertFile:    "/openbao/userconfig/openbao-tls/ca.crt",
			LeaderTLSServername: "openbao.example.internal",
		}
	}

	return &serverpreset.Config{
		ServerVersion:         "2.7.0",
		Arch:                  "arm64",
		PluginVolumeSizeLimit: "256Mi",
		UI:                    true,
		DisableStandbyReads:   true,
		Listener: serverpreset.Listener{
			Address: "[::]:8200", ClusterAddress: "[::]:8201",
			TLSCertFile: "/openbao/userconfig/openbao-tls/tls.crt",
			TLSKeyFile:  "/openbao/userconfig/openbao-tls/tls.key",
		},
		Raft: serverpreset.Raft{Path: "/openbao/data", Peers: peers},
		Seal: serverpreset.Seal{
			Type: "awskms", Region: "eu-example-1", KMSKeyID: "alias/openbao-unseal",
			Plugin: &serverpreset.SealPlugin{
				Image:        "registry.example.com/github/openbao/openbao-plugin-kms-aws",
				Digest:       "sha256:fe9fb94872048c9474156c044ea8852bb5c2e968fc9304a3725e4d434b488541",
				Version:      "v0.1.0",
				CopyImage:    "registry.example.com/quay/openbao/openbao:2.7.0",
				SHA256ByArch: map[string]string{"arm64": "9925bd77bb644fbf8a3a479deb39768e5a230e9b2b4eafad18971b54b3b580e2"},
			},
		},
		ServiceRegistration: "kubernetes",
		AuditDevice:         "to-stdout",
		AuditDescription:    "Every request and response, HMAC'd, to the pod log (example record 1).",
		Telemetry:           &serverpreset.Telemetry{MetricsAddress: "[::]:9101"},
		Plugins: []serverpreset.Plugin{{
			Kind: "auth", Name: "aws", Image: "ghcr.io/openbao/openbao-plugin-auth-aws",
			Version: "v0.1.1", BinaryName: "openbao-plugin-auth-aws",
			SHA256ByArch: map[string]string{"arm64": "3b03fb12b8cedd9d2d83ea282a32a4f70147c93a927af5937c9b081525830db2"},
		}},
	}
}

func handWrittenOptions() serverpreset.ServerValuesOptions {
	return serverpreset.ServerValuesOptions{
		PluginVolumeName: "openbao-plugins",
		Image:            serverpreset.ServerImage{Registry: "registry.example.com", Repository: "quay/openbao/openbao", Tag: "2.7.0"},
		TLSSecretName:    "openbao-tls",
		Endpoint:         "openbao.example.internal",
		Environment:      map[string]string{"AWS_REGION": "eu-example-1"},
		TLSReload: &serverpreset.TLSReloadOptions{
			PluginComment: handWrittenPlugin,
			Resources: map[string]any{
				"requests": map[string]any{"cpu": "5m", "memory": "8Mi"},
				"limits":   map[string]any{"memory": "32Mi"},
			},
			SecurityContext: map[string]any{
				"allowPrivilegeEscalation": false,
				"capabilities":             map[string]any{"drop": []any{"ALL"}},
			},
		},
		DataStorage: serverpreset.DataStorage{Size: "10Gi", StorageClass: "gp3"},
		Resources: map[string]any{
			"requests": map[string]any{"cpu": "100m", "memory": "256Mi"},
			"limits":   map[string]any{"memory": "512Mi"},
		},
		NodeSelector: map[string]any{"example.com/pool": "durable"},
		Tolerations: []any{
			map[string]any{"key": "example.com/dedicated", "operator": "Equal", "value": "true", "effect": "NoSchedule"},
			map[string]any{"key": "arch", "operator": "Equal", "value": "arm64", "effect": "NoSchedule"},
		},
		TopologySpreadConstraints: []any{map[string]any{
			"maxSkew": 1, "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "DoNotSchedule",
			"labelSelector": map[string]any{"matchLabels": map[string]any{
				"app.kubernetes.io/name": "openbao", "app.kubernetes.io/instance": "openbao", "component": "server",
			}},
		}},
	}
}

// withoutComments drops comment lines, trailing whitespace and blank lines:
// the two differences between a hand-written HCL and the rendered one that
// are not configuration.
func withoutComments(hcl string) string {
	var out []string

	for _, line := range strings.Split(hcl, "\n") {
		line = strings.TrimRight(line, " \t")
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		out = append(out, line)
	}

	return strings.Join(out, "\n") + "\n"
}

// shape is an HCL body as data: attributes by name with their literal value,
// blocks by type and labels, in order.
func shape(t *testing.T, src string) []string {
	t.Helper()

	f, diags := hclsyntax.ParseConfig([]byte(src), "server.hcl", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())

	var walk func(b *hclsyntax.Body, path string) []string

	walk = func(b *hclsyntax.Body, path string) []string {
		var out []string

		names := make([]string, 0, len(b.Attributes))
		for n := range b.Attributes {
			names = append(names, n)
		}

		sort.Strings(names)

		for _, n := range names {
			v, d := b.Attributes[n].Expr.Value(nil)
			require.False(t, d.HasErrors(), d.Error())
			out = append(out, fmt.Sprintf("%s%s = %#v", path, n, v))
		}

		for _, blk := range b.Blocks {
			p := path + blk.Type + " " + strings.Join(blk.Labels, " ") + "/"
			out = append(out, "block "+p)
			out = append(out, walk(blk.Body, p)...)
		}

		return out
	}

	return walk(f.Body.(*hclsyntax.Body), "")
}

func roundTrip(t *testing.T, v any) map[string]any {
	t.Helper()

	raw, err := json.Marshal(v)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))

	return out
}

// TestServerValuesEqualAHandWrittenServer is the adoption proof: for the
// inputs of a server that was written by hand, ServerValues renders the
// values it carried, and the HCL differs only by the comments the hand-written
// file has (which a renderer cannot carry).
func TestServerValuesEqualAHandWrittenServer(t *testing.T) {
	cfg := handWrittenConfig()

	got, err := cfg.ServerValues(handWrittenOptions())
	require.NoError(t, err)

	hcl, err := cfg.HCL()
	require.NoError(t, err)

	wantHCL, err := os.ReadFile(handWrittenHCL)
	require.NoError(t, err)

	// Every non-comment line is byte-equal, in the same order.
	assert.Equal(t, withoutComments(string(wantHCL)), withoutComments(hcl))
	// And both parse to the same structure.
	assert.Equal(t, shape(t, string(wantHCL)), shape(t, hcl))

	raw, err := os.ReadFile(handWrittenValues)
	require.NoError(t, err)

	var want map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &want))

	wantServer := want["server"].(map[string]any)
	wantRaft := wantServer["ha"].(map[string]any)["raft"].(map[string]any)
	require.Equal(t, "@HCL@", wantRaft["config"])
	// The hand-written values carry the HCL with its comments; compare the
	// rest as is, and the HCL as above.
	wantRaft["config"] = hcl

	assert.Equal(t, roundTrip(t, want), roundTrip(t, got))
}

func TestServerValuesWithoutOptionalParts(t *testing.T) {
	cfg := handWrittenConfig()
	cfg.UI = false
	cfg.Telemetry = nil

	opts := handWrittenOptions()
	opts.TLSReload = nil
	opts.Image.Registry = ""
	opts.DataStorage.StorageClass = ""
	opts.Replicas = 5

	got, err := cfg.ServerValues(opts)
	require.NoError(t, err)

	server := got["server"].(map[string]any)
	assert.NotContains(t, server, "extraContainers")
	assert.NotContains(t, server, "shareProcessNamespace")
	assert.NotContains(t, server, "extraPorts")
	assert.Equal(t, map[string]any{"repository": "quay/openbao/openbao", "tag": "2.7.0"}, server["image"])
	assert.Equal(t, map[string]any{"enabled": true, "size": "10Gi"}, server["dataStorage"])
	assert.Equal(t, 5, server["ha"].(map[string]any)["replicas"])
	assert.Equal(t, map[string]any{"enabled": false}, got["ui"])
}

func TestServerValuesRefusals(t *testing.T) {
	for name, mutate := range map[string]func(*serverpreset.ServerValuesOptions){
		"no image tag":       func(o *serverpreset.ServerValuesOptions) { o.Image.Tag = "" },
		"no endpoint":        func(o *serverpreset.ServerValuesOptions) { o.Endpoint = "" },
		"no storage size":    func(o *serverpreset.ServerValuesOptions) { o.DataStorage.Size = "" },
		"no volume name":     func(o *serverpreset.ServerValuesOptions) { o.PluginVolumeName = "" },
		"secret not mounted": func(o *serverpreset.ServerValuesOptions) { o.TLSSecretName = "other-tls" },
	} {
		t.Run(name, func(t *testing.T) {
			opts := handWrittenOptions()
			mutate(&opts)

			_, err := handWrittenConfig().ServerValues(opts)
			require.Error(t, err)
		})
	}
}

// An AuditDescription is optional: without one the audit block is what it
// was.
func TestAuditDescriptionIsOptional(t *testing.T) {
	cfg := handWrittenConfig()
	cfg.AuditDescription = ""

	hcl, err := cfg.HCL()
	require.NoError(t, err)
	assert.Contains(t, hcl, "audit \"file\" \"to-stdout\" {\n  options {\n")
	assert.NotContains(t, hcl, "description")
}
