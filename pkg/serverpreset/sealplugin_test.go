package serverpreset_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/openbao/pkg/serverpreset"
)

const sealPluginDigest = "sha256:fe9fb94872048c9474156c044ea8852bb5c2e968fc9304a3725e4d434b488541"

func sealPlugin() *serverpreset.SealPlugin {
	return &serverpreset.SealPlugin{
		Image:     "ghcr.io/openbao/openbao-plugin-kms-aws",
		Digest:    sealPluginDigest,
		Version:   "v0.1.0",
		CopyImage: "openbao/openbao:2.7.0",
	}
}

func sealConfig() *serverpreset.Config {
	return &serverpreset.Config{
		Arch:          "arm64",
		ServerVersion: "2.7.0",
		Listener:      serverpreset.Listener{Address: "[::]:8200"},
		Raft:          serverpreset.Raft{Path: "/openbao/data", Peers: []serverpreset.RaftPeer{{LeaderAPIAddr: "https://a:8200"}}},
		Seal:          serverpreset.Seal{Type: "awskms", Region: "eu-example-1", KMSKeyID: "alias/unseal", Plugin: sealPlugin()},
	}
}

// The 2.6 rendering is untouched: no Plugin, no version, no new lines.
func TestSealWithoutPluginRendersAsBefore(t *testing.T) {
	c := sealConfig()
	c.Seal.Plugin = nil
	c.ServerVersion = "2.6.3"

	seal, err := c.SealHCL()
	require.NoError(t, err)
	assert.Equal(t, "seal \"awskms\" {\n  region     = \"eu-example-1\"\n  kms_key_id = \"alias/unseal\"\n}\n", seal)

	plugins, err := c.PluginHCL()
	require.NoError(t, err)
	assert.Empty(t, plugins, "no plugin_directory without a plugin of any kind")

	values, err := c.Values("plugins")
	require.NoError(t, err)

	server, _ := values["server"].(map[string]any)
	assert.NotContains(t, server, "extraInitContainers")
	assert.NotContains(t, server, "volumes")
}

func TestSealPluginHCL(t *testing.T) {
	c := sealConfig()
	c.Seal.Endpoint = "https://kms.example.test"

	hcl, err := c.HCL()
	require.NoError(t, err)
	assert.Contains(t, hcl,
		"seal \"awskms\" {\n  region     = \"eu-example-1\"\n  kms_key_id = \"alias/unseal\"\n  endpoint   = \"https://kms.example.test\"\n}\n")
	assert.Contains(t, hcl, "plugin \"kms\" \"awskms\" {\n  command = \"kms-awskms-v0.1.0\"\n  version = \"v0.1.0\"\n}\n")
	assert.Contains(t, hcl, "plugin_directory = \"/openbao/plugins\"\n")
	// A local binary: nothing to download, so no download settings and no checksum.
	assert.NotContains(t, hcl, "plugin_auto_download")
	assert.NotContains(t, hcl, "plugin_download_behavior")
	assert.NotContains(t, hcl, "sha256sum")
	assert.Equal(t, 1, strings.Count(hcl, "plugin_directory"))
}

// With an auth plugin too, plugin_directory is still rendered once, the
// download settings belong to the auth plugin, and the seal plugin is not
// in the retry sidecar's watch list.
func TestSealPluginBesideAnAuthPlugin(t *testing.T) {
	c := sealConfig()
	c.Plugins = []serverpreset.Plugin{awsAuthPlugin()}

	hcl, err := c.HCL()
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(hcl, "plugin_directory"))
	assert.Contains(t, hcl, "plugin_auto_download     = true")
	assert.Contains(t, hcl, "plugin \"auth\" \"aws\"")
	assert.Contains(t, hcl, "plugin \"kms\" \"awskms\"")

	sidecar, err := c.RetrySidecarContainer(serverpreset.RetrySidecarOptions{Image: "openbao/openbao:2.7.0", VolumeName: "p"})
	require.NoError(t, err)

	args, _ := sidecar["args"].([]any)
	script, _ := args[0].(string)
	assert.Contains(t, script, "/openbao/plugins/auth-aws-v0.1.1")
	assert.NotContains(t, script, "kms-awskms")
}

func TestSealPluginValues(t *testing.T) {
	c := sealConfig()

	values, err := c.Values("openbao-plugins")
	require.NoError(t, err)

	server, _ := values["server"].(map[string]any)

	volumes, _ := server["volumes"].([]any)
	require.Len(t, volumes, 2)
	assert.Equal(t, map[string]any{
		"name": "seal-plugin-src",
		"image": map[string]any{
			"reference":  "ghcr.io/openbao/openbao-plugin-kms-aws@" + sealPluginDigest,
			"pullPolicy": "IfNotPresent",
		},
	}, volumes[1])

	// The server container mounts the plugin directory only: the image
	// volume is the init container's alone.
	mounts, _ := server["volumeMounts"].([]any)
	require.Len(t, mounts, 1)

	inits, _ := server["extraInitContainers"].([]any)
	require.Len(t, inits, 1)

	init, _ := inits[0].(map[string]any)
	assert.Equal(t, "openbao/openbao:2.7.0", init["image"])

	args, _ := init["args"].([]any)
	script, _ := args[0].(string)
	assert.Contains(t, script, "src=/seal-plugin-src/openbao-plugin-kms-aws\n")
	assert.Contains(t, script, "dst=/openbao/plugins/kms-awskms-v0.1.0\n")
	assert.Contains(t, script, `mv -f "$dst.tmp" "$dst"`)
}

func TestSealPluginPreinstalledRendersNoInit(t *testing.T) {
	c := sealConfig()
	c.Seal.Plugin = &serverpreset.SealPlugin{Delivery: serverpreset.DeliveryPreinstalled, Version: "v0.1.0"}

	values, err := c.Values("openbao-plugins")
	require.NoError(t, err)

	server, _ := values["server"].(map[string]any)
	assert.NotContains(t, server, "extraInitContainers")

	volumes, _ := server["volumes"].([]any)
	assert.Len(t, volumes, 1, "the plugin directory must still exist at startup")

	_, err = c.SealPluginInitContainer("openbao-plugins")
	require.Error(t, err)
}

func TestSealPluginRefusals(t *testing.T) {
	cases := map[string]struct {
		edit func(*serverpreset.Config)
		want string
	}{
		"2.7 with the built-in seal": {
			func(c *serverpreset.Config) { c.Seal.Plugin = nil },
			"no built-in awskms seal",
		},
		"plugin before 2.6": {
			func(c *serverpreset.Config) { c.ServerVersion = "2.5.4" },
			"predates KMS plugins",
		},
		"bad server version": {
			func(c *serverpreset.Config) { c.ServerVersion = "latest" },
			"not a version",
		},
		"no image": {
			func(c *serverpreset.Config) { c.Seal.Plugin.Image = "" },
			"no tag and no digest",
		},
		"tagged image": {
			func(c *serverpreset.Config) { c.Seal.Plugin.Image = "ghcr.io/openbao/openbao-plugin-kms-aws:v0.1.0" },
			"no tag and no digest",
		},
		"digest inside image": {
			func(c *serverpreset.Config) { c.Seal.Plugin.Image += "@" + sealPluginDigest },
			"no tag and no digest",
		},
		"registry port is not a tag": {
			func(c *serverpreset.Config) {
				c.Seal.Plugin.Image = "registry.example.test:5000/openbao-plugin-kms-aws"
			},
			"",
		},
		"no digest": {
			func(c *serverpreset.Config) { c.Seal.Plugin.Digest = "" },
			"pinned by digest",
		},
		"short digest": {
			func(c *serverpreset.Config) { c.Seal.Plugin.Digest = "sha256:abc" },
			"pinned by digest",
		},
		"no version": {
			func(c *serverpreset.Config) { c.Seal.Plugin.Version = "" },
			"Version",
		},
		"path in binary name": {
			func(c *serverpreset.Config) { c.Seal.Plugin.BinaryName = "../x" },
			"BinaryName",
		},
		"no copy image": {
			func(c *serverpreset.Config) { c.Seal.Plugin.CopyImage = "" },
			"CopyImage is required",
		},
		"relative plugin directory": {
			func(c *serverpreset.Config) { c.PluginDirectory = "plugins" },
			"absolute path",
		},
		"unknown delivery": {
			func(c *serverpreset.Config) { c.Seal.Plugin.Delivery = "download" },
			"Delivery",
		},
		"kms plugin in the download set": {
			func(c *serverpreset.Config) {
				p := awsAuthPlugin()
				p.Kind, p.Name = "kms", "awskms"
				c.Plugins = []serverpreset.Plugin{p}
			},
			"never downloaded by the server",
		},
		"bad endpoint": {
			func(c *serverpreset.Config) { c.Seal.Endpoint = "kms.example.test" },
			"Endpoint",
		},
		"plugin without a seal": {
			func(c *serverpreset.Config) { c.Seal.Type = "" },
			"no seal to serve",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := sealConfig()
			tc.edit(c)

			if tc.want == "" {
				require.NoError(t, c.Validate())

				return
			}

			for _, render := range []func() error{
				c.Validate,
				func() error { _, err := c.HCL(); return err },
				func() error { _, err := c.Values("p"); return err },
			} {
				err := render()
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.want)
			}
		})
	}
}

func TestSealPluginEgress(t *testing.T) {
	c := sealConfig()
	assert.Equal(t, []string{"kms.eu-example-1.amazonaws.com"}, c.EgressDomains(),
		"the kubelet pulls the image; the pod needs KMS and nothing else")

	c.Seal.Endpoint = "https://vpce-1.kms.eu-example-1.vpce.amazonaws.com"
	assert.Equal(t, []string{"vpce-1.kms.eu-example-1.vpce.amazonaws.com"}, c.EgressDomains())
}

func TestSealPluginChecksum(t *testing.T) {
	sum := strings.Repeat("c", 64)

	// From 2.7 a checksum is optional; given, it is rendered and verified
	// by the init container before anything is installed.
	c := sealConfig()
	c.Seal.Plugin.SHA256ByArch = map[string]string{"arm64": sum, "amd64": strings.Repeat("d", 64)}

	hcl, err := c.SealHCL()
	require.NoError(t, err)
	assert.Contains(t, hcl, "  sha256sum = \""+sum+"\"\n")

	init, err := c.SealPluginInitContainer("p")
	require.NoError(t, err)

	args, _ := init["args"].([]any)
	script, _ := args[0].(string)
	assert.Contains(t, script, `echo "`+sum+`  $src" | sha256sum -c -`)

	// A map that lacks the architecture is the mixed-arch mistake.
	c.Arch = "riscv64"
	_, err = c.SealHCL()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `no SHA256ByArch entry for arch "riscv64"`)

	// Below 2.7 it is mandatory: the server refuses a plugin without one.
	old := sealConfig()
	old.ServerVersion = "2.6.3"

	_, err = old.HCL()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no checksum provided")

	old.Seal.Plugin.SHA256ByArch = map[string]string{"arm64": sum}
	_, err = old.HCL()
	require.NoError(t, err)

	old.Seal.Plugin.SHA256ByArch["arm64"] = "nothex"
	_, err = old.HCL()
	require.Error(t, err)
}

func TestRestoreCheckValues(t *testing.T) {
	c := sealConfig()

	values, err := c.RestoreCheckValues()
	require.NoError(t, err)

	seal, err := c.SealHCL()
	require.NoError(t, err)
	assert.Equal(t, seal, values["sealConfig"], "the scratch server declares the seal and plugin exactly as the server does")

	plugin, _ := values["sealPlugin"].(map[string]any)
	assert.Equal(t, "/openbao/plugins", plugin["directory"])

	// The very same init container and image volume the server pod gets,
	// bound to the chart's volume name.
	init, err := c.SealPluginInitContainer(serverpreset.RestoreCheckPluginVolume)
	require.NoError(t, err)
	assert.Equal(t, init, plugin["initContainer"])
	assert.Equal(t, c.SealPluginSourceVolume(), plugin["sourceVolume"])
}

func TestRestoreCheckValuesPreinstalledIsDirectoryOnly(t *testing.T) {
	c := sealConfig()
	c.Seal.Plugin.Delivery = serverpreset.DeliveryPreinstalled

	values, err := c.RestoreCheckValues()
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"directory": "/openbao/plugins"}, values["sealPlugin"])
}

func TestRestoreCheckValuesRefusals(t *testing.T) {
	c := sealConfig()
	c.Seal.Plugin = nil
	_, err := c.RestoreCheckValues()
	require.Error(t, err)

	c = sealConfig()
	c.Seal.Plugin.Digest = ""
	_, err = c.RestoreCheckValues()
	require.Error(t, err)
}
