package serverpreset_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/openbao/pkg/serverpreset"
)

func awsAuthPlugin() serverpreset.Plugin {
	return serverpreset.Plugin{
		Kind:        "auth",
		Name:        "aws",
		Image:       "ghcr.io/openbao/openbao-plugin-auth-aws",
		Version:     "v0.1.1",
		BinaryName:  "openbao-plugin-auth-aws",
		EgressHosts: []string{"ghcr.io", "pkg-containers.githubusercontent.com"},
		RequiresSTS: true,
		SHA256ByArch: map[string]string{
			"amd64": strings.Repeat("a", 64),
			"arm64": strings.Repeat("b", 64),
		},
	}
}

// TestResolveArchRefusesMixedArch mirrors the private estate's
// TestAWSAuthPluginChecksumMatchesKernelArch idea, generalized: a node
// selection that could land a pod on more than one architecture cannot be
// served by one static checksum, and the answer is to narrow the
// selection before ever reaching for Config.Arch, not to guess.
func TestResolveArchRefusesMixedArch(t *testing.T) {
	_, err := serverpreset.ResolveArch([]string{"amd64", "arm64"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mixed-architecture")

	arch, err := serverpreset.ResolveArch([]string{"arm64", "arm64"})
	require.NoError(t, err)
	assert.Equal(t, "arm64", arch)

	_, err = serverpreset.ResolveArch(nil)
	require.Error(t, err)
}

// TestConfigRefusesMissingChecksumForArch is the failure ResolveArch
// exists to make unreachable from the OTHER side: a Config pinned to an
// architecture no plugin carries a checksum for.
func TestConfigRefusesMissingChecksumForArch(t *testing.T) {
	c := serverpreset.Config{
		Arch:    "riscv64",
		Plugins: []serverpreset.Plugin{awsAuthPlugin()},
	}

	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `no checksum recorded for arch "riscv64"`)
}

func TestConfigRefusesInvalidDownloadBehavior(t *testing.T) {
	c := serverpreset.Config{
		Arch:             "arm64",
		DownloadBehavior: "warn",
		Plugins:          []serverpreset.Plugin{awsAuthPlugin()},
	}

	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"fail" or "continue"`)
	assert.Contains(t, err.Error(), `"warn"`)
}

func TestConfigRefusesNoArch(t *testing.T) {
	c := serverpreset.Config{Plugins: []serverpreset.Plugin{awsAuthPlugin()}}

	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Arch is required")
}

func TestConfigRefusesDuplicatePlugin(t *testing.T) {
	c := serverpreset.Config{
		Arch:    "arm64",
		Plugins: []serverpreset.Plugin{awsAuthPlugin(), awsAuthPlugin()},
	}

	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "declared twice")
}

func TestPluginValidateRefusesUnsafeToken(t *testing.T) {
	p := awsAuthPlugin()
	p.Image = "ghcr.io/x\"; rm -rf /"

	err := p.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not one HCL-safe token")
}

func TestPluginValidateRefusesBadChecksum(t *testing.T) {
	p := awsAuthPlugin()
	p.SHA256ByArch["arm64"] = "not-a-checksum"

	err := p.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a lowercase sha256 hex digest")
}

func TestCommandIsTypeNameVersion(t *testing.T) {
	assert.Equal(t, "auth-aws-v0.1.1", awsAuthPlugin().Command())
}

// TestSealRefusesUnsupportedType documents the 2.7 hook: this package
// renders "awskms" only, and says why when asked for anything else.
func TestSealRefusesUnsupportedType(t *testing.T) {
	c := serverpreset.Config{
		Arch: "arm64",
		Seal: serverpreset.Seal{Type: "awskms-plugin", Region: "eu-example-1", KMSKeyID: "alias/x"},
	}

	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OpenBAO 2.7")
}

func TestSealRefusesIncompleteAWSKMS(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", Seal: serverpreset.Seal{Type: "awskms"}}

	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Region and KMSKeyID")
}

// TestPluginHCLIsEmptyWithNoPlugins: a server with nothing to download
// declares no plugin directory either.
func TestPluginHCLIsEmptyWithNoPlugins(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64"}

	hcl, err := c.PluginHCL()
	require.NoError(t, err)
	assert.Empty(t, hcl)
}

func TestPluginHCLRendersDeclarativeAutoRegisterAndContinue(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", Plugins: []serverpreset.Plugin{awsAuthPlugin()}}

	hcl, err := c.PluginHCL()
	require.NoError(t, err)

	for _, want := range []string{
		`plugin_directory         = "/openbao/plugins"`,
		`plugin_auto_download     = true`,
		`plugin_auto_register     = true`,
		`plugin_download_behavior = "continue"`,
		`plugin "auth" "aws" {`,
		`sha256sum   = "` + strings.Repeat("b", 64) + `"`,
	} {
		assert.Contains(t, hcl, want)
	}
}

func TestPluginHCLHonoursCustomDirectoryAndArch(t *testing.T) {
	c := serverpreset.Config{
		Arch:             "amd64",
		PluginDirectory:  "/custom/plugins",
		DownloadBehavior: "fail",
		Plugins:          []serverpreset.Plugin{awsAuthPlugin()},
	}

	hcl, err := c.PluginHCL()
	require.NoError(t, err)
	assert.Contains(t, hcl, `plugin_directory         = "/custom/plugins"`)
	assert.Contains(t, hcl, `plugin_download_behavior = "fail"`)
	assert.Contains(t, hcl, `sha256sum   = "`+strings.Repeat("a", 64)+`"`)
}

func TestEgressDomainsDerivesFromWhatIsEnabled(t *testing.T) {
	c := serverpreset.Config{
		Arch:    "arm64",
		Plugins: []serverpreset.Plugin{awsAuthPlugin()},
		Seal:    serverpreset.Seal{Type: "awskms", Region: "eu-example-1", KMSKeyID: "alias/openbao-unseal"},
	}

	assert.Equal(t, []string{
		"ghcr.io",
		"kms.eu-example-1.amazonaws.com",
		"pkg-containers.githubusercontent.com",
		"sts.amazonaws.com",
		"sts.eu-example-1.amazonaws.com",
	}, c.EgressDomains())
}

func TestEgressDomainsEmptyWithNothingEnabled(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64"}
	assert.Empty(t, c.EgressDomains())
}

func TestPluginVolumeAndMountAgreeOnDirectory(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", PluginDirectory: "/custom/plugins"}

	vol := c.PluginVolume("openbao-plugins")
	mount := c.PluginVolumeMount("openbao-plugins")

	assert.Equal(t, "openbao-plugins", vol["name"])
	assert.Equal(t, "openbao-plugins", mount["name"])
	assert.Equal(t, "/custom/plugins", mount["mountPath"])
	assert.Contains(t, vol, "emptyDir")
}

func TestHCLOrderMatchesReferenceShape(t *testing.T) {
	c := serverpreset.Config{
		Arch: "arm64",
		Listener: serverpreset.Listener{
			Address: "[::]:8200", ClusterAddress: "[::]:8201",
			TLSCertFile: "/tls/tls.crt", TLSKeyFile: "/tls/tls.key",
		},
		Raft: serverpreset.Raft{
			Path: "/openbao/data",
			Peers: []serverpreset.RaftPeer{
				{LeaderAPIAddr: "https://openbao-0.openbao-internal:8200", LeaderCACertFile: "/tls/ca.crt", LeaderTLSServername: "openbao.example.internal"},
			},
		},
		Seal:                serverpreset.Seal{Type: "awskms", Region: "eu-example-1", KMSKeyID: "alias/openbao-unseal"},
		ServiceRegistration: "kubernetes",
		Plugins:             []serverpreset.Plugin{awsAuthPlugin()},
		AuditDevice:         "to-stdout",
		UI:                  true,
		DisableStandbyReads: true,
	}

	hcl, err := c.HCL()
	require.NoError(t, err)

	order := []string{
		"ui = true",
		"disable_standby_reads = true",
		`listener "tcp" {`,
		`storage "raft" {`,
		`seal "awskms" {`,
		`service_registration "kubernetes" {}`,
		"plugin_directory",
		`plugin "auth" "aws" {`,
		`audit "file" "to-stdout" {`,
	}

	last := -1

	for _, want := range order {
		idx := strings.Index(hcl, want)
		require.Greater(t, idx, last, "expected %q after position %d, got %d\n%s", want, last, idx, hcl)
		last = idx
	}
}

func TestHCLRefusesInvalidConfig(t *testing.T) {
	c := serverpreset.Config{}

	_, err := c.HCL()
	require.Error(t, err)
}
