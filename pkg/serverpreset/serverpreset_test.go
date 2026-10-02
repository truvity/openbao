package serverpreset_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/openbao/pkg/model"
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

// A whole-server render refuses what it would otherwise write as
// `address = ""` or leave out; the plugin-only entry points stay usable
// with a bare Config.
func TestHCLRefusesAnEmptyListenerAndNoStorage(t *testing.T) {
	bare := serverpreset.Config{Arch: "arm64"}

	_, err := bare.HCL()
	require.ErrorContains(t, err, "Listener.Address")

	_, err = bare.Values("openbao-plugins")
	require.ErrorContains(t, err, "Listener.Address")

	withListener := serverpreset.Config{Arch: "arm64", Listener: serverpreset.Listener{Address: "[::]:8200"}}

	_, err = withListener.HCL()
	require.ErrorContains(t, err, "no storage block")

	withListener.ExternalStorage = true
	hcl, err := withListener.HCL()
	require.NoError(t, err)
	assert.NotContains(t, hcl, "storage")

	peers := serverpreset.Config{
		Arch:     "arm64",
		Listener: serverpreset.Listener{Address: "[::]:8200"},
		Raft:     serverpreset.Raft{Peers: []serverpreset.RaftPeer{{LeaderAPIAddr: "https://peer-0.example:8200"}}},
	}

	_, err = peers.HCL()
	require.ErrorContains(t, err, "Raft.Path")

	peers.Raft.Path = "/openbao/data"
	peers.Raft.Peers[0].LeaderAPIAddr = ""
	_, err = peers.HCL()
	require.ErrorContains(t, err, "LeaderAPIAddr")

	_, err = bare.PluginHCL()
	require.NoError(t, err)
	assert.Empty(t, bare.EgressDomains())
}

func desiredWithAWSMount(version string, registered bool) *model.Desired {
	desired := &model.Desired{Namespaces: []model.Namespace{{
		Name:    "dev",
		AWSAuth: []model.AWSAuthMount{{Path: "aws", PluginVersion: version}},
	}}}

	if registered {
		desired.Plugins = []model.Plugin{{Type: "auth", Name: "aws"}}
	}

	return desired
}

// A mount's plugin must resolve through one of the two registration paths.
func TestCheckMountsCrossChecksThePluginVersion(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", Plugins: []serverpreset.Plugin{awsAuthPlugin()}}

	require.NoError(t, c.CheckMounts(desiredWithAWSMount("v0.1.1", false)), "a pin the declarative catalog has")
	require.NoError(t, c.CheckMounts(desiredWithAWSMount("latest", false)), "latest resolves to whatever is registered")
	require.NoError(t, c.CheckMounts(desiredWithAWSMount("", true)), "an unpinned mount with an unversioned registration")
	require.NoError(t, c.CheckMounts(&model.Desired{}), "no AWS mount, nothing to check")

	require.ErrorContains(t, c.CheckMounts(desiredWithAWSMount("v9.9.9", false)), `pins plugin version "v9.9.9"`)
	require.ErrorContains(t, c.CheckMounts(desiredWithAWSMount("v9.9.9", true)), "cannot satisfy a pin")
	require.ErrorContains(t, c.CheckMounts(desiredWithAWSMount("", false)), "registers no auth/aws plugin")

	none := serverpreset.Config{Arch: "arm64"}
	require.ErrorContains(t, none.CheckMounts(desiredWithAWSMount("v0.1.1", false)), "declared: none")
}

func TestTelemetryRendersTheStanzaAndTheListenerBlock(t *testing.T) {
	c := serverpreset.Config{
		Arch: "arm64",
		Listener: serverpreset.Listener{
			Address: "[::]:8200", ClusterAddress: "[::]:8201",
			TLSCertFile: "/tls/tls.crt", TLSKeyFile: "/tls/tls.key",
		},
		ExternalStorage: true,
		Telemetry:       &serverpreset.Telemetry{UnauthenticatedMetricsAccess: true},
	}

	stanza, err := c.TelemetryHCL()
	require.NoError(t, err)
	assert.Equal(t, "telemetry {\n  prometheus_retention_time = \"24h\"\n  disable_hostname          = true\n}\n", stanza)

	assert.Equal(t, "  telemetry {\n    unauthenticated_metrics_access = true\n  }\n", c.ListenerTelemetryHCL())

	hcl, err := c.HCL()
	require.NoError(t, err)

	// The listener's block is inside the listener, the stanza outside it.
	_, afterOpen, found := strings.Cut(hcl, `listener "tcp" {`)
	require.True(t, found)

	listener, _, found := strings.Cut(afterOpen, "\n}\n")
	require.True(t, found)

	assert.Contains(t, listener, "unauthenticated_metrics_access = true")
	assert.NotContains(t, listener, "prometheus_retention_time")
	assert.Contains(t, hcl, stanza)
}

func TestTelemetryOffRendersNothing(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64"}

	stanza, err := c.TelemetryHCL()
	require.NoError(t, err)
	assert.Empty(t, stanza)
	assert.Empty(t, c.ListenerTelemetryHCL())

	// Retention alone does not open the endpoint.
	c.Telemetry = &serverpreset.Telemetry{PrometheusRetentionTime: "1h"}
	assert.Empty(t, c.ListenerTelemetryHCL())

	stanza, err = c.TelemetryHCL()
	require.NoError(t, err)
	assert.Contains(t, stanza, `prometheus_retention_time = "1h"`)
}

func TestTelemetryRefusesARetentionTheServerWouldNotServe(t *testing.T) {
	for _, bad := range []string{"soon", "0s", "-1h"} {
		c := serverpreset.Config{Arch: "arm64", Telemetry: &serverpreset.Telemetry{PrometheusRetentionTime: bad}}

		_, err := c.TelemetryHCL()
		require.Error(t, err, bad)
		require.Error(t, c.Validate(), bad)
	}
}
