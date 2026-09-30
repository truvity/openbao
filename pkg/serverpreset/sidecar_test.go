package serverpreset_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/openbao/pkg/serverpreset"
)

// TestRetrySidecarContainerRefusesWithNoPlugins is "sidecar rendered only
// with plugins": a server with nothing declarative to download has
// nothing for a retry sidecar to retry, and this package refuses to
// pretend otherwise rather than emit a container that loops checking for
// files that were never going to exist.
func TestRetrySidecarContainerRefusesWithNoPlugins(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64"}

	_, err := c.RetrySidecarContainer(serverpreset.RetrySidecarOptions{Image: "openbao/openbao:2.6.2", VolumeName: "openbao-plugins"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Plugins is empty")
}

func TestRetrySidecarContainerRefusesMissingImageOrVolume(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", Plugins: []serverpreset.Plugin{awsAuthPlugin()}}

	_, err := c.RetrySidecarContainer(serverpreset.RetrySidecarOptions{VolumeName: "openbao-plugins"})
	require.Error(t, err)

	_, err = c.RetrySidecarContainer(serverpreset.RetrySidecarOptions{Image: "openbao/openbao:2.6.2"})
	require.Error(t, err)
}

func TestRetrySidecarContainerShape(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", Plugins: []serverpreset.Plugin{awsAuthPlugin()}}

	container, err := c.RetrySidecarContainer(serverpreset.RetrySidecarOptions{
		Image: "openbao/openbao:2.6.2", VolumeName: "openbao-plugins",
	})
	require.NoError(t, err)

	assert.Equal(t, "plugin-retry", container["name"])
	assert.Equal(t, "openbao/openbao:2.6.2", container["image"])

	mounts, ok := container["volumeMounts"].([]any)
	require.True(t, ok)
	require.Len(t, mounts, 1)

	mount, ok := mounts[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "openbao-plugins", mount["name"])
	assert.Equal(t, "/openbao/plugins", mount["mountPath"])
	assert.Equal(t, true, mount["readOnly"])

	args, ok := container["args"].([]any)
	require.True(t, ok)
	require.Len(t, args, 1)

	script, ok := args[0].(string)
	require.True(t, ok)
	assert.Contains(t, script, "/openbao/plugins/auth-aws-v0.1.1")
	assert.Contains(t, script, "sys/health")
	assert.Contains(t, script, "kill -HUP")
}

// TestRetrySidecarScriptIsValidShell is the shellcheck/`sh -n` gate the
// task asks for: the script this package generates must at least PARSE
// as POSIX shell before it ever reaches a cluster. `sh -n` alone (parse,
// no execution) is run unconditionally; `shellcheck`, when the dev shell
// (devbox) has put it on PATH, adds the deeper static-analysis pass.
func TestRetrySidecarScriptIsValidShell(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", Plugins: []serverpreset.Plugin{awsAuthPlugin(), {
		Kind: "secret", Name: "example", Image: "ghcr.io/example/plugin", Version: "v1.0.0", BinaryName: "example",
		SHA256ByArch: map[string]string{"arm64": awsAuthPlugin().SHA256ByArch["arm64"]},
	}}}

	container, err := c.RetrySidecarContainer(serverpreset.RetrySidecarOptions{
		Image: "openbao/openbao:2.6.2", VolumeName: "openbao-plugins",
	})
	require.NoError(t, err)

	script := container["args"].([]any)[0].(string) //nolint:forcetypeassert,errcheck // shape asserted above

	dir := t.TempDir()
	path := filepath.Join(dir, "plugin-retry.sh")
	require.NoError(t, os.WriteFile(path, []byte(script), 0o600))

	out, err := exec.Command("sh", "-n", path).CombinedOutput()
	require.NoErrorf(t, err, "sh -n %s:\n%s\nscript:\n%s", path, out, script)

	if shellcheck, lookErr := exec.LookPath("shellcheck"); lookErr == nil {
		out, err := exec.Command(shellcheck, "-s", "sh", path).CombinedOutput()
		require.NoErrorf(t, err, "shellcheck %s:\n%s\nscript:\n%s", path, out, script)
	}
}

func TestRetrySidecarOptionsDefaults(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", Plugins: []serverpreset.Plugin{awsAuthPlugin()}}

	container, err := c.RetrySidecarContainer(serverpreset.RetrySidecarOptions{
		Image: "openbao/openbao:2.6.2", VolumeName: "openbao-plugins",
	})
	require.NoError(t, err)

	script := container["args"].([]any)[0].(string) //nolint:forcetypeassert,errcheck // shape asserted in TestRetrySidecarContainerShape
	assert.Contains(t, script, "port=8200")
	assert.Contains(t, script, "health_timeout=300")
	assert.Contains(t, script, "attempts=20")
	assert.Contains(t, script, "interval=30")
}

func tlsReloadOptions() serverpreset.TLSReloadOptions {
	return serverpreset.TLSReloadOptions{
		Image:             "openbao/openbao:2.7.0",
		CertificateFile:   "/openbao/userconfig/openbao-tls/tls.crt",
		CertificateVolume: "userconfig-openbao-tls",
		PluginVolume:      "openbao-plugins",
	}
}

func TestTLSReloadSidecarContainerShape(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", Plugins: []serverpreset.Plugin{awsAuthPlugin()}}

	opts := tlsReloadOptions()
	opts.Resources = map[string]any{"limits": map[string]any{"memory": "32Mi"}}
	opts.SecurityContext = map[string]any{"readOnlyRootFilesystem": true}

	container, err := c.TLSReloadSidecarContainer(opts)
	require.NoError(t, err)

	assert.Equal(t, "tls-reload", container["name"])
	assert.Equal(t, opts.Resources, container["resources"])
	assert.Equal(t, opts.SecurityContext, container["securityContext"])

	mounts, ok := container["volumeMounts"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{
		map[string]any{"name": "userconfig-openbao-tls", "mountPath": "/openbao/userconfig/openbao-tls", "readOnly": true},
		map[string]any{"name": "openbao-plugins", "mountPath": "/openbao/plugins", "readOnly": true},
	}, mounts)

	script := container["args"].([]any)[0].(string) //nolint:forcetypeassert,errcheck // shape asserted by the test
	assert.Contains(t, script, "plugin=/openbao/plugins/auth-aws-v0.1.1\n")
	assert.Contains(t, script, `[ "$ready" -lt 60 ]`)
	assert.Contains(t, script, "(up to 5 min)")
	assert.Contains(t, script, `[ "$attempt" -le 20 ]`)
	assert.Contains(t, script, "sleep 30")
	assert.Contains(t, script, "crt=/openbao/userconfig/openbao-tls/tls.crt")
	assert.Contains(t, script, "while sleep 60")
	assert.Contains(t, script, "openbao-tls changed: reloaded bao")
	assert.Contains(t, script, "sys/health?standbyok=true&sealedcode=200&uninitcode=200")
	assert.NotContains(t, script, "@")
}

// TestTLSReloadSidecarOmitsOptionalFields: with no resources or security
// context given, none is rendered.
func TestTLSReloadSidecarOmitsOptionalFields(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", Plugins: []serverpreset.Plugin{awsAuthPlugin()}}

	container, err := c.TLSReloadSidecarContainer(tlsReloadOptions())
	require.NoError(t, err)

	assert.NotContains(t, container, "resources")
	assert.NotContains(t, container, "securityContext")
}

func TestTLSReloadSidecarPluginComment(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", Plugins: []serverpreset.Plugin{awsAuthPlugin()}}

	opts := tlsReloadOptions()
	opts.PluginComment = "first line\n\nthird"

	container, err := c.TLSReloadSidecarContainer(opts)
	require.NoError(t, err)

	script := container["args"].([]any)[0].(string) //nolint:forcetypeassert,errcheck // shape asserted by the test
	assert.True(t, strings.HasPrefix(script, "# first line\n#\n# third\nplugin="), script)
}

func TestTLSReloadSidecarRefusals(t *testing.T) {
	one := serverpreset.Config{Arch: "arm64", Plugins: []serverpreset.Plugin{awsAuthPlugin()}}

	_, err := (&serverpreset.Config{Arch: "arm64"}).TLSReloadSidecarContainer(tlsReloadOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one")

	for _, mutate := range []func(*serverpreset.TLSReloadOptions){
		func(o *serverpreset.TLSReloadOptions) { o.Image = "" },
		func(o *serverpreset.TLSReloadOptions) { o.CertificateFile = "" },
		func(o *serverpreset.TLSReloadOptions) { o.CertificateVolume = "" },
		func(o *serverpreset.TLSReloadOptions) { o.PluginVolume = "" },
		func(o *serverpreset.TLSReloadOptions) { o.CertificateFile = "tls.crt" },
	} {
		opts := tlsReloadOptions()
		mutate(&opts)

		_, err := one.TLSReloadSidecarContainer(opts)
		require.Error(t, err)
	}
}

func TestTLSReloadScriptIsValidShell(t *testing.T) {
	c := serverpreset.Config{Arch: "arm64", Plugins: []serverpreset.Plugin{awsAuthPlugin()}}

	container, err := c.TLSReloadSidecarContainer(tlsReloadOptions())
	require.NoError(t, err)

	script := container["args"].([]any)[0].(string) //nolint:forcetypeassert,errcheck // shape asserted above

	path := filepath.Join(t.TempDir(), "tls-reload.sh")
	require.NoError(t, os.WriteFile(path, []byte(script), 0o600))

	out, err := exec.Command("sh", "-n", path).CombinedOutput()
	require.NoErrorf(t, err, "sh -n %s:\n%s\nscript:\n%s", path, out, script)

	if shellcheck, lookErr := exec.LookPath("shellcheck"); lookErr == nil {
		out, err := exec.Command(shellcheck, "-s", "sh", path).CombinedOutput()
		require.NoErrorf(t, err, "shellcheck %s:\n%s\nscript:\n%s", path, out, script)
	}
}

func TestPluginVolumeSizeLimit(t *testing.T) {
	c := serverpreset.Config{}
	assert.Equal(t, map[string]any{}, c.PluginVolume("openbao-plugins")["emptyDir"])

	c.PluginVolumeSizeLimit = "256Mi"
	assert.Equal(t, map[string]any{"sizeLimit": "256Mi"}, c.PluginVolume("openbao-plugins")["emptyDir"])
}
