package serverpreset_test

import (
	"os"
	"os/exec"
	"path/filepath"
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
