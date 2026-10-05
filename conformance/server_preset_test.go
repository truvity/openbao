// Package conformance_test also proves pkg/serverpreset's plugin HCL
// against a real, non-dev `bao server`: the three faults a 2026-09-28
// production rollout hit, each reproduced here so a future change to this
// package's rendering can only pass if it still avoids them.
//
// Every subtest points a plugin at "invalid.invalid" -- RFC 2606's
// reserved, guaranteed-unresolvable TLD -- rather than relying on the
// sandbox actually having no route to a real registry: the download must
// fail because DNS itself refuses it, not because of an environment
// property this test cannot control.
package conformance_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/serverpreset"
)

// address, in this file, is always freeAddress(t)'s picked loopback host:port,
// threaded through minimalHCL and runServer explicitly rather than
// re-parsed out of the rendered config: this test proves the plugin
// stanza, not an HCL scraper.

func unresolvablePlugin() serverpreset.Plugin {
	return serverpreset.Plugin{
		Kind:       "auth",
		Name:       "aws",
		Image:      "invalid.invalid/openbao/openbao-plugin-auth-aws",
		Version:    "v0.1.1",
		BinaryName: "openbao-plugin-auth-aws",
		SHA256ByArch: map[string]string{
			"amd64": "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
			"arm64": "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
		},
	}
}

// freeAddress hands back a loopback address nothing is listening on yet,
// the same way devServer (roster_test.go) picks one for `-dev`.
func freeAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	return address
}

// minimalHCL wraps pluginHCL with the smallest storage and listener that
// let a non-dev `bao server` start at all: single-node Raft (the `file`
// backend is gone in OpenBAO 2.7, and Raft is what the preset renders
// anyway) and TLS disabled (the plugin download's egress is what is under
// test, not the listener's certificate).
func minimalHCL(t *testing.T, dataDir, address, pluginHCL string) string {
	t.Helper()

	// 2.7 creates a missing Raft directory, 2.6 does not.
	require.NoError(t, os.MkdirAll(dataDir, 0o700))

	host, port, err := net.SplitHostPort(address)
	require.NoError(t, err)

	portNumber, err := strconv.Atoi(port)
	require.NoError(t, err)

	return `
storage "raft" {
  path    = "` + dataDir + `"
  node_id = "rehearsal"
}
api_addr     = "http://` + address + `"
cluster_addr = "http://` + net.JoinHostPort(host, strconv.Itoa(portNumber+1)) + `"
listener "tcp" {
  address     = "` + address + `"
  tls_disable = "true"
}
` + pluginHCL
}

// runServer starts `bao server` (never -dev: the config file above is the
// whole point) against the given address and waits either for its API to
// answer or for the process to exit, whichever comes first. It never
// fails the test itself -- each subtest asserts what SHOULD have happened
// -- and always returns the logs, so a failing assertion shows the
// server's own words.
//
// done closes exactly once, when the process has exited; exitErr reads
// the exit error after that (safe to call any number of times, from the
// subtest AND from t.Cleanup below -- a closed channel, unlike a single
// buffered value, has as many readers as anything cares to give it).
func runServer(t *testing.T, binary, configPath, address string) (healthy bool, done <-chan struct{}, exitErr func() error, logs *bytes.Buffer) {
	t.Helper()

	logs = &bytes.Buffer{}

	ctx, cancel := context.WithCancel(t.Context())
	server := exec.CommandContext(ctx, binary, "server", "-config="+configPath)
	server.Env = []string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
	server.Stdout, server.Stderr = logs, logs
	require.NoError(t, server.Start())

	doneCh := make(chan struct{})

	var waitErr error

	go func() {
		waitErr = server.Wait()
		close(doneCh)
	}()

	t.Cleanup(func() {
		cancel()
		<-doneCh
	})

	base := "http://" + address
	deadline := time.Now().Add(20 * time.Second)

	for time.Now().Before(deadline) {
		select {
		case <-doneCh:
			return false, doneCh, func() error { return waitErr }, logs
		default:
		}

		response, err := http.Get(base + "/v1/sys/health?standbyok=true&uninitcode=200")
		if err == nil {
			_ = response.Body.Close()

			if response.StatusCode == http.StatusOK {
				return true, doneCh, func() error { return waitErr }, logs
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	return false, doneCh, func() error { return waitErr }, logs
}

// TestPluginDirectoryMustExist reproduces the FIRST 2026-09-28 fault:
// plugin_directory must exist before `bao server` starts, whether or not
// the download that follows succeeds. A failed download never creates it
// -- so a config that declares a plugin but whose directory nothing
// created makes the server exit, not warn and continue.
func TestPluginDirectoryMustExist(t *testing.T) {
	binary := tool(t, "bao")

	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "plugins") // never created

	cfg := serverpreset.Config{
		Arch:    "amd64",
		Plugins: []serverpreset.Plugin{unresolvablePlugin()},
	}
	cfg.PluginDirectory = pluginDir

	pluginHCL, err := cfg.PluginHCL()
	require.NoError(t, err)

	address := freeAddress(t)
	configPath := filepath.Join(dir, "server.hcl")
	require.NoError(t, os.WriteFile(configPath,
		[]byte(minimalHCL(t, filepath.Join(dir, "data"), address, pluginHCL)), 0o600))

	healthy, done, exitErr, logs := runServer(t, binary, configPath, address)
	assert.False(t, healthy, "a server whose plugin_directory does not exist must not come up healthy:\n%s", logs.String())

	select {
	case <-done:
		assert.Error(t, exitErr(), "the server should have exited non-zero on a missing plugin_directory:\n%s", logs.String())
	case <-time.After(2 * time.Second):
		t.Fatalf("the server neither became healthy nor exited on a missing plugin_directory:\n%s", logs.String())
	}
}

// TestContinueBehaviorSurvivesAFailedDownload reproduces the recovery from
// the SECOND and THIRD faults together: plugin_directory exists (this
// package's contract: create it before the server ever runs), the
// download of an unresolvable image fails, and
// plugin_download_behavior = "continue" (this package's default) means
// that failure logs and the server still starts -- never a crash-looping
// voter over one plugin nobody can reach yet.
func TestContinueBehaviorSurvivesAFailedDownload(t *testing.T) {
	binary := tool(t, "bao")

	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "plugins")
	require.NoError(t, os.MkdirAll(pluginDir, 0o700)) // the fix: exists BEFORE the server starts

	cfg := serverpreset.Config{
		Arch:    "amd64",
		Plugins: []serverpreset.Plugin{unresolvablePlugin()},
	}
	cfg.PluginDirectory = pluginDir

	pluginHCL, err := cfg.PluginHCL()
	require.NoError(t, err)
	assert.Contains(t, pluginHCL, `plugin_download_behavior = "continue"`)

	address := freeAddress(t)
	configPath := filepath.Join(dir, "server.hcl")
	require.NoError(t, os.WriteFile(configPath,
		[]byte(minimalHCL(t, filepath.Join(dir, "data"), address, pluginHCL)), 0o600))

	healthy, _, _, logs := runServer(t, binary, configPath, address)
	assert.True(t, healthy, "a \"continue\" failure must not stop the server:\n%s", logs.String())

	entries, err := os.ReadDir(pluginDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "the download of an unresolvable image should have failed, leaving the plugin directory empty")
}

// TestFailBehaviorRefusesToStart is DownloadBehavior's other legal value,
// for contrast: "fail" refuses to start at all on a failed download,
// which is the right choice for an install that would rather stay down
// than run without a plugin it depends on.
func TestFailBehaviorRefusesToStart(t *testing.T) {
	binary := tool(t, "bao")

	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "plugins")
	require.NoError(t, os.MkdirAll(pluginDir, 0o700))

	cfg := serverpreset.Config{
		Arch:             "amd64",
		DownloadBehavior: "fail",
		Plugins:          []serverpreset.Plugin{unresolvablePlugin()},
	}
	cfg.PluginDirectory = pluginDir

	pluginHCL, err := cfg.PluginHCL()
	require.NoError(t, err)

	address := freeAddress(t)
	configPath := filepath.Join(dir, "server.hcl")
	require.NoError(t, os.WriteFile(configPath,
		[]byte(minimalHCL(t, filepath.Join(dir, "data"), address, pluginHCL)), 0o600))

	healthy, done, exitErr, logs := runServer(t, binary, configPath, address)
	assert.False(t, healthy, "plugin_download_behavior = \"fail\" should refuse to start on a failed download:\n%s", logs.String())

	select {
	case <-done:
		assert.Error(t, exitErr(), "the server should have exited non-zero:\n%s", logs.String())
	case <-time.After(2 * time.Second):
		t.Fatalf("the server neither became healthy nor exited with plugin_download_behavior = \"fail\":\n%s", logs.String())
	}
}

// TestMetricsListenerServesMetricsAndNothingElse proves, against a real
// `bao server`, what docs/server.md claims of the rendered metrics listener:
// /v1/sys/metrics answers there without a token, no other path does, and the
// API listener (which sets no telemetry block) refuses the same read.
func TestMetricsListenerServesMetricsAndNothingElse(t *testing.T) {
	binary := tool(t, "bao")

	dir := t.TempDir()
	apiAddress := freeAddress(t)
	metricsAddress := freeAddress(t)

	cfg := serverpreset.Config{
		Arch:      "amd64",
		Listener:  serverpreset.Listener{Address: apiAddress, TLSCertFile: "/tls.crt", TLSKeyFile: "/tls.key"},
		Telemetry: &serverpreset.Telemetry{MetricsAddress: metricsAddress},
	}

	// TLS is not what is under test: swap the certificate files the preset
	// renders for tls_disable, and keep every other line it renders.
	metricsHCL := strings.NewReplacer(
		`  tls_cert_file = "/tls.crt"`, `  tls_disable   = "true"`,
		`  tls_key_file  = "/tls.key"`+"\n", "",
	).Replace(cfg.MetricsListenerHCL())
	require.Contains(t, metricsHCL, "metrics_only")

	telemetry, err := cfg.TelemetryHCL()
	require.NoError(t, err)

	configPath := filepath.Join(dir, "server.hcl")
	require.NoError(t, os.WriteFile(configPath,
		[]byte(minimalHCL(t, filepath.Join(dir, "data"), apiAddress, metricsHCL+telemetry)), 0o600))

	healthy, _, _, logs := runServer(t, binary, configPath, apiAddress)
	require.True(t, healthy, "the server did not start:\n%s", logs.String())

	status := func(address, path string) int {
		response, err := http.Get("http://" + address + path)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())

		return response.StatusCode
	}

	assert.Equal(t, http.StatusOK, status(metricsAddress, "/v1/sys/metrics?format=prometheus"), "the metrics listener answers without a token")
	assert.NotEqual(t, http.StatusOK, status(metricsAddress, "/v1/sys/health"), "the metrics listener serves no other path")
	assert.NotEqual(t, http.StatusOK, status(metricsAddress, "/v1/sys/seal-status"), "the metrics listener serves no other path")
	assert.NotEqual(t, http.StatusOK, status(apiAddress, "/v1/sys/metrics?format=prometheus"), "the API listener does not answer the metrics without a token")
}
