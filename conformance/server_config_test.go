// Package conformance_test also proves, against a real `bao` binary of each
// supported release, that the server configuration pkg/serverpreset renders
// is one that OpenBAO accepts: it parses, and the server gets as far as the
// seal before it stops.
//
// The seal is where an offline run has to stop. The awskms seal reaches AWS
// KMS at startup, and on 2.7 it is an external plugin besides, so a server
// started here can never unseal. Everything before that point is what this
// test judges: a stanza the release does not know, a value it refuses, a
// directory it needs and is not given -- each ends the server before the
// seal, with a configuration error, and fails the test. What is expected
// instead is the seal's own error (`Error configuring seal "awskms"`).
//
// The server runs in a network namespace with no interface at all, so the
// proof does not depend on the machine having no route out: nothing can
// resolve a name or open a connection, the plugin download included.
//
// Not part of `just test`: it needs a `bao` binary of the release under test
// (OPENBAO_BAO_BINARY) and unprivileged user and network namespaces, and CI's
// server-config job runs it once per release. See docs/server.md.
package conformance_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/examples/server"
	"github.com/truvity/secrets/pkg/serverpreset"
)

// serverConfigVariable names the `bao` binary under test. Unset, the tests
// skip; set, every missing prerequisite is a failure, not a skip.
const serverConfigVariable = "OPENBAO_BAO_BINARY"

// configError matches what a server prints when it refuses its configuration
// (or half-accepts it: a value it logs and ignores is as wrong as one it
// refuses). The seal's own errors, and the plugin handshake's, match none of
// it.
var configError = regexp.MustCompile(
	`(?i)error loading configuration|error parsing|unknown (field|key|stanza)|unsupported|invalid|ignor(ed|ing)`)

// ansi strips the colour `bao operator diagnose` always prints.
var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type serverBinary struct {
	path    string
	version string
}

func requireServerBinary(t *testing.T) serverBinary {
	t.Helper()

	path := os.Getenv(serverConfigVariable)
	if path == "" {
		t.Skipf("%s is unset: the server-config CI job runs this against each release", serverConfigVariable)
	}

	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		t.Fatalf("unprivileged network namespaces are needed (unshare -rn): %v", err)
	}

	out, err := exec.Command(path, "version").Output()
	require.NoError(t, err)

	fields := strings.Fields(string(out)) // "OpenBao v2.7.0 (sha), committed ..."
	require.GreaterOrEqual(t, len(fields), 2, string(out))

	return serverBinary{path: path, version: strings.TrimPrefix(fields[1], "v")}
}

// seal27 reports whether the release builds awskms in no longer.
func (b serverBinary) seal27() bool {
	return !strings.HasPrefix(b.version, "2.6.") && !strings.HasPrefix(b.version, "2.5.")
}

// writeDummyTLS writes the listener's certificate, key and CA, self-signed
// and good for a day: the server reads them, nothing connects.
func writeDummyTLS(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o700))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: server.Endpoint},
		DNSNames:     []string{server.Endpoint, "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// Self-signed, so the certificate is its own CA file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), crt, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.crt"), crt, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
}

// scenario is one rendered configuration on disk, with the directories it
// names created the way a pod's volumes would have.
type scenario struct {
	config string
	env    []string
}

// materialise points cfg at directories under a fresh temp dir, renders it,
// and writes the file. A seal plugin, when cfg has one, is a dummy
// executable whose checksum cfg is made to carry: the plugin directory and
// the checksum are real, so the server gets to start the plugin, which then
// fails its handshake -- at the seal, as intended.
func materialise(t *testing.T, cfg *serverpreset.Config) scenario {
	t.Helper()

	root := t.TempDir()
	tls := filepath.Join(root, "tls")
	writeDummyTLS(t, tls)

	cfg.Listener.TLSCertFile = filepath.Join(tls, "tls.crt")
	cfg.Listener.TLSKeyFile = filepath.Join(tls, "tls.key")
	cfg.PluginDirectory = filepath.Join(root, "plugins")
	cfg.Raft.Path = filepath.Join(root, "data")

	for i := range cfg.Raft.Peers {
		cfg.Raft.Peers[i].LeaderCACertFile = filepath.Join(tls, "ca.crt")
	}

	require.NoError(t, os.MkdirAll(cfg.PluginDirectory, 0o700))
	require.NoError(t, os.MkdirAll(cfg.Raft.Path, 0o700))

	if p := cfg.Seal.Plugin; p != nil {
		dummy := []byte("#!/bin/sh\nexit 1\n")
		sum := sha256.Sum256(dummy)
		p.SHA256ByArch = map[string]string{runtime.GOARCH: hex.EncodeToString(sum[:])}

		require.NoError(t, os.WriteFile(filepath.Join(cfg.PluginDirectory, cfg.SealPluginCommand()), dummy, 0o700))
	}

	hcl, err := cfg.HCL()
	require.NoError(t, err)

	path := filepath.Join(root, "config.hcl")
	require.NoError(t, os.WriteFile(path, []byte(hcl), 0o600))
	t.Logf("rendered configuration:\n%s", hcl)

	return scenario{
		config: path,
		// What the chart's environment gives a pod, and the HCL leaves out.
		env: []string{
			"BAO_API_ADDR=https://localhost:8200",
			"BAO_CLUSTER_ADDR=https://localhost:8201",
			"BAO_K8S_NAMESPACE=openbao",
			"BAO_K8S_POD_NAME=openbao-0",
			"HOME=" + root,
			"PATH=" + os.Getenv("PATH"),
		},
	}
}

// syncBuffer is a bytes.Buffer a process writes while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// inNoNetwork runs `bao args...` in a network namespace of its own with no
// interface in it, and gives it limit to finish. --kill-child takes the
// server down with its namespace's init, whatever way the test ends.
func (b serverBinary) inNoNetwork(t *testing.T, s scenario, limit time.Duration, until func(string) bool, args ...string) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), limit)
	defer cancel()

	cmd := exec.CommandContext(ctx, "unshare", append([]string{"-rn", "--kill-child", b.path}, args...)...)
	cmd.Env = s.env

	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 5 * time.Second

	require.NoError(t, cmd.Start())

	done := make(chan error, 1)

	go func() { done <- cmd.Wait() }()

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case err := <-done:
			return out.String(), err
		case <-tick.C:
			if until != nil && until(out.String()) {
				cancel()
				<-done

				return out.String(), nil
			}
		}
	}
}

// requireNoConfigError fails with the server's own words.
func requireNoConfigError(t *testing.T, logs string) {
	t.Helper()

	for _, line := range strings.Split(logs, "\n") {
		assert.Falsef(t, configError.MatchString(line), "the server objects to its configuration: %s\n\nfull log:\n%s", line, logs)
	}
}

// sealStageLine is the first line the server prints about its seal when it
// cannot reach it: its error, or on a build that runs the seal as a plugin,
// the plugin's.
func sealStageLine(logs string) string {
	for _, line := range strings.Split(logs, "\n") {
		if strings.HasPrefix(line, `Error configuring seal "awskms"`) {
			return line
		}
	}

	return ""
}

func presetConfig(b serverBinary) *serverpreset.Config {
	if b.seal27() {
		return server.Config27(runtime.GOARCH)
	}

	return server.Config(runtime.GOARCH)
}

// TestServerAcceptsTheRenderedPreset renders the example server -- three-voter
// Raft, awskms auto-unseal, a TLS listener, the metrics listener, telemetry,
// a declarative auth plugin (whose download fails here, as `continue` allows)
// and an audit device -- and starts a real server on it with no network. The
// server must reach its seal and stop there. The kubernetes service
// registration is left out: the server starts it before the seal, and it needs
// a pod's service account, which TestDiagnoseParsesTheRenderedPreset covers.
func TestServerAcceptsTheRenderedPreset(t *testing.T) {
	bao := requireServerBinary(t)

	cfg := presetConfig(bao)
	cfg.ServiceRegistration = ""

	s := materialise(t, cfg)

	logs, _ := bao.inNoNetwork(t, s, 60*time.Second, nil, "server", "-config="+s.config)

	requireNoConfigError(t, logs)

	line := sealStageLine(logs)
	require.NotEmpty(t, line, "the server never reached the seal; log:\n%s", logs)
	t.Logf("OpenBAO %s seal stage: %s", bao.version, strings.SplitN(line, "\n", 2)[0])
}

// TestServerStartsOnTheRenderedPresetWithoutASeal drops what needs AWS, and
// the server must then run: the listeners, Raft, telemetry and audit device
// are all accepted, and it waits uninitialised.
func TestServerStartsOnTheRenderedPresetWithoutASeal(t *testing.T) {
	bao := requireServerBinary(t)

	cfg := presetConfig(bao)
	cfg.Seal = serverpreset.Seal{}
	cfg.ServerVersion = ""
	cfg.ServiceRegistration = ""
	cfg.Plugins = nil
	cfg.Raft.Peers = []serverpreset.RaftPeer{{
		LeaderAPIAddr: "https://localhost:8200", LeaderTLSServername: server.Endpoint,
	}}

	s := materialise(t, cfg)

	ready := func(logs string) bool { return strings.Contains(logs, "security barrier not initialized") }
	logs, err := bao.inNoNetwork(t, s, 60*time.Second, ready, "server", "-config="+s.config)

	require.NoError(t, err, "the server exited; log:\n%s", logs)
	requireNoConfigError(t, logs)
	require.True(t, ready(logs), "the server never finished starting; log:\n%s", logs)
}

// TestDiagnoseParsesTheRenderedPreset runs `bao operator diagnose`, which
// is offline for the checks it makes before the seal, on the whole preset
// (the service registration included): the configuration must parse, the plugin
// catalog and service discovery must be accepted, the storage backend must be
// created and the listeners' certificates must load. Its seal check reaches AWS
// and is not asserted, nor is its telemetry check, which fails on any
// configuration without a Stackdriver project.
func TestDiagnoseParsesTheRenderedPreset(t *testing.T) {
	bao := requireServerBinary(t)
	s := materialise(t, presetConfig(bao))

	logs, _ := bao.inNoNetwork(t, s, 60*time.Second, nil, "operator", "diagnose", "-config="+s.config)
	logs = ansi.ReplaceAllString(logs, "")

	for _, check := range []string{"Parse Configuration", "Check KMS Plugin Catalog", "Check Service Discovery", "Create Storage Backend"} {
		assert.Contains(t, logs, "[ success ] "+check, "diagnose output:\n%s", logs)
	}

	assert.NotContains(t, logs, "[ failure ] Check Listener TLS", "diagnose output:\n%s", logs)
	assert.NotContains(t, logs, "[ failure ] Start Listeners", "diagnose output:\n%s", logs)
}
