package conformance_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/examples/server"
	"github.com/truvity/secrets/pkg/serverpreset"
)

// sealRehearsalVariable gates the seal-plugin rehearsal. It needs a Docker
// daemon (28 or later, for image mounts) and pulls its images, so it is not
// part of `just test`; `just rehearse-seal-plugin` runs it. Unset, the test
// skips; set it to "required" to make a missing docker or a failed pull a
// failure.
//
// What it proves, on real servers: with the seal as an external KMS plugin
// (OpenBAO 2.7), a server that has NO route to the internet — no registry,
// no DNS, nothing but the KMS emulator beside it — cold-starts and unseals,
// unseals again on restart with nobody helping it, and a three-voter Raft
// cluster rolls 2.6.3 to 2.7.0 one node at a time without a node ever
// staying sealed or the cluster losing quorum. The plugin is delivered by
// the init container serverpreset renders, run here exactly as rendered
// (the same image, script, mounts and image volume), with a Docker image
// mount standing in for the kubelet's image volume.
const sealRehearsalVariable = "OPENBAO_SEAL_REHEARSAL"

const (
	// The server images, pinned by digest so the rehearsal is the same
	// rehearsal next month.
	rehearsalServerOld = "openbao/openbao:2.6.3@sha256:a60afafda36337abe833c4a63894bf1095098f29abea4091e7e555a33dd52889"
	rehearsalServerNew = "openbao/openbao:2.7.0@sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315"
	// The KMS emulator: moto, a Python AWS mock. It answers the KMS API
	// with real encrypt/decrypt round trips, which is all the seal asks.
	rehearsalKMS = "motoserver/moto:latest@sha256:91fd602a21f49cf9eb82fdf474015a3c131d40104c8297ea6a2ca920708ae32c"

	rehearsalEndpointName = "openbao.example.internal"
	rehearsalRegion       = "us-east-1"
	rehearsalUID          = "100:1000" // the upstream chart's runAsUser:fsGroup
)

// rehearsal is one run's Docker resources: an internal network (no route
// out — that is the "no internet" of the whole exercise), the KMS emulator
// on it, and the certificates every server serves.
type rehearsal struct {
	t       *testing.T
	prefix  string
	network string
	tlsDir  string
	keyID   string
	timings []string
}

func dockerBinary(t *testing.T) string {
	t.Helper()

	path, err := exec.LookPath("docker")
	if err != nil {
		if os.Getenv(sealRehearsalVariable) == "required" {
			t.Fatalf("%s=required and no `docker` on PATH", sealRehearsalVariable)
		}

		t.Skip("no `docker` on PATH")
	}

	return path
}

func (r *rehearsal) docker(args ...string) (string, error) {
	r.t.Helper()

	var out bytes.Buffer

	command := exec.Command("docker", args...)
	command.Stdout, command.Stderr = &out, &out
	err := command.Run()

	return strings.TrimSpace(out.String()), err
}

func (r *rehearsal) mustDocker(args ...string) string {
	r.t.Helper()

	out, err := r.docker(args...)
	require.NoError(r.t, err, "docker %s:\n%s", strings.Join(args, " "), out)

	return out
}

func newRehearsal(t *testing.T) *rehearsal {
	t.Helper()

	dockerBinary(t)

	if os.Getenv(sealRehearsalVariable) == "" {
		t.Skipf("%s is unset: `just rehearse-seal-plugin` runs this (needs a Docker daemon with image mounts and network for the pulls)", sealRehearsalVariable)
	}

	r := &rehearsal{t: t, prefix: fmt.Sprintf("obsp-%d-", time.Now().UnixNano()%1_000_000_000)}
	r.network = r.prefix + "net"

	for _, image := range []string{rehearsalServerOld, rehearsalServerNew, rehearsalKMS, server.SealPluginImage + "@" + server.SealPluginDigest} {
		if _, err := r.docker("image", "inspect", image); err == nil {
			continue
		}

		if out, err := r.docker("pull", "--quiet", image); err != nil {
			if os.Getenv(sealRehearsalVariable) == "required" {
				t.Fatalf("pull %s: %v\n%s", image, err, out)
			}

			t.Skipf("cannot pull %s (%v); %s=required makes this a failure", image, err, sealRehearsalVariable)
		}
	}

	t.Cleanup(func() {
		names, _ := r.docker("ps", "-aq", "--filter", "name="+r.prefix)
		for _, id := range strings.Fields(names) {
			_, _ = r.docker("rm", "-f", id)
		}

		volumes, _ := r.docker("volume", "ls", "-q", "--filter", "name="+r.prefix)
		for _, v := range strings.Fields(volumes) {
			_, _ = r.docker("volume", "rm", "-f", v)
		}

		_, _ = r.docker("network", "rm", r.network)
	})

	// --internal: the network has no gateway. A container on it reaches
	// only the other containers on it; a registry, a DNS name outside it
	// and the internet are all unreachable.
	r.mustDocker("network", "create", "--internal", r.network)

	r.writeTLS()
	r.startKMS()

	return r
}

// writeTLS makes one CA and one leaf every server serves, carrying the one
// endpoint name (the "verify one name" shape of docs/server.md) and every
// pod's name.
func (r *rehearsal) writeTLS() {
	r.t.Helper()

	r.tlsDir = r.t.TempDir()
	require.NoError(r.t, os.Chmod(r.tlsDir, 0o755)) //nolint:gosec // a container user must read it

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(r.t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rehearsal CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(r.t, err)

	ca, err := x509.ParseCertificate(caDER)
	require.NoError(r.t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(r.t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: rehearsalEndpointName},
		DNSNames:    []string{rehearsalEndpointName, "bao-0", "bao-1", "bao-2", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	require.NoError(r.t, err)

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(r.t, err)

	for name, block := range map[string]*pem.Block{
		"ca.crt":  {Type: "CERTIFICATE", Bytes: caDER},
		"tls.crt": {Type: "CERTIFICATE", Bytes: leafDER},
		"tls.key": {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		require.NoError(r.t, os.WriteFile(filepath.Join(r.tlsDir, name), pem.EncodeToMemory(block), 0o644)) //nolint:gosec // as above
	}
}

// startKMS runs the emulator on the internal network only — no published
// port — and creates the seal's key in it.
func (r *rehearsal) startKMS() {
	r.t.Helper()

	r.mustDocker("run", "-d", "--name", r.prefix+"kms", "--network", r.network, "--network-alias", "kms", rehearsalKMS)

	// The region is in the credential scope of the (unchecked) signature.
	authorization := "AWS4-HMAC-SHA256 Credential=x/20260930/" + rehearsalRegion + "/kms/aws4_request, SignedHeaders=host, Signature=x"
	create := `import json,urllib.request
headers={"X-Amz-Target":"TrentService.CreateKey","Content-Type":"application/x-amz-json-1.1","Authorization":"` + authorization + `"}
r=urllib.request.Request("http://localhost:5000/",data=b"{}",headers=headers)
print(json.load(urllib.request.urlopen(r))["KeyMetadata"]["KeyId"])`

	deadline := time.Now().Add(60 * time.Second)

	for {
		out, err := r.docker("exec", r.prefix+"kms", "python", "-c", create)
		if err == nil {
			r.keyID = out

			return
		}

		if time.Now().After(deadline) {
			r.t.Fatalf("the KMS emulator never answered: %v\n%s", err, out)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// config is the preset's Config for one rehearsal server generation. Every
// node gets the same HCL, as with the upstream chart. sealPlugin false is
// the 2.6 rendering: the built-in seal, nothing else.
func (r *rehearsal) config(version string, sealPlugin, checksum bool, voters int) *serverpreset.Config {
	peers := make([]serverpreset.RaftPeer, voters)
	for i := range peers {
		peers[i] = serverpreset.RaftPeer{
			LeaderAPIAddr:       fmt.Sprintf("https://bao-%d:8200", i),
			LeaderCACertFile:    "/tls/ca.crt",
			LeaderTLSServername: rehearsalEndpointName,
		}
	}

	cfg := &serverpreset.Config{
		Arch:                runtimeArch(),
		ServerVersion:       version,
		DisableStandbyReads: true,
		Listener: serverpreset.Listener{
			Address: "[::]:8200", ClusterAddress: "[::]:8201",
			TLSCertFile: "/tls/tls.crt", TLSKeyFile: "/tls/tls.key",
		},
		Raft: serverpreset.Raft{Path: "/openbao/data", Peers: peers},
		Seal: serverpreset.Seal{Type: "awskms", Region: rehearsalRegion, KMSKeyID: r.keyID, Endpoint: "http://kms:5000"},
	}

	if sealPlugin {
		cfg.Seal.Plugin = &serverpreset.SealPlugin{
			Image:     server.SealPluginImage,
			Digest:    server.SealPluginDigest,
			Version:   server.SealPluginVersion,
			CopyImage: rehearsalServerNew,
		}
		if checksum {
			cfg.Seal.Plugin.SHA256ByArch = server.SealPluginSHA256ByArch
		}
	}

	return cfg
}

func runtimeArch() string {
	out, err := exec.Command("docker", "version", "--format", "{{.Server.Arch}}").Output()
	if err != nil {
		return "amd64"
	}

	return strings.TrimSpace(string(out))
}

// node is one server: its name, its data volume (Raft's disk, which
// outlives the pod) and the plugin volume (an emptyDir, which does not).
type node struct {
	name, data string
}

// prepareVolume makes a fresh volume writable by the server's user, the
// job the pod's fsGroup does in Kubernetes.
func (r *rehearsal) prepareVolume(name string) {
	r.t.Helper()

	r.mustDocker("volume", "create", name)
	r.mustDocker("run", "--rm", "--network", "none", "--user", "0", "-v", name+":/v", "--entrypoint", "chown", rehearsalServerNew, "-R", rehearsalUID, "/v")
}

// installSealPlugin runs the init container serverpreset renders, exactly
// as rendered: its image, its script, its mounts, no network. The image
// volume is a Docker image mount of the reference the preset renders — the
// kubelet's job.
func (r *rehearsal) installSealPlugin(cfg *serverpreset.Config, pluginVolume string) time.Duration {
	r.t.Helper()

	start := time.Now()

	init, err := cfg.SealPluginInitContainer("plugins")
	require.NoError(r.t, err)

	source := cfg.SealPluginSourceVolume()
	image, _ := source["image"].(map[string]any)
	reference, _ := image["reference"].(string)
	require.NotEmpty(r.t, reference)

	args := []string{
		"run", "--rm", "--network", "none", "--user", rehearsalUID, "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
	}

	mounts, _ := init["volumeMounts"].([]any)
	for _, m := range mounts {
		mount, _ := m.(map[string]any)
		path, _ := mount["mountPath"].(string)

		if mount["name"] == source["name"] {
			args = append(args, "--mount", "type=image,source="+reference+",destination="+path)
		} else {
			args = append(args, "-v", pluginVolume+":"+path)
		}
	}

	command, _ := init["command"].([]any)
	scriptArgs, _ := init["args"].([]any)
	initImage, _ := init["image"].(string)

	args = append(args, "--entrypoint", command[0].(string), initImage) //nolint:forcetypeassert // rendered by us
	for _, c := range command[1:] {
		args = append(args, c.(string)) //nolint:forcetypeassert
	}

	for _, a := range scriptArgs {
		args = append(args, a.(string)) //nolint:forcetypeassert
	}

	out := r.mustDocker(args...)
	assert.Contains(r.t, out, "seal-plugin-install: installed /openbao/plugins/kms-awskms-"+server.SealPluginVersion)

	return time.Since(start)
}

// startServer launches `bao server` on the exact rendered HCL, on an
// internal network only.
func (r *rehearsal) startServer(n node, cfg *serverpreset.Config, image, pluginVolume string) {
	r.t.Helper()

	hcl, err := cfg.HCL()
	require.NoError(r.t, err)

	hclPath := filepath.Join(r.t.TempDir(), n.name+".hcl")
	require.NoError(r.t, os.WriteFile(hclPath, []byte(hcl), 0o644)) //nolint:gosec // a container user must read it
	require.NoError(r.t, os.Chmod(filepath.Dir(hclPath), 0o755))    //nolint:gosec // as above

	// A node name is reused across the rehearsal's phases; an earlier
	// phase's container must not still hold it (or its network alias).
	_, _ = r.docker("rm", "-f", r.prefix+n.name)

	args := []string{
		"run", "-d", "--name", r.prefix + n.name, "--network", r.network, "--network-alias", n.name,
		"--user", rehearsalUID,
		"-e", "AWS_ACCESS_KEY_ID=rehearsal", "-e", "AWS_SECRET_ACCESS_KEY=rehearsal",
		"-e", "BAO_RAFT_NODE_ID=" + n.name,
		"-e", "BAO_API_ADDR=https://" + n.name + ":8200", "-e", "BAO_CLUSTER_ADDR=https://" + n.name + ":8201",
		"-v", r.tlsDir + ":/tls:ro", "-v", hclPath + ":/etc/bao/server.hcl:ro",
		"-v", n.data + ":/openbao/data",
	}

	if cfg.Seal.Plugin != nil {
		args = append(args, "-v", pluginVolume+":/openbao/plugins")
	}

	args = append(args, image, "bao", "server", "-config=/etc/bao/server.hcl")

	r.mustDocker(args...)
}

func (r *rehearsal) logs(n node) string {
	out, _ := r.docker("logs", r.prefix+n.name)

	return out
}

// status is `bao status` on one node. Its JSON leaves out the HA mode, so
// this reads the table; `bao status` exits 2 while sealed but still prints
// it. Nil while the node does not answer.
type status struct {
	Initialized bool
	Sealed      bool
	Version     string
	HAMode      string
	Type        string
}

func (r *rehearsal) exec(n node, token string, args ...string) (string, error) {
	command := []string{
		"exec", "-e", "BAO_ADDR=https://127.0.0.1:8200", "-e", "BAO_CACERT=/tls/ca.crt", "-e", "BAO_TLS_SERVER_NAME=" + rehearsalEndpointName,
	}
	if token != "" {
		command = append(command, "-e", "BAO_TOKEN="+token)
	}

	command = append(command, r.prefix+n.name, "bao")

	return r.docker(append(command, args...)...)
}

func (r *rehearsal) status(n node) *status {
	out, _ := r.exec(n, "", "status")

	fields := map[string]string{}

	for _, line := range strings.Split(out, "\n") {
		if key, value, ok := splitStatusLine(line); ok {
			fields[key] = value
		}
	}

	if fields["Sealed"] == "" {
		return nil
	}

	return &status{
		Initialized: fields["Initialized"] == "true",
		Sealed:      fields["Sealed"] == "true",
		Version:     fields["Version"],
		HAMode:      fields["HA Mode"],
		Type:        fields["Seal Type"],
	}
}

// splitStatusLine splits a "Key      Value" line of the status table.
func splitStatusLine(line string) (key, value string, ok bool) {
	parts := regexp.MustCompile(`\s{2,}`).Split(strings.TrimSpace(line), 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}

// waitUnsealed polls until the node is initialized and unsealed, and fails
// with the server's own log when it is not by the deadline.
func (r *rehearsal) waitUnsealed(n node, within time.Duration) time.Duration {
	r.t.Helper()

	start := time.Now()

	for time.Since(start) < within {
		if s := r.status(n); s != nil && s.Initialized && !s.Sealed {
			return time.Since(start)
		}

		if running, _ := r.docker("inspect", "-f", "{{.State.Running}}", r.prefix+n.name); running != "true" {
			r.t.Fatalf("%s exited while waiting to unseal:\n%s", n.name, r.logs(n))
		}

		time.Sleep(250 * time.Millisecond)
	}

	r.t.Fatalf("%s still not unsealed after %s:\n%s", n.name, within, r.logs(n))

	return 0
}

func (r *rehearsal) record(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	r.timings = append(r.timings, line)
	r.t.Log(line)
}

// initialize is `bao operator init` on a node, returning the root token.
func (r *rehearsal) initialize(n node) string {
	r.t.Helper()

	deadline := time.Now().Add(60 * time.Second)

	var out string

	var err error

	for time.Now().Before(deadline) {
		out, err = r.exec(n, "", "operator", "init", "-recovery-shares=1", "-recovery-threshold=1", "-format=json")
		if err == nil {
			break
		}

		time.Sleep(500 * time.Millisecond)
	}

	require.NoError(r.t, err, "init: %s\n%s", out, r.logs(n))

	var response struct {
		RootToken string `json:"root_token"`
	}

	require.NoError(r.t, json.Unmarshal([]byte(out), &response), out)

	return response.RootToken
}

// probe writes a value and reads it back through one node — a write is a
// quorum commit, so it is the proof the cluster still has one.
func (r *rehearsal) probe(n node, token, value string) {
	r.t.Helper()

	deadline := time.Now().Add(30 * time.Second)

	var out string

	var err error

	for time.Now().Before(deadline) {
		if out, err = r.exec(n, token, "kv", "put", "-mount=kv", "probe", "v="+value); err == nil {
			got, gerr := r.exec(n, token, "kv", "get", "-mount=kv", "-field=v", "probe")
			if gerr == nil && got == value {
				return
			}

			out, err = got, gerr
		}

		time.Sleep(500 * time.Millisecond)
	}

	r.t.Fatalf("no committed write/read through %s: %v\n%s", n.name, err, out)
}

type peer struct {
	NodeID string `json:"node_id"`
	Voter  bool   `json:"voter"`
	Leader bool   `json:"leader"`
}

// peers is Raft's own view of its voters, read through one node.
func (r *rehearsal) peers(n node, token string) []peer {
	out, err := r.exec(n, token, "operator", "raft", "list-peers", "-format=json")
	if err != nil {
		return nil
	}

	var response struct {
		Data struct {
			Config struct {
				Servers []peer `json:"servers"`
			} `json:"config"`
		} `json:"data"`
	}

	if json.Unmarshal([]byte(out), &response) != nil {
		return nil
	}

	return response.Data.Config.Servers
}

func (r *rehearsal) waitVoters(n node, token string, want int) {
	r.t.Helper()

	deadline := time.Now().Add(60 * time.Second)

	for time.Now().Before(deadline) {
		voters := 0

		for _, p := range r.peers(n, token) {
			if p.Voter {
				voters++
			}
		}

		if voters == want {
			return
		}

		time.Sleep(500 * time.Millisecond)
	}

	r.t.Fatalf("Raft never showed %d voters through %s: %+v", want, n.name, r.peers(n, token))
}

// TestSealPluginRehearsal is the OpenBAO 2.7 seal-as-plugin rehearsal: see
// sealRehearsalVariable.
func TestSealPluginRehearsal(t *testing.T) {
	r := newRehearsal(t)

	t.Run("the server has no route out", func(t *testing.T) {
		// A probe on the servers' own network: no registry name resolves
		// and no address answers, so anything below that unseals did so
		// with nothing but the KMS emulator beside it.
		out, err := r.docker("run", "--rm", "--network", r.network, "--entrypoint", "sh", rehearsalServerNew, "-c",
			"wget -q -T 4 -O /dev/null https://1.1.1.1/ && echo REACHED; "+
				"nslookup ghcr.io 2>&1 | grep -q 'can.t find\\|NXDOMAIN\\|bad address\\|timed out\\|refused' && echo NO-DNS")
		_ = err

		assert.NotContains(t, out, "REACHED", "an internal network must have no route to the internet")
		assert.Contains(t, out, "NO-DNS", "a registry name must not resolve:\n%s", out)
	})

	t.Run("a 2.7 server refuses the built-in seal", func(t *testing.T) {
		// The reason this work exists: the same config that renders for
		// 2.6 (no plugin) does not start on 2.7.
		n := node{name: "bao-legacy", data: r.prefix + "legacy-data"}
		r.prepareVolume(n.data)

		cfg := r.config("2.6.3", false, false, 1)
		r.startServer(n, cfg, rehearsalServerNew, "")

		time.Sleep(4 * time.Second)

		running, _ := r.docker("inspect", "-f", "{{.State.Running}}", r.prefix+n.name)
		assert.Equal(t, "false", running, "2.7.0 must exit on a seal it no longer has:\n%s", r.logs(n))
		assert.Contains(t, r.logs(n), "awskms", "the log should name the seal")
		t.Logf("2.7.0 with the 2.6 rendering exits: %s", lastLine(r.logs(n)))

		// And the preset itself refuses to render it for 2.7.
		cfg.ServerVersion = "2.7.0"
		_, err := cfg.HCL()
		require.Error(t, err)
	})

	t.Run("the server without its plugin does not start", func(t *testing.T) {
		// The startup requirement, demonstrated: the config is right but
		// the binary is not there, and the server EXITS rather than
		// serving sealed. This is why the plugin is installed before the
		// server, by an init container, and never downloaded by it.
		n := node{name: "bao-noplugin", data: r.prefix + "noplugin-data"}
		r.prepareVolume(n.data)

		empty := r.prefix + "noplugin-plugins"
		r.prepareVolume(empty)

		r.startServer(n, r.config("2.7.0", true, false, 1), rehearsalServerNew, empty)
		time.Sleep(4 * time.Second)

		running, _ := r.docker("inspect", "-f", "{{.State.Running}}", r.prefix+n.name)
		assert.Equal(t, "false", running, "a missing seal plugin must stop the server:\n%s", r.logs(n))
		assert.Contains(t, r.logs(n), "no such file or directory")
	})

	t.Run("cold start and restart on 2.7.0, no internet", func(t *testing.T) {
		n := node{name: "bao-0", data: r.prefix + "cold-data"}
		plugins := r.prefix + "cold-plugins"
		r.prepareVolume(n.data)
		r.prepareVolume(plugins)

		cfg := r.config("2.7.0", true, true, 1)
		hcl, err := cfg.HCL()
		require.NoError(t, err)
		t.Logf("rendered HCL:\n%s", hcl)

		install := r.installSealPlugin(cfg, plugins)
		r.record("cold: init container installed the seal plugin in %s", install.Round(time.Millisecond))

		start := time.Now()
		r.startServer(n, cfg, rehearsalServerNew, plugins)

		token := r.initialize(n)
		r.record("cold: container start to initialized and unsealed: %s", time.Since(start).Round(time.Millisecond))

		s := r.status(n)
		require.NotNil(t, s)
		assert.False(t, s.Sealed)
		assert.Equal(t, "2.7.0", s.Version)
		assert.Equal(t, "awskms", s.Type)
		assert.Contains(t, r.logs(n), "builtin: false", "the seal must be the plugin, not a built-in")

		_, err = r.exec(n, token, "secrets", "enable", "-path=kv", "kv-v2")
		require.NoError(t, err)
		r.probe(n, token, "cold")

		// Restart the container: the plugin directory (an emptyDir)
		// survives, the server comes back and unseals by itself.
		start = time.Now()
		r.mustDocker("restart", r.prefix+n.name)
		took := r.waitUnsealed(n, 90*time.Second)
		r.record("restart (container): unsealed with no help in %s (restart command to unsealed %s)",
			took.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
		r.probe(n, token, "restart")

		// Restart the POD: a new emptyDir, so the init container runs
		// again from nothing, then the server unseals from the same disk.
		r.mustDocker("rm", "-f", r.prefix+n.name)
		r.mustDocker("volume", "rm", "-f", plugins)
		r.prepareVolume(plugins)

		start = time.Now()
		install = r.installSealPlugin(cfg, plugins)
		r.startServer(n, cfg, rehearsalServerNew, plugins)
		r.waitUnsealed(n, 90*time.Second)
		r.record("restart (pod, empty plugin directory): init container %s, unsealed with no help in %s total",
			install.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
		r.probe(n, token, "pod")
	})

	t.Run("2.6.3 runs the same seal plugin (stage it before the version change)", func(t *testing.T) {
		// 2.6 already supports KMS plugins, and a plugin shadows the
		// built-in seal: the plugin form can be rolled on 2.6.3 first, so
		// the seal change and the version change are two rolls, not one.
		n := node{name: "bao-0", data: r.prefix + "stage-data"}
		plugins := r.prefix + "stage-plugins"
		r.prepareVolume(n.data)
		r.prepareVolume(plugins)

		cfg := r.config("2.6.3", true, true, 1)
		r.installSealPlugin(cfg, plugins)
		r.startServer(n, cfg, rehearsalServerOld, plugins)
		token := r.initialize(n)
		took := r.waitUnsealed(n, 90*time.Second)

		s := r.status(n)
		require.NotNil(t, s)
		assert.Equal(t, "2.6.3", s.Version)
		assert.Contains(t, r.logs(n), "builtin: false", "the plugin must shadow the built-in seal on 2.6.3")
		_, err := r.exec(n, token, "secrets", "enable", "-path=kv", "kv-v2")
		require.NoError(t, err)
		r.probe(n, token, "staged")
		r.record("stage: 2.6.3 with the seal plugin (builtin: false) unsealed in %s", took.Round(time.Millisecond))

		// Then the version change alone, on the same data: 2.7.0, same HCL.
		r.mustDocker("rm", "-f", r.prefix+n.name)

		next := r.config("2.7.0", true, true, 1)
		plugins2 := r.prefix + "stage-plugins-2"
		r.prepareVolume(plugins2)
		r.installSealPlugin(next, plugins2)
		r.startServer(n, next, rehearsalServerNew, plugins2)
		r.waitUnsealed(n, 90*time.Second)
		r.probe(n, token, "staged-2.7")
	})

	t.Run("three voters roll 2.6.3 to 2.7.0 one node at a time", func(t *testing.T) {
		nodes := []node{
			{name: "bao-0", data: r.prefix + "roll-data-0"},
			{name: "bao-1", data: r.prefix + "roll-data-1"},
			{name: "bao-2", data: r.prefix + "roll-data-2"},
		}
		for _, n := range nodes {
			_, _ = r.docker("rm", "-f", r.prefix+n.name)
		}

		old := r.config("2.6.3", false, false, 3)
		oldHCL, err := old.HCL()
		require.NoError(t, err)
		t.Logf("2.6.3 rendered HCL (unchanged shape):\n%s", oldHCL)

		for _, n := range nodes {
			r.prepareVolume(n.data)
			r.startServer(n, old, rehearsalServerOld, "")
		}

		token := r.initialize(nodes[0])
		for _, n := range nodes {
			assert.Equal(t, "2.6.3", func() string { r.waitUnsealed(n, 90*time.Second); return r.status(n).Version }())
		}

		r.waitVoters(nodes[0], token, 3)
		_, err = r.exec(nodes[0], token, "secrets", "enable", "-path=kv", "kv-v2")
		require.NoError(t, err)
		r.probe(nodes[0], token, "before")

		// A snapshot first, as the runbook says.
		_, err = r.exec(nodes[0], token, "operator", "raft", "snapshot", "save", "/tmp/before-2.7.snap")
		require.NoError(t, err)

		// Standbys first, the active node last.
		var order []node

		var leader node

		for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
			order, leader = nil, node{}

			for _, n := range nodes {
				if s := r.status(n); s != nil && s.HAMode == "active" {
					leader = n

					continue
				}

				order = append(order, n)
			}

			if leader.name != "" && len(order) == 2 {
				break
			}
		}

		require.NotEmpty(t, leader.name, "no active node")

		order = append(order, leader)

		next := r.config("2.7.0", true, false, 3)
		nextHCL, err := next.HCL()
		require.NoError(t, err)
		t.Logf("2.7.0 rendered HCL:\n%s", nextHCL)

		rollStart := time.Now()

		for i, n := range order {
			stepStart := time.Now()

			// Delete the pod: stop the container; its emptyDir goes with
			// it; its data volume stays.
			r.mustDocker("stop", "--time", "30", r.prefix+n.name)
			r.mustDocker("rm", r.prefix+n.name)

			plugins := fmt.Sprintf("%sroll-plugins-%s-%d", r.prefix, n.name, i)
			r.prepareVolume(plugins)
			install := r.installSealPlugin(next, plugins)
			r.startServer(n, next, rehearsalServerNew, plugins)

			unsealed := r.waitUnsealed(n, 120*time.Second)

			s := r.status(n)
			require.NotNil(t, s)
			require.Equal(t, "2.7.0", s.Version, "%s must run 2.7.0", n.name)
			assert.Equal(t, "awskms", s.Type)

			// Stop at the first node that is not Ready: every other node
			// is checked too, and the cluster must still commit a write.
			via := nodes[(i+1)%3]
			if via.name == n.name {
				via = nodes[(i+2)%3]
			}

			for _, other := range nodes {
				if s := r.status(other); s == nil || s.Sealed {
					t.Fatalf("%s is sealed or unreachable after %s was upgraded:\n%s", other.name, n.name, r.logs(other))
				}
			}

			r.waitVoters(via, token, 3)
			r.probe(via, token, fmt.Sprintf("after-%s", n.name))

			if i == 0 {
				r.revertStandby(n, old, nodes, token)

				// And forward again, to carry on with the roll.
				r.mustDocker("stop", "--time", "30", r.prefix+n.name)
				r.mustDocker("rm", r.prefix+n.name)

				plugins = fmt.Sprintf("%sroll-plugins-%s-%d-again", r.prefix, n.name, i)
				r.prepareVolume(plugins)
				r.installSealPlugin(next, plugins)
				r.startServer(n, next, rehearsalServerNew, plugins)
				r.waitUnsealed(n, 120*time.Second)
				r.waitVoters(via, token, 3)
			}

			role := "standby"
			if n.name == leader.name {
				role = "active"
			}

			r.record("roll step %d/3: %s (%s) stopped, plugin installed in %s, unsealed %s after start, step total %s; 3 voters, quorum write OK",
				i+1, n.name, role, install.Round(time.Millisecond), unsealed.Round(time.Millisecond), time.Since(stepStart).Round(time.Millisecond))
		}

		r.record("roll: whole cluster 2.6.3 -> 2.7.0 in %s, never a sealed node, never lost quorum", time.Since(rollStart).Round(time.Millisecond))

		// Finally every node restarts at once: a full cold start of the
		// cluster on 2.7.0, no help.
		start := time.Now()

		for _, n := range nodes {
			r.mustDocker("restart", "--time", "30", r.prefix+n.name)
		}

		for _, n := range nodes {
			r.waitUnsealed(n, 120*time.Second)
		}

		r.waitVoters(nodes[0], token, 3)
		r.probe(nodes[1], token, "all-restarted")
		r.record("restart (all three at once): all unsealed with no help, quorum write OK, in %s", time.Since(start).Round(time.Millisecond))
	})

	t.Log("\nTimings:\n  " + strings.Join(r.timings, "\n  "))
}

// revertStandby is the runbook's revert path: the first standby that took
// 2.7.0 goes back to 2.6.3 and the 2.6 rendering (unchanged, no plugin), on
// its own data, while the other two voters (one still on 2.6.3, the active
// node too) keep the cluster.
func (r *rehearsal) revertStandby(n node, old *serverpreset.Config, nodes []node, token string) {
	r.t.Helper()

	start := time.Now()

	r.mustDocker("stop", "--time", "30", r.prefix+n.name)
	r.mustDocker("rm", r.prefix+n.name)
	r.startServer(n, old, rehearsalServerOld, "")

	took := r.waitUnsealed(n, 120*time.Second)

	s := r.status(n)
	require.NotNil(r.t, s)
	require.Equal(r.t, "2.6.3", s.Version, "%s must be back on 2.6.3", n.name)

	via := nodes[0]
	if via.name == n.name {
		via = nodes[1]
	}

	r.waitVoters(via, token, 3)
	r.probe(via, token, "reverted-"+n.name)
	r.record("revert: %s back on 2.6.3 with the 2.6 rendering, unsealed %s after start, 3 voters, quorum write OK (step total %s)",
		n.name, took.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")

	return lines[len(lines)-1]
}
