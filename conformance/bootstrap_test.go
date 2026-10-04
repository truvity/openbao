// Package conformance_test also proves, against a real `bao` binary of each
// supported release, the whole bootstrap lifecycle of a fresh server through
// the real openbaoctl: init, configure, revoke-root (which runs the
// generate-root drill on every recovery share) and the lock-out guards on
// the way.
//
// The server is a real `bao server`: TLS on loopback, one Raft voter, a
// declarative audit device and a static seal. The static seal is an
// auto-unseal seal, so initialization splits a recovery key exactly as the
// awskms seal does, with no cloud account: it is the offline stand-in for
// the seal a production install uses. The roster issuer is the fake issuer
// of internal/fakeissuer. Nothing leaves the machine.
//
// Like server_config_test.go it is gated on OPENBAO_BAO_BINARY (CI's
// server-config job sets it once per release) and skips without it. See
// docs/bootstrap.md.
package conformance_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/openbao/internal/fakeissuer"
	"github.com/truvity/openbao/pkg/bootstrap"
	"github.com/truvity/openbao/pkg/bootstrap/filekeeper"
	"github.com/truvity/openbao/pkg/model"
)

const bootstrapGroup = "example:operators"

// bootstrapRig is one real server, one issuer, one built openbaoctl and one
// keeper directory.
type bootstrapRig struct {
	t        *testing.T
	baseURL  string
	ca       string
	keeper   string
	identity string
	ctl      string
	issuer   *fakeissuer.Issuer
	http     *http.Client
	keepers  *filekeeper.Keeper
	// transcript is everything every openbaoctl run printed.
	transcript bytes.Buffer
}

func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer func() { _ = listener.Close() }()

	return listener.Addr().(*net.TCPAddr).Port
}

func newBootstrapRig(t *testing.T) *bootstrapRig {
	t.Helper()

	path := os.Getenv(serverConfigVariable)
	if path == "" {
		t.Skipf("%s is unset: the server-config CI job runs this against each release", serverConfigVariable)
	}

	root := t.TempDir()
	tlsDir := filepath.Join(root, "tls")
	writeDummyTLS(t, tlsDir)

	port, clusterPort := freePort(t), freePort(t)

	sealKey := make([]byte, 32)
	_, err := rand.Read(sealKey)
	require.NoError(t, err)

	config := fmt.Sprintf(`
disable_mlock = true
api_addr      = "https://127.0.0.1:%[1]d"
cluster_addr  = "https://127.0.0.1:%[2]d"

storage "raft" {
  path    = "%[3]s/data"
  node_id = "bootstrap-conformance"
}

listener "tcp" {
  address         = "127.0.0.1:%[1]d"
  cluster_address = "127.0.0.1:%[2]d"
  tls_cert_file   = "%[4]s/tls.crt"
  tls_key_file    = "%[4]s/tls.key"
}

seal "static" {
  current_key_id = "conformance"
  current_key    = "%[5]s"
}

audit "file" "to-stdout" {
  description = "conformance"
  options {
    file_path = "stdout"
  }
}
`, port, clusterPort, root, tlsDir, base64.StdEncoding.EncodeToString(sealKey))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "data"), 0o700))

	configPath := filepath.Join(root, "config.hcl")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

	ctx, cancel := context.WithCancel(t.Context())
	server := exec.CommandContext(ctx, path, "server", "-config="+configPath)
	server.Env = []string{"HOME=" + root, "PATH=" + os.Getenv("PATH")}

	logs := &syncBuffer{}
	server.Stdout, server.Stderr = logs, logs
	server.WaitDelay = 5 * time.Second

	require.NoError(t, server.Start())
	t.Cleanup(func() {
		cancel()
		_ = server.Wait()

		if t.Failed() {
			t.Logf("bao server log:\n%s", logs.String())
		}
	})

	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(tlsDir, "ca.crt"))
	require.NoError(t, err)
	require.True(t, pool.AppendCertsFromPEM(caPEM))

	rig := &bootstrapRig{
		t:       t,
		baseURL: fmt.Sprintf("https://127.0.0.1:%d", port),
		ca:      filepath.Join(tlsDir, "ca.crt"),
		keeper:  filepath.Join(root, "keeper"),
		ctl:     filepath.Join(root, "openbaoctl"),
		http: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12},
		}},
	}

	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	rig.identity = filepath.Join(root, "age-identity.txt")
	require.NoError(t, os.WriteFile(rig.identity, []byte(identity.String()+"\n"), 0o600))

	rig.keepers, err = filekeeper.New(rig.keeper, nil, rig.identity)
	require.NoError(t, err)

	rig.issuer, err = fakeissuer.New(nil)
	require.NoError(t, err)
	t.Cleanup(rig.issuer.Close)

	build := exec.CommandContext(t.Context(), "go", "build", "-o", rig.ctl, "github.com/truvity/openbao/cmd/openbaoctl")
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))

	require.Eventually(t, func() bool {
		status, _ := rig.get("sys/seal-status", "")

		return status == http.StatusOK
	}, 60*time.Second, 200*time.Millisecond, "the server never answered; log:\n%s", logs.String())

	return rig
}

func (r *bootstrapRig) get(path, token string) (int, string) {
	r.t.Helper()

	request, err := http.NewRequestWithContext(r.t.Context(), http.MethodGet, r.baseURL+"/v1/"+path, nil)
	require.NoError(r.t, err)

	if token != "" {
		request.Header.Set("X-Vault-Token", token)
	}

	response, err := r.http.Do(request)
	if err != nil {
		return 0, err.Error()
	}

	defer func() { _ = response.Body.Close() }()

	var body bytes.Buffer

	_, _ = body.ReadFrom(response.Body)

	return response.StatusCode, body.String()
}

func (r *bootstrapRig) connection() []string {
	return []string{
		"--addr", r.baseURL, "--ca-file", r.ca, "--tls-server-name", "localhost",
		"--keeper-dir", r.keeper, "--age-identity-file", r.identity,
		"--voters", "1", "--description", "conformance",
	}
}

// ctlRun runs openbaoctl and returns its stdout and stderr.
func (r *bootstrapRig) ctlRun(args ...string) (stdout, stderr string, err error) {
	r.t.Helper()

	ctx, cancel := context.WithTimeout(r.t.Context(), 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.ctl, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}

	var out, errOut bytes.Buffer

	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()

	r.transcript.WriteString(out.String())
	r.transcript.WriteString(errOut.String())

	return out.String(), errOut.String(), err
}

func (r *bootstrapRig) reveal(title string) string {
	r.t.Helper()

	secret, err := r.keepers.Reveal(r.t.Context(), title)
	require.NoError(r.t, err, title)

	return string(secret)
}

func (r *bootstrapRig) operatorToken(t *testing.T, groups ...string) string {
	t.Helper()

	file := filepath.Join(t.TempDir(), "operator.jwt")
	token := r.issuer.Token(fakeissuer.Claims{
		Subject: "operator@example.com", Audience: model.RosterAudience, Email: "operator@example.com", Groups: groups,
	})
	require.NoError(t, os.WriteFile(file, []byte(token+"\n"), 0o600))

	return file
}

func TestFreshServerLifecycle(t *testing.T) {
	rig := newBootstrapRig(t)
	ctx := t.Context()

	// init: shares and the root token go to the keeper, and nowhere else.
	stdout, _, err := rig.ctlRun(append([]string{"init"}, rig.connection()...)...)
	require.NoError(t, err)
	assert.Empty(t, stdout, "init prints nothing to stdout unless asked to print the shares")

	root := rig.reveal(bootstrap.RootTokenItem)
	shares := make([]string, 5)

	for n := range shares {
		shares[n] = rig.reveal(bootstrap.RecoveryItem(n + 1))
		assert.NotEmpty(t, shares[n])
	}

	status, _ := rig.get("auth/token/lookup-self", root)
	require.Equal(t, http.StatusOK, status, "the stored root token works")

	// init again: a verification, nothing more.
	_, _, err = rig.ctlRun(append([]string{"init"}, rig.connection()...)...)
	require.NoError(t, err)

	// configure: twice, because it converges.
	configure := append([]string{"configure", "--issuer", rig.issuer.URL, "--operator-group", bootstrapGroup}, rig.connection()...)
	for range 2 {
		_, _, err = rig.ctlRun(configure...)
		require.NoError(t, err)
	}

	revoke := append([]string{"revoke-root", "--operator-group", bootstrapGroup}, rig.connection()...)

	// Never revoke before an operator login is proven.
	t.Run("refuses with no login proof", func(t *testing.T) {
		_, _, err := rig.ctlRun(revoke...)
		require.Error(t, err)

		status, _ := rig.get("auth/token/lookup-self", root)
		assert.Equal(t, http.StatusOK, status, "the root token was revoked with no operator proven")
	})

	t.Run("refuses a login that does not carry the operator policy", func(t *testing.T) {
		stranger := rig.operatorToken(t, "someone:else")

		_, stderr, err := rig.ctlRun(append(revoke, "--operator-jwt-file", stranger)...)
		require.Error(t, err)
		assert.Contains(t, stderr+err.Error(), "lock operators out")

		status, _ := rig.get("auth/token/lookup-self", root)
		assert.Equal(t, http.StatusOK, status, "the root token was revoked on a login that is not an operator's")
	})

	t.Run("refuses a token the issuer's audience check rejects", func(t *testing.T) {
		wrong := filepath.Join(t.TempDir(), "wrong.jwt")
		token := rig.issuer.Token(fakeissuer.Claims{Subject: "x", Audience: "not-openbao", Groups: []string{bootstrapGroup}})
		require.NoError(t, os.WriteFile(wrong, []byte(token), 0o600))

		_, _, err := rig.ctlRun(append(revoke, "--operator-jwt-file", wrong)...)
		require.Error(t, err)

		status, _ := rig.get("auth/token/lookup-self", root)
		assert.Equal(t, http.StatusOK, status)
	})

	// The drill and the revocation, for real.
	good := rig.operatorToken(t, bootstrapGroup)

	_, _, err = rig.ctlRun(append(revoke, "--operator-jwt-file", good)...)
	require.NoError(t, err)

	status, _ = rig.get("auth/token/lookup-self", root)
	assert.Equal(t, http.StatusForbidden, status, "the bootstrap root token is revoked")

	titles, err := rig.keepers.Titles(ctx)
	require.NoError(t, err)
	assert.False(t, titles[bootstrap.RootTokenItem], "the root token item is archived")
	assert.Len(t, titles, 6, "every recovery share and the recorded split are still on file")

	archived, err := filepath.Glob(filepath.Join(rig.keeper, "archive", bootstrap.RootTokenItem+".*.age"))
	require.NoError(t, err)
	assert.Len(t, archived, 1)

	// The operators still get in, which is what revoking root must never break.
	loginStatus, loginBody := rig.login(t, good)
	require.Equal(t, http.StatusOK, loginStatus, loginBody)
	assert.Contains(t, loginBody, bootstrapGroup, "the operator's login carries the operator policy")

	_, _, err = rig.ctlRun(append(revoke, "--operator-jwt-file", good)...)
	require.NoError(t, err, "a second revoke-root has nothing left to do")

	// Nothing secret reached any output of any command.
	for _, secret := range append(shares, root) {
		assert.NotContains(t, rig.transcript.String(), secret, "a secret reached the output of an openbaoctl command")
	}
}

func TestFreshServerPrintsSharesOnlyWhenAsked(t *testing.T) {
	rig := newBootstrapRig(t)

	stdout, stderr, err := rig.ctlRun(append([]string{"init", "--insecure-print-recovery-shares-to-stdout"}, rig.connection()...)...)
	require.NoError(t, err)
	assert.Contains(t, stderr, "WARNING")

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	require.Len(t, lines, 5)

	for n, line := range lines {
		assert.Equal(t, fmt.Sprintf("%s %s", bootstrap.RecoveryItem(n+1), rig.reveal(bootstrap.RecoveryItem(n+1))), line)
	}

	assert.NotContains(t, stdout+stderr, rig.reveal(bootstrap.RootTokenItem), "the root token is never printed")

	// A re-run against the initialized server prints nothing: the flag is
	// for the run that creates the shares, not a way to dump them later.
	stdout, stderr, err = rig.ctlRun(append([]string{"init", "--insecure-print-recovery-shares-to-stdout"}, rig.connection()...)...)
	require.NoError(t, err)
	assert.Empty(t, stdout, "a re-run printed the shares of an install it did not create")
	assert.Contains(t, stderr, "NOT printed")
}

// The library's own gate, with no login proof: a member must be on file.
func TestFreshServerRevokesOnMembershipEvidenceOnlyOnceSomeoneLoggedIn(t *testing.T) {
	rig := newBootstrapRig(t)

	_, _, err := rig.ctlRun(append([]string{"init"}, rig.connection()...)...)
	require.NoError(t, err)

	root := rig.reveal(bootstrap.RootTokenItem)

	_, _, err = rig.ctlRun(append([]string{"configure", "--issuer", rig.issuer.URL, "--operator-group", bootstrapGroup}, rig.connection()...)...)
	require.NoError(t, err)

	revoke := append([]string{"revoke-root", "--membership-evidence-only", "--operator-group", bootstrapGroup}, rig.connection()...)

	// The server-side check, not the CLI's flag check: nobody has logged in.
	_, stderr, err := rig.ctlRun(revoke...)
	require.Error(t, err)
	assert.Contains(t, stderr+err.Error(), "nobody has logged in")

	status, _ := rig.get("auth/token/lookup-self", root)
	require.Equal(t, http.StatusOK, status, "the root token was revoked with no member on file")

	// An operator logs in once; now a member is on file.
	status, body := rig.login(t, rig.operatorToken(t, bootstrapGroup))
	require.Equal(t, http.StatusOK, status, body)

	_, _, err = rig.ctlRun(revoke...)
	require.NoError(t, err)

	status, _ = rig.get("auth/token/lookup-self", root)
	assert.Equal(t, http.StatusForbidden, status)
}

func (r *bootstrapRig) login(t *testing.T, jwtFile string) (int, string) {
	t.Helper()

	jwt, err := os.ReadFile(jwtFile)
	require.NoError(t, err)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, r.baseURL+"/v1/auth/"+model.RosterMount+"/login",
		strings.NewReader(fmt.Sprintf(`{"role":%q,"jwt":%q}`, model.RosterRole, strings.TrimSpace(string(jwt)))))
	require.NoError(t, err)

	response, err := r.http.Do(request)
	require.NoError(t, err)

	var body bytes.Buffer

	_, _ = body.ReadFrom(response.Body)
	require.NoError(t, response.Body.Close())

	return response.StatusCode, body.String()
}

func TestFreshServerRefusesANonEmptyServerUnlessTold(t *testing.T) {
	rig := newBootstrapRig(t)

	_, _, err := rig.ctlRun(append([]string{"init"}, rig.connection()...)...)
	require.NoError(t, err)

	root := rig.reveal(bootstrap.RootTokenItem)

	// A mount made behind the bootstrap's back.
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rig.baseURL+"/v1/sys/mounts/kv",
		strings.NewReader(`{"type":"kv"}`))
	require.NoError(t, err)
	request.Header.Set("X-Vault-Token", root)

	response, err := rig.http.Do(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Less(t, response.StatusCode, 300)

	configure := append([]string{"configure", "--issuer", rig.issuer.URL, "--operator-group", bootstrapGroup}, rig.connection()...)

	_, stderr, err := rig.ctlRun(configure...)
	require.Error(t, err)
	assert.Contains(t, stderr+err.Error(), "not empty")

	status, _ := rig.get("sys/auth", root)
	require.Equal(t, http.StatusOK, status)

	_, _, err = rig.ctlRun(append(configure, "--allow-non-empty")...)
	require.NoError(t, err)
}
