package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAWSLogin stands in for [stsLogin]: it hands back a fixed
// [loginRequest] (or an error), so every test here proves the OpenBAO-
// facing protocol and the local file/reload behavior with no real AWS
// account, credential or network call anywhere in reach. What it does
// NOT prove is [stsLogin] itself -- see this package's own doc comment
// (renew.go) for exactly what that leaves unverified.
type fakeAWSLogin struct {
	req loginRequest
	err error
}

func (f fakeAWSLogin) Login(context.Context, string, string) (loginRequest, error) {
	return f.req, f.err
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()

	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// baoDouble is a minimal OpenBAO stand-in: a login endpoint that hands
// back one fixed token, and a sign endpoint that hands back a fixed
// (or per-call) certificate. Both record every request they saw.
type baoDouble struct {
	t *testing.T

	token          string
	certificates   []string // popped one per sign call; last one repeats
	loginRequests  []map[string]any
	signRequests   []map[string]any
	loginNamespace []string
	signNamespace  []string
	loginStatus    int
	signStatus     int
}

func newBaoDouble(t *testing.T, token string, certs ...string) *baoDouble {
	t.Helper()

	return &baoDouble{t: t, token: token, certificates: certs, loginStatus: http.StatusOK, signStatus: http.StatusOK}
}

func (d *baoDouble) server() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/aws/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any

		require.NoError(d.t, json.NewDecoder(r.Body).Decode(&body))

		d.loginRequests = append(d.loginRequests, body)
		d.loginNamespace = append(d.loginNamespace, r.Header.Get("X-Vault-Namespace"))

		if d.loginStatus != http.StatusOK {
			w.WriteHeader(d.loginStatus)

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": d.token},
		})
	})

	mux.HandleFunc("/v1/ssh-host/sign/router", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(d.t, d.token, r.Header.Get("X-Vault-Token"))

		var body map[string]any

		require.NoError(d.t, json.NewDecoder(r.Body).Decode(&body))

		d.signRequests = append(d.signRequests, body)
		d.signNamespace = append(d.signNamespace, r.Header.Get("X-Vault-Namespace"))

		if d.signStatus != http.StatusOK {
			w.WriteHeader(d.signStatus)

			return
		}

		cert := d.certificates[0]
		if len(d.certificates) > 1 {
			d.certificates = d.certificates[1:]
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"signed_key": cert},
		})
	})

	return httptest.NewServer(mux)
}

func baseConfig(t *testing.T, address, certPath string) Config {
	t.Helper()

	dir := t.TempDir()

	pub := filepath.Join(dir, "host_key.pub")
	require.NoError(t, os.WriteFile(pub, []byte("ssh-ed25519 AAAAexamplepublickey\n"), 0o644))

	return Config{
		Address:        address,
		AuthMount:      "aws",
		AuthRole:       "router-host",
		ServerIDHeader: "dev-openbao-aws-host",
		SSHMount:       "ssh-host",
		SSHRole:        "router",
		Principals:     []string{"host-1.tailnet-example.ts.net"},
		PublicKeyPath:  pub,
		CertPath:       certPath,
	}
}

func TestRenewWritesTheCertificateAndSendsTheLoginBody(t *testing.T) {
	double := newBaoDouble(t, "s.token", "ssh-ed25519-cert-v01@openbao AAAAexamplecert one")
	server := double.server()
	t.Cleanup(server.Close)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "host_key-cert.pub")

	cfg := baseConfig(t, server.URL, certPath)
	cfg.Namespace = "dev"

	login := fakeAWSLogin{req: loginRequest{
		Role:                 "router-host",
		IAMHTTPRequestMethod: "POST",
		IAMRequestURL:        "aHR0cHM6Ly9zdHMuYW1hem9uYXdzLmNvbS8=",
		IAMRequestBody:       "QWN0aW9uPUdldENhbGxlcklkZW50aXR5JlZlcnNpb249MjAxMS0wNi0xNQ==",
		IAMRequestHeaders:    "e30=",
	}}

	require.NoError(t, Renew(context.Background(), testLogger(t), cfg, login))

	got, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, "ssh-ed25519-cert-v01@openbao AAAAexamplecert one", string(got))

	require.Len(t, double.loginRequests, 1)
	assert.Equal(t, "router-host", double.loginRequests[0]["role"])
	assert.Equal(t, "POST", double.loginRequests[0]["iam_http_request_method"])
	assert.Equal(t, "dev", double.loginNamespace[0])

	require.Len(t, double.signRequests, 1)
	assert.Equal(t, "host", double.signRequests[0]["cert_type"])
	assert.Equal(t, "ssh-ed25519 AAAAexamplepublickey\n", double.signRequests[0]["public_key"])
	assert.Equal(t, "host-1.tailnet-example.ts.net", double.signRequests[0]["valid_principals"])
	assert.Equal(t, "dev", double.signNamespace[0])
}

func TestRenewReloadsOnlyWhenTheCertificateChanged(t *testing.T) {
	double := newBaoDouble(t, "s.token", "cert-one", "cert-one", "cert-two")
	server := double.server()
	t.Cleanup(server.Close)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "host_key-cert.pub")

	reloads := 0
	reloadMarker := filepath.Join(dir, "reloaded")
	cfg := baseConfig(t, server.URL, certPath)
	cfg.ReloadCommand = "echo reload >> " + reloadMarker

	countReloads := func() int {
		raw, err := os.ReadFile(reloadMarker)
		if err != nil {
			return 0
		}

		reloads = len(raw) // any write at all means at least one reload; exact count not needed
		if reloads > 0 {
			return 1
		}

		return 0
	}

	// First run: no certificate on disk yet, so it always "changes".
	require.NoError(t, Renew(context.Background(), testLogger(t), cfg, fakeAWSLogin{}))
	assert.Equal(t, 1, countReloads(), "first run must reload")

	require.NoError(t, os.Remove(reloadMarker))

	// Second run: OpenBAO hands back the SAME bytes -- no reload.
	require.NoError(t, Renew(context.Background(), testLogger(t), cfg, fakeAWSLogin{}))
	assert.Equal(t, 0, countReloads(), "unchanged certificate must not reload")

	// Third run: a genuinely new certificate -- reload again.
	require.NoError(t, Renew(context.Background(), testLogger(t), cfg, fakeAWSLogin{}))
	assert.Equal(t, 1, countReloads(), "changed certificate must reload")
}

func TestRenewChangesNothingOnALoginFailure(t *testing.T) {
	double := newBaoDouble(t, "s.token", "cert-one")
	server := double.server()
	t.Cleanup(server.Close)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "host_key-cert.pub")
	require.NoError(t, os.WriteFile(certPath, []byte("previous certificate"), 0o644))

	cfg := baseConfig(t, server.URL, certPath)

	err := Renew(context.Background(), testLogger(t), cfg, fakeAWSLogin{err: errors.New("no instance role credentials")})
	require.Error(t, err)

	got, readErr := os.ReadFile(certPath)
	require.NoError(t, readErr)
	assert.Equal(t, "previous certificate", string(got), "a login failure must not touch the existing certificate")

	assert.Empty(t, double.loginRequests, "a login failure before the HTTP call reaches OpenBAO makes no request")
}

func TestRenewChangesNothingWhenOpenBAORefusesTheLogin(t *testing.T) {
	double := newBaoDouble(t, "s.token", "cert-one")
	double.loginStatus = http.StatusForbidden
	server := double.server()
	t.Cleanup(server.Close)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "host_key-cert.pub")
	require.NoError(t, os.WriteFile(certPath, []byte("previous certificate"), 0o644))

	cfg := baseConfig(t, server.URL, certPath)

	err := Renew(context.Background(), testLogger(t), cfg, fakeAWSLogin{})
	require.Error(t, err)

	got, readErr := os.ReadFile(certPath)
	require.NoError(t, readErr)
	assert.Equal(t, "previous certificate", string(got))
	assert.Empty(t, double.signRequests, "a refused login must never reach the sign call")
}

func TestRenewChangesNothingWhenOpenBAORefusesTheSign(t *testing.T) {
	double := newBaoDouble(t, "s.token", "cert-one")
	double.signStatus = http.StatusForbidden
	server := double.server()
	t.Cleanup(server.Close)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "host_key-cert.pub")
	require.NoError(t, os.WriteFile(certPath, []byte("previous certificate"), 0o644))

	cfg := baseConfig(t, server.URL, certPath)

	err := Renew(context.Background(), testLogger(t), cfg, fakeAWSLogin{})
	require.Error(t, err)

	got, readErr := os.ReadFile(certPath)
	require.NoError(t, readErr)
	assert.Equal(t, "previous certificate", string(got))
}

func TestRenewRefusesNoPrincipals(t *testing.T) {
	cfg := baseConfig(t, "https://unreachable.example.invalid", filepath.Join(t.TempDir(), "cert"))
	cfg.Principals = nil

	err := Renew(context.Background(), testLogger(t), cfg, fakeAWSLogin{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no principals")
}

func TestWriteIfChangedIsAtomicAndLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert")

	changed, err := writeIfChanged(path, []byte("one"))
	require.NoError(t, err)
	assert.True(t, changed)

	changed, err = writeIfChanged(path, []byte("one"))
	require.NoError(t, err)
	assert.False(t, changed)

	changed, err = writeIfChanged(path, []byte("two"))
	require.NoError(t, err)
	assert.True(t, changed)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temp file left behind")

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "two", string(got))
}

func TestCheckPrincipalPatterns(t *testing.T) {
	for _, tc := range []struct {
		name       string
		principals []string
		patterns   []string
		wantErr    string
	}{
		{"no patterns configured: anything passes", []string{"anything.example"}, nil, ""},
		{"a match", []string{"host-1.tailnet-example.ts.net"}, []string{"host-*.tailnet-example.ts.net"}, ""},
		{"one of several patterns matches", []string{"host-1.tailnet-example.ts.net"}, []string{"other-*", "host-*.tailnet-example.ts.net"}, ""},
		{
			"no pattern matches", []string{"host-1.other-tailnet.ts.net"}, []string{"host-*.tailnet-example.ts.net"},
			`principal "host-1.other-tailnet.ts.net" matches none of the configured patterns`,
		},
		{
			"one of several principals fails", []string{"host-1.tailnet-example.ts.net", "evil.example"}, []string{"host-*.tailnet-example.ts.net"},
			`principal "evil.example" matches none`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPrincipalPatterns(tc.principals, tc.patterns)

			if tc.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestRenewRefusesAPrincipalOutsideItsPattern(t *testing.T) {
	double := newBaoDouble(t, "s.token", "cert-one")
	server := double.server()
	t.Cleanup(server.Close)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "host_key-cert.pub")
	require.NoError(t, os.WriteFile(certPath, []byte("previous certificate"), 0o644))

	cfg := baseConfig(t, server.URL, certPath)
	cfg.PrincipalPatterns = []string{"other-*"}

	err := Renew(context.Background(), testLogger(t), cfg, fakeAWSLogin{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "matches none of the configured patterns")

	got, readErr := os.ReadFile(certPath)
	require.NoError(t, readErr)
	assert.Equal(t, "previous certificate", string(got))
	assert.Empty(t, double.loginRequests, "a principal-pattern refusal must happen before any network call")
}
