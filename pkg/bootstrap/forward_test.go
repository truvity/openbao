package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The test binary doubles as kubectl for the port-forward tests: with
// BOOTSTRAP_FAKE_KUBECTL_TARGET set it answers `get secret` with the CA in
// BOOTSTRAP_FAKE_KUBECTL_CA (base64) and `port-forward` with a real TCP
// proxy to the target, which dies with the process, as kubectl's does.
func TestMain(m *testing.M) {
	if target := os.Getenv("BOOTSTRAP_FAKE_KUBECTL_TARGET"); target != "" {
		os.Exit(fakeKubectl(target, os.Args[1:]))
	}

	os.Exit(m.Run())
}

func fakeKubectl(target string, args []string) int {
	switch {
	case slicesContain(args, "secret"):
		fmt.Print(os.Getenv("BOOTSTRAP_FAKE_KUBECTL_CA"))

		return 0
	case slicesContain(args, "port-forward"):
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 1
		}

		fmt.Printf("Forwarding from 127.0.0.1:%d -> 8200\n", listener.Addr().(*net.TCPAddr).Port)

		for {
			client, err := listener.Accept()
			if err != nil {
				return 1
			}

			go func() {
				upstream, err := net.Dial("tcp", target)
				if err != nil {
					_ = client.Close()

					return
				}

				go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close() }()
				_, _ = io.Copy(client, upstream)
				_ = client.Close()
			}()
		}
	}

	return 2
}

func slicesContain(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}

	return false
}

// R1: with --port-forward the cleanups after a cancellation go through a
// forward that is still alive, because it ends only through stop().
func TestCleanupsStillReachTheServerOverAPortForwardAfterACancellation(t *testing.T) {
	fake := newBareFake()

	tlsServer := httptest.NewTLSServer(fake)
	t.Cleanup(tlsServer.Close)

	t.Setenv("BOOTSTRAP_FAKE_KUBECTL_TARGET", strings.TrimPrefix(tlsServer.URL, "https://"))
	t.Setenv("BOOTSTRAP_FAKE_KUBECTL_CA", base64.StdEncoding.EncodeToString(pemOf(tlsServer)))

	self, err := os.Executable()
	require.NoError(t, err)

	// The same cancellable context reaches the forward and the bootstrap, as
	// the signal context does in openbaoctl.
	ctx := cancelDuring(fake, secondShare())

	api, stop, err := PortForward{
		Namespace: "ns", Pod: "pod", TLSSecret: "tls", TLSServerName: "example.com", Kubectl: self,
	}.Connect(ctx)
	require.NoError(t, err)

	defer stop()

	b := &Bootstrap{
		API: api, Keeper: newFakeKeeper(), Logger: slog.New(slog.DiscardHandler), Poll: time.Millisecond, Now: time.Now,
	}

	require.NoError(t, b.Initialize(context.Background()))
	require.NoError(t, b.Configure(context.Background(), login))
	fake.login(operators)

	err = b.RevokeRoot(ctx, operators)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.NotContains(t, err.Error(), "could NOT be", "a cleanup failed: the forward died with the caller's context")

	fake.mu.Lock()
	defer fake.mu.Unlock()

	assert.Nil(t, fake.generation, "the pending generation was left behind")
}

func pemOf(server *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
}

// newBareFake is a fake server with no httptest wrapper, to be served over TLS.
func newBareFake() *fakeBao {
	return &fakeBao{
		recoverySeal: true, audit: true, voters: 3,
		tokens: map[string]fakeToken{}, mounts: map[string]mount{}, roles: map[string]map[string]any{},
		policies: map[string]string{}, groups: map[string]*group{},
	}
}
