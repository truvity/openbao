package kv_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/kv"
)

func server(t *testing.T) (*httptest.Server, []byte) {
	t.Helper()

	store := map[string]map[string]string{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "devel", r.Header.Get(kv.NamespaceHeader))

		switch {
		case r.URL.Path == "/v1/auth/jwt/login":
			_, _ = w.Write([]byte(`{"auth":{"client_token":"tok"}}`))
		case r.URL.Path == "/v1/auth/token/revoke-self":
			require.Equal(t, "tok", r.Header.Get(kv.TokenHeader))
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost:
			var in struct {
				Data map[string]string `json:"data"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			store[r.URL.Path] = in.Data
			_, _ = w.Write([]byte(`{}`))
		default:
			data, ok := store[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)

				return
			}

			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": data}}))
		}
	}))
	t.Cleanup(srv.Close)

	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	return srv, ca
}

func TestRoundTrip(t *testing.T) {
	srv, ca := server(t)
	ctx := context.Background()

	c, err := kv.New(srv.URL+"/", "devel", "kv", ca)
	require.NoError(t, err)
	require.Equal(t, "devel", c.Namespace())
	require.Equal(t, "kv", c.Mount())
	require.NoError(t, c.Login(ctx, "jwt", "role", "jwt-token"))

	missing, err := c.Read(ctx, "a/b")
	require.NoError(t, err)
	require.Nil(t, missing)

	require.NoError(t, c.Write(ctx, "a/b", map[string]string{"k": "v"}))

	got, err := c.Read(ctx, "a/b")
	require.NoError(t, err)
	require.Equal(t, map[string]string{"k": "v"}, got)

	c.Revoke(ctx)
}

func TestNewRefusesEmptyCA(t *testing.T) {
	_, err := kv.New("https://x", "devel", "kv", []byte("nope"))
	require.Error(t, err)
}

func TestUntrustedServerRefused(t *testing.T) {
	srv, _ := server(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unrelated"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,

		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	other := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	c, err := kv.New(srv.URL, "devel", "kv", other)
	require.NoError(t, err)
	require.Error(t, c.Login(context.Background(), "jwt", "role", "t"))
}
