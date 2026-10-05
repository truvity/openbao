// Package kv is the plain HTTP client for reading and writing one secret
// in an OpenBAO namespace's KV v2 mount: log in on a JWT mount with a
// token the caller already holds, read or write, give the token back.
//
// Not the Pulumi vault provider, on purpose, and for two reasons a
// caller cannot work around:
//
//  1. WHAT IS READ CONFIGURES ANOTHER PROVIDER. A GitHub App's key or a
//     Keycloak client's secret is needed as a VALUE while the program
//     builds the provider that uses it, not as an Output the engine
//     resolves later.
//  2. THE SECRET LIVES IN A NAMESPACE. The caller signs in there, not in
//     root, whose policies are a different ladder.
//
// Nothing here is declared to Pulumi and nothing here is state: a read
// is a read. The client trusts the server through the CA bundle it is
// given and never switches verification off.
package kv

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	timeout = 30 * time.Second
	// NamespaceHeader is OpenBAO's (Vault-compatible) namespace request
	// header. Exported for the fakes that stand in for a server in tests.
	NamespaceHeader = "X-Vault-Namespace"
	// TokenHeader is OpenBAO's (Vault-compatible) token request header.
	TokenHeader = "X-Vault-Token"
)

type (
	// Client is one namespace's KV v2 mount: log in, read (and, where a
	// caller must, write) one secret, and give the token back.
	//
	// A caller logs in inside the namespace that holds the secret, never
	// in root: its identity holds its policies in that namespace.
	Client struct {
		client    *http.Client
		addr      string
		namespace string
		mount     string
		token     string
	}

	// statusError is a non-2xx answer; its body names the reason
	// ("permission denied") and never a secret value.
	statusError struct {
		status int
		body   string
	}
)

// New returns a client for one namespace's KV mount that trusts
// OpenBAO's endpoint through caPEM alone.
func New(addr, namespace, mount string, caPEM []byte) (*Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("openbao: the CA for %s holds no certificate", addr)
	}

	return &Client{
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
		addr:      strings.TrimSuffix(addr, "/"),
		namespace: namespace,
		mount:     mount,
	}, nil
}

// Login exchanges a roster token for an OpenBAO token on a JWT mount.
func (b *Client) Login(ctx context.Context, authMount, role, jwt string) error {
	var out struct {
		Auth *struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}

	body := map[string]string{"role": role, "jwt": jwt}
	if err := b.do(ctx, http.MethodPost, "/v1/auth/"+authMount+"/login", body, &out); err != nil {
		return fmt.Errorf("openbao login on %s/auth/%s: %w", b.namespace, authMount, err)
	}

	if out.Auth == nil || out.Auth.ClientToken == "" {
		return fmt.Errorf("openbao login on %s/auth/%s returned no token", b.namespace, authMount)
	}

	b.token = out.Auth.ClientToken

	return nil
}

// Read returns the latest version of one KV v2 secret, or nil when there is
// none -- a key the caller has to tell apart from a refusal.
func (b *Client) Read(ctx context.Context, key string) (map[string]string, error) {
	var out struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}

	err := b.do(ctx, http.MethodGet, "/v1/"+b.mount+"/data/"+key, nil, &out)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("openbao read %s/%s/%s: %w", b.namespace, b.mount, key, err)
	}

	return out.Data.Data, nil
}

// Write puts a new version of one KV v2 secret.
func (b *Client) Write(ctx context.Context, key string, data map[string]string) error {
	if err := b.do(ctx, http.MethodPost, "/v1/"+b.mount+"/data/"+key, map[string]any{"data": data}, nil); err != nil {
		return fmt.Errorf("openbao write %s/%s/%s: %w", b.namespace, b.mount, key, err)
	}

	return nil
}

// Revoke gives the token back. Best effort: it expires on its own.
func (b *Client) Revoke(ctx context.Context) {
	if b.token == "" {
		return
	}

	_ = b.do(ctx, http.MethodPost, "/v1/auth/token/revoke-self", nil, nil)
	b.token = ""
}

func (e *statusError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.status, e.body)
}

func isNotFound(err error) bool {
	var status *statusError

	return errors.As(err, &status) && status.status == http.StatusNotFound
}

func (b *Client) do(ctx context.Context, method, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var body io.Reader

	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}

		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, b.addr+path, body)
	if err != nil {
		return err
	}

	req.Header.Set(NamespaceHeader, b.namespace)

	if b.token != "" {
		req.Header.Set(TokenHeader, b.token)
	}

	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The body of an error names the reason ("permission denied") and
		// never a secret value.
		return &statusError{status: resp.StatusCode, body: strings.TrimSpace(string(raw))}
	}

	if out == nil || len(raw) == 0 {
		return nil
	}

	return json.Unmarshal(raw, out)
}

// Namespace is the namespace this client is signed in to; callers name
// it in their errors, so an operator knows where to look.
func (b *Client) Namespace() string {
	return b.namespace
}

// Mount is the KV v2 mount this client reads.
func (b *Client) Mount() string {
	return b.mount
}
