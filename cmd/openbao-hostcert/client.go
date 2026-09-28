package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// baoClient is a minimal OpenBAO HTTP client: exactly the two calls this
// tool makes (an AWS IAM login, then one SSH host-certificate sign), never
// a general-purpose API client. No token is ever written to disk --
// [Renew] holds it in memory only, for the one sign call that follows the
// login that minted it.
type baoClient struct {
	address   string
	namespace string
	http      *http.Client
}

// newBaoClient builds a client trusting the system roots, plus caCertPath's
// PEM certificates when it is non-empty (OpenBAO served by a private CA
// the OS trust store does not carry).
func newBaoClient(address, namespace, caCertPath string, timeout time.Duration) (*baoClient, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if caCertPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}

		pem, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle %s: %w", caCertPath, err)
		}

		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA bundle %s has no usable certificate", caCertPath)
		}

		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	return &baoClient{
		address:   address,
		namespace: namespace,
		http:      &http.Client{Transport: transport, Timeout: timeout},
	}, nil
}

// do sends one request and decodes a successful response's JSON "data"
// (or the whole body when into is nil) -- OpenBAO's own envelope shape,
// {"auth": {...}} for a login and {"data": {...}} for a sign.
func (c *baoClient) do(ctx context.Context, method, path string, token string, body, into any) error {
	var reqBody io.Reader

	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}

		reqBody = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.address+path, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}

	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s %s: read response: %w", method, path, err)
	}

	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(raw))
	}

	if into == nil {
		return nil
	}

	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("%s %s: decode response: %w", method, path, err)
	}

	return nil
}

// login exchanges a [loginRequest] for a client token. The token is never
// persisted -- no `-no-store`-equivalent to configure, because this
// client never has a token helper to store it in.
func (c *baoClient) login(ctx context.Context, mount string, req loginRequest) (string, error) {
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}

	if err := c.do(ctx, http.MethodPost, "/v1/auth/"+mount+"/login", "", req, &out); err != nil {
		return "", fmt.Errorf("aws login: %w", err)
	}

	if out.Auth.ClientToken == "" {
		return "", fmt.Errorf("aws login: response carried no client_token")
	}

	return out.Auth.ClientToken, nil
}

// signHostCert asks mount/sign/role for a host certificate over
// publicKey, valid for principals. cert_type=host is always sent: this
// client signs nothing else, ever, whatever the caller passes.
func (c *baoClient) signHostCert(ctx context.Context, token, mount, role, publicKey string, principals []string) (string, error) {
	body := map[string]any{
		"cert_type":  "host",
		"public_key": publicKey,
	}

	if len(principals) > 0 {
		body["valid_principals"] = joinComma(principals)
	}

	var out struct {
		Data struct {
			SignedKey string `json:"signed_key"`
		} `json:"data"`
	}

	if err := c.do(ctx, http.MethodPost, "/v1/"+mount+"/sign/"+role, token, body, &out); err != nil {
		return "", fmt.Errorf("sign host certificate: %w", err)
	}

	if out.Data.SignedKey == "" {
		return "", fmt.Errorf("sign host certificate: response carried no signed_key")
	}

	return out.Data.SignedKey, nil
}

func joinComma(values []string) string {
	out := values[0]
	for _, v := range values[1:] {
		out += "," + v
	}

	return out
}
