package bootstrap

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
	maxAnswer = 1 << 20
	// RequestTimeout bounds one API call made through [NewTLSClient].
	RequestTimeout = 30 * time.Second
)

type (
	// Client speaks the few OpenBAO API calls the bootstrap needs.
	Client struct {
		base     string
		http     *http.Client
		token    []byte
		redactor *redactor
	}

	// APIError is an answer OpenBAO gave with a non-2xx status. Its messages
	// are scrubbed of every secret the client has seen.
	APIError struct {
		Method string
		Path   string
		Status int
		Errors []string
	}
)

// NewClient talks to base (scheme, host and port, no path) over httpClient.
//
// The client never follows a redirect: a 3xx is an error. Go would re-send the
// token header, and for 307 and 308 the body (a recovery share), to wherever
// the answer points, an http:// URL included. Calls are bounded by
// [RequestTimeout] each through their context, not by the http.Client.
func NewClient(base string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	own := *httpClient
	own.Timeout = 0
	own.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &Client{base: base, http: &own, redactor: &redactor{}}
}

// NewTLSClient talks to base over TLS, trusting only caPEM and expecting the
// server certificate to hold serverName (empty: the host of base).
func NewTLSClient(base string, caPEM []byte, serverName string) (*Client, error) {
	if !strings.HasPrefix(base, "https://") {
		return nil, errors.New("the API address must be an https:// URL: a root token and recovery shares never travel in the clear")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the CA bundle holds no usable certificate")
	}

	return NewClient(base, &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12},
		},
	}), nil
}

// WithToken returns a client that authenticates every call with token. The
// client keeps its own copy; [Client.Wipe] zeroes it.
func (c *Client) WithToken(token []byte) *Client {
	c.redactor.add(token)

	return &Client{base: c.base, http: c.http, token: track(bytes.Clone(token)), redactor: c.redactor}
}

// Wipe zeroes the client's token.
func (c *Client) Wipe() {
	zero(c.token)
	c.token = nil
}

func (e *APIError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("%s /v1/%s: HTTP %d", e.Method, e.Path, e.Status)
	}

	return fmt.Sprintf("%s /v1/%s: HTTP %d: %v", e.Method, e.Path, e.Status, e.Errors)
}

// hasStatus reports whether err is an OpenBAO answer with that status.
func hasStatus(err error, status int) bool {
	var apiErr *APIError

	return errors.As(err, &apiErr) && apiErr.Status == status
}

// do sends body as JSON (when not nil) and decodes the answer into out (when
// not nil). Error text carries OpenBAO's own messages, never the request, and
// is scrubbed. The request and answer buffers are zeroed once used.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	return c.doWithin(ctx, RequestTimeout, method, path, body, out)
}

// doWithin is [Client.do] with its own bound on the call.
func (c *Client) doWithin(ctx context.Context, limit time.Duration, method, path string, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	var payload io.Reader

	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode %s /v1/%s: %w", method, path, c.redactor.scrubErr(err))
		}

		defer zero(track(raw))

		payload = bytes.NewReader(raw)
	}

	request, err := http.NewRequestWithContext(ctx, method, c.base+"/v1/"+path, payload)
	if err != nil {
		return fmt.Errorf("build %s /v1/%s: %w", method, path, c.redactor.scrubErr(err))
	}

	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	if len(c.token) > 0 {
		request.Header.Set("X-Vault-Token", string(c.token))
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%s /v1/%s: %w", method, path, c.redactor.scrubErr(err))
	}
	defer func() { _ = response.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(response.Body, maxAnswer))
	defer zero(track(raw))

	if err != nil {
		return fmt.Errorf("read %s /v1/%s: %w", method, path, c.redactor.scrubErr(err))
	}

	if response.StatusCode >= http.StatusMultipleChoices {
		var answer struct {
			Errors []string `json:"errors"`
		}

		_ = json.Unmarshal(raw, &answer)

		for i, message := range answer.Errors {
			answer.Errors[i] = c.redactor.scrub(message)
		}

		return &APIError{Method: method, Path: path, Status: response.StatusCode, Errors: answer.Errors}
	}

	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}

	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode %s /v1/%s: %w", method, path, c.redactor.scrubErr(err))
	}

	return nil
}

// Initialized reports whether the server is initialized (an unauthenticated
// read).
func (c *Client) Initialized(ctx context.Context) (bool, error) {
	var status struct {
		Initialized bool `json:"initialized"`
	}

	if err := c.do(ctx, http.MethodGet, "sys/init", nil, &status); err != nil {
		return false, err
	}

	return status.Initialized, nil
}
