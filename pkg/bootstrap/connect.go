package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	forwardTimeout = 30 * time.Second
	// DefaultAPIPort is the port OpenBAO listens on inside its pod.
	DefaultAPIPort = 8200
)

// PortForward reaches an OpenBAO pod through kubectl port-forward. It has
// to: before initialization no pod is ready, so neither the Service nor a
// load balancer has an endpoint. TLS is still verified, against the CA in the
// install's own TLS secret and a name the certificate holds. Nothing secret
// passes through kubectl: the secret it reads is the public ca.crt.
type PortForward struct {
	// Kubeconfig, when set, is exported as KUBECONFIG to kubectl.
	Kubeconfig string
	// Context, when set, is passed as --context.
	Context string
	// Namespace and Pod name the bootstrap pod (the first Raft voter).
	Namespace string
	Pod       string
	// Port is the API port inside the pod; default [DefaultAPIPort].
	Port int
	// TLSSecret holds ca.crt, the CA of the certificate the server serves.
	TLSSecret string
	// TLSServerName is a name that certificate holds; the pod is reached on
	// 127.0.0.1, which it does not.
	TLSServerName string
	// Kubectl is the binary; default kubectl.
	Kubectl string
	// Stderr receives kubectl's own diagnostics; default os.Stderr.
	Stderr io.Writer
}

// Connect opens the forward and returns a client on it and the function that
// closes it.
func (p PortForward) Connect(ctx context.Context) (*Client, func(), error) {
	for name, value := range map[string]string{"namespace": p.Namespace, "pod": p.Pod, "TLS secret": p.TLSSecret} {
		if value == "" {
			return nil, nil, fmt.Errorf("port-forward: the %s is required", name)
		}
	}

	pem, err := p.caPEM(ctx)
	if err != nil {
		return nil, nil, err
	}

	port, stop, err := p.forward(ctx)
	if err != nil {
		return nil, nil, err
	}

	client, err := NewTLSClient("https://127.0.0.1:"+port, pem, p.TLSServerName)
	if err != nil {
		stop()

		return nil, nil, fmt.Errorf("secret %s/%s: %w", p.Namespace, p.TLSSecret, err)
	}

	return client, stop, nil
}

func (p PortForward) remotePort() int {
	if p.Port == 0 {
		return DefaultAPIPort
	}

	return p.Port
}

func (p PortForward) kubectl(ctx context.Context, args ...string) *exec.Cmd {
	binary := p.Kubectl
	if binary == "" {
		binary = "kubectl"
	}

	if p.Context != "" {
		args = append([]string{"--context", p.Context}, args...)
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	if p.Kubeconfig != "" {
		cmd.Env = append(os.Environ(), "KUBECONFIG="+p.Kubeconfig)
	}

	return cmd
}

// caPEM reads the public ca.crt of the TLS secret, and nothing else of it.
func (p PortForward) caPEM(ctx context.Context) ([]byte, error) {
	cmd := p.kubectl(ctx, "get", "secret", p.TLSSecret, "-n", p.Namespace, "-o", `jsonpath={.data.ca\.crt}`)

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read the CA from secret %s/%s: %w: %s", p.Namespace, p.TLSSecret, err, strings.TrimSpace(stderr.String()))
	}

	pem, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, fmt.Errorf("decode the CA from secret %s/%s: %w", p.Namespace, p.TLSSecret, err)
	}

	if len(pem) == 0 {
		return nil, fmt.Errorf("secret %s/%s holds no ca.crt", p.Namespace, p.TLSSecret)
	}

	return pem, nil
}

func (p PortForward) forward(ctx context.Context) (port string, stop func(), err error) {
	listening := regexp.MustCompile(`^Forwarding from 127\.0\.0\.1:(\d+) -> ` + strconv.Itoa(p.remotePort()))

	// The forward must outlive the caller's cancellation: after Ctrl-C the
	// bootstrap's cleanups (cancel a pending root generation, revoke a token
	// it generated) still go through it. It ends only through stop(), which
	// the caller runs after those cleanups. It also leaves the terminal's
	// process group, so the SIGINT that cancelled the caller does not reach it.
	forwardCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	cmd := p.kubectl(forwardCtx, "port-forward", "-n", p.Namespace, "pod/"+p.Pod, ":"+strconv.Itoa(p.remotePort()))

	cmd.SysProcAttr = forwardProcAttr()

	cmd.Stderr = p.Stderr
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()

		return "", nil, fmt.Errorf("port-forward stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()

		return "", nil, fmt.Errorf("start port-forward: %w", err)
	}

	stop = func() {
		cancel()

		_ = cmd.Wait()
	}

	ports := make(chan string, 1)

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if match := listening.FindStringSubmatch(scanner.Text()); match != nil {
				select {
				case ports <- match[1]:
				default:
				}
			}
		}

		// Keep draining so kubectl never blocks on a full pipe.
		_, _ = io.Copy(io.Discard, stdout)
		close(ports)
	}()

	select {
	case forwarded, ok := <-ports:
		if !ok {
			stop()

			return "", nil, errors.New("port-forward exited before it listened")
		}

		return forwarded, stop, nil
	case <-time.After(forwardTimeout):
		stop()

		return "", nil, fmt.Errorf("port-forward to %s did not listen within %s", p.Pod, forwardTimeout)
	}
}
