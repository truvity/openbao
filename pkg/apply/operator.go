package apply

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/truvity/secrets/pkg/model"
)

// RosterLogin is the operator's Login into root: a roster token for the
// roster audience from the operator's own `accessctl` sign-in (or the job's
// token in CI), verified against caFile, on the roster door
// ([model.RosterMount], [model.RosterRole]). Nothing is stored; the token
// is short-lived and used as is.
func RosterLogin(caFile, issuer string) Login {
	return Login{
		Mount:      model.RosterMount,
		Role:       model.RosterRole,
		CACertFile: caFile,
		Token: func(ctx context.Context) (string, error) {
			return RosterToken(ctx, issuer)
		},
	}
}

// RosterToken asks `accessctl token` for a token for the roster audience
// ([model.RosterAudience]) from the given issuer: the operator's laptop
// sign-in, or the job's own token in CI. accessctl must be on PATH.
func RosterToken(ctx context.Context, issuer string) (string, error) {
	cmd := exec.CommandContext(ctx, "accessctl", "token", "--issuer", issuer, "--audience", model.RosterAudience)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("accessctl token --audience %s (access-roster >= 1.6.0; sign in with `accessctl login` first): %w",
			model.RosterAudience, err)
	}

	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", fmt.Errorf("accessctl returned no token for %s", model.RosterAudience)
	}

	return token, nil
}

// RenameFrom is an Options.Rename that keeps the names resources have
// always had: a name in kept maps to its old name, every other name is
// unchanged. A nil or empty map renames nothing.
func RenameFrom(kept map[string]string) func(string) string {
	return func(name string) string {
		if old, ok := kept[name]; ok {
			return old
		}

		return name
	}
}

// WriteCABundle writes the PEM parts, in order, as one file named name in
// the OS temp directory (mode 0600) and returns its path: what
// [Login.CACertFile] and the provider's CA option read. Each part is
// trimmed and ends in one newline; empty parts are skipped.
func WriteCABundle(name string, parts ...[]byte) (string, error) {
	var bundle strings.Builder

	for _, part := range parts {
		pem := strings.TrimSpace(string(part))
		if pem == "" {
			continue
		}

		bundle.WriteString(pem)
		bundle.WriteString("\n")
	}

	path := filepath.Join(os.TempDir(), name)
	if err := os.WriteFile(path, []byte(bundle.String()), 0o600); err != nil {
		return "", fmt.Errorf("write the CA bundle %s: %w", name, err)
	}

	return path, nil
}

// DeliveredSecret is a Kubernetes Secret another system delivers, read
// key by key through kubectl, for what an apply needs before it touches the
// server (an OIDC client secret, say).
type DeliveredSecret struct {
	Namespace, Name string
	// Hint ends every error: what to do when the Secret is not there yet.
	Hint string
}

// Key is one decoded key of the Secret. An empty value is an error: a
// consumer such as an oidc mount configures fine with no secret and then
// fails every sign-in. The value never reaches an error.
func (s DeliveredSecret) Key(ctx context.Context, kubectl Kubectl, key string) (string, error) {
	where := s.Namespace + "/" + s.Name

	out, err := kubectl(ctx, "get", "secret", s.Name, "-n", s.Namespace,
		"-o", "jsonpath={.data."+strings.ReplaceAll(key, ".", `\.`)+"}")
	if err != nil {
		return "", fmt.Errorf("read %s from secret %s (%s): %w", key, where, s.Hint, err)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", fmt.Errorf("decode %s from secret %s: not base64", key, where)
	}

	if len(decoded) == 0 {
		return "", fmt.Errorf("secret %s has no %s (%s)", where, key, s.Hint)
	}

	return string(decoded), nil
}
