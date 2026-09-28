// Command openbao-hostcert renews one SSH host certificate from an
// OpenBAO AWS IAM auth login and, if it changed, reloads sshd. See this
// package's own doc comment (renew.go) for the design and what its tests
// do and do not prove.
//
//	openbao-hostcert \
//	  --address https://openbao.example.internal \
//	  --namespace example \
//	  --auth-mount aws --auth-role router-host --server-id-header example-openbao-aws-router-host \
//	  --ssh-mount ssh-host --ssh-role router \
//	  --principal ip-10-0-0-1.tailnet.example.ts.net \
//	  --public-key /etc/ssh/ssh_host_ed25519_key.pub \
//	  --cert-path /etc/ssh/ssh_host_ed25519_key-cert.pub \
//	  --reload-cmd "systemctl reload sshd"
//
// Every flag also reads from an environment variable of the same name,
// upper-cased with `-` as `_` and prefixed `OPENBAO_HOSTCERT_`
// (--server-id-header is OPENBAO_HOSTCERT_SERVER_ID_HEADER) -- a systemd
// unit's own config file is an EnvironmentFile of these, not a bespoke
// format this binary would otherwise need to parse (systemd/*.service,
// this release's own assets).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
)

// Version is stamped by the release, the same convention openbaoctl uses.
var Version = "dev"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cmd := &cli.Command{
		Name:    "openbao-hostcert",
		Usage:   "renew one SSH host certificate from an OpenBAO AWS IAM auth login",
		Version: Version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name: "address", Required: true, Sources: cli.EnvVars("OPENBAO_HOSTCERT_ADDRESS"),
				Usage: "OpenBAO's URL (https://..., no trailing slash)",
			},
			&cli.StringFlag{
				Name: "ca-cert", Sources: cli.EnvVars("OPENBAO_HOSTCERT_CA_CERT"),
				Usage: "PEM bundle to trust beyond the OS roots",
			},
			&cli.StringFlag{
				Name: "namespace", Sources: cli.EnvVars("OPENBAO_HOSTCERT_NAMESPACE"),
				Usage: "OpenBAO namespace (empty: root)",
			},
			&cli.StringFlag{
				Name: "auth-mount", Required: true, Sources: cli.EnvVars("OPENBAO_HOSTCERT_AUTH_MOUNT"),
				Usage: "the AWS IAM auth mount's path",
			},
			&cli.StringFlag{
				Name: "auth-role", Required: true, Sources: cli.EnvVars("OPENBAO_HOSTCERT_AUTH_ROLE"),
				Usage: "the role this host's instance ARN is bound to",
			},
			&cli.StringFlag{
				Name: "server-id-header", Required: true, Sources: cli.EnvVars("OPENBAO_HOSTCERT_SERVER_ID_HEADER"),
				Usage: "the mount's pinned X-Vault-AWS-IAM-Server-ID value",
			},
			&cli.StringFlag{
				Name: "ssh-mount", Required: true, Sources: cli.EnvVars("OPENBAO_HOSTCERT_SSH_MOUNT"),
				Usage: "the SSH host-CA mount",
			},
			&cli.StringFlag{
				Name: "ssh-role", Required: true, Sources: cli.EnvVars("OPENBAO_HOSTCERT_SSH_ROLE"),
				Usage: "the SSH host-CA role",
			},
			&cli.StringSliceFlag{
				Name: "principal", Required: true, Sources: cli.EnvVars("OPENBAO_HOSTCERT_PRINCIPALS"),
				Usage: "a valid_principals entry (repeatable; the env var is comma-separated)",
			},
			&cli.StringSliceFlag{
				Name: "principal-pattern", Sources: cli.EnvVars("OPENBAO_HOSTCERT_PRINCIPAL_PATTERNS"),
				Usage: "a path.Match glob every --principal must match at least one of (repeatable; defense in depth -- empty: no restriction)",
			},
			&cli.StringFlag{
				Name: "public-key", Required: true, Sources: cli.EnvVars("OPENBAO_HOSTCERT_PUBLIC_KEY"),
				Usage: "the host key's public half to sign",
			},
			&cli.StringFlag{
				Name: "cert-path", Required: true, Sources: cli.EnvVars("OPENBAO_HOSTCERT_CERT_PATH"),
				Usage: "where to write the signed certificate, atomically",
			},
			&cli.StringFlag{
				Name: "reload-cmd", Sources: cli.EnvVars("OPENBAO_HOSTCERT_RELOAD_CMD"),
				Usage: "run via sh -c, only when the certificate changed",
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			return Renew(ctx, logger, Config{
				Address:           c.String("address"),
				CACertPath:        c.String("ca-cert"),
				Namespace:         c.String("namespace"),
				AuthMount:         c.String("auth-mount"),
				AuthRole:          c.String("auth-role"),
				ServerIDHeader:    c.String("server-id-header"),
				SSHMount:          c.String("ssh-mount"),
				SSHRole:           c.String("ssh-role"),
				Principals:        splitEnvList(c.StringSlice("principal")),
				PrincipalPatterns: splitEnvList(c.StringSlice("principal-pattern")),
				PublicKeyPath:     c.String("public-key"),
				CertPath:          c.String("cert-path"),
				ReloadCommand:     c.String("reload-cmd"),
			}, stsLogin{})
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// splitEnvList makes a StringSliceFlag's env-var form (one comma-separated
// string) behave identically to its repeated --flag form: urfave/cli's own
// StringSliceFlag does not split an env var's value on commas by itself,
// so OPENBAO_HOSTCERT_PRINCIPALS=a,b would otherwise arrive as the single
// element "a,b".
func splitEnvList(values []string) []string {
	if len(values) == 1 && strings.Contains(values[0], ",") {
		return strings.Split(values[0], ",")
	}

	return values
}
