// Command openbaoctl drives the OpenBAO operations that have no Kubernetes
// or Pulumi resource. Today that is the KMS-rooted CA ceremony
// (pkg/ceremony), authored as one hierarchy file:
//
//	openbaoctl pki create-root --hierarchy pki.yaml --key-arn <primary key ARN>
//	openbaoctl pki sign-intermediate --hierarchy pki.yaml --trust-domain private --csr private.csr --print-template
//	openbaoctl pki sign-intermediate --hierarchy pki.yaml --trust-domain private --csr private.csr --confirm-template <sha256>
//	openbaoctl pki verify-intermediate --hierarchy pki.yaml --trust-domain private --chain-out private-chain.pem
//	openbaoctl pki sign-emergency-server --hierarchy pki.yaml --csr openbao.csr --print-template
//	openbaoctl pki install-emergency-server --certificate openbao.crt --private-key openbao.key \
//	  --ca-bundle root.crt --namespace openbao --kube-context <context>       # --kube-context is required
//
// The bootstrap of a fresh server (pkg/bootstrap, docs/bootstrap.md):
//
//	openbaoctl init --addr https://127.0.0.1:8200 --ca-file ca.pem --keeper-dir ./keeper --age-identity-file id.txt
//	openbaoctl configure ... --issuer https://issuer.example --operator-group openbao:operators
//	openbaoctl revoke-root ... --operator-group openbao:operators --operator-jwt-file token.jwt
//	openbaoctl drill start|forward|stop --kube-context <context> --namespace openbao
//
// Every signing command asks the root key for at most one signature, and
// only for a template whose hash the operator confirmed. See
// docs/ceremony.md.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"
)

// Version is stamped by the release.
var Version = "dev"

func main() { os.Exit(run()) }

// run is main's body, so its deferred stop runs before the process exits.
func run() int {
	cmd := &cli.Command{
		Name:    "openbaoctl",
		Usage:   "OpenBAO operations that have no Kubernetes or Pulumi resource",
		Version: Version,
		Commands: append([]*cli.Command{
			pkiCommand(),
		}, bootstrapCommands()...),
	}

	// Ctrl-C, SIGTERM and SIGHUP (a closed terminal) cancel the context instead of killing the process,
	// so a bootstrap step in flight runs its cleanups (cancel a pending
	// root generation, revoke a token it generated) before it exits.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	if err := cmd.Run(ctx, os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)

		return 1
	}

	return 0
}
