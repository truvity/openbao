// Command openbaoctl drives the OpenBAO operations that have no Kubernetes
// or Pulumi resource. Today that is the KMS-rooted CA ceremony
// (pkg/ceremony), authored as one hierarchy file:
//
//	openbaoctl pki create-root --hierarchy pki.yaml --key-arn <primary key ARN>
//	openbaoctl pki sign-intermediate --hierarchy pki.yaml --trust-domain private --csr private.csr --print-template
//	openbaoctl pki sign-intermediate --hierarchy pki.yaml --trust-domain private --csr private.csr --confirm-template <sha256>
//	openbaoctl pki verify-intermediate --hierarchy pki.yaml --trust-domain private --chain-out private-chain.pem
//	openbaoctl pki sign-emergency-server --hierarchy pki.yaml --csr openbao.csr --print-template
//
// Every signing command asks the root key for at most one signature, and
// only for a template whose hash the operator confirmed. See
// docs/ceremony.md.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
)

// Version is stamped by the release.
var Version = "dev"

func main() {
	cmd := &cli.Command{
		Name:    "openbaoctl",
		Usage:   "OpenBAO operations that have no Kubernetes or Pulumi resource",
		Version: Version,
		Commands: []*cli.Command{
			pkiCommand(),
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
