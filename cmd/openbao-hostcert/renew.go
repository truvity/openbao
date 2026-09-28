// Package main is openbao-hostcert: a small, generic renewer for one SSH
// HOST certificate, signed by an OpenBAO AWS IAM auth login. It fits any
// AWS-hosted machine that has an IAM instance role but no Kubernetes
// ServiceAccount to log in with otherwise -- an EC2 subnet router is the
// first consumer, never the only one this tool assumes.
//
// It does one thing, once, per invocation: log in, sign, write, maybe
// reload. A systemd timer (systemd/openbao-hostcert.timer, this release's
// own asset) is the scheduler; this binary carries no loop, no daemon
// mode and no retry -- a failed run exits non-zero and changes nothing on
// disk, so sshd keeps serving whatever host key and certificate (if any)
// were already there. Fail-safe by construction, not by a flag: there is
// no way to ask this tool to remove or truncate the certificate it did
// not just successfully mint.
//
// What this tool's own test suite proves, and what it does not: renew.go
// and client.go are exercised against an httptest double standing in for
// OpenBAO, and login.go's [awsLogin] interface is replaced by a fake in
// every test -- so the OpenBAO-facing protocol (the login body's shape,
// the sign call, the atomic write, the conditional reload) is proved, but
// the actual AWS SigV4 signing in [stsLogin] (login.go) is not: that
// needs a real AWS credential (IMDSv2 on a real EC2 instance, or an
// assumed role) and a real STS endpoint, neither of which this
// repository's test suite has. See login.go's own doc comment for the
// exact mechanism and the reference it follows.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"
)

// requestTimeout bounds each HTTP call to OpenBAO: a router with a
// network problem should fail this run quickly, not hang the timer's
// next invocation.
const requestTimeout = 30 * time.Second

// Config is everything one renewal run needs. Every field is required
// unless its own comment says otherwise -- main.go's flags/env map onto
// it one to one.
type Config struct {
	// Address is OpenBAO's URL as this host reaches it
	// (https://openbao.example.internal). No trailing slash.
	Address string
	// CACertPath is a PEM bundle to trust beyond the OS roots. Empty:
	// the OS trust store alone.
	CACertPath string
	// Namespace is the OpenBAO namespace both the login and the sign
	// call are made in. Empty: root.
	Namespace string
	// AuthMount and AuthRole are the AWS IAM auth mount's path and the
	// role this host's instance-role ARN is bound to.
	AuthMount string
	AuthRole  string
	// ServerIDHeader is the value the mount's client configuration pins
	// as iam_server_id_header_value -- must match exactly, or AWS auth
	// refuses the login (docs/safety.md "AWS IAM auth").
	ServerIDHeader string
	// SSHMount and SSHRole are the SSH HOST-CA mount and role this host's
	// certificate is signed with.
	SSHMount string
	SSHRole  string
	// Principals are the certificate's valid_principals -- the hostname
	// forms this run's certificate may claim. At least one is required:
	// this tool does not guess a host's own name (main.go's doc comment
	// says why -- it would make the binary estate-specific, the one
	// thing it is designed not to be).
	Principals []string
	// PrincipalPatterns, when non-empty, are glob patterns (path.Match
	// syntax: `*`, `?`, character classes) every entry of Principals must
	// match at least one of -- defense in depth, checked before this
	// tool ever asks OpenBAO to sign anything. OpenBAO's own SSH secrets
	// engine has no CIDR- or glob-aware way to restrict which hostname a
	// role may sign for (only an exact match or a DNS-suffix match,
	// verified against openbao/openbao's source -- see this tool's own
	// docs), so a caller whose SSHMount/SSHRole spans more than one
	// environment's or one host's names should set this to the
	// pattern(s) that keep a misconfigured or compromised Principals
	// value from asking for something OpenBAO would sign but nobody
	// meant it to. Empty (the default): no restriction beyond whatever
	// SSHMount/SSHRole itself enforces.
	PrincipalPatterns []string
	// PublicKeyPath is the host key's public half to sign.
	PublicKeyPath string
	// CertPath is where the signed certificate is written, atomically:
	// a temporary file in the SAME directory, renamed over it.
	CertPath string
	// ReloadCommand runs, via `sh -c`, only when CertPath's content
	// changed. Empty: never reload (the caller's own choice, not an
	// error) -- a systemd unit that itself restarts sshd on a file
	// change (a path unit) would set this empty on purpose.
	ReloadCommand string
}

// Renew logs in with login, reads Config.PublicKeyPath, signs one host
// certificate and writes it to Config.CertPath if it changed, reloading
// only then. It returns an error and changes NOTHING on disk on any
// failure before the write: a login failure, a sign failure or an unread
// public key all leave CertPath exactly as they found it.
func Renew(ctx context.Context, logger *slog.Logger, cfg Config, login awsLogin) error {
	if len(cfg.Principals) == 0 {
		return fmt.Errorf("openbao-hostcert: no principals configured -- refusing to sign a certificate for nobody")
	}

	if err := checkPrincipalPatterns(cfg.Principals, cfg.PrincipalPatterns); err != nil {
		return fmt.Errorf("openbao-hostcert: %w", err)
	}

	client, err := newBaoClient(cfg.Address, cfg.Namespace, cfg.CACertPath, requestTimeout)
	if err != nil {
		return fmt.Errorf("openbao-hostcert: %w", err)
	}

	req, err := login.Login(ctx, cfg.AuthRole, cfg.ServerIDHeader)
	if err != nil {
		return fmt.Errorf("openbao-hostcert: AWS login: %w", err)
	}

	token, err := client.login(ctx, cfg.AuthMount, req)
	if err != nil {
		return fmt.Errorf("openbao-hostcert: %w", err)
	}

	publicKey, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("openbao-hostcert: read public key: %w", err)
	}

	signed, err := client.signHostCert(ctx, token, cfg.SSHMount, cfg.SSHRole, string(publicKey), cfg.Principals)
	if err != nil {
		return fmt.Errorf("openbao-hostcert: %w", err)
	}

	changed, err := writeIfChanged(cfg.CertPath, []byte(signed))
	if err != nil {
		return fmt.Errorf("openbao-hostcert: write certificate: %w", err)
	}

	logger.InfoContext(ctx, "signed host certificate",
		slog.String("mount", cfg.SSHMount), slog.String("role", cfg.SSHRole),
		slog.Bool("changed", changed), slog.String("path", cfg.CertPath))

	if !changed || cfg.ReloadCommand == "" {
		return nil
	}

	if err := reload(ctx, cfg.ReloadCommand); err != nil {
		// The certificate is already written -- sshd will pick it up on
		// its OWN next reload or restart even if this one failed to
		// trigger it. Reported, not silently dropped, but not a reason
		// to have left the certificate unwritten.
		return fmt.Errorf("openbao-hostcert: certificate written but reload failed: %w", err)
	}

	logger.InfoContext(ctx, "reloaded", slog.String("command", cfg.ReloadCommand))

	return nil
}

// checkPrincipalPatterns refuses any of principals that matches none of
// patterns -- an empty patterns is "no restriction" (returns nil for
// anything), not "match nothing": the CALLER decides whether to set this
// at all (Config.PrincipalPatterns's own doc comment).
func checkPrincipalPatterns(principals, patterns []string) error {
	if len(patterns) == 0 {
		return nil
	}

	for _, principal := range principals {
		matched := false

		for _, pattern := range patterns {
			ok, err := path.Match(pattern, principal)
			if err != nil {
				return fmt.Errorf("principal pattern %q: %w", pattern, err)
			}

			if ok {
				matched = true

				break
			}
		}

		if !matched {
			return fmt.Errorf("principal %q matches none of the configured patterns %v -- refusing to ask OpenBAO to sign it", principal, patterns)
		}
	}

	return nil
}

// writeIfChanged writes content to path atomically -- a temporary file in
// path's own directory, fsynced, renamed over path -- and reports whether
// path's content actually changed. Comparing first, before ever touching
// disk, means a certificate that (implausibly) came back byte-identical
// to the one already there triggers no reload and no unnecessary write.
func writeIfChanged(path string, content []byte) (bool, error) {
	existing, err := os.ReadFile(path)
	if err == nil && bytes.Equal(existing, content) {
		return false, nil
	}

	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".openbao-hostcert-*")
	if err != nil {
		return false, fmt.Errorf("create temp file in %s: %w", dir, err)
	}

	tmpPath := tmp.Name()

	// Any failure from here removes the temp file: nothing is left
	// behind for a later run to trip over, and CertPath is untouched.
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()

		return false, fmt.Errorf("write temp file: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()

		return false, fmt.Errorf("sync temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return false, fmt.Errorf("chmod temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return false, fmt.Errorf("rename into place: %w", err)
	}

	cleanup = false

	return true, nil
}

// reload runs command through the shell, so a caller can pass
// "systemctl reload sshd" or "systemctl reload sshd || systemctl restart
// sshd" without this tool parsing either.
func reload(ctx context.Context, command string) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%q: %w: %s", command, err, bytes.TrimSpace(out))
	}

	return nil
}
