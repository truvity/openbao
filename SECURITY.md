# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately via
[GitHub Security Advisories](https://github.com/truvity/openbao/security/advisories/new).

Do NOT open a public issue for security vulnerabilities.

## Supported Versions

Only the latest release is supported with security updates.

## What is in scope

This repository publishes:

- The Go packages: `pkg/model`, `pkg/apply`, `pkg/serverpreset`, `pkg/ceremony`, `pkg/custody`, `pkg/pki`, `pkg/kmssigner` and `pkg/approvercheck`.
- The commands: `openbaoctl` (the CA ceremony), `approvercheck` (the approver-layer proof) and `openbao-hostcert` (the EC2 host-certificate renewer, which runs as root).
- The charts `openbao-ops` and `openbao-consumers`, and the examples, including the access-roster preset (`model.Roster`).
- The documentation, where it tells an adopter to do something unsafe.

Reports that matter most:

- A chart default or a preset that weakens TLS, trust, network policy or who may read, write or issue.
- A refusal that accepts input it should reject: a policy the approver check calls approved when it is not, a hierarchy or template the ceremony signs without the review it promises, a model that applies wider access than it states.
- A key, token, seed or other secret reaching a log line, an error, a rendered manifest or a committed artifact, or a CA key custody policy that lets administration sign.
- `openbao-hostcert` or `openbaoctl` doing more than their documentation says with the credentials they hold.

A finding that depends on how a particular deployment uses this repository
belongs with that deployment's owner.
