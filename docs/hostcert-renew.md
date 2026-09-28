# openbao-hostcert: a generic EC2 host-certificate renewer

A small, standalone binary that logs in to OpenBAO with an AWS IAM auth
role (`model.AWSAuthMount`, see [model.md](model.md)'s SSH section) and
signs one SSH host certificate. It fits any AWS-hosted machine that has
an IAM instance role but no Kubernetes ServiceAccount to log in with
otherwise -- the [SSH](model.md#ssh) section's "who may sign a host
certificate" already covers the Kubernetes-hosted case (a projected
ServiceAccount token on a `jwt` role); this tool is the other half, and
names no estate, no router and no consumer of its own.

## What it does, once, per invocation

1. Signs an STS `GetCallerIdentity` request with the process's own AWS
   credentials -- on EC2, IMDSv2-derived instance-role credentials, via
   the AWS SDK's default credential chain (no IMDS call written here by
   name).
2. Logs in to OpenBAO's AWS IAM auth (`auth/<mount>/login`) with that
   signed request.
3. Reads the host key's public half and asks
   `<ssh-mount>/sign/<ssh-role>` for a host certificate
   (`cert_type=host`) naming the configured principals.
4. Writes the certificate atomically (a temp file in the same directory,
   fsynced, renamed over the target) -- only when its content actually
   changed from what was already there.
5. Reloads (`--reload-cmd`, run via `sh -c`) only when the certificate
   changed.

There is no loop, no daemon mode and no retry: a systemd timer
(`systemd/openbao-hostcert.timer`, this release's own asset) is the
scheduler, and a failed run exits non-zero having changed nothing on
disk. **Fail-safe by construction**: this binary has no code path that
removes or truncates an existing certificate -- a login failure, a
refused login, a refused sign, an unreadable public key or a failed
reload all leave `--cert-path` exactly as they found it, so sshd keeps
serving whatever host key (and, if one was already signed, certificate)
it had.

## Configuration

Every value is a flag, and every flag also reads an environment variable
of the same name (`OPENBAO_HOSTCERT_<FLAG_NAME>`, upper-cased,
`-` becomes `_`) -- an `EnvironmentFile` is the "config file" a systemd
unit gives this tool, not a bespoke format it would otherwise need to
parse:

| Flag | Env var | Meaning |
|---|---|---|
| `--address` | `OPENBAO_HOSTCERT_ADDRESS` | OpenBAO's URL, no trailing slash |
| `--ca-cert` | `OPENBAO_HOSTCERT_CA_CERT` | PEM bundle to trust beyond the OS roots (empty: OS roots alone) |
| `--namespace` | `OPENBAO_HOSTCERT_NAMESPACE` | OpenBAO namespace for both calls (empty: root) |
| `--auth-mount` | `OPENBAO_HOSTCERT_AUTH_MOUNT` | the AWS IAM auth mount's path |
| `--auth-role` | `OPENBAO_HOSTCERT_AUTH_ROLE` | the role this host's instance ARN is bound to |
| `--server-id-header` | `OPENBAO_HOSTCERT_SERVER_ID_HEADER` | the mount's pinned `iamServerIdHeaderValue`, exactly |
| `--ssh-mount` | `OPENBAO_HOSTCERT_SSH_MOUNT` | the SSH host-CA mount |
| `--ssh-role` | `OPENBAO_HOSTCERT_SSH_ROLE` | the SSH host-CA role |
| `--principal` (repeatable) | `OPENBAO_HOSTCERT_PRINCIPALS` (comma-separated) | `valid_principals` -- required, at least one |
| `--principal-pattern` (repeatable) | `OPENBAO_HOSTCERT_PRINCIPAL_PATTERNS` (comma-separated) | a `path.Match` glob every `--principal` must match at least one of; empty: no restriction |
| `--public-key` | `OPENBAO_HOSTCERT_PUBLIC_KEY` | the host key's public half to sign |
| `--cert-path` | `OPENBAO_HOSTCERT_CERT_PATH` | where the signed certificate is written |
| `--reload-cmd` | `OPENBAO_HOSTCERT_RELOAD_CMD` | run via `sh -c`, only when the certificate changed; empty: never reload |

`--principal` is deliberately never auto-detected from the local
hostname: doing so would make this binary know something about the
estate it runs in (how a router's tailnet name is formed, say), which is
exactly what keeps it generic. Whatever writes this host's
`EnvironmentFile` -- a launch-template user-data block, a config
management run -- is where that estate-specific discovery belongs.

`--principal-pattern` is defense in depth, not the primary guard.
OpenBAO's own SSH secrets engine has no CIDR- or glob-aware way to
restrict which hostname a host-CA role may sign for -- only an exact
match or a DNS-suffix match (checked against `openbao/openbao`'s source,
`internal/builtin/logical/ssh/path_issue_sign.go`'s
`validateValidPrincipalForHosts`). A caller whose `--ssh-mount`/
`--ssh-role` is shared across more than one environment or host class
should set this so a misconfigured or compromised `--principal` value
is refused here, before this tool ever asks OpenBAO to sign it, rather
than relying on OpenBAO to refuse it -- it will not. The actual boundary
against a signed certificate being trusted for the wrong host is
client-side (the `known_hosts` `@cert-authority` line's own pattern);
this flag only stops THIS tool from asking for something out of scope
in the first place.

## systemd

`systemd/openbao-hostcert.service` and `.timer` are release assets
(`goreleaser`'s `release.extra_files`, checksummed in `checksums.txt`
the same as every archive), not archived with the binary: a unit is
installed once, and re-downloading it on every binary upgrade would
silently reformat one an installer had customized. The timer runs the
service every 12 hours, plus once ~2 minutes after boot, with up to 10
minutes of random jitter so a fleet does not all call OpenBAO in the
same second. `SSHHostRole.MaxTTL`'s cap (30 days in this repository;
most estates set their own certificate lifetime far shorter -- 24h is
the nix-worker pilot's own choice, see `model.md`) decides how much
slack a 12-hour cadence actually has; a shorter certificate lifetime
than roughly 2x the renewal interval leaves too little margin for a
missed run.

## What is proved, and what is not

`cmd/openbao-hostcert/renew_test.go` runs every test against an
`httptest` double standing in for OpenBAO, with the AWS login itself
replaced by a fake (`awsLogin`, `login.go`) -- so the OpenBAO-facing
protocol (the login body's exact shape, the sign call, the atomic write,
the conditional reload, and every failure path leaving the existing
certificate untouched) is proved with no real AWS account or network
call anywhere in reach.

What that leaves unproved: `stsLogin` (`login.go`) -- the actual SigV4
signing of the STS `GetCallerIdentity` request and its
`X-Vault-AWS-IAM-Server-ID` header -- needs a real AWS credential
(IMDSv2 on a real EC2 instance, or an assumed role) and a real STS
endpoint, neither of which this repository's test suite has. Its design
follows the documented AWS IAM auth method contract exactly (a signed,
non-presigned `POST` to the global STS endpoint, never a presigned
query-string URL -- the two are different SigV4 modes, and OpenBAO's
verifier needs the header-carrying one) and the AWS SDK's own signer
primitives (`aws-sdk-go-v2/aws/signer/v4`), but was not exercised
against a real OpenBAO `aws` auth backend from this repository's test
environment. Whoever wires this into a real router should smoke-test one
real login before relying on the timer.
