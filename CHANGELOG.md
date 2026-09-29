# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. Both charts are released at every version, and
from v0.2.0 on the Go module and `openbaoctl` with them.

## v0.19.1

- README rewritten in the component contract's heading order with `Consumers` and `Neighbours`; the doctrine link points at the policy component contract; `Status` states the AWS KMS coupling of `serverpreset`, `ceremony` and `custody` as of 2026-09-29.

## v0.19.0

### Added

- **`openbaoctl pki`: a `pkg/pki` contract in place of a hierarchy file.**
  `create-root`, `sign-intermediate`, `verify-intermediate` and
  `sign-emergency-server` now also accept `--contract <file> --generation
  <id>` (docs/pki.md) alongside the existing `--hierarchy <file>`, with no
  new command: a `pkiSource` resolves either shape to the same
  `ceremony.RootSpec`/`IntermediateSpec`/`EmergencyServerSpec`.
  `--artifacts <dir>` overrides a contract's own artifact directory;
  `--environment <env> --zone <value>` (`sign-intermediate`,
  `verify-intermediate`) sign or verify one environment's own root-signed
  CA under a workload-identity domain instead of the domain's shared
  intermediate; `--dns-name <name>` (`sign-emergency-server`) gives the
  break-glass name a hierarchy file instead bakes into
  `emergencyServer.dnsName`. `--hierarchy` is unchanged.

### Changed

- **`pkg/ceremony`: `Hierarchy`'s intermediates may override
  `maxPathLen`.** `HierarchyIntermediate.MaxPathLen` (optional) replaces
  the default (the root's own minus one) so a leaf-issuing CA signed
  directly by the root — nothing of its own below it, spending more of
  the root's budget at once — can be declared in a hierarchy file the
  same way an ordinary domain intermediate is. Every existing hierarchy
  file, which leaves the field out, renders identically.

- **`pkg/apply`: the two-phase bootstrap for a workload-identity
  environment's root-signed CA, as library code.** `BootstrapEnvironmentCA`
  registers phase A (docs/pki.md, "per-environment identity CAs"): the
  unsigned key and its certificate signing request, on a mount it also
  creates for an environment reaching its root-signed CA from a cold
  start, or on an existing one for an environment moving there from a
  shared domain intermediate's issuing CA. Both are protected: replacing
  either is an explicit, reviewed migration.
- **`pkg/apply`: `EnvironmentCARoleRename` and `ComposeRename`.** Moving
  an environment's identity role to its new root-signed CA's issuer
  changes the role's Pulumi logical name (`PKIRoleResourceName`, now
  exported), which — without `Options.Rename` — makes Pulumi create the
  new logical resource and DELETE the old one, and both write the SAME
  OpenBAO path (`<mount>/roles/<role>`): the delete removes what the
  create just wrote. `EnvironmentCARoleRename(oldIssuer, newIssuer,
  roleNames...)` returns the `Rename` entries that keep the role in
  place instead (an update, not a replace); `ComposeRename` merges them
  with a caller's own `Rename`. Proved by
  `TestEnvironmentCARoleMoveIsInPlace`: the same move, without the fix,
  registers the role under a different name (what a real diff would
  delete); with it, under the same one.

## v0.18.2

### Fixed

- **`internal/fakeissuer`: `authorize` no longer even hands the
  caller-supplied `redirect_uri` to `url.Parse`/`http.Redirect`.**
  v0.18.1 (below) validated it with `slices.Contains` but still parsed
  and redirected to that same tainted string, which is the shape CodeQL
  keeps flagging as `go/unvalidated-url-redirection` (alert #1)
  regardless of the check that ran first -- a taint tracker follows data
  flow, not the conditionals guarding it. The redirect target is now the
  matching entry read back out of the client's own registered
  `RedirectURIs` (`client.RedirectURIs[index]`) -- a value with no data-flow
  edge from the request at all, since it originates from this server's
  own trusted client table, never from `r.URL.Query()`. Same behavior
  (the two strings are identical whenever the check passes); different,
  now-untainted, provenance.

## v0.18.1

### Added

- **Daily `govulncheck` scanning (`.github/workflows/security.yaml`)**,
  matching the shape already running in `truvity/cloudflare` and
  `truvity/tailscale`: the shared `check.yaml` workflow's `vuln` recipe,
  on push, on pull request, and on a 6am UTC daily schedule. Until now
  this repository relied on CodeQL alone, which does not reach a
  known-vulnerable dependency the way `govulncheck` does.

### Changed

- **`truvity/ci-workflows` pins bumped from v3.0.1 to v3.13.1** across
  `ci.yaml`, `auto-release.yaml` and `release.yaml`. No caller-visible
  input changed for this repository's usage across that range; the
  composite actions the workflows call moved to `truvity/ci-actions`
  at v3.9.0, transparently to every workflow-level caller.

### Fixed

- **`golang.org/x/crypto` bumped v0.55.0 -> v0.56.0**, closing GO-2026-6355
  and GO-2026-6354 (DoS on a deadlocked SSH channel, established and
  undecided). `govulncheck` found both as package-level only -- this
  repository's own code does not call the vulnerable symbols -- so
  nothing else changes. A third finding, GO-2026-5932
  (`golang.org/x/crypto/openpgp` is unmaintained and unsafe by design),
  has no fix released (`Fixed in: N/A`) and is not reachable from this
  repository's code either; nothing to bump.
- **`internal/fakeissuer`: the authorize endpoint no longer redirects to
  an unregistered `redirect_uri`** (CodeQL alert #1,
  `go/unvalidated-url-redirection`). It now refuses, with 400, before a
  code is ever issued, any `redirect_uri` that is not exactly one its
  client registered -- the same shape a real OIDC client registration
  takes. `fakeissuer.New`'s client map now carries a `Client{Secret,
  RedirectURIs}` per id instead of a bare secret string; every caller in
  this repository (`internal/fakeissuer`, `conformance`) is updated.
  This is a test double with no production exposure, fixed anyway so the
  contract it proves stays honest.

## v0.18.0

### Added

- **`pkg/pki`: the authored private-PKI contract, above `pkg/ceremony`.**
  Loading and validating a hierarchy's policy — how many root generations
  exist and their AWS KMS custody, the DNS- and URI-shaped trust domains
  below them, the leaf roles each domain offers per environment, and a
  workload-identity domain's per-environment issuing CAs signed DIRECTLY
  by the root (a real OpenBAO 2.6.2 limitation this avoids —
  [openbao/openbao#4104](https://github.com/openbao/openbao/issues/4104),
  see [docs/pki.md](docs/pki.md#per-environment-identity-cas-and-why) —
  rather than a preference) — used to be something every consuming estate
  wrote for itself. `Contract.Validate` carries the invariants (immutable
  crypto policy with a declared, allow-listed exception for the one leaf
  curve a caller's own client cannot be told to change; strictly
  decreasing lifetimes root > domain intermediate > cluster intermediate
  > leaf; exactly one active generation; a domain that
  `requireTrusted` actually is); `Contract.RootSpec` /
  `DNSIntermediateSpec` / `URIIntermediateSpec` / `EnvironmentCASpec` /
  `EmergencyServerSpec` turn it into the `ceremony.RootSpec` /
  `IntermediateSpec` / `EmergencyServerSpec` values `pkg/ceremony` signs
  from, and `Contract.TrustAnchors` / `LoadSignedIntermediate` /
  `IntermediateSigned` read the committed artifacts back, offline, with no
  KMS credential. See [docs/pki.md](docs/pki.md).

- **A server preset (`pkg/serverpreset`) for the plugin catalog, the
  seal, the listener and Raft** on the upstream `openbao/openbao-helm`
  chart's server — a values fragment, not a wrapper chart (see
  docs/server.md, "Why a values preset, not a wrapper chart"), carrying
  the operational lessons of running an external plugin (OpenBAO, unlike
  Vault, ships no cloud auth or secrets method built in) safely on a
  real, multi-pod server:
  - `plugin_directory` must exist before `bao server` starts, whether or
    not the download that follows succeeds — a failed download never
    creates it, and a missing directory makes the server EXIT, not warn
    and continue. `Config.PluginVolume`/`Config.PluginVolumeMount` render
    the emptyDir that keeps this true on every pod.
  - `plugin_download_behavior` accepts exactly `"fail"` or `"continue"` —
    any other value, `"warn"` included, is accepted by the server's
    config parser and silently ignored. `Config.Validate` refuses
    anything else at render time.
  - A fresh pod's first plugin download races whatever admits its
    egress. `Config.RetrySidecarContainer` waits for the server's own
    listener (never signalling it before it is serving — SIGHUP's
    default disposition would restart the container instead) and then
    SIGHUPs `bao server` on a timer, which re-runs the same declarative
    download and registration until it succeeds.
  - `Config.Arch` is an explicit, never-derived architecture selector:
    `ResolveArch` is the general form of refusing a node selection that
    could resolve to more than one architecture, before a checksum is
    ever picked for it — a single sha256sum can only ever verify one
    architecture's binary.
  - `Config.EgressDomains()` derives the egress allowlist a rendered
    `Config` needs from what is actually enabled (each plugin's OCI
    registry and blob hosts, AWS STS for a plugin that verifies a caller
    against it, the seal's KMS host), for `openbao-ops`'s own
    `networkPolicy.egress.rules` or a consumer's own policy to build
    from.

  [`examples/server`](examples/server) is a complete, neutral example
  proven two ways: `values.yaml` beside it is its golden (`pkg/model`'s
  and `pkg/apply`'s desired-state examples already work the same way),
  and [`conformance/server_preset_test.go`](conformance/server_preset_test.go)
  boots a real, non-dev `bao server` from exactly its rendered HCL — with
  a local plugin directory and no route to the plugin's registry — to
  prove a `"continue"` failure never stops the server and a missing
  plugin directory always does. docs/server.md's rewritten around the
  preset, with a plugin rollout runbook (canary one standby, verify the
  catalog entry, then the rest, leader last) and a migration note for an
  install that already hand-authors this HCL.

## v0.17.0

### Changed

- **`pkg/ceremony`: `IntermediateSpec.MaxPathLen` no longer needs to be
  exactly one less than the root's.** The offline ceremony that signs a
  domain intermediate under a committed root artifact
  (`PrepareIntermediate`/`SignIntermediate`) required
  `root.MaxPathLen == spec.MaxPathLen + 1`, on the assumption that every
  intermediate signed directly by the root is itself followed by another
  CA. That is not true of a leaf-issuing CA signed directly by the root
  with no domain intermediate above it and no CA of its own below it --
  for example a per-environment issuing CA with `maxPathLen: 0` under a
  root of `maxPathLen: 3`. The check is now `spec.MaxPathLen <
  root.MaxPathLen`: a domain intermediate that still spends exactly one
  level of the root's budget continues to validate unchanged, and a
  leaf-issuing CA may now spend more of it at once. RFC 5280's
  `pathLenConstraint` only bounds how many CA certificates may follow; it
  never required each level to consume exactly one unit of the budget.
  The refusal message changed from `root maxPathLen must be exactly N`
  to `root maxPathLen must be greater than this intermediate's maxPathLen
  N`.

## v0.16.0

### Added

- **`pkg/model`: `AWSAuthMount` gains `pluginVersion`, to pin the plugin
  catalog version an `awsAuth[]` mount is created at.** A server that
  registers the `aws` auth plugin as a VERSIONED catalog entry (a real
  server's `v0.1.1`, say, rather than the unversioned key a plain
  `Plugins` registration normally occupies) refuses an unversioned mount
  outright with `plugin not found in the catalog`; `pluginVersion` closes
  that gap. It takes OpenBAO's own `latest` sentinel or a `v`-prefixed
  semver, such as `v0.1.1`; left unset, a mount is unversioned, exactly
  as before this field existed.

### Fixed

- **`pkg/apply`: an `awsAuth[]` mount with `pluginVersion` set is now
  created through the provider's generic `sys/auth/<path>` endpoint,
  never `vault.AuthBackend`.** pulumi-vault v7's `AuthBackend` resource
  (and its tune block) carries no `pluginVersion` input anywhere, so it
  can only ever create the unversioned kind of mount -- useless against a
  catalog that holds the plugin only as a versioned entry. The client
  configuration and every role still wait for the mount and still
  address it by the same plain path; a mount with no `pluginVersion` is
  unaffected, still built the same `vault.AuthBackend` way as before.

## v0.15.0

### Added

- **`pkg/model`/`pkg/apply`: a `Plugin` entry registers one binary in
  OpenBAO's plugin catalog.** OpenBAO ships no cloud auth methods in the
  server binary; an external plugin (an `aws` IAM auth method, for
  instance) must be registered before any namespace can mount it, and
  registration is a root-scoped call above the namespace tree, not a
  per-namespace one. `Desired.Plugins` is applied once, before a single
  namespace is, through the Pulumi vault provider's `Plugin` resource.
  It assumes the binary is already on every server node, under the
  server's own `plugin_directory` -- placing it there (typically a
  declarative `plugin` block in the server's own HCL config, downloaded
  and verified by OpenBAO itself) is a different, independently reviewed
  change.

### Fixed

- **`pkg/apply`: a plugin-backed mount now waits for its own catalog
  registration.** `Deploy` already registered every `Plugins` entry
  before a single namespace, but that only orders the Go program that
  builds a Pulumi deployment, never the deployment itself: two resources
  with no dependency edge between them are created in whatever order
  Pulumi likes, so a fresh apply could still create an `aws` auth mount
  before its plugin was registered and reproduce the exact `plugin not
  found in the catalog: aws` error `Plugin` was added to prevent. Every
  mount the apply builds whose type matches a declared plugin's name now
  gets an explicit `DependsOn` that registration; a mount of a built-in
  type (`jwt`, `oidc`, ...) matches nothing and is unaffected.

## v0.14.0

### Fixed

- **`pkg/apply`: an identity-shaped PKI role no longer diffs on every
  refresh.** Building the role that carries `AllowedURISANs` (ADR 0002's
  identity shape), the apply sent `cn_validations` as an empty list --
  confirmed against a real OpenBAO 2.6.2 server, the API accepts an
  empty list but silently substitutes its own default
  (`["email","hostname"]`) when it is empty, so the very next read (and
  so a Pulumi refresh, forever after) never matched what was written.
  The apply now writes that same default explicitly for an identity
  role, same as `RequireCn: false` already makes the field inert for one
  either way -- an identity certificate carries no CN for either
  validation to ever apply to. `TestIdentityRoleShape` now asserts the
  actual persisted value instead of the value that was sent and never
  stuck.

## v0.13.0

### Added

- **`pkg/model`, `pkg/apply`: AWS IAM auth, for a host that runs on AWS
  but has no Kubernetes ServiceAccount to bind a `jwt` role to** -- an EC2
  subnet router, signing its own SSH host certificate, is the first
  consumer. `Namespace.AWSAuth` (`AWSAuthMount`/`AWSAuthRole`) mounts the
  `aws` auth backend's `iam` login type only, never `ec2`: a login signs
  an STS `GetCallerIdentity` request with its own IAM credentials, which
  OpenBAO verifies against AWS directly rather than trusting a bearer
  token or the unsigned EC2 instance-identity document. A role binds one
  or more literal instance-role ARNs (no wildcard), grants `Policies`
  directly with no identity group or alias -- the same machine-login
  shape a `jwt` role's `BoundSubject` takes -- and its `TTL`/`MaxTTL` are
  a plain Go duration pair, same as every other role in this model.
  `IAMServerIDHeaderValue` is required on the mount (refused empty by
  `Validate`): it is the `X-Vault-AWS-IAM-Server-ID` header every login
  must carry, and without it a signed request captured for any other AWS
  auth mount, anywhere, would be accepted here too.
  `AWSAuthRole.ResolveAWSUniqueIDs` is written explicitly per role, no
  default: `true` survives an IAM role deleted and recreated under the
  same name, but costs an `iam:GetRole`/`iam:GetUser` grant -- a
  cross-account one, when the bound ARN's account is not the one OpenBAO
  itself runs in -- that this library does not create by itself; `false`
  needs none. See `docs/model.md`'s SSH section and `docs/safety.md`'s
  "AWS IAM auth" for the full reasoning, and
  `pkg/model/testdata/desired.yaml`'s `dev.awsAuth` for a worked example
  signing into the same `ssh-host/sign/host` role a Kubernetes host
  agent already can. No live-AWS conformance test: verifying a real
  signed STS login needs a real AWS credential this repository's test
  suite does not have, the same boundary `pkg/ceremony`'s KMS double
  already draws for the real KMS root.

- **`cmd/openbao-hostcert`: a generic EC2 host-certificate renewer**, the
  operational half of the AWS IAM auth support above -- a small,
  standalone binary (not an `openbaoctl` subcommand: it runs unattended,
  as root, with no kubeconfig or KMS credential in reach, and dragging
  in `openbaoctl`'s ceremony/Kubernetes dependencies would bloat every
  host that installs it for no reason) that signs an STS
  `GetCallerIdentity` request with the process's own AWS credentials
  (IMDSv2 instance-role, via the AWS SDK's default chain), logs in to an
  `AWSAuthMount`, and asks a `SSHHostMount` role to sign the host's own
  public key (`cert_type=host`, configured `valid_principals`).
  `--principal-pattern` refuses to even ask for a principal outside a
  configured glob -- defense in depth, since OpenBAO's own SSH secrets
  engine has no CIDR- or glob-aware way to restrict which hostname a
  role may sign for (exact or DNS-suffix match only; see this release's
  `pkg/model` entry above and `docs/hostcert-renew.md`). The
  certificate is written atomically and sshd is reloaded
  (`--reload-cmd`) only when it actually changed; every failure path --
  a refused login, a refused sign, an unreadable public key -- leaves
  whatever certificate (or none) was already on disk untouched. No loop,
  no retry: `systemd/openbao-hostcert.timer` (this release's own asset,
  published via `release.extra_files`, checksummed like every archive)
  is the scheduler, every 12h plus once near boot with jitter. Every
  input is a flag or its matching `OPENBAO_HOSTCERT_*` environment
  variable, so a systemd `EnvironmentFile` is the whole of its
  configuration surface -- see `docs/hostcert-renew.md`, including what
  its test suite proves (the OpenBAO-facing protocol, against an
  `httptest` double, with the AWS login itself faked) and what it does
  not (the real SigV4 signing, which needs a real AWS credential and STS
  endpoint this repository's tests do not have).

## v0.12.0

### Added

- **`openbaoctl pki install-emergency-server`: the other half of the
  break-glass ceremony.** `pki sign-emergency-server` produces a leaf and
  needs no cluster; getting that leaf, its key and the root into the
  Kubernetes Secret OpenBAO's listener mounts is now its own command,
  needing a kubeconfig and no KMS credential. `--kube-context` is
  required -- there is no current-context fallback, because the one
  thing a break-glass write must confirm is the cluster. It refuses a
  certificate that does not chain to the given `--ca-bundle` alone, a
  private key that is not the certificate's, one that is a CA, and one
  that is expired or lives past the 30-day break-glass cap
  (`ceremony.MaxEmergencyServerLifetime`); prints what it is about to
  write -- the resolved context and API server, the Secret, its data
  keys, the certificate's subject, names, validity and fingerprint --
  and never the private key; and requires `--yes` or a typed
  confirmation before writing. A Secret that already exists (an expired
  certificate on a running cluster) keeps its type, annotations, labels
  and every other data key -- only the certificate, key and CA entries
  are replaced. A Secret that does not exist yet (a new cluster, or a
  restore onto one, before OpenBAO or cert-manager exist) is created as
  `kubernetes.io/tls` when the data key names are the upstream chart's
  defaults (`docs/server.md`). See `docs/ceremony.md` §4.
- **A rehearsal that proves the whole restore-path TLS bootstrap without
  AWS.** `conformance.TestBootstrapTLS` (`just rehearse-bootstrap-tls`,
  and part of `just test`/`just check` in CI) signs a break-glass leaf
  with a local stand-in for the KMS root -- the same double
  `pkg/ceremony`'s own tests use -- installs it, starts a real `bao
  server` with it, and proves a client holding only the root verifies it.
  It then simulates the normal issuer taking over: a domain intermediate
  signed by the same root issues its own leaf, swapped onto disk and
  reloaded with `SIGHUP`, and the same client still verifies. `docs/ceremony.md`
  now also describes the yearly drill that runs this same path once with
  the real KMS root, by hand, and records it in the consuming estate's
  restore runbook.

## v0.11.0

### Added

- **pkg/ceremony: URI name constraints, independent of DNS ones.**
  `IntermediateSpec` (and the hierarchy file's `permittedUriDomains`) grow
  a URI subtree alongside the existing DNS one -- either, both or neither
  may be set, and setting either makes the whole name-constraints
  extension present and critical (Go's `x509.Certificate` has one
  criticality flag for the extension, not one per subtree kind).
  `IntermediateTemplate` builds the two independently, and
  `verifyIntermediate` checks the signed certificate against whichever the
  spec authored, symmetrically. This is
  [ADR 0002](docs/decisions/0002-workload-mtls-service-and-identity-roles.md)'s
  workload-identity domain intermediate: a URI subtree alone, no DNS one,
  minted by the ceremony because OpenBAO 2.6.2's own
  `pki/root/generate/internal` and `pki/intermediate/generate/internal`
  endpoints silently ignore `permitted_uri_domains` (confirmed against a
  real server while building this -- the same gap `excludedIpRanges`
  already had, [docs/model.md](docs/model.md) documents). A new
  `identity` fixture and golden prove the shape, and a test proves with
  Go's own `x509.Verify` that a SPIFFE leaf under the permitted trust
  domain verifies and one under a foreign domain fails name-constraint
  verification.
- **pkg/model: an identity-shaped `PKIRole`.** `PKIRole` grows
  `AllowedURISANs` and `AllowedURISANsTemplate`: a URI SAN alone, never
  mixed with the existing DNS shape's `AllowedDomains` (`Validate` refuses
  both non-empty at once, and the DNS shape's
  `AllowBareDomains`/`AllowSubdomains`/`AllowWildcards` flags on an
  identity role). `Validate` also refuses an identity role with an empty
  URI list and a wildcard trust domain (`spiffe://*`) that is not
  templated to the caller's own identity -- a wildcard held to a fixed
  trust domain with only the path open (`spiffe://<trust
  domain>/*`) is exactly the documented CSI-driven fallback and is
  allowed untemplated. `pkg/apply/pki.go`'s `pkiRole` renders the role's
  own `AllowedURISANs`/`AllowedURISANsTemplate` instead of always sending
  an empty list, and, for an identity role, also turns off `use_csr_sans`,
  `enforce_hostnames` and CN validation. `use_csr_sans` matters more than
  it looks: confirmed against a real server while building this, OpenBAO
  2.6.2 defaults it to true, and when true the request's own `uri_sans`
  parameter is silently dropped -- the signed certificate carries no URI
  SAN at all, which is not a refusal, it is a certificate that looks
  scoped but never got the identity onto it. Existing (DNS-shaped) roles
  render byte-identical apart from the new, always-`[]`/`false`
  `allowedUriSans`/`allowedUriSansTemplate` fields.
- **docs: the identity role's templating finding, and the CSI-flow
  amendment to ADR 0002.** `allowed_uri_sans_template` binding a URI SAN
  to the caller's own identity
  (`{{identity.entity.aliases.<accessor>.metadata.…}}`, fed by a JWT
  role's `claimMappings`) works, proved against a real server: a workload
  login bound to one ServiceAccount gets a certificate for exactly its own
  SPIFFE ID and is refused for another's. In the estate's actual flow,
  though, certificates are requested by cert-manager's CSI SPIFFE driver
  on cert-manager's own login, never the pod's -- so this templating
  cannot bind to the requesting pod's identity there, and the model's
  identity role instead uses the fixed-trust-domain, open-path fallback
  above, leaving per-pod attestation to the SPIFFE approver. See
  [docs/model.md](docs/model.md#pki-mounts-issuers-roles) and
  [ADR 0002](docs/decisions/0002-workload-mtls-service-and-identity-roles.md)'s
  2026-09-28 amendment.

## v0.10.0

### Added

- **pkg/model: project namespaces, `<environment>/<project>`.**
  `Namespace.Projects` holds `ProjectNamespace`s, nested one level below
  their environment ([ADR 0001](docs/decisions/0001-namespaces-are-environment-project.md)).
  A `ProjectNamespace` carries `KV` and `PKI` mounts and nothing else --
  it has no `Auth`, `Policies`, `Groups`, `SSH`, `SSHHost` or nested
  `Projects` field at all, so most of what the record refuses is refused
  by the type's own shape, the same way `SSHHostMount` being a sibling
  type of `SSHMount` refuses a host role on a user mount. `Validate`
  refuses a project with no name or an unsafe one, one declared twice,
  one whose name collides with a mount the environment holds directly, a
  PKI issuer that is not signed by that SAME environment's own issuer
  (never root's, a sibling project's, or the project's own root or an
  external signer), and a credential role inside a project's PKI mount,
  which needs an auth mount to read a subject from and a project holds
  none.
  `model.ProjectPath(project, mount, subpath)` builds the policy-rule
  path (`<project>/<mount>/<subpath>`) an environment-level policy grants
  a project's mount through, with no second login (proved against a real
  server in `conformance/project_test.go`); `Validate` refuses a rule
  naming a project or a project's mount the environment does not declare,
  and, in any environment with a project, a rule whose first path segment
  carries a glob (`*` or `+`) rather than one literal name -- a bare `*`
  or a prefix glob such as `bill*` reaches every project the environment
  declares (a partner's among them) exactly as readily as the
  environment's own mounts, so it is refused whether or not a project
  happens to collide with it today.
  `Validate` (`Desired.validateSignerDepth`) also refuses an issuer whose
  `MaxPathLength` is too short for the CA levels the model actually puts
  beneath it — root → a domain intermediate → an environment's issuing CA
  → a project's issuing CA is four levels, and a path-length constraint
  counts the whole remaining chain, not just the next hop (RFC 5280
  4.2.1.9), so **an environment CA that will sign a project's needs
  `MaxPathLength` at least 1, not the 0 that was enough while it only
  signed leaves**. The refusal names both the issuer and the descendant
  it cannot cover. Raising an existing environment CA's `MaxPathLength`
  is not an in-place change — OpenBAO fixes it when the issuer is
  created — so one created with 0 needs a new issuer generation
  (docs/model.md) before it can sign a project.
- **pkg/apply: applies project namespaces.** `projectNamespace` creates a
  project's namespace after its environment's own mounts, and its KV and
  PKI mounts inside it -- the project's issuing CA signed by the
  environment's issuer the same way an environment's own CA is signed
  across a namespace hop today. Deleting a project is its mounts, then
  its namespace; OpenBAO refuses to delete a namespace with children, so
  this is never a one-step operation.
- `examples/roster` gains a project namespace, `partner`, beside its
  existing policy-path project (`orders`): its own `kv` and issuing CA,
  granted to `dev:partner:reader` by `ProjectPath`. `pkg/model/testdata/desired.yaml`
  gains one too (`billing`), beside `dev`'s own `kv` mount -- an
  environment holds its own platform mounts and its projects side by
  side; nothing forces platform data into a project.

## v0.9.0

### Added

- **pkg/model: SSH host certificates.** `Namespace.SSHHost`
  (`SSHHostMount`/`SSHHostRole`) is a host CA on a mount of its own --
  never the same key as an `SSHMount`'s user CA, because a key clients
  are told to trust for hosts must never also be one sshd trusts for
  users. A host role signs the literal domains in `AllowedDomains` (no
  `*`, no template), needs at least one of `AllowBareDomains`/
  `AllowSubdomains`, and is capped at 30 days (`hostCertMaxTTL`), always
  -- `CredentialMaxTTL` does not reach it. `pkg/apply`'s `sshHostMount`
  registers the CA and its roles the same way `sshMount` does (generated
  inside OpenBAO, only the public key exported, everything protected),
  and `Result.SSHHostCAPublicKeys` carries that public key per mount for
  a consumer to render into an `@cert-authority <domains> <key>` line.
  Who may sign a host certificate is not a new auth method: an existing
  workload login (a Kubernetes pod's projected ServiceAccount token, on a
  `jwt` mount role bound to that ServiceAccount) whose policy grants
  `update` on exactly `<host mount>/sign/<host role>`.
  `examples/roster` and `pkg/model/testdata/desired.yaml` both carry a
  worked host CA, host role and workload login;
  `conformance/roster_test.go` signs a host certificate through it
  against a real server, and refuses a name outside `allowedDomains`, a
  user certificate from the host role, and the workload login signing on
  the user mount without a grant.
- **pkg/model: `SSHRole.ForceCommand`.** A machine role may force one
  command on every certificate it signs; the apply renders it as the
  role's only `default_critical_options` entry. `Validate` refuses
  `ForceCommand` alongside `permit-pty` or a forwarding extension -- a
  forced command that can still open a terminal or forward a port is not
  forced. Existing roles that leave `ForceCommand` empty render exactly
  as before.
- **pkg/model: `Rule.DeniedParameters`.** Renders a policy path's
  `denied_parameters`, refusing a request that carries a named parameter
  at all, whatever it is shaped like -- the ACL layer refuses it before
  the secrets engine sees it. This is the only way found to make
  `ForceCommand` unconditional: OpenBAO's own SSH secrets engine applies
  `default_critical_options` only when the request's `critical_options`
  is entirely absent, and otherwise takes the request's map exactly as
  given, in place of the default; `allowed_critical_options` limits which
  keys a present map may name, but not whether the caller may present
  one at all. `Namespace.Validate` now refuses a policy that grants a
  force-command role's sign path without denying `critical_options`
  there (docs/safety.md, "A forced command that a caller can still
  replace").

### Documentation

- **docs/model.md, docs/safety.md, docs/reference.md** describe the host
  CA, the force-command role and the `denied_parameters` grant it needs,
  and the render-order trade-off in OpenBAO's SSH secrets engine that
  makes the grant necessary in the first place.

## v0.8.0

### Added

- **pkg/model: `JWTMount.SupportedAlgorithms` states what a door accepts.**
  The JWT/OIDC plugin's own default is RS256 alone for an oidc-type role
  (`all` for a jwt-type role), so an issuer that has moved to ES256 or
  ES384 was refused at login by any mount this library applied, silently:
  nothing in the model said which algorithms a door trusted. A mount may
  now name `supportedAlgorithms` explicitly; `Validate` refuses a name the
  plugin does not sign with (so no `HS*` or `none`, ever, whatever is
  named) and a name repeated. `JWTMount.Algorithms()` is the one place the
  default resolves -- `DefaultSupportedAlgorithms` (RS256, ES256, ES384) --
  and pkg/apply calls it for every mount, jwt and oidc alike, so
  `jwt_supported_algs` is now always set, never left to the plugin's own
  default.

### Changed

- **Every mount now states its algorithms explicitly.** A caller who set
  no `supportedAlgorithms` sees `jwt_supported_algs` go from unset (the
  plugin's default) to `[RS256, ES256, ES384]` on the next apply: a jwt
  mount that previously accepted any algorithm now accepts these three, and
  an oidc mount that accepted RS256 alone now also accepts ES256 and
  ES384. Nothing that only ever spoke RS256 changes behaviour. Proved by
  `conformance/roster_test.go` (an RS256 token and an ES384 token both log
  in on the same mount, and a mount that names `["RS256"]` explicitly
  still refuses ES384) and `internal/fakeissuer`, which now signs and
  publishes an ES384 key alongside its RS256 one.

### Documentation

- **`docs/integrations/access-roster.md`, `docs/team-secrets.md` and the
  README follow access-roster through `accessctl credential` and
  `accessctl secrets`'s removal (access-roster v1.34.0).** Every recipe
  now reads `accessctl bao` (SSH and any other OpenBAO call, a passthrough
  onto the real `bao` binary, its login cached and reused rather than
  revoked after each call), `accessctl pg`/`accessctl psql` (a Postgres
  client certificate, then a command), and opkssh -- the target for
  people's own SSH once an installation has moved its hosts to it, with
  the `user`/`admin` OpenBAO SSH CA roles staying supported, and modelled,
  until then. `requires`' second job -- deciding which groups a minted
  token carries, not only who may be issued one, now that access-roster's
  groups scoping can narrow it -- is spelled out where a reader would look
  for it, twice.

  **`docs/team-secrets.md` also flips its KV layout**: a repository is now
  one KV secret, every variable a FIELD of it named after the variable,
  rather than one path per variable. A read is one
  `accessctl bao kv get -format=env` call for the whole repository; a
  write is `kv put` to create it (which replaces every field, said
  plainly) and `kv patch` — including its `-remove-data`, checked against
  `bao kv patch -h` in this repository's own devbox — to rotate, add or
  remove one field without touching the others. The trade is stated
  plainly too: KV v2 still versions every rotation, now per repository
  rather than per variable.

  The discovery bullet stops claiming the issuer signs RS256 only: it
  signs several algorithms at once, chosen per audience, and both
  JWT/OIDC mounts should set `jwt_supported_algs` (`model.JWTMount`'s
  `supportedAlgorithms` field, added above) rather than rely on the
  mount's own factory default.

## v0.7.0

### Added

- **openbao-ops: the S3 presets reach any store that speaks the S3 API.**
  `snapshot.upload.s3`, `restoreCheck.fetch.s3` and every
  `snapshotAge.stores[].s3` drive the AWS CLI, which reaches AWS unless
  told otherwise, so the presets were AWS-only by omission: a caller
  whose backups sit in MinIO, Ceph RGW or Cloudflare R2 had no way to say
  so, and no way to give the jobs credentials on a store with no pod
  identity. Three values on each preset, all inert by default, so an
  existing values file renders byte-for-byte what v0.6.1 rendered:
  `endpoint` (empty keeps AWS; set, it is `AWS_ENDPOINT_URL_S3`, and the
  CLI's default request and response checksums are turned down to
  `when_required`, which a store that is not AWS may not implement),
  `pathStyle` (the bucket as `endpoint/bucket/key`; the CLI reads that
  from its config file alone, so the script writes the one line and
  `AWS_CONFIG_FILE` names it) and `existingSecret` (static keys through
  `envFrom`, so a session token is carried too). An `endpoint` that is
  not an `http(s)` URL is refused at render time. The upload's
  `--checksum-algorithm SHA256` is unchanged and still sent. Proved by
  `conformance/watch_test.go`: the list container is run against a
  stand-in for the CLI, which must be handed the file the script wrote.

### Fixed

- **openbao-ops: a limit under an hour prints in minutes.** The
  job-success and snapshot-age watches printed every span in whole
  hours, so the root-generation watch's thirty-minute limit read as
  "last succeeded 0h ago, under the 0h limit" — an impossible bar.
  Minutes under an hour, hours above, in the report and the alert
  alike. Cosmetic; no values change.

## v0.6.1

A value is data. `charts/openbao-ops` rendered several of a values file's
strings straight into the shell scripts its jobs run, and Helm's `quote`
is a DOUBLE-quoted string — so a value carrying a backtick or a `$(` was
EXECUTED by the container that was meant to print it.

Found in an install, not in a review: a runbook that said to cancel a
ceremony with `bao operator generate-root -cancel` — backticks being the
ordinary way to write a command — ran `bao` inside the alert container,
where there is no `bao`. The command failed, and the one sentence that
says how to stop what the alert is reporting never reached the alert.

- **`charts/openbao-ops`**: every value a script uses is now either a
  single-quoted shell WORD (the new `ops.shellArg`) or an environment
  variable, which a shell never looks at twice. That covers a store's and
  a CronJob's `description`, `clusterName`, `prefix`, `name`, a bucket, a
  topic ARN, an Alertmanager URL, the JWT mount and role the root watch
  logs in as, and — in both presets and in `certificateExpiry` — the
  `runbook`, `alertname`, `severity` and `release`. The Alertmanager body
  is built in a heredoc that expands, so its values arrive through the
  environment and go out through the same JSON escaper the alert's own
  words already used.
- **`charts/openbao-ops`**: `certificateExpiry`'s SNS message is handed to
  the CLI as a FILE, as every other alert here already was. It was the
  last one built as a shell argument.
- **`conformance/watch_test.go`**: `TestValuesAreNeverRunAsShell` renders
  the watches with the values a person really writes — a command in
  backticks, a path in `$( )` — plus a marker that leaves a file behind if
  anything evaluates it, runs the scripts, and looks for the file. Against
  the previous release it fails, and the file is there.
- **`conformance`**: the harness now runs each script with the environment
  its container declares. A test that ran the command without it was
  running something the pod never runs.

## v0.6.0

The failures an install dies of that nothing was looking
at: a store with no fresh backup in it, a job that has quietly stopped
succeeding, and a root token being generated. Three watches in
`openbao-ops`, all off by default -- an existing values file renders
byte-for-byte what v0.5.0 rendered -- and nothing in `pkg/apply`,
`pkg/ceremony`, `pkg/custody`, `pkg/model` or `openbaoctl` changes.
Beside them, a guide to a team's shared secrets on one KV prefix, and the
grants and conformance case that prove it.

- **`charts/openbao-ops`**: `snapshotAge` asks the STORE, not the snapshot
  job, whether there is a fresh backup in it: one `list` container per
  store writes the newest object's name, a `check` container reads the
  `<taken-at>` out of it -- the name the upload contract gives an object --
  and reports every store that is over its own limit. Several stores is
  also how replication is watched: a copy that stops getting newer is a
  stalled replication seen from the data's side, and needs a listing
  rather than a metric the object store has to publish. The `s3` preset
  lists one prefix and reads no object, which is less than the snapshot
  job's write and less than the restore check's read.
- **`charts/openbao-ops`**: `jobSuccess` reads `status.lastSuccessfulTime`
  of the CronJobs it is given, granted by name in its Role. Not "did one
  fail": a CronJob that stops being scheduled -- suspended, orphaned,
  deleted with the release that owned it -- never produces a failed Job,
  and that is the case this sees. An estate with a metrics pipeline gets
  this fleet-wide and should prefer that; this is for one that has none.
- **`charts/openbao-ops`**: `rootGeneration` reads
  `sys/generate-root-token/attempt` as a role whose policy is that one
  read, and reports an attempt that is open, with `generate-root -cancel`
  as the way back. It is the logical path, not the unauthenticated
  `sys/generate-root/attempt` that `bao operator generate-root -status`
  uses and that OpenBAO 2.6 does not answer -- so the watch needs no root
  token, no recovery share and no unauthenticated endpoint. It sees an
  attempt while it is OPEN, which the ceremony's own pace makes the common
  case; a completed one is recorded in the audit device and nowhere else.
- **`charts/openbao-ops`**: one alert contract for all three
  (`/work/alert`: the first line a summary, the rest the description),
  with the same `sns` and `alertmanager` presets `certificateExpiry`
  ships, so an estate configures one channel and not three. A probe never
  fails the pod -- a store it cannot list, an API that refuses, a role
  that was taken away each become an alert rather than a crash, because an
  initContainer that exits non-zero takes the alert container down with
  it. Fourteen new refusals, each with a fixture.
- **`conformance/watch_test.go`**: every script the watches render is RUN.
  The snapshot check over fabricated listings (fresh, stale, empty,
  unlistable, and an object whose name carries no `<taken-at>`); the list
  preset against a stand-in for the CLI, including the failure it must
  turn into an answer; the job read against a stand-in for kubectl,
  including a suspended CronJob that every other signal calls healthy; and
  the root watch against a real `bao server -dev` behind a real JWT login,
  with an attempt really opened and the policy really taken away.
- **`docs/team-secrets.md`**: a team's shared development credentials on
  one KV prefix, as three grants of the access-roster contract -- the
  project's viewer reading `kv/data/<project>/*`, its deployer and
  approver writing it, and a repository as a path segment inside it. The
  paths, the four calls a person's fetch makes, rotation, what revocation
  at the issuer does and does not reach, and why production values are
  not what the pattern is for. `examples/roster` gains the three groups,
  so the prefix a reader copies is one that is applied to a server.
- **`conformance/roster_test.go`**: the guide, executed. A deployer writes
  a secret and a viewer reads that value back and lists the names; the
  viewer's write is refused; a read outside the prefix is refused and a
  missing path inside it is a 404, which is how the two are told apart; a
  rotation is picked up by the next read; and the same person without the
  group, with no groups, and with a group name OpenBAO was never told
  about logs in every time and is refused the read every time. A tutorial
  that has never executed is a tutorial that lies.
- **`docs/doctrine.md`**: what a watch is for, the three rules they share,
  the new container contracts and presets, and what a watch does not
  replace -- a metrics pipeline, or the audit device.

## v0.5.0

Not yet tagged. What a consumer with one cluster and no SNS needs: a
second alerting implementation, the seal's cost written down, the
single-cluster path, and a one-environment model example. `openbao-ops`
renders exactly what v0.4.0 rendered unless the new preset is turned on,
and nothing in `pkg/apply`, `pkg/ceremony`, `pkg/custody` or `openbaoctl`
changes.

- **`charts/openbao-ops`**: `certificateExpiry.alert.alertmanager`, a
  second implementation of the alert contract beside `sns`. It posts one
  alert to `<url>/api/v2/alerts` with the labels the consumer sets
  (`alertname`, `severity`, `release`), a `runbook` annotation, and
  cert-manager's Ready message escaped into the body; it carries its own
  image, because `alert.image` defaults to the AWS CLI. New refusals,
  each with a fixture: no `url`, a `url` that is not an `http(s)` origin,
  and both presets at once.
- **`conformance/`**: the alert contract is now proved by running it.
  Both presets are rendered and their container's own script executed
  over a `/work/status` inside and outside the window -- the SNS one
  against a recording stand-in for the CLI it publishes with, the
  Alertmanager one against a webhook that really receives the post. The
  dev shell pins `curl` for it.
- **`docs/server.md`**: what `seal "awskms"` costs. Each replica
  round-trips `Encrypt`+`Decrypt` against the key on a timer; measured on
  a five-replica cluster, about 960 KMS requests a day, ~192 per replica.
  `replicas: 3` is the reference for that reason as well as quorum.
- **`docs/adoption.md`**: a **Single cluster** section -- one cluster is
  one token issuer, where each mount of that one door lives and why, the
  values both charts give the same name, the two charts as one sync-wave
  sequence, and what has to happen between the waves.
- **`pkg/model/testdata/desired-one-env.yaml`**: the small example --
  one environment on the cluster that runs the server -- which
  [model.md](docs/model.md) now opens with, the two-environment file
  staying as the whole shape. `conformance/` applies it to a real server
  through the same capture-and-replay path as the roster example.

## v0.4.0

The access-roster integration becomes one documented, tested contract.
Both charts render exactly what v0.3.0 rendered, and nothing in
`pkg/apply`, `pkg/ceremony`, `pkg/custody` or `openbaoctl` changes.

- **`docs/integrations/access-roster.md`**: the contract end to end --
  what the issuer must provide (discovery, `iss`, a flat `groups` claim,
  the `openbao` exchange client and the `openbao-ui` confidential client,
  and why their `requires` match), the `jwt-roster` and `oidc` doors and
  `namespace_in_state`, groups to identity groups to policies, the
  operators' door, the paths and key types `accessctl credential` uses,
  CI jobs, and every failure mode with its status and exit code.
- **`pkg/model`**: `Roster` and `RosterUI`, a preset for an issuer shaped
  like access-roster's: `Door`, `UIDoor`, `Doors` and `DoorPaths` build
  the two auth mounts, `Grant` and `JobGrant` a policy named after a group
  with the group admitted through the right doors, `Identity` the identity
  settings, `Bootstrap` and `RootUI` the operators' door; `OperatorPolicy`,
  `UICallback` and the default names as constants. Additive: no existing
  type changes.
- **`examples/roster`**: a neutral, whole server built with the preset
  (operators' door, one environment with SSH and database credential
  roles, a reader and a CI job's read), with its golden `desired.yaml`.
- **`conformance/`**: a test that applies what `pkg/apply` registers for
  that example to a real `bao server -dev`, trusting a fake issuer, and
  proves login -> policy -> `ssh/sign` and `pki/sign`, the UI's code flow
  across namespaces, a CI job's one read, and the refusals. The dev shell
  pins `openbao` for it; `just test` requires it.

## v0.3.0

OpenBAO's own configuration arrives as a model and its apply; both charts
render exactly what v0.2.0 rendered, and nothing in `pkg/ceremony`,
`pkg/custody` or `openbaoctl` changes.

- **`pkg/model`**: OpenBAO's desired state per namespace and engine -- KV
  v2 mounts with a restore canary, JWT and OIDC auth mounts with workload
  roles (a bound ServiceAccount subject) and people roles (an issuer's
  groups claim), identity groups with one identity group per door, ACL
  policies, PKI mounts whose issuers are self-signed, signed by an issuer
  of an earlier mount or signed outside OpenBAO, host-name and credential
  roles, and SSH user CAs with their roles. The namespace tree is one
  level: root and one namespace per environment. The types carry yaml
  tags; `Validate` refuses a state that could not be applied as it reads
  (docs/safety.md lists every refusal). `KVLayout` is the writer/reader
  contract of a KV mount's keys. No loader and no configuration format.
- **`pkg/apply`**: `Deploy` converges a server onto a model with the Pulumi
  vault provider: it validates, runs `BeforeApply` on an apply only, logs
  in with a JWT whose token it fetches afterwards, and registers every
  resource on the caller's context, never the bootstrap door it logs in
  through. CA keys, certificates, issuers, mount configuration, SSH engines
  and credential roles are protected; every signature waits for its signer
  mount's URLs. Resource names follow a fixed scheme (docs/model.md) that
  never changes in a minor, and `Options.Rename` keeps a running
  configuration's own names, so adoption previews empty.
  `SnapshotJob` is the pre-apply snapshot from `openbao-ops`' CronJob;
  `NewProvider` logs another program in the same way.

## v0.2.0

The Go module and `openbaoctl` arrive; both charts render exactly what
v0.1.0 rendered.

- **`pkg/ceremony`**: the CA ceremony with the root key in AWS KMS (P-384,
  `ECDSA_SHA_384`). The root's self-signature (or the import of an
  existing root), domain intermediates signed from an OpenBAO-held key's
  CSR in two steps (the template and its SHA-256, reviewed offline; then
  the signature, only for that hash), and a break-glass server leaf
  straight from the root. Every signature is reserved by an `.attempt`
  file first and never repeated; every result is proven and recorded as a
  public artifact. `LoadSignedIntermediate` proves a committed
  intermediate and returns the chain OpenBAO's `set-signed` takes.
  Deterministic serials are derived under `SerialNamespace`.
- **`pkg/custody`**: the root key's custody as a Pulumi Go module: per
  generation a protected, retained multi-region P-384 key and replica with
  aliases; a key policy that separates break-glass recovery,
  administration without signing or deletion, and ceremony read/sign
  (`kms:SigningAlgorithm`); the admin and ceremony roles; and a Sign alarm
  (CloudTrail → EventBridge → SNS, plus a CloudWatch alarm) in each region.
  Resources register on the caller's context, so existing custody is
  adopted with an empty preview.
- **`pkg/kmssigner`**: a `crypto.Signer` over a KMS P-384 key.
- **`openbaoctl`**: `pki create-root`, `pki sign-intermediate`,
  `pki verify-intermediate` and `pki sign-emergency-server`, from a
  hierarchy file.

## v0.1.0

The first release.

- **`openbao-ops`**: snapshots verified against their own `SHA256SUMS`
  before they are stored, in retention tiers; a weekly restore check that
  restores the newest snapshot into a throwaway server under the
  production seal, logs in as the snapshot's own identity, reads a canary
  in every namespace (listed, or every one the copy lists) that must name
  its own namespace, and fails on a stale snapshot; optionally the same
  check walks the restored PKI from a committed root to every namespace's
  issuing CA, proves the role's refusals and issues a fresh leaf in each
  (`restoreCheck.pki`); a daily serving-certificate expiry check that
  alerts before the end (`certificateExpiry`, SNS preset); network
  policies, with isolated pods and egress rules of any kind; a serving
  certificate with generated SANs, or the endpoint alone for a
  name-constrained chain (`serviceDnsNames: false`), verified by the jobs
  through `server.tlsServerName`; the `tlsReload` sidecar fragment for the
  upstream chart.
- **`openbao-consumers`**: reader ClusterSecretStores bounded by namespace
  conditions, writer stores that present the writer's own
  ServiceAccount token, cert-manager issuers backed by OpenBAO's PKI (one
  per signing path, with extra token audiences), trust anchors distributed
  by a trust bundle that carries every root, and certificates.
- Object storage and alerting as container contracts, with S3 and SNS
  presets. Every object name is a value and nothing carries Helm's own
  labels, so objects rendered by other means can be adopted in place.
