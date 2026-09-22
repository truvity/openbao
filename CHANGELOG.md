# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. Both charts are released at every version, and
from v0.2.0 on the Go module and `openbaoctl` with them.

## Unreleased

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
