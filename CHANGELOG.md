# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. Both charts are released at every version, and
from v0.2.0 on the Go module and `openbaoctl` with them.

## Unreleased

### Added

- **`pkg/esoaws`: External Secrets reading AWS Parameter Store in another account**, with each cluster in exactly one `IdentityMode` (no default; the two are mutually exclusive). `PodIdentity`, for EKS: `NewClusterIdentity` makes the External Secrets controller's Pod Identity role in the cluster's account, which may only assume the listed reader roles (exact ARNs). `WebIdentity`, for any cluster whose ServiceAccount issuer AWS can reach: nothing ambient; `NewReaders` registers the cluster's issuer as an IAM OIDC provider (or takes an existing one), and each reader role trusts one ServiceAccount's tokens (`sub` and `aud`). `NewReaders` makes one reader role per grant in the parameters' account, reading exact parameters or prefixes (`GetParametersByPath` on prefixes only), with `kms:Decrypt` through SSM only when the parameters use a customer-managed key; the default `aws/ssm` key needs no grant, because the read happens inside the parameters' account. Every trust that allows `sts:TagSession` admits only EKS Pod Identity's tag keys, and an inline policy over IAM's 10,240 characters is refused before anything registers. Outputs: `ClusterIdentity.RoleARN`, `Readers.RoleARNs` by grant and `Readers.OIDCProviderARNs` by cluster. See [docs/esoaws.md](docs/esoaws.md).
- **`openbao-consumers`: `awsStores`**, one `ClusterSecretStore` per (cluster, grant) on AWS Parameter Store, in the one mode `aws.identity` names (required with `awsStores`, no default). In `podIdentity` mode, a store carries the grant's reader `role` and no auth. In `webIdentity` mode, a store carries `auth.jwt.serviceAccountRef` (name and namespace, the only auth shape), and the chart renders that ServiceAccount, annotated with the role, unless `serviceAccount.create: false`. A store that does not match the mode is refused. It needs no `server` or `caBundle`. Store names share one namespace with `stores` and `writers`.
- **`openbao-consumers`: `aws.admissionPolicy`**, on by default in `podIdentity` mode (Kubernetes 1.30+). It refuses an AWS `SecretStore`, `ECRAuthorizationToken` or `STSSessionToken` with no auth of its own, which would borrow the controller's AWS identity, and an AWS `ClusterSecretStore` that is not one of the release's. Proved by `just admission-conformance` against External Secrets' CRDs. Turn off the upstream chart's `rbac.aggregateToEdit` and `rbac.aggregateToAdmin` as well ([docs/safety.md](docs/safety.md#an-aws-identity-any-namespace-can-borrow)).
- **`openbao-consumers`: store conditions must select something.** The schema now refuses an empty condition, an empty `namespaces` list and an empty `namespaceSelector`, and the render refuses a `namespaceRegexes` entry that matches every namespace. This applies to `stores` as well as `awsStores`. Every condition that selects specific namespaces renders as before; `awsStores` take no regexes at all.

## v0.37.0

### Changed

- **`openbao-ops`: the snapshot upload is one PUT up to 1GB** (`snapshot.upload.s3.multipartThreshold`, default `1GB`; the AWS CLI's own is 8MB). A snapshot that grew past 8MB became a multipart upload, which into an SSE-KMS bucket also needs `kms:Decrypt` on the key, and a write-only backup role got `AccessDenied` on `UploadPart`. Empty keeps the CLI's default.
- **`awsserver.SnapshotPolicy` grants `kms:Decrypt` on the backup key**, which S3 needs for a multipart upload into an SSE-KMS bucket, so a snapshot above the threshold no longer fails on `UploadPart`. The role still reads no object (no `s3:GetObject`). The backup key's policy already admits the writer role for `kms:Decrypt`.

## v0.36.0

### Added

- **`estate.Ops*` constants and `estate.OpsJobs`**: the ServiceAccount names, snapshot prefixes and limits `charts/openbao-ops` defaults to, as Go constants held equal to the chart's `values.yaml` by a test, and `Jobs` for the chart's jobs as shipped. An estate that runs the chart as shipped passes none of them as values and states none of them in code.

## v0.35.0

### Added

- **`estate.PKI.Issuer`, `SharedLoginIssuer`, `IdentityIssuer`, `IdentityEnvironmentSigned`, `IdentityEnvironmentCA`**: the consumer's view of the private PKI. What a cluster's cert-manager needs per trust domain (the ClusterIssuer, its sign path on the issuing mount, the login role, the extra audience of a shared login, and the certificate policy of the role it signs through, read from the contract) comes from the inputs the server's side is derived from, and the identity domain's issuer and CA bundle wait for the environment's own signed CA. Also `estate.CertManagerAudiencePrefix`.
- **`estate.ConfigOutputs`**: the configuration stack's public outputs as an estate commits them, with `Validate`, `ValidateSSHKeyTypes`, `SSHUserCAPublicKey`, `SSHHostCAPublicKey` and `Ready`.
- **`estate.Writer.Validate`**: the shape rule `Build` applies to writers and exporters, for an estate that wants it to fail at load and test time.
- **`model.RosterClientSecret`**: the name of the Secret the issuer delivers for one of its confidential clients.

## v0.34.0

### Added

- **`builder.CISecretGrants`**: the CI job secrets' path grammar and policy naming. A map of secret path to the groups that read it becomes the sorted single-secret `SecretGrant`s `Environment.Secrets` takes, with each policy named by `builder.CISecretPolicy` (`ci/goreleaser` is `ci-goreleaser`); it refuses a path that is not `<prefix>/<key>` of lower-case segments, a path nobody reads, and two paths that derive one policy name.

## v0.33.0

### Added

- **`serverpreset.Config.ApplyHA`**: the reference HA shape in one call: the API, cluster and metrics listeners, Raft retry-joining every pod by name through the headless Service, the Kubernetes service registration, the declarative audit device and standby reads off. Also `serverpreset.AuthAWSPlugin(version, sha256ByArch)` (the aws auth method's catalog entry), `ZoneSpread(release)`, `PodName`, and the port, path and name constants they use.

### Changed

- **`ServerValues` gives the tls-reload sidecar the Pod Security "restricted" container context** when `TLSReload.SecurityContext` is nil (it named none, which failed `restricted` on that one container).

## v0.32.0

### Added

- **`pki.Contract.TrustBundlePEM`**: the trust bundle every client of the private services verifies against, one PEM CERTIFICATE block per trusted generation in the authored order; an empty set is an error.
- **`pki.Contract.VerifyCustodyOutputs`**: the signing-request-free half of `VerifyCustody`, for a consumer that only reads the custody outputs.

## v0.31.8

### Added

- **`pkg/awsserver`: `NewServer`, a server's whole AWS side.** The unseal key and role, the snapshot and restore-check roles, the watches' and the certificate-expiry topics with their roles, and the endpoint record, from caller inputs, with the outputs the charts read; the backup-dependent pieces and the endpoint are skipped until what they need exists. `WithLegacyParent` adopts roles created under another component type. Moved out of the consuming repository; no resource name changes.

### Changed

- **`estate.Deploy` and `estate.OIDCClientSecret` move to `pkg/estate/stack`** (`stack.Deploy`, `stack.Options`, `stack.OIDCClientSecret`), so `pkg/estate` links no Pulumi and an estate's configuration loaders can build and review the state without the provider SDKs. `Chains`, `Chain`, `Desired.SignedChain` and the new `Desired.PrivateZone` stay in `pkg/estate`. A consumer of v0.31.7 renames the calls; nothing else changes.

## v0.31.7

### Added

- **`pkg/estate`: `Deploy`, the stack.** `estate.Deploy(ctx, &desired, opts)` applies the state through `pkg/apply` under the adopted names, loads every External issuer's chain from the ceremony's committed artifacts (`Chains`; `Desired.SignedChain` for a caller applying a trimmed model), bootstraps an identity environment CA that is not signed yet, and exports the namespaces, the trust root, the SSH CA keys and the certificate requests the ceremony signs. `estate.OIDCClientSecret` reads a delivered OIDC client secret and checks its client id. Moved out of the consuming repository; no resource name changes.

## v0.31.6

### Added

- **The presets as a Go package.** `github.com/truvity/secrets/charts/openbao-consumers/presets` embeds the three values presets (`Names`, `Raw`, `Values`), for a consumer that composes an upstream chart's values in code under its own instead of copying the file. The chart does not package the `.go` files (`.helmignore`).

## v0.31.5

### Added

- **`pkg/estate`: an estate's whole desired state from typed inputs.** `estate.Build(estate.Inputs)` derives one server serving several Kubernetes clusters -- the store logins, CI runners, host-signing workers, the management cluster's writers, exporters and service, host fleets, project grants, CI secret reads, root jobs, and the private PKI with a legacy chain beside it -- as a reviewed view (`Desired`) and as the `pkg/model` state `pkg/apply` converges on (`Desired.Model`). `Desired.LegacyResourceNames` is the rename map that adopts existing state with an empty preview, and `StoreKinds` evaluates the rules that say which store kinds a cluster runs. Every name is an input. Moved out of the consuming repository; no resource name changes. See [docs/estate.md](docs/estate.md).

## v0.31.4

### Added

- **`pkg/custody`: `Args.WithPlacements` and `Custody.Export`.** The two pieces an estate's custody stack wrote around `Deploy`. `WithPlacements` takes the generations as a contract authors them, each with its custody account, profile and trusted principal, and refuses placements that disagree (the two roles are one pair for every generation). `Export` publishes the role ARNs and each generation's alias, key ARNs and regions under the names consumers already read. No resource name changes.

## v0.31.3

### Added

- **Presets for cert-manager, trust-manager and External Secrets.** Three values files under `charts/openbao-consumers/presets/`, for the upstream charts an OpenBAO-backed cluster runs on: CRDs, metrics scraping, requests, and control-plane HA for the two cert-manager charts. Opt-in (`-f`, or Argo CD `valueFiles`), before your own values; scheduling stays yours. See [docs/presets.md](docs/presets.md).

## v0.31.2

### Added

- **`pkg/apply`: the operator-side helpers an estate's stack needs around `Deploy`.** `RosterLogin` and `RosterToken` (the operator's login into root through `accessctl token`), `RenameFrom` (an `Options.Rename` that keeps the names resources already have), `WriteCABundle` (the PEM file the provider verifies the server with) and `DeliveredSecret.Key` (one decoded key of a Secret another system delivers, read before the apply touches the server). Moved out of the consuming repository; no resource name changes.

## v0.31.1

### Added

- **`pkg/kv`: one HTTP client for a namespace's KV v2 mount.** `kv.New(addr, namespace, mount, caPEM)`, then `Login` on a JWT mount, `Read` (nil when the secret is absent, an error on a refusal), `Write`, `Revoke`. It trusts the server through the given CA bundle alone and never switches verification off. It is the estate's Pulumi programs' client moved out of the consuming repository, so one implementation serves every importer.

## v0.31.0

### Changed

- **The repository is `truvity/secrets`, and the Go module path moves with it: `github.com/truvity/secrets`.** The repository was `truvity/openbao`; it becomes the home of the secrets concern (OpenBAO now; cert-manager, trust-manager and External Secrets presets are planned, see the README). An importer changes its import paths from `github.com/truvity/openbao/...` to `github.com/truvity/secrets/...` and takes this version; nothing else moves. Earlier versions stay resolvable under the old path. Chart names and OCI paths (`openbao-ops`, `openbao-consumers`), the `openbaoctl` and `openbao-hostcert` binaries and every Go package name are unchanged.

## v0.30.2

### Added

- **`examples/org`: the worked example, in six capability levels, each proven with no cluster.** One made-up organisation built up from level 0 (the server preset, its serving certificate and alerts) through 1 (KV per environment, a JWT mount per cluster, the External Secrets stores, snapshot and restore check), 2 (SSH user and host CAs, host certificates through the aws auth plugin), 3 (the private-PKI contract, cert-manager issuers, trust bundle, the restore check's PKI proof), 4 (a URI trust domain with a root-signed environment CA, the identity issuer, the approver layer) to 5 (a project namespace and the admission policy). A level directory holds complete `spec.yaml`, `contract.yaml` and chart values files, and each level contains the one below it. CI proves each level by contract validation, the `pkg/apply` preview under Pulumi's mocks (resources committed per level, nothing of a higher level registered, nothing below dropped or renamed), `helm template` of both charts against committed goldens (`hack/golden.sh examples`), and checks that the chart values and the desired state agree (every store and issuer logs in as a declared role, with the audience cert-manager asks for, and may sign where it signs). New `just examples` recipe and CI job; `just check` includes it. `hack/leak-canary.sh` now also holds `examples/org` to made-up names and the reserved example domains. See [examples/org](examples/org/README.md).

## v0.30.1

### Fixed

- **One serial-namespace default, named the same everywhere.** `pkg/ceremony`'s `DefaultSerialNamespace` (`private-pki`) is the only default; `pkg/pki`'s contract documentation, `docs/pki.md`, `docs/ceremony.md`, `docs/reference.md` and `docs/adoption.md` all say so, and a test pins that a contract without `serialNamespace` hands every ceremony spec an empty namespace, so no second default can appear in `pkg/pki`. An estate that adopted a root created under another prefix still sets `serialNamespace` explicitly, as before. No behaviour change.

- **The path-length rules in `docs/pki.md` and `docs/ceremony.md` say what validation enforces.** A domain intermediate is exactly one less than the root's; a CA the root signs directly for leaves alone is strictly less (0 when nothing sits below it), which the hierarchy-file table had as "each layer is exactly one less than its parent". The example contract's `maxPathLen` values are annotated with the rule that fixes them.

- **"Worked example" means one thing.** It is reserved for `examples/org`; the model's and the builder's examples are called examples. The README heading `Install and a worked example` stays, because the component contract (C8) requires it. Documentation only.

## v0.30.0

### Added

- **`pkg/awsserver`: the server's AWS resources as Pulumi components, with a hook for adopting existing state.** `NewUnsealKey` (multi-region key, replica and aliases), `NewPodRole` (Pod Identity role, inline policy and association), `NewAlertTopic` (SNS topic and e-mail subscriptions), `NewBackupBucket` (versioned, KMS-encrypted, private bucket with Object Lock COMPLIANCE, resource policies and cross-region replication), `NewEndpointRecord`, and the least-privilege policy documents of the server's and the jobs' roles. Every particular is an argument. The Pulumi type and logical name of every child are documented in [docs/awsserver.md](docs/awsserver.md) and pinned by tests, because they are the child's URN; every constructor takes `WithResourceOptions(func(kind, logicalName string) []pulumi.ResourceOption)`, applied to every resource it registers, so a caller that already has the resources in its state adds `pulumi.Aliases` and the first preview is empty. KMS keys and buckets carry `Protect` and `RetainOnDelete` by default.

## v0.29.1

### Added

- **`pkg/bootstrap`: initialize a fresh server, open operator login, and retire the root token, with the secrets in the caller's custody.** `Bootstrap.Initialize` verifies a `Keeper` (write, read back, delete a canary) before it initializes, refuses a shamir seal and the stale items of an earlier install, and stores every recovery share and the root token, each read back. `Bootstrap.Configure` waits for an unsealed server with every Raft voter, refuses an unaudited server and a non-empty one (`Settings.AllowNonEmpty` says it is deliberate), and converges the operators' door (the roster JWT mount, the operator policy and an external identity group, via `model.Roster.Bootstrap`). `Bootstrap.RevokeRoot` refuses until an operator login is proven (`Bootstrap.OperatorJWT`: a real login that must return the operator policy; without it, a group member on file), reconstructs the recovery key from the shares with every share submitted at least once, revoking each generated token at once, and only then revokes the bootstrap token and archives its item. `RestoreDrill` is the rebuild drill's scratch pod (start, forward, stop), `PortForward` reaches a pod that is not ready yet through `kubectl port-forward` with TLS verified. The package never persists or logs a secret: shares and tokens are `[]byte` zeroed after use, errors are scrubbed of every secret seen, and `Keeper` is an interface the caller implements; `pkg/bootstrap/filekeeper` is an age-encrypted file reference. The estate's facts (share split, voters, audit device, issuer, group) are inputs with documented defaults. See [docs/bootstrap.md](docs/bootstrap.md) for the threat model, the secret flows and the invariants with the tests that prove them.

- **`openbaoctl init | configure | revoke-root | drill start | forward | stop`.** The reference command over `pkg/bootstrap` with the file/age keeper. The recovery shares are never printed unless `init --insecure-print-recovery-shares-to-stdout` is given (a warning goes to stderr; the root token is never printed); `revoke-root` needs `--operator-jwt-file` (a login proof) or the explicitly weaker `--membership-evidence-only`; TLS is always verified and there is no insecure flag. The client never follows a redirect, a cancelled context (Ctrl-C) still cancels a pending root generation and revokes a drill token on a context of its own, and `init` records the recovery split (`openbao-recovery-split`) that later steps hold to. A conformance test (`conformance/bootstrap_test.go`) takes a real `bao server` on a static seal through init, configure and revoke-root on OpenBAO 2.6.2 and 2.7.0 in CI's `server-config` job, offline.

### Fixed

- **`pkg/bootstrap` and `openbaoctl` build on every OS.** The forward's process-group setting was tagged `!linux`, which took in Windows, where it does not exist. It is now per OS (Linux with the parent-death signal, other Unix with a process group, Windows with a new process group), and CI cross-builds the module for Linux, macOS and Windows.

## v0.29.0

### Added

- **`charts/openbao-ops`: `serverAlerts.pluginDownload` (opt-in; off, every existing render is byte for byte unchanged).** Two LogsQL alerts on the server's own log, as a `VMRule` labelled `observability.rule-type: vlogs` so a log ruler reads it: `OpenBAOPluginDownloadFailing` (a `failed to download plugin` with no `successfully downloaded and validated plugin` in the same window) and `OpenBAOPluginDownloadSidecarGaveUp` (the retry sidecar's `giving up after N attempts`). With `plugin_download_behavior = "continue"` a failed download never crashes the server and has no metric, so these are the only loud signal. `plugin` is required; the cluster label, runbook, containers and sidecar attempts are values. See the [chart README](charts/openbao-ops/README.md#serveralertsplugindownload).

- **`charts/openbao-consumers`: `pki.bundles[]`, several trust bundles beside the single `pki.bundle` (opt-in; empty by default, every existing render is byte for byte unchanged).** Each entry is one trust-manager `Bundle` with its own `name`, `annotations` (passed through as given, a GitOps controller's sync options included), inline `sources` (rendered as given, in order), `target.key` and `target.namespaceSelector`: an identity chain delivered to the namespaces that opt in by label, and the same chain to one namespace by name, since a selector matches a label or a name, not both. The schema and the render refuse an entry without a name, sources, a target key or a selector, a source that is not inline, a duplicate name, and a name `pki.bundle` owns. See [docs/reference.md](docs/reference.md).

- **`pkg/serverpreset`: `Config.ServerValues`, the complete valuesObject for the upstream openbao chart's server, and `Config.AuditDescription` (both opt-in; every existing `HCL()` and `Values()` render is byte for byte unchanged).** `ServerValues(ServerValuesOptions)` returns what `Values` leaves out: the serving Secret and the in-pod CLI pointed at it, the metrics container port, the `ui` Service (every ready pod an endpoint), `podManagementPolicy: Parallel`, the pod-security container context, no injector, CSI provider, auth delegator or audit volume, and optionally the signalling sidecar. The image, resources, placement and storage are options; the HCL is `Config.HCL()`. A test proves that for the inputs of a hand-written three-voter server the rendered values equal its values, and the HCL equals its HCL except for comments, byte for byte line by line and structurally under an HCL parser. `AuditDescription` renders the audit device's optional `description` line.

## v0.28.0

### Changed

- **The server's metrics are served on a listener of their own, and only the scraper can reach it.** `serverpreset.Telemetry.UnauthenticatedMetricsAccess` is gone (a breaking change to a v0.27.0 field; its one consumer moves with this release) and `ListenerTelemetryHCL()` with it. `Telemetry.MetricsAddress` (`"[::]:9101"`) renders a second `listener "tcp"` with the API listener's certificate whose `telemetry` block sets `metrics_only` and `unauthenticated_metrics_access`, via the new `MetricsListenerHCL()`. OpenBAO's `metrics_only` makes that listener refuse every path but `/v1/sys/metrics`, and the API listener no longer sets `unauthenticated_metrics_access`, so the metrics need a token on the API port. `Validate` refuses a `MetricsAddress` equal to the API or cluster address. `charts/openbao-ops`: new `serverMetrics.port` (default `9101`); the `serverMetrics.scraper` rule in `networkPolicy.serverIngress` opens that port only, no longer the API port (every other rule is unchanged); `serverMetrics.podMonitor.port` defaults to the container port name `metrics`, and the pods must declare it. A conformance test starts a real `bao server` with the rendered listener and checks the metrics answer there without a token and no other path does. The server's configuration is read at start, so adopting this is a roll of the StatefulSet. See [docs/server.md](docs/server.md#metrics).

## v0.27.0

### Added

- **`charts/openbao-ops`: `serverMetrics` (opt-in; off, every existing render is byte for byte unchanged), and `serverpreset.Config.Telemetry`.** `Config.Telemetry` renders the `telemetry` stanza (`prometheus_retention_time`, `disable_hostname`) and the listener's `unauthenticated_metrics_access`, so `/v1/sys/metrics` answers a scraper without a token; `TelemetryHCL()` and `ListenerTelemetryHCL()` return the two pieces. `serverMetrics` renders a `PodMonitor` that verifies the listener's certificate (CA from the serving Secret, `server.tlsServerName`), a rule in `networkPolicy.serverIngress` for the scraper (`serverMetrics.scraper`, added to the client, peer and job rules), and `serverMetrics.alerts` as a `VMRule`, `PrometheusRule` or rules file: sealed, no active node, fewer than three healthy voters, a follower behind the leader, audit log failures, p99 latency, a scrape target down, no metrics. `promtool` checks every format and unit-tests every alert. The metrics share the API's port, so the policy cannot admit the scraper to them alone. See [docs/server.md](docs/server.md#metrics).

### Fixed

- **`charts/openbao-ops`: the restore check's pod is pinned to the architecture its seal plugin checksum belongs to.** The plugin image volume resolves to the node's architecture and the init container verifies one architecture's checksum, so a restore check scheduled on a node of the other architecture failed `does not match the pinned checksum`. `restoreCheck.sealPlugin.arch` is now required with an init container (`RestoreCheckValues` renders it from `Config.Arch`) and becomes `nodeSelector: kubernetes.io/arch`; a `restoreCheck.nodeSelector` that pins another architecture fails the render. **A caller that sets `restoreCheck.sealPlugin` by hand must add `arch`.**

## v0.26.0

### Added

- **`pkg/serverpreset`: `Config.TLSReloadSidecarContainer`, and `Config.PluginVolumeSizeLimit`** (both opt-in; every existing render is byte for byte unchanged). `TLSReloadSidecarContainer` renders the one sidecar a server pod needs for both signalling jobs: a health-gated SIGHUP retry of the declarative plugin download (as `RetrySidecarContainer`), then a watch on the serving certificate's checksum that SIGHUPs `bao server` when it changes. `TLSReloadOptions` carries the image, the certificate file and its volume, the plugin volume, the retry bounds (defaults 300 s / 20 attempts / 30 s / 60 s) and optional resources and security context. `PluginVolumeSizeLimit` adds a `sizeLimit` to the plugin emptyDir that `PluginVolume` renders.

## v0.25.0

### Added

- **`pkg/builder`: the desired state's non-PKI half, derived from declarative per-engine contracts.** A platform keeps its rows and a thin adapter; the library owns what a login, a grant or an SSH role *is*. `builder.Spec` (Go, and YAML through `builder.Load`, which refuses an unknown key) names the roster, the operators, and per environment: `trusts[]` (a cluster's JWT mount and the `workloads[]` that log in on it, each a role pinned to one ServiceAccount subject plus the one policy it carries; `optional` declares a mount only if somebody logs in on it), `ssh` (a user CA whose roles each sign for one principal, a forced-command role with no extension whose sign grant denies `critical_options`, and a host CA on a mount of its own, all sharing one `shape`), `hostAuth` and `hostLogins[]` (fleets of hosts with no Kubernetes identity signing their own host certificates with an IAM instance role: one AWS auth mount, and per fleet an auth role, a host role on its own domain and the policy joining them), `grants[]` (a policy named after a group, admitted through the roster's doors, or `jobsOnly` through the first), `secrets[]` and `reserved[]` (one-secret reads held by jobs, refused inside a reserved prefix), and `projects[]` (project namespaces holding a KV mount). What a policy grants is an ordered `access`: KV `read`, `write`, `push`, one `key`, a project's `secrets` (through the project's own namespace mount if the environment declares one, its prefix in the shared mount if not), `all`, `sign`, `sign-forced`, `ca`, `canary` and raw `rules` (with `SnapshotRule`, `NamespacesRule`, `RootGenerationRule` and `PluginCatalogRule` for the system paths a job of OpenBAO's own needs). `Spec.Build` returns the validated `model.Desired` (plugins included) and the parts a review wants apart; the output is stable (mounts in declaration order, policies and groups sorted, host-login policies last), so `pki.Derivation.Apply` joins the PKI to it and a consuming estate's existing state and Pulumi resource names stay byte-identical. Additive: nothing existing changes, and `model.Roster` and `model.RosterUI` gain yaml tags. See [docs/builder.md](docs/builder.md); `pkg/builder/testdata/spec.yaml` and its golden `desired.yaml` are the worked example.

- **`charts/openbao-ops`: `restoreCheck.sealPlugin`, and `serverpreset.Config.RestoreCheckValues`** (opt-in; with it unset every existing render is byte for byte unchanged). On OpenBAO 2.7 the `awskms` seal is an external plugin, and the restore check's scratch `bao server` (the same image, the consumer's `sealConfig`) exited `unknown wrapper: awskms` because its Job had no plugin directory, no plugin and no `plugin "kms"` block. `sealPlugin` takes `directory`, `initContainer` and `sourceVolume`: the Job then runs the init container first (copy from a digest-pinned image volume, checksum-verified, atomic), mounts the plugin emptyDir into the scratch server and writes `plugin_directory` into its HCL. The schema refuses a tag-only plugin image, and the render an init container without its source volume (or the reverse) or one that installs elsewhere than `directory`. `Config.RestoreCheckValues()` renders `sealConfig` (the seal and `plugin "kms"` stanzas) and `sealPlugin` from the Config the server already uses, so the two cannot drift; `conformance` renders the chart from it. See [docs/server.md](docs/server.md#the-restore-check-needs-the-plugin-too).

### Changed

- CI runs the component-contract check in report-only mode: it reports a rule that fails and does not fail the build.

## v0.24.0

### Added

- **`openbaoctl pki`: a pre-signing custody cross-check, `--custody-outputs FILE`.** `create-root`, `sign-intermediate` (shared intermediates and, with `--environment`/`--zone`, environment CAs) and `sign-emergency-server` verify the key, role and profile they are about to sign with against the custody outputs the custody side publishes (`pki.CustodyOutputs`, `pki.LoadCustodyOutputs`, `Contract.VerifyCustody`; the file is `adminRoleArn`, `ceremonyRoleArn` and per generation `alias`, `primaryKeyArn`, `primaryRegion`, `replicaKeyArn`, `replicaRegion`, `ceremonyRoleArn`) and the contract, offline, before anything is reserved or signed, and refuse on the first disagreement with both sides named: outputs that contradict themselves (one role for both jobs, a replica that is not the primary's key, a key outside the roles' account, a non-multi-region key), an authored generation that is not published or a published one that is not authored, a key account, primary region or replica region that is not the contract's, a signing key (`--key-arn` or the root artifact's) that is not the generation's published primary, a `--role-arn` that is not the published ceremony role, an `--aws-profile` that is not the contract's `custody.profile`. `--role-arn` and `--aws-profile` may now be omitted with the check: the published role and the contract's profile are used. What was verified is printed with `--print-template` (which needs no credential; the rerun line repeats the flag) and with the signing result. The template hash flow is unchanged. See [docs/pki.md](docs/pki.md#the-custody-cross-check).

### Changed

- **Behaviour change, `openbaoctl pki` with `--contract`**: the custody cross-check is required. Signing (`create-root`, `sign-intermediate`, `sign-emergency-server`) with `--contract` and neither `--custody-outputs FILE` nor `--skip-custody-check "<reason>"` is refused, because a contract always declares custody; `--print-template` runs the same check, so it is refused too. Pass the custody outputs, or the reason (printed with the review and logged as a warning). `--hierarchy` declares no custody and is unchanged; both new flags are refused with it.

## v0.23.0

### Added

- **`pkg/serverpreset`: the OpenBAO 2.7 seal as an external KMS plugin** (`Seal.Plugin`, `serverpreset.SealPlugin`; nil keeps the 2.6 rendering byte for byte, and `examples/server/values.yaml` is unchanged). OpenBAO 2.7.0 no longer builds the `awskms` seal in, and a seal cannot wait for the server to be Ready, so the plugin is installed before `bao server` starts: the render adds the `plugin "kms" "awskms"` block, `plugin_directory`, and (default `DeliveryInitCopy`) an init container, run from the server's own image, that copies the binary out of a digest-pinned plugin image mounted as a Kubernetes image volume into the plugin directory (atomic, executable, checksum-verified when `SHA256ByArch` is set). The kubelet pulls the image, so the pod needs no registry egress and there is no runtime download or startup race; `SealPlugin.Image` is where an adopter names its own mirror or pull-through cache. `DeliveryPreinstalled` renders only the HCL for a binary baked into an image. New `Seal.Endpoint` (a VPC endpoint; `EgressDomains` names its host) and `Config.ServerVersion` (a guard: 2.7 or later with a seal and no plugin is refused, a plugin below 2.6 is refused). `Validate` refuses a seal plugin that cannot be satisfied at startup: a relative plugin directory, a tag or no digest, no copy image, a `kms` entry in `Plugins`, and a server below 2.7 with no checksum for `Arch` (2.6 refuses a manually installed plugin without one). New `Config.SealPluginCommand`, `SealPluginSourceVolume` and `SealPluginInitContainer`, and `examples/server` `Config27`/`Values27` with a `values-2.7.yaml` golden. **`just rehearse-seal-plugin`** (`OPENBAO_SEAL_REHEARSAL`, Docker 28+, not part of `just test`) boots real servers from the exact rendered HCL on a network with no route out and the KMS emulated: cold start, container and pod restart, 2.6.3 running the same plugin, a three-voter cluster rolled 2.6.3 to 2.7.0 one node at a time with quorum checked after each, a standby reverted, and a full restart, all unsealing unaided. docs/server.md has "The seal as a plugin (OpenBAO 2.7)" (why an init container and not an image volume at the plugin directory, a download, or `bao plugin init`; what the render refuses; the other 2.7 removals against this repository) and the runbook "2.6 to 2.7 with the KMS seal plugin" (snapshot first, standby first, stop at the first pod that is not Ready, revert). docs/trust/hierarchy.md gains the seal key and seal plugin trust note, and docs/trust/status.md a row.

### Changed

- The `conformance/server_preset_test.go` server boots single-node Raft instead of the `file` storage backend, which OpenBAO 2.7 removes; the test proves the same three faults on 2.6 and 2.7.

## v0.22.0

### Added

- **`charts/openbao-consumers`: `approverPolicy.extraPolicies[]`** (default empty; the default render is byte-for-byte unchanged). `approverPolicy` rendered a policy only for issuers in `pki.issuers` and demanded a dnsNames/uris/ipAddresses/emailAddresses shape. An entry now names any issuer directly (`issuerRef` group/kind/name: a SelfSigned or CA `Issuer`, a `ClusterIssuer` not backed by OpenBAO), with `allowed` (commonName, so a commonName-only policy works, dnsNames, uris, ipAddresses, emailAddresses, usages, isCA), `constraints` (private key, durations), `selector.namespace` (`matchNames` or `matchLabels`), and optional `syncWave` and `annotations`. Each gets its own `ClusterRole` and binding for `use`, named `<roleName>-<name>` (or the entry's `roleName`), at the wave before the policy. No defaults are applied. Missing `issuerRef`, an `allowed` that names nothing and a `spiffe:` URI fail the render. `approvercheck` evaluates the rendered policies like any other. See [docs/approver.md](docs/approver.md#the-policies).

- **`pkg/pki` is the single PKI contract, and derives the desired state.** `Contract.Derive` turns a validated contract plus the per-environment facts it cannot author (`Environment`: each trust domain's `{zone}` value, the names of any `catalog` role, the URI domains whose root-signed CA is not committed yet) into every domain intermediate, issuing CA, leaf role and credential role, and `Derivation.RootMounts` / `EnvironmentMounts` / `Apply` put them into a `model.Desired` (a mount the state already holds keeps its own settings and gains the derived issuers and roles). Additive, schema version unchanged (a v1 file validates and derives as before); the new optional fields: `domainMount`, `issuingMount`, `domainMountDescription`, `issuingMountDescription` and `issuingCA.commonNameSuffix` on either kind of trust domain (the mounts an estate already deployed, and what they are called); `credentialRoles[]` on a DNS domain (roles that sign a caller's own CSR: `subjectMount`, `cnValidations`, `usage`, `keyCurve`, `lifetimes`); and for a URI domain `domainIntermediate` and `lifetimes.domainIntermediate` are optional when every environment has its own root-signed CA (no shared intermediate), `rootSignedEnvironments` may then be omitted, and `environmentCA.issuerNamePattern` names each environment CA's issuer. `pki.LoadFS(fsys, name, dir)` reads a contract, its committed artifacts included, from an embedded file system; `Contract.IntermediateSigned` and `LoadSignedIntermediateAt` complete it, and `ceremony.ParseRootArtifact` / `ParseIntermediateArtifact` read an artifact from bytes. `URITrustDomain.IsRootSigned` and `URIRole.URISAN` are the accessors. See [docs/pki.md](docs/pki.md#deriving-the-desired-state).

- **`approvercheck`: `--certificates`, repeatable `--policies`.** `--certificates FILE` (with `--namespace`) reads cert-manager `Certificate`s and checks the `CertificateRequest` cert-manager would create for each, offline, so a tenant that does not exist yet (a CI namespace that mints its own Issuers under a fresh name) is proven before it runs; `--policies` may be given more than once, for a set rendered in pieces. The package gains `LoadCertificates`, `RequestsForCertificates` and `LoadPolicyFiles`. Every existing invocation behaves as before.

### Fixed

- fix(model): identity and auth stand alone. `identity.primaryDoor` is required only when some namespace declares a group (it only names identity groups); a desired state with none validates without it. A `jwt` mount may name its keys by `jwksUrl` or static `validationPubkeys` instead of `discoveryUrl` (exactly one of the three, as OpenBAO takes them; an `oidc` mount still needs `discoveryUrl`), with an optional `boundIssuer` that defaults to the discovery URL. Every existing configuration validates and applies byte-for-byte as before.
- fix(pki): a contract without trust domains does not force alerting or DR. With no trust domain, `signAlerts.notify`, `migration.trustedGenerations`, the four `alerts.thresholds` and `disasterRecovery` may be left out (anything stated is still validated; `alerts.enabled` still may not be `true`). With any trust domain every one is required exactly as before. `pkg/custody`: an empty `Generation.ReplicaRegion` now creates the primary key alone (no replica, replica alias, or second-region sign alert); a set one behaves exactly as before, and a replica region equal to the primary is still refused.
- fix(serverpreset): validate listener and raft; cross-check plugin versions. `Config.HCL()` and `Config.Values()` now refuse an empty `Listener.Address` (was rendered as `address = ""`), Raft peers with no `Path` or a peer with no `LeaderAPIAddr`, and a Config with no storage block; the new `Config.ExternalStorage` is the explicit alternative for a backend configured elsewhere. A complete Config renders byte-for-byte as before (the example's golden is unchanged), and `PluginHCL`, `SealHCL`, `EgressDomains` and the retry sidecar validate as before. New opt-in `Config.CheckMounts(desired)` cross-checks the two plugin registration paths: a mount's pinned plugin version must be a declarative plugin's `Version`, and an unpinned mount needs a `Desired.Plugins` entry.
- fix(charts): restore-check and PKI auth mount stand alone. `openbao-ops` `restoreCheck.loginOnly` (default `false`): with `canary` and `pki` both off, the check refuses to render as before unless `loginOnly: true`, which accepts the login to the restored copy as the whole proof (an install with no KV mount and no PKI); `sealConfig` stays required, because a snapshot opens only under the seal that wrapped it. `openbao-consumers` `pki.authMountPath` (default empty, meaning `auth.mountPath`) is the auth mount the cert-manager issuers log in on, so it can differ from the stores'. Every existing render is byte-for-byte unchanged (all goldens).

## v0.21.0

### Added

- **The approver layer for OpenBAO-issued certificates.** cert-manager's built-in blanket approver approves every request, which turns a certificate's identity into decoration; switching it off needs something else to approve, proven first. Three pieces, one guide ([docs/approver.md](docs/approver.md)):
  - **`cmd/approvercheck`** and **`pkg/approvercheck`**: an offline port of approver-policy v0.28.0's evaluator (selector, allowed, constraints, and the RBAC check as a read-only `SubjectAccessReview`), fail-closed on every policy field it does not evaluate and on every request field no policy names. `--policies` with `--requests` checks the shape offline; `--live` lists the cluster's requests and proves the RBAC half too. `--context` picks the cluster instead of the kubeconfig's current-context (which the run now prints, since a green run against the wrong cluster proves nothing), `--identity-signer` names the signers csi-driver-spiffe owns, and `--require-blanket-approver-off` asserts cert-manager's `--controllers=*,-certificaterequests-approver`. Released as `approvercheck` archives beside `openbaoctl`.
  - **`charts/openbao-consumers`: optional `approverPolicy`** (off by default; the default render is unchanged): one `CertificateRequestPolicy` per issuer the chart creates, shaped from that issuer's entry under `approverPolicy.issuers` (allowed DNS names, URIs, key algorithm ECDSA 256 to 384 to match the P-384 default and the P-256 tolerance, durations), an optional allow-all policy for namespaced `Issuer`s, and the `ClusterRole` and binding granting cert-manager `use`. New `pki.issuers[].identity` marks the SPIFFE identity issuer, which never gets a policy: the render refuses a policy for it or any `spiffe:` URI, because csi-driver-spiffe's own approver owns that signer. An issuer with no shape, a `kind: Issuer` next to the allow-all policy, or a certificate asking for a usage its policy omits fails the render.
  - **docs/approver.md**: why the blanket approver must be off, who approves what, the policies, `approvercheck`, the cutover runbook (approver-policy first with the blanket approver still on, renew all, `approvercheck --live` exit 0, the flag off, the refusal test), and csi-driver-spiffe example values.

- **`charts/openbao-consumers`: issuance-chain alerts, format selectable** (`alerts.enabled`, off by default; the default render is unchanged). When certificate issuance breaks, workloads silently lose certificates; the chart now ships the rules that notice: `IssuanceCertificateNotReady`, `IssuanceCertificateRequestDenied` (opt-in), `IssuanceCsiDriverSpiffeUnavailable`, `IssuanceApproverPolicyUnavailable`, `IssuanceCertificateExpiringSoon`, `IssuanceCertificateRenewalOverdue`, `IssuanceCaExpiring` (opt-in) and `IssuanceMetricsAbsent`. `alerts.format` picks a `vmrule`, a `prometheusrule` or a plain rules file in a `configmap`; `alerts.labels`, `.annotations`, `.ruleLabels`, `.selector`, and per-rule `enabled`, `for`, `severity` and thresholds tune them. cert-manager exports no CertificateRequest metric and approver-policy no denial metric, so a stuck or denied request surfaces as a Certificate not Ready, and the exact denial rule and the CA-expiry rule read a metric the cluster exports itself; the gaps are in [docs/trust/issuance.md](docs/trust/issuance.md#alerts). Every format of every alerts case is parse-checked with `promtool check rules` in `just test` (`prometheus` 3.14.0, `promtool` from its `cli` output, is now pinned in the dev shell), so a render with an unparseable expression fails CI.

- **`charts/openbao-consumers`: an admission policy for namespaces at mTLS level `enforced`** (`admissionPolicy.enabled`, off by default; the default render is unchanged). A `ValidatingAdmissionPolicy` and binding (`admissionregistration.k8s.io/v1`, Kubernetes 1.30+) that, only in namespaces carrying the opt-in label (`mtls-level=enforced` by default), refuses a container that does not mount the workload-identity CSI volume (`spiffe.csi.cert-manager.io` by default), a pod on the `default` ServiceAccount, and a Service port that is not TLS (`appProtocol` in `https`, `tls`, `grpcs`, `kubernetes.io/wss`; a gateway-fronted Service opts out by annotation or allow list). Pods and the pod templates of Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs and CronJobs are both checked, so a bad workload fails at apply time. `failurePolicy: Fail`; `validationActions: [Warn, Audit]` is the dry run; a per-object annotation with a non-empty reason is the only exemption. Proved on a real API server by `just admission-conformance` (kind), see [docs/trust/workload-identity.md](docs/trust/workload-identity.md#the-admission-policy).

### Fixed

- fix(apply): BootstrapEnvironmentCA names match Deploy's (with aliases from the old names). The mount is now registered as `<namespace>-<mount>` (slashes become `-`; the bare mount path in root) and the certificate request as `<KeyName>-csr`, exactly what `Deploy` derives, so moving from phase A to phase B creates and deletes neither. `ResourceName` is now optional: a stack already created under the old scheme (mount `<ResourceName>-mount`, request `<ResourceName>`) keeps setting it, and those names become Pulumi aliases, so the state moves to the new names in place. New `Rename` option takes the same `Options.Rename` given to `Deploy`.

### Changed

- **Behaviour change, `charts/openbao-consumers`**: `certificateDefaults.privateKey.size` now defaults to `384` (ECDSA P-384, was `256`), so a new adopter's first certificate is accepted by the P-384 leaf roles. An installation that relied on the P-256 default sets `certificateDefaults.privateKey.size: 256` itself (or per certificate); P-256 still signs, see the next item.
- **Leaf PKI roles accept P-256 as well as P-384** (`apply.LeafKeyBits`, new): OpenBAO reads an EC role's `key_bits` as a minimum, so a P-384 leaf role is now written with `key_bits` 256 and signs both curves (checked against a real server in `conformance/leafkeys_test.go`). A P-256 role is unchanged, a P-521 role keeps 521, RSA is still refused, credential roles (`model.CredentialRole`) keep their exact curve, and CA keys are still generated at the contract curve's size. The next apply updates every P-384 leaf role's `key_bits` in place (no replace).
- Documentation only: ADR 0002's promised CI check that the blanket approver is off is now `approvercheck --live --require-blanket-approver-off`; the reference table states the `certificateDefaults.privateKey` default as ECDSA 384; the namespace tree is `<environment>/<project>` everywhere (README, safety); the doctrine counts four silent-failure watches; `awsAuth[]` plugin registration is documented as declarative-in-server-config for an OCI-downloaded plugin (`Desired.Plugins` only for a binary already on disk); ADR 0002 is marked superseded for the CA shape by the per-environment identity CAs in docs/pki.md; the `openbaoctl pki --contract` flags are in docs/reference.md; the README states plainly that AWS KMS is used only for the auto-unseal and the offline root signer, and drops a stale consumer row.

## v0.20.0

### Added

- **`charts/openbao-ops`**: a fourth watch, `pluginCatalog`, complementing
  the three that shipped in v0.6.1. OpenBAO downloads an external plugin
  declaratively at startup, and `plugin_download_behavior = "continue"`
  (the default) lets the server start anyway when that download fails --
  the plugin simply missing until something retries it, and silent until
  a mount tries to use it. `pluginCatalog` re-reads
  `sys/plugins/catalog/<type>/<name>` for every entry an estate
  configures (`type`, `name`, `version`, optionally `oci` and
  `declarative`) and reports any that are missing, at the wrong version,
  or -- with `oci`/`declarative` checked -- registered by an API call
  rather than the declarative download itself. It is off by default, logs
  in the same audience-scoped, short-lived way `rootGeneration` does, and
  delivers through the same alert contract and presets as the other three.
  Reading the catalog needs a policy granting **both** `read` and `sudo`
  on `sys/plugins/catalog/<type>/<name>`, per entry, in the root
  namespace -- this chart never creates that policy or the role bound to
  it (docs/doctrine.md's ownership contract).

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
