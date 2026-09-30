# Status (living)

**This page is updated after each delivery.** It is the one table to check before
relying on a sentence in the rest of `docs/trust/`. A pull request that changes a
trust path moves the affected row and adds a dated line under
[Changes](#changes) in the same pull request (see
[the contributor note](README.md#contributing-a-trust-path-change-updates-this-directory)).

Last reviewed: 2026-09-30.

- **LIVE**: delivered and in use in the shape the page describes.
- **IN PROGRESS**: partly delivered; the note says which part.
- **PLANNED**: decided, not built. Nothing else is assumed to depend on it.

## Capability by state

### PKI and issuance

| Capability | State | Notes |
|---|---|---|
| KMS-held root, custody, Sign alarm, ceremony | LIVE | [hierarchy.md](hierarchy.md) |
| private and origin domain intermediates | LIVE | DNS-constrained and unconstrained respectively |
| per-environment issuing CAs and host roles | LIVE | |
| per-environment identity CAs signed by the root, exact URI constraint | LIVE | for every environment that has been added to the contract |
| cert-manager `ClusterIssuer`s backed by OpenBAO | LIVE | |
| trust bundles: private root, environment identity, origin roots file | LIVE | |
| approver layer: blanket approver off, per-issuer policies, driver approver | LIVE | blanket approver off on every environment, each proven by a refusal test |
| approver policies rendered by `openbao-consumers` (`approverPolicy`, `extraPolicies`) | LIVE | the consumer no longer hand-writes `CertificateRequestPolicy` objects; `extraPolicies` covers issuers that are not OpenBAO, such as a self-signed bootstrap issuer ([issuance.md](issuance.md#the-policies)) |
| `approvercheck` (shape, live RBAC, flag) | LIVE | consolidated into the library: `--certificates` and a repeatable `--policies` |
| consumer loads the library's `pkg/pki` contract (schema v1) | LIVE | Pulumi resource names proven stable: a name-set golden and a zero-diff preview |
| `openbaoctl` custody cross-check before signing (`--custody-outputs`, `--skip-custody-check <reason>`) | LIVE | v0.24.0; [hierarchy.md](hierarchy.md#two-phase-creation-of-a-ca) |
| approval covers every request shape (CI tenants, subject fields) | LIVE | fixed after the first cutover missed them |
| issuance-chain alerts (`openbao-consumers` v0.21.0) | LIVE | rendered as a VMRule on the management cluster |
| expiry alerts on CA certificates | PARTIAL | `openbao-consumers` ships the issuance alerts (off by default, [issuance.md](issuance.md#alerts)); Certificates cert-manager holds are covered natively, the CAs held in OpenBAO need an exporter and stay opt-in |
| break-glass leaf | LIVE | yearly drill by hand |
| promotion verification gate | LIVE | waits until every pod of the promoted release is at the new version and Ready (up to 25 minutes), then bakes on a sample count (at least 10 prober journeys, at most 5% failures, end-to-end green, no restarts or alerts); a separate check that the environment's applications render the promoted chart version |

### Servers, edge and hostnames

| Capability | State | Notes |
|---|---|---|
| private zone, exact records, ClusterIP-first private exposure | LIVE | |
| public exposure: tunnel, origin chain, pinned roots file | LIVE | |
| split data planes per exposure | LIVE | |
| gateway signs people in (`proxy.engine: envoy`) | LIVE | every browser application; a few consoles still on the older proxy |
| per-host Cloudflare certificate packs, Total TLS | LIVE | |
| Cloudflare root token and least-privilege children | LIVE | a legacy user token is being retired in two stages |
| storage credentials broker | LIVE | |
| OpenBAO 2.6.3 security release on the management cluster | LIVE | nine advisories, including a cross-namespace policy-cache traversal; other clusters follow their own roll |
| OpenBAO 2.7 seal as an external KMS plugin (`serverpreset.SealPlugin`) | IN PROGRESS | the preset, its validation and a Docker rehearsal (v0.23.0: no route out, KMS emulated: cold start, restarts, three-voter roll 2.6.3 to 2.7.0, revert of a standby) are delivered in this library; the move is under way for the management cluster, and the other clusters still run the built-in seal on 2.6.x ([server.md](../server.md#runbook-26-to-27-with-the-kms-seal-plugin)) |
| customer and machine exposures | PLANNED | |
| gateway to backend with a client certificate (`BackendTLSPolicy`) | PLANNED | adopted capability, not used on the application hop; gateway identity NOT decided |

### Workload identity

| Capability | State | Notes |
|---|---|---|
| CSI driver, driver approver, identity role | LIVE | |
| one project on identity, `permissive` | IN PROGRESS | a pilot in one development environment |
| calls catalogue and its render-time checks | LIVE | |
| `enforced` level: admission policy (identity volume, ServiceAccount, TLS ports) | PARTIAL | shipped in `openbao-consumers` (off by default, dry-run mode), proved on a real API server and now deployed on the management cluster, but inert: no namespace has opted in yet |
| strict components | PLANNED | nothing is strict today |
| ServiceAccount per component | IN PROGRESS | mandatory; rolling out across projects; charts render it, others to migrate |
| single-identity, non-CA leaf checks in the transport libraries | LIVE | Go, Python and the Kotlin example (policy v1.32.0); a leaf that is a CA, may sign certificates or CRLs, or lacks exactly one URI name is refused |
| broker mapping identity to a user (NATS `verify_and_map`) | LIVE | connecting with its identity and no token, mapped over TLS 1.3, in a development environment and a staging environment; the transitional shared-account entry is removed in the first |
| federation of identity across environments | PLANNED | [workload-identity.md](workload-identity.md#federation-planned) |

### Databases

| Capability | State | Notes |
|---|---|---|
| server certificate from the private chain | LIVE | opt-in per project and environment |
| server certificate served without restart on renewal | LIVE | server-TLS and server-CA Secrets carry `cnpg.io/reload` (truvity/cnpg-cluster v2.0.1 and v1.2.2); a forced renewal was served within 10 s in a development environment |
| PostgreSQL phase 1: server on the private chain, clients `verify-full` | LIVE | an identity server (own ServiceAccount, FQDN host, root mounted as a directory) in development and production; the url-shortener example (`database.tls.mode`, policy v1.33.0) in development; the platform's audit and dashboard databases on the management cluster; the document service's database servers on the private chain in every environment, with clients verifying where the chart version allows (development today) |
| phase 0 spikes (client CA without key, per-database CA, people path) | LIVE | all GO; one open design point on trust-manager sources ([databases.md](databases.md#the-per-database-ca)) |
| Java client key format (DER PKCS#8) via cert-manager `additionalOutputFormats` | PLANNED | to be verified |
| per-database CA, owner and runtime client certificates | PLANNED | phase 3 |
| chart renders client CA, replication certificate, `pg_ident`, people line | PLANNED | phase 2 |
| `accessctl psql` client half (`db-client`, 1 hour, key on the laptop) | LIVE | |
| server half for people: private root in the client-CA file, map and rows | PLANNED | |
| `accessctl psql --as` and `--target` | PLANNED | |
| tested invariant: no issuer under the root signs a bare CN | PLANNED | today by role shape |
| password fallback toggle | LIVE | per role |
| owner certificate before migration hooks | PLANNED | with phase 3 |

### People

| Capability | State | Notes |
|---|---|---|
| sign-in, token exchange, `accessctl` | LIVE | |
| OpenBAO JWT login, groups to policies | LIVE | |
| opkssh for people | LIVE | on the instance-based routers of the environments that use it |
| opkssh dot-delimiter shim | LIVE | temporary; remove after the upstream fix |
| SSH user CA for machines, forced command with the `critical_options` denial | LIVE | |
| SSH host CA and `known-hosts` | LIVE | pods; the cloud-identity renewer is built |
| people's OpenBAO SSH role | retired | where opkssh has replaced it |
| ES384 default with per-audience exceptions | LIVE | |
| a managed Kubernetes API server accepting non-RS256 | to be confirmed | assumed RS256-only |

## To be confirmed

Statements in this directory that could not be verified from the sources at
hand. They are marked in place and listed here so a reviewer can close them.

1. ~~Which environments have the approver layer cut over~~ Resolved 2026-09-29:
   all, each proven by a refusal test.
2. Whether pgjdbc's SSL factory reads its files per new connection (source
   reading; needs a rotation test with `pg_stat_ssl`). The key format half is
   resolved (DER PKCS#8 only); whether cert-manager `additionalOutputFormats: DER`
   suffices is still to be verified.
3. The exact `pg_hba` user and database fields of the people line (the map
   and rows were proven in a spike; the final fields are not fixed).
4. Whether a database's initdb owner can be managed by a `DatabaseRole`.
5. ~~Whether a `clientCASecret` with no key behaves as expected~~ Resolved
   2026-09-29 on operator 1.30 (chart 0.29): accepted, replication healthy. Other
   operator versions are not tested. The client-CA file must hold the
   intermediate(s) as well as the root. Still open: how the private root reaches
   the file when the per-database CA lives outside the trust namespace.
6. What PostgreSQL's `system_user` records for a certificate login, exactly.
7. Whether a managed Kubernetes OIDC integration accepts ES384/ES256 (assumed
   RS256-only).
8. Where the CN invariant test lives (`pkg/pki`'s `Validate` is the natural
   home).
9. The federation design (deliberately unspecified).
10. ~~Which per-consumer databases already verify with `verify-full`~~ Resolved
    2026-09-30: see the databases table above. Remaining: document-service clients
    outside development, which wait on the chart version that supports it.

## Changes

Newest first. One line per delivery; link the pull request once merged.

- **2026-09-30** -- PostgreSQL phase 1 delivered (server on the private chain,
  clients `verify-full`): the identity server (development and production), the
  url-shortener example (development), the platform's audit and dashboard
  databases (management cluster), and the document service's database servers in
  every environment, with clients verifying where the chart version allows
  (development). Renewed server certificates are served without restart
  (`cnpg.io/reload`; truvity/cnpg-cluster v2.0.1 and v1.2.2).
- **2026-09-30** -- approver policies are rendered by the `openbao-consumers`
  chart (`approverPolicy`, with `extraPolicies` for issuers that are not OpenBAO,
  such as a self-signed bootstrap issuer); the consumer no longer hand-writes
  them. `approvercheck` is consolidated into the library (`--certificates`,
  repeatable `--policies`).
- **2026-09-30** -- issuance-chain alerts (`openbao-consumers` v0.21.0) live on
  the management cluster as a VMRule. The admission policy for `enforced`
  namespaces is deployed there but inert: no namespace has opted in.
- **2026-09-30** -- the consumer loads the library's `pkg/pki` contract
  (schema v1). Pulumi resource names proven stable by a name-set golden and a
  zero-diff preview.
- **2026-09-30** -- `openbaoctl` cross-checks custody before signing (v0.24.0):
  `--custody-outputs` verifies against the published outputs, `--skip-custody-check
  <reason>` records why it was skipped.
- **2026-09-30** -- OpenBAO 2.6.3 (nine security advisories, including a
  cross-namespace policy-cache traversal) rolled on the management cluster. The
  2.7 move with the KMS seal as an external plugin is rehearsed in the library
  (v0.23.0) and IN PROGRESS for that cluster. Lesson recorded in
  [servers-and-edge.md](servers-and-edge.md#pin-the-server-image-tag): a chart's
  `server.image` without a tag runs the chart's appVersion.
- **2026-09-30** -- NATS workload identity live in a development environment and a
  staging environment. New decisions:
  [T-26](decisions.md#t-26-heavy-lifting-lives-in-the-library-consumers-keep-rows-values-and-thin-adapters),
  [T-27](decisions.md#t-27-the-kms-seal-plugin-arrives-by-init-container-from-a-digest-pinned-image-volume).

- **2026-09-30** -- `pkg/serverpreset` supports the OpenBAO 2.7 seal as an
  external KMS plugin: `Seal.Plugin` renders the `plugin "kms"` block and an
  init container plus image volume that install a digest-pinned binary before
  the server starts (no pod egress, no runtime download); the 2.6 rendering is
  unchanged. Proven by `just rehearse-seal-plugin`; runbook in
  [server.md](../server.md#runbook-26-to-27-with-the-kms-seal-plugin). No
  cluster has been moved yet.

- **2026-09-29** -- phase 0 database spikes recorded (all GO; findings in
  [databases.md](databases.md#the-per-database-ca)): client CA without a key,
  per-database CA, people path, intermediates in the client-CA file, CN-only
  leaves under a DNS-constrained intermediate, the Java driver's DER PKCS#8
  requirement, and `pg_` as a reserved role prefix. New rules:
  [T-24](decisions.md#t-24-cnpg-secrets-always-carry-cnpgioreload),
  [T-25](decisions.md#t-25-people-ladder-roles-avoid-the-reserved-pg_-prefix).
- **2026-09-29** -- delivered: truvity/cnpg-cluster v2.0.1 and v1.2.2 label the
  server-TLS and server-CA Secrets for reload (forced renewal served within 10 s,
  no restart); an identity server's database connection on `verify-full` with its
  own ServiceAccount, live in development and production; truvity/policy v1.33.0
  (url-shortener `database.tls.mode`, no unused password to the stat component;
  rollout pending); the NATS identity pilot live in a development environment
  with the shared-account entry removed; peer verification refusing CA-capable
  and multi-URI leaves (policy v1.32.0); the promotion verification gate waits
  for the full rollout before baking; the approver layer confirmed cut over on
  every environment.
- **2026-09-29** -- documentation set added: certificate families, PKI
  hierarchy, issuance, servers and edge, workload identity, databases, people,
  decision log and this page. The PostgreSQL plan (per-database CA, people via
  `db-client` and a map, no local proxy) is recorded as decided and PLANNED.
  ADR 0002 amended: an environment's identity bundle holds only that
  environment's CA.
