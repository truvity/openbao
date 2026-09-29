# Status (living)

**This page is updated after each delivery.** It is the one table to check before
relying on a sentence in the rest of `docs/trust/`. A pull request that changes a
trust path moves the affected row and adds a dated line under
[Changes](#changes) in the same pull request (see
[the contributor note](README.md#contributing-a-trust-path-change-updates-this-directory)).

Last reviewed: 2026-09-29.

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
| approver layer: blanket approver off, per-issuer policies, driver approver | LIVE | cut over first in one development environment; other environments to be confirmed |
| `approvercheck` (shape, live RBAC, flag) | LIVE | |
| approval covers every request shape (CI tenants, subject fields) | LIVE | fixed after the first cutover missed them |
| expiry alerts on CA certificates | PLANNED | authored thresholds exist; alerting is off until a consumer does |
| break-glass leaf | LIVE | yearly drill by hand |

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
| customer and machine exposures | PLANNED | |
| gateway to backend with a client certificate (`BackendTLSPolicy`) | PLANNED | adopted capability, not used on the application hop; gateway identity NOT decided |

### Workload identity

| Capability | State | Notes |
|---|---|---|
| CSI driver, driver approver, identity role | LIVE | |
| one project on identity, `permissive` | IN PROGRESS | a pilot in one development environment |
| calls catalogue and its render-time checks | LIVE | |
| `enforced` level and strict components | PLANNED | nothing is strict today |
| ServiceAccount per component | IN PROGRESS | mandatory; rolling out across projects; charts render it, others to migrate |
| single-identity, non-CA leaf checks in the transport libraries | LIVE | Go and Python |
| broker mapping identity to a user (NATS `verify_and_map`) | IN PROGRESS | a pilot with one publisher in one development environment |
| federation of identity across environments | PLANNED | [workload-identity.md](workload-identity.md#federation-planned) |

### Databases

| Capability | State | Notes |
|---|---|---|
| server certificate from the private chain | LIVE | opt-in per project and environment |
| clients `verify-full` | IN PROGRESS | adopted client by client; to be confirmed per consumer |
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

1. Which environments have the approver layer cut over (the first has).
2. Whether pgjdbc's SSL factory reads its files per new connection (source
   reading; needs a rotation test with `pg_stat_ssl`).
3. The exact `pg_hba` user and database fields of the people line.
4. Whether a database's initdb owner can be managed by a `DatabaseRole`.
5. Whether a `clientCASecret` holding the per-database CA and the private root,
   with no key, behaves as expected across operator versions (needs a spike on
   a small cluster).
6. What PostgreSQL's `system_user` records for a certificate login, exactly.
7. Whether a managed Kubernetes OIDC integration accepts ES384/ES256 (assumed
   RS256-only).
8. Where the CN invariant test lives (`pkg/pki`'s `Validate` is the natural
   home).
9. The federation design (deliberately unspecified).
10. Which per-consumer databases already verify with `verify-full`.

## Changes

Newest first. One line per delivery; link the pull request once merged.

- **2026-09-29** -- documentation set added: certificate families, PKI
  hierarchy, issuance, servers and edge, workload identity, databases, people,
  decision log and this page. The PostgreSQL plan (per-database CA, people via
  `db-client` and a map, no local proxy) is recorded as decided and PLANNED.
  ADR 0002 amended: an environment's identity bundle holds only that
  environment's CA.
