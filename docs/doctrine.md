# Doctrine — the design rules

## Two halves the upstream chart leaves out

The **server** is upstream's `openbao/openbao` chart and is not here
([server.md](server.md) is the shape these charts assume of it). These
charts are what an install is judged on when it fails:

- **openbao-ops** runs beside the server: snapshots, the restore check,
  the serving certificate's expiry check, network policies, the serving
  certificate and the sidecar that reloads it.
- **openbao-consumers** runs on every cluster that consumes the server:
  External Secrets stores for readers and writers, cert-manager issuers
  backed by OpenBAO's PKI, the trust anchors and bundle, and certificates.

Every part of either chart is off until enabled, so an install carries
exactly the parts that belong to the deployment it is in — the serving
certificate can be rendered by one install and the jobs by another, the
issuers apart from the stores — each at its own point in that
deployment's ordering.

## Storage and alerting are containers with a contract

The chart does not know S3 or SNS. It knows a **container with a
contract**, and ships an AWS preset as one implementation of each. The
contract is the one thing a replacement must honour:

| Container | Reads | Environment | Must |
|---|---|---|---|
| `snapshot.upload` | `/work/openbao.snap`, `/work/taken-at` | `SNAPSHOT_PREFIX`, `HOME` | store the bytes at `$SNAPSHOT_PREFIX<taken-at>.snap` |
| `restoreCheck.fetch` | the store | `MAX_SNAPSHOT_AGE_SECONDS`, `HOME` | write the newest snapshot to `/work/openbao.snap` and its name to `/work/key`, and **fail** when it is older than the limit |
| `certificateExpiry.alert` | `/work/status`: notAfter, the Ready status, its message, one per line | `ALERT_BEFORE_SECONDS`, `HOME` | alert and exit non-zero when fewer seconds than that are left |

## The restored PKI is judged against a root you hold

A restore that proves the PKI's bytes came back proves little: a copy
agrees with itself. The restore check's PKI walk starts from a root
certificate the estate committed — never from whatever the restored copy
holds — and expects a two-tier hierarchy under an offline root:

```
<pki.trustAnchor>                                      the committed root
└── <intermediate.mount>/issuer/<intermediate.issuer>            in the root namespace
    └── <ns>/<issuing.mount>/issuer/<issuing.issuerPrefix>-<ns>    one per namespace
        └── <role>.<ns>.<domain>                                   a fresh leaf per run
```

Each link is `bao pki verify-sign`: signature, path, key id, subject and
trust, which also evaluates path length and name constraints.

## The root key is in KMS, and the ceremony is not a resource

The PKI's root is a KMS key (P-384, multi-region, protected and retained)
and its certificate is signed by an explicit operator ceremony, never by a
Pulumi resource or a controller: an imperative, once-only signature has no
safe create/read lifecycle, and an apply callback can run again on a
refresh or a retry. So the two are separate on purpose:

- **`pkg/custody`** is declarative and signs nothing: the key, its policy,
  the two roles and the Sign alarm ([custody.md](custody.md)).
- **`pkg/ceremony`** signs, at most once per artifact, only a template a
  person reviewed, and writes public artifacts the estate commits
  ([ceremony.md](ceremony.md)).

Intermediates' keys live in OpenBAO; the root certifies them and never
sees them. The break-glass leaf exists so that OpenBAO's own serving
certificate can come from the same hierarchy as everything else, with no
second PKI kept aside for the day OpenBAO cannot issue.

## Ownership contract

| This repository | The consuming estate |
|---|---|
| the jobs, their order, and what counts as a pass | where backups live, which key seals them, which region |
| the auth shape: audience-scoped, short-lived, projected tokens | mounts, roles, policies, namespaces |
| that a snapshot is verified before it is stored and read back after | the schedule and retention that suit its risk |
| the object and container contracts | the images, the CNI, the issuers, the trust roots, the alert channel |
| the ceremony's checks, the artifact format, the key policy's shape | the hierarchy (names, lifetimes, constraints), the custody account, the regions, who may assume the roles, who is told of a Sign |

The charts assume, and do not create, a least-privilege split:

| Identity | OpenBAO | Object storage / alerting | Kubernetes |
|---|---|---|---|
| `snapshot` | read `sys/storage/raft/snapshot` | write under the prefixes; no list, no read | none (no token automounted) |
| `restoreCheck` | on the RESTORED copy: read the canaries, issue from `pki.role` | read the newest snapshot; decrypt with the seal's key | none |
| `certificateExpiry` | none | publish to one topic | `get` on one Certificate (the chart's Role) |
| issuers | `pki.issuers[].role`, bound to the issuer's audience | — | cert-manager mints the login's tokens (the chart's Role) |
| stores | `stores[].role` / `writers[].name` | — | the presented ServiceAccount's token |

## Issuer logins

Every issuer logs in as `pki.issuerServiceAccount` with a token
cert-manager mints per request — there is no stored credential.
cert-manager always requests the audience `vault://<name>`
(`vault://<namespace>/<name>` for an `Issuer`), so an OpenBAO role can be
bound to exactly one issuer. `audiences` adds more: a second issuer that
signs on another path of the SAME chain reaches the first issuer's role by
asking for its audience too, instead of a login of its own that would be
the same ServiceAccount under another name.

## Rules a change must keep

- **Identities hold no stored token.** Every login is a projected,
  audience-scoped, short-lived ServiceAccount token.
- **Object names are values, never the release name.** An estate that
  runs these objects today adopts them without a rename, and nothing
  carries Helm's own labels, so a render compares object for object with
  what runs.
- **Names that can be derived are.** A certificate's in-cluster SANs come
  from the Services; a store's role defaults to its name, so the policy
  bounding it is findable from it.
- **A refusal comes with its fixture** in `tests/invalid/<chart>/`.
- **Nothing signs without a confirmed template hash**, and nothing signs
  twice for one artifact.
- **A Pulumi name or input the module derives never changes in a minor.**
  Adopted custody must preview empty on every upgrade.
- **A new capability renders nothing until asked for**, so an existing
  values file renders byte-for-byte the same after an upgrade unless the
  release says otherwise.
