# openbao

OpenBAO for Kubernetes estates, as reusable mechanism: the two halves the
upstream server chart leaves out.

| Artifact | What | Status |
|---|---|---|
| `charts/openbao-ops` | Beside the server: snapshots verified before they are stored, a weekly restore that opens one, network policies, a serving certificate, and the sidecar that reloads it | shipped |
| `charts/openbao-consumers` | On every consuming cluster: External Secrets stores (readers and writers), a cert-manager issuer backed by OpenBAO's PKI, the trust bundle, and workload certificates | shipped |

Charts publish to `oci://ghcr.io/truvity/charts/<chart>` on every tag.

The **server** is not here: install it from upstream's `openbao/openbao`
chart. These charts are what an install is judged on when it fails.

## The rule that makes this repository public

**Mechanism only.** Nothing here names a cloud, a bucket, a key, a region,
a cluster, a hostname or a secret path. Every such thing is an input with a
neutral default, and the consuming estate supplies it from its own
(private) repository. `hack/leak-canary.sh` enforces this in CI, and public
history cannot be unpublished — so the rule is mechanical, not remembered.

Object storage is the sharpest case. The chart does not know S3: it knows a
**container with a contract**, and ships an S3 preset as one implementation
of it. The contract is in the values and repeated here because it is the
one thing a replacement must honour:

| Job | Reads | Must produce |
|---|---|---|
| `snapshot.upload` | `/work/openbao.snap`, `/work/taken-at` | the object stored at `<prefix><taken-at>.snap` |
| `restoreCheck.fetch` | the store | `/work/openbao.snap` and `/work/key`, failing if the newest is older than `maxSnapshotAgeSeconds` |

## charts/openbao-ops

```sh
helm install openbao-ops oci://ghcr.io/truvity/charts/openbao-ops \
  --namespace openbao --values ops-values.yaml
```

```yaml
snapshot:
  enabled: true
  upload:
    s3: { enabled: true, bucket: example-openbao-backups, region: eu-example-1 }

restoreCheck:
  enabled: true
  fetch:
    s3: { enabled: true, bucket: example-openbao-backups, region: eu-example-1 }
  canary:
    namespaces: [devel, prod]      # a value that must survive the restore
  sealConfig: |                     # the scratch server needs the same seal
    seal "awskms" {
      region     = "eu-example-1"
      kms_key_id = "alias/openbao-unseal"
    }
```

Four decisions are worth stating, because each is the difference between a
backup regime and the appearance of one:

- **A snapshot is verified before it is stored.** Taking it is an
  initContainer, uploading is the main container, and between them the
  archive is extracted and checked against the `SHA256SUMS` it carries. A
  truncated snapshot therefore never becomes an object, and never counts.
- **The restore check reads data back.** It fetches the newest snapshot
  into a throwaway loopback-only server, restores it, then logs in **as the
  snapshot's own identity** — the scratch root token dies with the restore —
  and reads a canary per namespace. Judging a restore on the process exiting
  zero proves only that a process ran.
- **A stale newest snapshot fails the check.** If the snapshot job stopped
  three days ago, nothing else notices; the restore would happily pass on
  old data. That is exactly the failure this is for.
- **The restore-check pod admits no ingress at all.** For the life of one
  pod it holds a full plaintext copy of production.

| Value | Default | Notes |
|---|---|---|
| `snapshot.jobs` | two tiers, 6-hourly and weekly | `prefix` per tier, so a lifecycle rule can expire them differently |
| `snapshot.upload` / `restoreCheck.fetch` | none | either an `s3` preset or an explicit `command`; the render fails if neither |
| `restoreCheck.maxSnapshotAgeSeconds` | `43200` | twelve hours |
| `restoreCheck.sealConfig` | `""` | raw HCL; a snapshot from an auto-unsealed cluster needs the same seal, or a replica of its key |
| `restoreCheck.verifyIssue` | `false` | also issue a certificate from the restored PKI — proof it survived as an authority, not only as bytes |
| `networkPolicy.clientCidrs` | *required when enabled* | egress is CIDR-based: naming hostnames needs a CNI extension whose shape differs by provider |
| `serverCertificate` | disabled | SANs are generated from the Services, never listed; it deliberately does not name a load balancer, so a replaced one needs no reissue |
| `tlsReload` | fragment | see below |

### The tls-reload sidecar

`tlsReload` is not an object: it is a fragment for the **upstream** chart's
`server.extraContainers`.

```yaml
# in the upstream openbao chart's values
server:
  shareProcessNamespace: true
  extraContainers: |
    {{- include "ops.tlsReloadContainer" . | nindent 2 }}
```

It exists because of a specific, invisible failure. The upstream chart runs
`bao server` under a `/bin/sh -ec` wrapper, so PID 1 is the shell and a
SIGHUP sent to the pod is swallowed. cert-manager renews the certificate on
disk, nothing reloads it, and the server keeps presenting the old one until
something restarts it — usually an expiry outage. The sidecar watches the
file and signals the `bao` process itself.

## charts/openbao-consumers

```sh
helm install openbao-consumers oci://ghcr.io/truvity/charts/openbao-consumers \
  --namespace external-secrets --values consumer-values.yaml
```

```yaml
server: https://openbao.example.internal:8200
caBundle: <base64 PEM of the CA that signed the SERVER's certificate>
vaultNamespace: devel
auth: { mountPath: jwt-devel }

stores:
  - name: example-app
    conditions: [{ namespaces: [example-app] }]   # required

writers:
  - name: example-writer
    namespace: example-system
    serviceAccount: openbao-writer
    environments: [devel, prod]

pki:
  enabled: true
  trustRootCaBundle: <base64 PEM of the ROOT that signs what OpenBAO issues>
```

Three things here are easy to get subtly wrong, so the chart fixes them:

- **Two different CAs.** `caBundle` verifies the server a client is about
  to send a token to. `pki.trustRootCaBundle` verifies the certificates
  OpenBAO **issues**. They are usually different authorities and there is
  no reason for them to agree; confusing them produces an issuer that
  works and a chain nobody trusts.
- **A writer presents its own token.** A reader store authenticates as
  External Secrets; a writer store authenticates as the writer's own
  ServiceAccount, so nothing else on the cluster can write through it. Note
  the asymmetry: the **auth mount** is this cluster's, the **Vault
  namespace** is the target environment's. One identity, minted here,
  admitted there.
- **The bundle can carry two roots.** During a root migration, trusting the
  old and the new at once is what lets leaves be reissued in any order. A
  single-source bundle makes it a flag day.

| Value | Default | Notes |
|---|---|---|
| `stores[].conditions` | *required* | a ClusterSecretStore without them is readable from every namespace on the cluster |
| `stores[].role` | the store's name | so the OpenBAO policy bounding a store is findable from the store |
| `auth.expirationSeconds` | `600` | audience-scoped and short: a leaked token is worth almost nothing |
| `pki.issuerKind` | `ClusterIssuer` | `Issuer` scopes it to one namespace |
| `certificateDefaults` | 720h / 240h | renewal at a third of the lifetime, so it has two chances before anything expires |

## Ownership contract

| This repository | The consuming estate |
|---|---|
| the jobs, their order, and what counts as a pass | where backups live, which key seals them, which region |
| the auth shape: audience-scoped, short-lived, projected tokens | mounts, roles, policies, namespaces |
| that a snapshot is verified before it is stored and read back after | the schedule and retention that suit its risk |
| the object and container contracts | the images, the CNI, the issuer, the trust root |

The chart assumes, and does not create, a least-privilege split: the
snapshot identity can write to the store but not list or read it back; the
restore identity can read but not write. Both are the estate's to grant.

## Development

```sh
devbox shell        # or direnv
just check          # lint + golden renders + leak canary
just golden         # regenerate tests/golden after a template change — review the diff
```

`tests/invalid/<chart>/` holds one fixture per validation rule. Each must
fail to render; `just lint` proves it. A rule without a fixture is a rule
that will quietly stop working.

## Releasing

Push a tag `vX.Y.Z`. The shared release workflow creates the GitHub Release
and pushes every chart at that version — a chart's own `version` field is a
placeholder that never moves.

## Licence

MIT — see [LICENSE](LICENSE).
