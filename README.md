# openbao

OpenBAO for Kubernetes estates, as reusable mechanism: the two halves the
upstream server chart leaves out.

| Artifact | What | Reference |
|---|---|---|
| `charts/openbao-ops` | Beside the server: snapshots verified before they are stored, a weekly restore that reads data back and walks the restored PKI from a root you hold, a serving-certificate expiry alert, network policies, a serving certificate, and the sidecar that reloads it | [docs/openbao-ops.md](docs/openbao-ops.md) |
| `charts/openbao-consumers` | On every consuming cluster: External Secrets stores (readers and writers), cert-manager issuers backed by OpenBAO's PKI, the trust anchors and bundle, and certificates | [docs/openbao-consumers.md](docs/openbao-consumers.md) |

Charts publish to `oci://ghcr.io/truvity/charts/<chart>` on every tag.

The **server** is not here: install it from upstream's `openbao/openbao`
chart. [docs/server.md](docs/server.md) describes the shape these charts
assume of it — HA Raft, auto-unseal, one verified endpoint name, a declared
audit device, and a certificate reloaded without a restart. These charts
are what an install is judged on when it fails.

## The rule that makes this repository public

**Mechanism only.** Nothing here names a cloud account, a bucket, a key, a
region, a cluster, a hostname or a secret path. Every such thing is an
input with a neutral default, and the consuming estate supplies it from its
own (private) repository. `hack/leak-canary.sh` enforces this in CI, and
public history cannot be unpublished — so the rule is mechanical, not
remembered.

Object storage and alerting are the sharpest cases. The chart does not
know S3 or SNS: it knows a **container with a contract**, and ships an AWS
preset as one implementation of each.

| Container | Reads | Must produce |
|---|---|---|
| `snapshot.upload` | `/work/openbao.snap`, `/work/taken-at` | the object stored at `$SNAPSHOT_PREFIX<taken-at>.snap` |
| `restoreCheck.fetch` | the store | `/work/openbao.snap` and `/work/key`, failing if the newest is older than `$MAX_SNAPSHOT_AGE_SECONDS` |
| `certificateExpiry.alert` | `/work/status` | an alert and a non-zero exit when fewer than `$ALERT_BEFORE_SECONDS` are left |

## charts/openbao-ops

```sh
helm install openbao-ops oci://ghcr.io/truvity/charts/openbao-ops \
  --namespace openbao --values ops-values.yaml
```

```yaml
auth:
  mountPath: jwt-example
snapshot:
  enabled: true
  upload:
    s3: { enabled: true, bucket: example-openbao-backups, region: eu-example-1 }
restoreCheck:
  enabled: true
  fetch:
    s3: { enabled: true, bucket: example-openbao-backups, region: eu-example-1 }
  sealConfig: |                     # the snapshot's seal, or a replica of its key
    seal "awskms" {
      region     = "eu-example-2"
      kms_key_id = "alias/openbao-unseal"
    }
certificateExpiry:
  enabled: true
  alert:
    sns: { enabled: true, topicArn: <topic>, region: eu-example-1 }
```

Five decisions are worth stating, because each is the difference between a
backup regime and the appearance of one:

- **A snapshot is verified before it is stored.** Taking it is an
  initContainer, uploading is the main container, and between them the
  archive is extracted and checked against the `SHA256SUMS` it carries. A
  truncated snapshot therefore never becomes an object, and never counts.
- **The restore check reads data back.** It restores the newest snapshot
  into a throwaway loopback-only server, then logs in **as the snapshot's
  own identity** — the scratch root token dies with the restore — and
  reads a canary in every namespace. Judging a restore on the process
  exiting zero proves only that a process ran.
- **The restored PKI is walked from the root you hold.** Optionally, the
  check verifies the restored hierarchy link by link from a committed root
  certificate — never the restored copy's own — proves the role refuses
  what it must, and issues a fresh leaf in every namespace.
- **A stale newest snapshot fails the check.** If the snapshot job stopped
  three days ago, nothing else notices; the restore would happily pass on
  old data. That is exactly the failure this is for.
- **The restore-check pod admits no ingress at all.** For the life of one
  pod it holds a full plaintext copy of production.

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
  trustAnchors:
    - name: example-root-2026
      certificate: <base64 PEM of the ROOT that signs what OpenBAO issues>
  issuers:
    - name: example-private
      signPath: pki/sign/private
      role: example-private
```

## Ownership contract

| This repository | The consuming estate |
|---|---|
| the jobs, their order, and what counts as a pass | where backups live, which key seals them, which region |
| the auth shape: audience-scoped, short-lived, projected tokens | mounts, roles, policies, namespaces |
| that a snapshot is verified before it is stored and read back after | the schedule and retention that suit its risk |
| the object and container contracts | the images, the CNI, the issuers, the trust roots |

The chart assumes, and does not create, a least-privilege split: the
snapshot identity can write to the store but not list or read it back; the
restore identity can read but not write. Both are the estate's to grant
([docs/openbao-ops.md](docs/openbao-ops.md#contracts)).

## Adopting objects you already run

Every object name is a value and none carries the release name or Helm's
own labels, so an estate that renders these objects from its own templates
can switch to the charts without a rename. Render both, compare them
object by object, and move them in ONE deployment change — with Argo CD,
add the chart as a source of the same Application that renders them today,
in the same revision that stops rendering them: a source in a second
Application prunes the objects before recreating them.

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
