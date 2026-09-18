# openbao

OpenBAO for Kubernetes estates, as reusable mechanism: the two halves the
upstream server chart leaves out.

| Artifact | What | Status |
|---|---|---|
| `charts/openbao-ops` | Beside the server: snapshots verified before they are stored, a weekly restore that opens one, network policies, a serving certificate, and the sidecar that reloads it | unreleased |
| `charts/openbao-consumers` | On every consuming cluster: External Secrets stores (readers and writers), a cert-manager issuer backed by OpenBAO's PKI, the trust bundle, and workload certificates | unreleased |

Charts publish to `oci://ghcr.io/truvity/charts/<chart>` on every tag,
from the first release on.

## Who it is for

A platform team running OpenBAO on Kubernetes from upstream's
`openbao/openbao` chart, with cert-manager, trust-manager and External
Secrets, that wants backups it has seen restored, a serving certificate
that reloads itself, and clusters that read, write and issue through
OpenBAO without a stored token. The **server** is not here: these charts
are what an install is judged on when it fails.

## The model

Two halves. **openbao-ops** sits beside the server and owns its
operational life: a snapshot is taken, verified and only then stored; a
weekly restore opens the newest one in a throwaway server and reads a
canary back; the server is reachable from its clients and the jobs from
nothing. **openbao-consumers** sits on every cluster that uses the server:
reader stores bounded by namespace conditions, writer stores that present
the writer's own token, and a cert-manager issuer whose root is
distributed as a trust bundle. Object storage is a container with a
contract, with S3 as one preset; see [docs/doctrine.md](docs/doctrine.md).

## Install and a worked example

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

The serving-certificate reload is a fragment for the upstream chart
([docs/safety.md](docs/safety.md#a-renewed-certificate-that-nothing-loads)
says why):

```yaml
# in the upstream openbao chart's values
server:
  shareProcessNamespace: true
  extraContainers: |
    {{- include "ops.tlsReloadContainer" . | nindent 2 }}
```

On each consuming cluster:

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

## Documentation

- [docs/adoption.md](docs/adoption.md) — prerequisites, install order,
  the zero-diff gate
- [docs/safety.md](docs/safety.md) — the backup regime, the traps, and
  every render-time refusal
- [docs/reference.md](docs/reference.md) — every value of both charts
- [docs/doctrine.md](docs/doctrine.md) — the two halves, the storage
  contract, and the ownership contract
- [CHANGELOG.md](CHANGELOG.md) — what changed for a consumer, per version

## The rule that makes this repository public

**Mechanism only.** Nothing here names a cloud, a bucket, a key, a region,
a cluster, a hostname or a secret path. Every such thing is an input with a
neutral default, and the consuming estate supplies it from its own
(private) repository. `hack/leak-canary.sh` enforces this in CI, and public
history cannot be unpublished — so the rule is mechanical, not remembered.

This repository follows the shared
[component contract](https://github.com/truvity/ci-workflows/blob/master/docs/component-contract.md).

## Status

Extracted from a production estate, where the same mechanism runs. The
charts themselves are not yet released; the first release is v0.1.0.

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
and pushes both charts at that version — a chart's own `version` field is a
placeholder that never moves.

The first release is a manual tag: auto-release never cuts one. It is
present but not armed (`vars.AUTO_RELEASE` is unset); when armed it cuts
**patches only** — at once for a merged `security`-labelled pull request,
weekly for dependency bumps. Minors and majors are always manual, tagged
when the change merges and after its CHANGELOG heading.

## Licence

MIT — see [LICENSE](LICENSE).
