# openbao

OpenBAO for Kubernetes estates, as reusable mechanism: the two halves the
upstream server chart leaves out, the desired state of OpenBAO's own
configuration and its apply, and the KMS-rooted CA ceremony its PKI hangs
from.

| Artifact | What | Status |
|---|---|---|
| `charts/openbao-ops` | Beside the server: snapshots verified before they are stored, a weekly restore that reads data back and walks the restored PKI from a root you hold, an alert before the serving certificate ends, watches for the failures that are otherwise silent, network policies, a serving certificate, and the sidecar that reloads it | unreleased |
| `charts/openbao-consumers` | On every consuming cluster: External Secrets stores (readers and writers), cert-manager issuers backed by OpenBAO's PKI, the trust anchors and bundle, and certificates | unreleased |
| `pkg/ceremony` (Go) | The CA ceremony with the root key in AWS KMS: the root's self-signature, domain intermediates from OpenBAO-held keys (review a template hash, then sign it once), the break-glass server leaf, and the committed artifact format | unreleased |
| `pkg/custody` (Go, Pulumi) | The root key's custody: a multi-region P-384 key per generation, a key policy that separates administration from signing, the two roles, and a Sign alarm in each region | unreleased |
| `pkg/model` (Go) | OpenBAO's desired state per namespace and engine: KV mounts, JWT/OIDC auth mounts and roles, identity groups and aliases, policies, PKI mounts with issuers and roles, SSH CAs and roles; yaml-tagged, validated, no loader | unreleased |
| `pkg/apply` (Go, Pulumi) | Converges a server onto a `pkg/model` state with the Pulumi vault provider, after a pre-apply snapshot, with resource names an existing configuration adopts unchanged | unreleased |
| `openbaoctl` | The CLI over the ceremony, from a hierarchy file; linux and darwin binaries on every release | unreleased |
| access-roster integration | The contract with an access-roster issuer -- people, CI jobs and operators signing in by their groups, SSH and database certificates for `accessctl credential` -- as a `pkg/model` preset (`model.Roster`), a neutral example (`examples/roster`) and a conformance test against a real `bao server -dev` | unreleased |

Charts publish to `oci://ghcr.io/truvity/charts/<chart>` on every tag,
from v0.1.0 on; from v0.2.0 on the same tag is also the Go module
`github.com/truvity/openbao`'s version (`pkg/model` and `pkg/apply` from
v0.3.0 on), and `openbaoctl` is attached to the GitHub Release.

## Who it is for

A platform team running OpenBAO on Kubernetes from upstream's
`openbao/openbao` chart, with cert-manager, trust-manager and External
Secrets, that wants backups it has seen restored, a serving certificate
that reloads itself and is noticed before it ends, and clusters that read,
write and issue through OpenBAO without a stored token. The **server** is
not here: [docs/server.md](docs/server.md) describes the shape these charts
assume of it. These charts are what an install is judged on when it fails.

The model and its apply are for a team that configures OpenBAO itself --
its namespaces, logins, policies, PKI and SSH engines -- from a Pulumi Go
program, and wants that configuration derived from its own sources,
reviewed as a file, and refused before it is applied when it would lock
someone out or admit more than it names.

The ceremony and custody are for a team whose OpenBAO PKI should chain to
a root nobody can copy: an AWS account holds the root key in KMS, a Pulumi
Go program deploys its custody, and a person runs the ceremony with a
second person checking the template. They do not create OpenBAO's mounts
or roles, and they sign nothing on their own.

## The model

Two halves. **openbao-ops** sits beside the server and owns its
operational life: a snapshot is taken, verified and only then stored; a
weekly restore opens the newest one in a throwaway server, reads a canary
back in every namespace and walks the restored PKI from a root you
committed; a daily check alerts weeks before the serving certificate ends;
watches say when the store has no fresh backup in it, when a job has quietly
stopped succeeding and when someone is generating a root token; the server
is reachable from its clients and the jobs from nothing.
**openbao-consumers** sits on every cluster that uses the server: reader
stores bounded by namespace conditions, writer stores that present the
writer's own token, and cert-manager issuers whose roots are distributed as
a trust bundle. Object storage and alerting are containers with a
contract, with S3, SNS and an Alertmanager webhook as presets; see
[docs/doctrine.md](docs/doctrine.md).

Inside the server, the **desired state** (`pkg/model`) is one level of
namespaces -- root, and one per environment -- each holding the same
engines: KV, JWT/OIDC doors, identity groups admitted through those doors,
policies, PKI mounts whose issuers are self-signed, signed by an earlier
issuer or signed outside OpenBAO, and SSH CAs. The estate derives it;
`pkg/apply` writes it, never touching the door it logs in through
([docs/model.md](docs/model.md)).

Above everything sits the **root**: a KMS key that signs a handful of
certificates in its life -- itself, one intermediate per trust domain
(whose keys stay in OpenBAO), and a break-glass leaf when OpenBAO cannot
issue its own serving certificate. Each signature is a reviewed template,
signed once, recorded as a public artifact the estate commits, and
announced by an alarm.

## Install and a worked example

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
    sns: { enabled: true, topicArn: example-topic-arn, region: eu-example-1 }
snapshotAge:                        # is there a fresh backup where the backups are kept?
  enabled: true
  stores:
    - name: primary
      description: the object store the snapshots are written to
      prefix: raft/
      maxAgeSeconds: 43200          # every 6 hours above, so this is two missed runs
      s3: { enabled: true, bucket: example-openbao-backups, region: eu-example-1 }
  alert:
    sns: { enabled: true, topicArn: example-topic-arn, region: eu-example-1 }
jobSuccess:                         # have these jobs actually succeeded lately?
  enabled: true
  cronJobs:
    - name: openbao-restore-check
      maxAgeSeconds: 777600         # weekly, plus two days for a run that starts late
  alert:
    sns: { enabled: true, topicArn: example-topic-arn, region: eu-example-1 }
rootGeneration:                     # is someone generating a root token?
  enabled: true
  alert:
    sns: { enabled: true, topicArn: example-topic-arn, region: eu-example-1 }
```

The S3 presets reach any store that speaks the S3 API. Three values, all
inert by default, say which: `endpoint` (empty keeps AWS), `pathStyle`
(the bucket as `endpoint/bucket/key`, a property of the store's
certificate) and `existingSecret` (static keys through `envFrom`, for a
store with no pod identity). The same on every preset, once per store:

```yaml
snapshot:
  upload:
    s3:
      enabled: true
      bucket: example-openbao-backups
      region: example                 # MinIO, Ceph RGW: as the store is configured
      endpoint: https://objects.example.internal
      pathStyle: true                 # its certificate covers the host, not a bucket subdomain
      existingSecret: openbao-backup-keys   # AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
# Cloudflare R2: endpoint https://<account>.r2.cloudflarestorage.com, region auto
```

The serving-certificate reload is a fragment for the upstream chart
([docs/safety.md](docs/safety.md#a-renewed-certificate-that-nothing-loads)
says why, [docs/server.md](docs/server.md) shows the rest of the server's
values):

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
  trustAnchors:
    - name: example-root-2026
      certificate: <base64 PEM of the ROOT that signs what OpenBAO issues>
  issuers:
    - name: example-private
      signPath: pki/sign/private
      role: example-private
```

OpenBAO's own configuration, from a Pulumi Go program
([docs/model.md](docs/model.md) has the whole shape):

```go
desired := &model.Desired{
    Bootstrap: operatorsDoor, // declared for review, never applied
    Identity:  model.Identity{PrimaryDoor: "jwt-people"},
    Namespaces: []model.Namespace{{
        Name: "dev",
        KV:   []model.KVMount{{Path: "kv", Canary: "restore-canary"}},
        Auth: []model.JWTMount{{
            Path: "jwt-dev", DiscoveryURL: "https://oidc.dev.example.com",
            Roles: []model.Role{{
                Name: "external-secrets", BoundAudiences: []string{"openbao"},
                BoundSubject: model.ServiceAccountSubject("external-secrets", "external-secrets"),
                UserClaim: "sub", Policies: []string{"eso-app"}, TTL: "1h",
            }},
        }},
        Policies: []model.Policy{{Name: "eso-app", Rules: []model.Rule{
            {Path: "kv/data/app/*", Capabilities: []string{"read"}},
        }}},
    }},
}

_, err := apply.Deploy(c, desired, apply.Options{ // c is the *pulumi.Context
    Address: "https://openbao.example.com",
    Login:   apply.Login{Mount: "jwt-people", Role: "people", Token: operatorToken},
})
```

For the ceremony, a hierarchy file and one command per step
([docs/ceremony.md](docs/ceremony.md) walks through all of them):

```sh
go install github.com/truvity/openbao/cmd/openbaoctl@latest   # or the release archive
openbaoctl pki sign-intermediate --hierarchy pki.yaml --trust-domain private \
  --csr private.csr --print-template                         # no credential; prints the hash
openbaoctl pki sign-intermediate --hierarchy pki.yaml --trust-domain private \
  --csr private.csr --confirm-template <sha256> --role-arn <ceremony role ARN>
```

```go
// the custody, from a Pulumi Go program
_, err := custody.Deploy(ctx, custody.Args{
    AccountID:                  "111122223333",
    TrustedPrincipalARNPattern: "arn:aws:iam::111122223333:role/example-admin-*",
    AdminRoleName:              "private-pki-root-admin",
    CeremonyRoleName:           "private-pki-root-ceremony",
    Generations:                []custody.Generation{{ID: "example-root-2026-01", Region: "eu-example-1", ReplicaRegion: "eu-example-2"}},
    Notify:                     []string{"security@example.com"},
})
```

## Documentation

- [docs/adoption.md](docs/adoption.md) — prerequisites, install order,
  adopting objects that already run, the zero-diff gate
- [docs/safety.md](docs/safety.md) — the backup regime, the traps, and
  every render-time refusal
- [docs/reference.md](docs/reference.md) — every value of both charts,
  the hierarchy file, `openbaoctl`, `pkg/custody`, `pkg/model` and
  `pkg/apply`
- [docs/doctrine.md](docs/doctrine.md) — the two halves, the container
  contracts, and the ownership contract
- [docs/server.md](docs/server.md) — the upstream server's values these
  charts assume
- [docs/ceremony.md](docs/ceremony.md) — the KMS-rooted CA ceremony,
  step by step
- [docs/custody.md](docs/custody.md) — the root key's policy, roles and
  Sign alarm
- [docs/model.md](docs/model.md) — OpenBAO's desired state per engine,
  its apply, and the resource names an existing configuration adopts
- [docs/integrations/access-roster.md](docs/integrations/access-roster.md)
  — the access-roster issuer, end to end: the two doors, groups to
  policies, the operators' door, the credential paths, CI, and every
  failure mode
- [docs/team-secrets.md](docs/team-secrets.md) — a team's shared
  secrets on one KV prefix: the three groups, the paths, the fetch,
  rotation, what revocation does and does not do, and what never goes in
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

Used in production by its maintainers. The charts are released from
v0.1.0; the Go module and `openbaoctl` from v0.2.0; `pkg/model` and
`pkg/apply` arrive in v0.3.0.

## Development

```sh
devbox shell        # or direnv
just check          # build + lint + golden renders + Go tests (a real bao server -dev included) + leak canary
just golden         # regenerate tests/golden, the ceremony's template goldens, the model example and the apply's resources — review the diff
```

The access-roster conformance test (`conformance/`) starts the `bao`
binary the dev shell pins; outside it the test skips, and `just test` sets
`OPENBAO_CONFORMANCE=required` so that it never does there.

`tests/invalid/<chart>/` holds one fixture per validation rule. Each must
fail to render; `just lint` proves it. A rule without a fixture is a rule
that will quietly stop working.

## Releasing

Push a tag `vX.Y.Z`. The shared release workflow creates the GitHub Release
with the `openbaoctl` binaries and pushes both charts at that version — a
chart's own `version` field is a placeholder that never moves — and the
tag is the Go module's version.

The first release is a manual tag: auto-release never cuts one. It is
present but not armed (`vars.AUTO_RELEASE` is unset); when armed it cuts
**patches only** — at once for a merged `security`-labelled pull request,
weekly for dependency bumps. Minors and majors are always manual, tagged
when the change merges and after its CHANGELOG heading.

## Licence

MIT — see [LICENSE](LICENSE).
