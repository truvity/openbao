# Doctrine — the design rules

## Two halves the upstream chart leaves out

The **server** is upstream's `openbao/openbao` chart and is not here
([server.md](server.md) is the shape these charts assume of it). These
charts are what an install is judged on when it fails:

- **openbao-ops** runs beside the server: snapshots, the restore check,
  the serving certificate's expiry check, the watches, network policies,
  the serving certificate and the sidecar that reloads it.
- **openbao-consumers** runs on every cluster that consumes the server:
  External Secrets stores for readers and writers, cert-manager issuers
  backed by OpenBAO's PKI, the trust anchors and bundle, and certificates.

Every part of either chart is off until enabled, so an install carries
exactly the parts that belong to the deployment it is in — the serving
certificate can be rendered by one install and the jobs by another, the
issuers apart from the stores — each at its own point in that
deployment's ordering.

## Storage and alerting are containers with a contract

The chart does not know S3, SNS or Alertmanager. It knows a **container
with a contract**, and ships presets as implementations of it. The
contract is the one thing a replacement must honour:

| Container | Reads | Environment | Must |
|---|---|---|---|
| `snapshot.upload` | `/work/openbao.snap`, `/work/taken-at` | `SNAPSHOT_PREFIX`, `HOME` | store the bytes at `$SNAPSHOT_PREFIX<taken-at>.snap` |
| `restoreCheck.fetch` | the store | `MAX_SNAPSHOT_AGE_SECONDS`, `HOME` | write the newest snapshot to `/work/openbao.snap` and its name to `/work/key`, and **fail** when it is older than the limit |
| `certificateExpiry.alert` | `/work/status`: notAfter, the Ready status, its message, one per line | `ALERT_BEFORE_SECONDS`, `HOME` | alert and exit non-zero when fewer seconds than that are left |
| `snapshotAge.list` | the store | `SNAPSHOT_PREFIX`, `STORE_NAME`, `HOME` | write the NAME of the newest object under that prefix to `/work/newest/$STORE_NAME` — empty when there is none — and **exit zero even when the store cannot be reached**, leaving the reason in `/work/error/$STORE_NAME` |
| `<watch>.alert` | `/work/alert`: the first line a summary, the rest the description | `HOME` | deliver it and exit non-zero; an empty or absent file is silence, and then exit zero |

A preset is one implementation, and the only place a cloud or a channel
is named. Alerting ships two, because an estate that has no SNS still has
somewhere its alerts arrive:

| Preset | Container | What it does |
|---|---|---|
| `snapshot.upload.s3` | `snapshot.upload` | `aws s3 cp` with a checksum, to AWS or to any store that speaks the S3 API (`endpoint`, `pathStyle`, `existingSecret`; the same three on every S3 preset) |
| `restoreCheck.fetch.s3` | `restoreCheck.fetch` | fetches the newest object under a prefix, and fails on one that is too old |
| `certificateExpiry.alert.sns` | `certificateExpiry.alert` | one `aws sns publish` |
| `certificateExpiry.alert.alertmanager` | `certificateExpiry.alert` | one POST to `<url>/api/v2/alerts`, carrying the labels the consumer sets: `alertname`, `severity` and the release |
| `snapshotAge.list.s3` | `snapshotAge.list` | one `aws s3api list-objects-v2` over a prefix, reading no object |
| `<watch>.alert.sns` | `<watch>.alert` | one `aws sns publish`, the report handed over as a file |
| `<watch>.alert.alertmanager` | `<watch>.alert` | one POST to `<url>/api/v2/alerts`, the same labels |

Two presets for one container are refused at render time: the job alerts
once, so a second channel would be silently dropped. Every alerting preset
is held to its contract by a test that renders the chart and runs the
container's own script (`conformance/alert_test.go`,
`conformance/watch_test.go`) -- a preset only a reviewer has read is a
preset nobody has run.

`certificateExpiry.alert` came first and reads the thing it is alerting
about, so every implementation of it repeats the same arithmetic. The
watches split the two halves instead: a probe decides whether something is
wrong and writes the whole report to `/work/alert`, and the alert
container only delivers it. That is what lets one alert container serve
every watch and one preset serve every channel, and it is the shape a new
check should take.

## A watch is for a failure that is otherwise silent

Three of the ways an install dies leave no trace anyone is looking at, and
each has a part of its own:

| Watch | Asks | Because |
|---|---|---|
| `snapshotAge` | is there a fresh backup where the backups are kept? | the snapshot job can be green while the store is empty — a wrong prefix, a credential that lost its write, a lifecycle that expires faster than the schedule refills. The store is where a restore will look, so it is where the question belongs |
| `jobSuccess` | have these jobs actually SUCCEEDED lately? | a CronJob that stops being scheduled never produces a failed Job, so "no failures" is not "working". `status.lastSuccessfulTime` is missing in exactly that case |
| `rootGeneration` | is someone generating a root token? | a root token is bound by no policy, and generating one uses a quorum of the recovery-key holders rather than any credential that could be revoked |

Three rules they share, each learned from a way a check can be worse than
none:

- **A probe never fails the pod.** The alert container is the only thing
  that tells anyone, and an initContainer that exits non-zero takes it
  down. A store nothing can reach, an API that refuses, a role that was
  taken away: each becomes an alert, not a crash.
- **Being unable to ask is itself the alert.** Removing the watch's access
  is a step someone would take before doing the thing it watches for.
- **A report says what broke, what to look at and the way back.** It is
  read by whoever is woken by it, who may not be whoever wrote the values.

`snapshotAge` lists several stores rather than one, and that is also how
replication is watched: a copy in another region only counts if it is
still arriving, and a replica that stops getting newer is the same failure
seen from the data's side. It needs nothing but a listing, where a
replication metric needs the object store to publish one.

What a watch does NOT replace is a metrics pipeline. An estate that has
one gets `jobSuccess` fleet-wide, over every job it runs, and should
prefer that; these exist so that an install with no such pipeline still
cannot stop backing itself up in silence. Nor does `rootGeneration`
replace the audit device: it sees an attempt that is OPEN, because the
ceremony takes a share from each of several people and is therefore slow,
but the record of a COMPLETED one is in the audit stream and nowhere
else.

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

## The model is a shape; the derivation is the estate's

OpenBAO's own configuration -- namespaces, mounts, roles, policies,
identity groups, the PKI and SSH engines -- is described by `pkg/model` and
applied by `pkg/apply` ([model.md](model.md)). The model is deliberately
not a configuration format. What decides that a cluster's External Secrets
may read one prefix, that a group of people may sign SSH certificates for
one account, that a PKI role may sign the names of an edge catalog, lives
in the estate's own sources and vocabulary; the estate derives the model
from them, and reviews the derived model as a golden file. So the estate
keeps its rules and this repository keeps the mechanism: how each engine is
written to OpenBAO, what is refused before it is, what is protected, and
what a name is.

Three positions follow:

- **One namespace level.** Root and one namespace per environment;
  projects are policy paths and identity groups. A namespace per project
  multiplies mounts, issuing CAs and logins for no isolation a policy does
  not already give.
- **The apply never owns its own door.** The bootstrap is declared for
  review and created by the server's initialisation.
- **Registration on the caller's context.** Like `pkg/custody`, the apply
  registers every resource on the caller's context rather than inside a
  component, so a running configuration is adopted without a URN change,
  and its derived names are an API.

## Ownership contract

| This repository | The consuming estate |
|---|---|
| the jobs, their order, and what counts as a pass | where backups live, which key seals them, which region |
| the auth shape: audience-scoped, short-lived, projected tokens | mounts, roles, policies, namespaces |
| that a snapshot is verified before it is stored and read back after | the schedule and retention that suit its risk |
| the object and container contracts | the images, the CNI, the issuers, the trust roots, the alert channel |
| the ceremony's checks, the artifact format, the key policy's shape | the hierarchy (names, lifetimes, constraints), the custody account, the regions, who may assume the roles, who is told of a Sign |
| the model's shape and refusals, how each engine is written, what is protected, the resource names | the model's content: which namespaces, mounts, roles, policies and groups, derived from its own sources, and the login the apply uses |

The charts assume, and do not create, a least-privilege split:

| Identity | OpenBAO | Object storage / alerting | Kubernetes |
|---|---|---|---|
| `snapshot` | read `sys/storage/raft/snapshot` | write under the prefixes; no list, no read | none (no token automounted) |
| `restoreCheck` | on the RESTORED copy: read the canaries, issue from `pki.role` | read the newest snapshot; decrypt with the seal's key | none |
| `certificateExpiry` | none | publish to one topic | `get` on one Certificate (the chart's Role) |
| `snapshotAge` | none | LIST one prefix; no read, no write | none (no token automounted) |
| `jobSuccess` | none | publish to one topic | `get` on the named CronJobs (the chart's Role) |
| `rootGeneration` | read `sys/generate-root-token/attempt` | publish to one topic | none (no token automounted) |
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
  Adopted custody and an adopted OpenBAO configuration must preview empty
  on every upgrade.
- **A refusal in the model comes with a test** in `pkg/model`, and every
  resource the worked example registers is in `pkg/apply`'s golden.
- **A new capability renders nothing until asked for**, so an existing
  values file renders byte-for-byte the same after an upgrade unless the
  release says otherwise.
