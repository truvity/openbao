# Adoption

## Prerequisites

- The server, from upstream's `openbao/openbao` chart, with Raft storage
  and auto-unseal — [server.md](server.md) is the shape these charts
  assume.
- cert-manager, for the serving certificate and the PKI issuers, and
  trust-manager for the trust bundle.
- External Secrets, for the stores.
- A JWT auth mount per consuming cluster that trusts that cluster's
  ServiceAccount issuer (one cluster, one issuer — see
  [Single cluster](#single-cluster)), and the roles and policies the
  charts name
  (`snapshot.baoRole`, `restoreCheck.baoRole`, `stores[].role`,
  `writers[].name`, `pki.issuers[].role`). Those are the estate's: the
  charts assume them and never create them
  ([doctrine.md](doctrine.md#ownership-contract) lists what each needs).
- For the restore check's canary: in every namespace it reads,
  `<canary.kvMount>/<canary.path>` holding exactly
  `{namespace: <that namespace>}`.

For the desired-state model and its apply ([model.md](model.md)): a Pulumi
Go program to call `pkg/apply` from, an auth mount and role in root the
program logs in through (the model's bootstrap, created by the server's
initialisation), and the server's `disable_standby_reads = true`.

For the ceremony ([ceremony.md](ceremony.md)) and its custody
([custody.md](custody.md)): an AWS account for the root key, a
multi-region CloudTrail trail logging management events in it, a Pulumi
program to call `pkg/custody` from, and the OpenBAO PKI mounts whose keys
the intermediates certify.

## Install order

1. `openbao-ops` beside the server. Splice the `tlsReload` fragment into
   the upstream chart's `server.extraContainers` and set
   `shareProcessNamespace: true` there.
2. Turn on `snapshot` and let one run; then turn on `restoreCheck` and
   let one pass before relying on either. Trigger a first run by hand
   (`kubectl create job --from=cronjob/<name>`) rather than waiting a week.
3. Turn on `certificateExpiry` once the serving certificate is issued.
4. `openbao-consumers` on each consuming cluster — which may be this one
   ([Single cluster](#single-cluster)). With `pki.enabled`,
   issue one disposable certificate per issuer (`certificates:`) to prove
   the login, the chain and renewal before any existing workload changes
   its `issuerRef`.

## Single cluster

The smallest install: the server, its jobs and its consumers on one
cluster — the one the server itself runs on. No value means anything
different there; what changes is that the values which name "the
consuming cluster" all name this one, and that the two charts are
ordered inside one deployment instead of following two clocks.

**One cluster is one token issuer.** A JWT auth mount trusts exactly one
issuer, and here there is one: this cluster's ServiceAccount issuer. What
there is one of is the *door*, not the mount object — anything logging in
does so in the OpenBAO namespace it works in, so the mount is created in
each namespace that is logged in to:

| Who logs in | Where | Mount |
|---|---|---|
| the ops jobs (snapshot, restore check) | root: `sys/storage/raft/snapshot` is a root path, and the restore check lists namespaces from there | `auth.mountPath` in root |
| the stores and the cert-manager issuers | the environment's namespace, the one they read and sign in | `auth.mountPath` in that namespace |

Both trust the same issuer, take the same audience and carry the same
name, so both charts are given the same `auth.mountPath` and
`auth.audience` and there is one discovery URL in the whole install. A
second name, with a second issuer to keep in step, appears when a second
CLUSTER does — never because a namespace was added.
[`pkg/model/testdata/desired-one-env.yaml`](../pkg/model/testdata/desired-one-env.yaml)
is that shape as desired state, and the conformance harness applies it to
a server.

**The values that collapse to one name.**

| openbao-ops | openbao-consumers | On one cluster |
|---|---|---|
| `auth.mountPath`, `auth.audience` | `auth.mountPath`, `auth.audience`, `writerAuthMount` | one mount name and one audience; `writerAuthMount` stays empty, because the writer's cluster is this one |
| `server.activeService` (what the jobs dial) | `server` | the same endpoint: the consumers are in this cluster too, so they dial the Service rather than an external name |
| `server.tlsSecretName`, `server.caKey` | `caBundle` | the CA that signed the SERVER's certificate — not a root that verifies what OpenBAO issues |
| `restoreCheck.canary.namespaces`, `restoreCheck.pki.namespaces` | `vaultNamespace` | the one environment |
| `restoreCheck.pki.issuing.issuerPrefix` | `pki.issuers[].signPath` | the one environment's issuing CA |
| `certificateExpiry.clusterName` | — | this cluster, in the alert's text |

**One wave sequence, not two clocks.** With two clusters the charts are
two Applications that sync independently. Here they belong to one, as two
sources or as two Applications in one project, and the install order
above is a sync-wave order — each chart's `annotations` carry the wave:

| Wave | What |
|---|---|
| 0 | `openbao-ops` with only `serverCertificate` on: the server cannot serve without its Secret |
| 5 | the server, upstream's chart, with the `tlsReload` fragment spliced in |
| 10 | `openbao-ops`' jobs and policies: `snapshot`, `restoreCheck`, `certificateExpiry`, `networkPolicy` |
| 20 | `openbao-consumers`: the stores, the issuers, the anchors and the bundle |

What happens between waves 5 and 10 is not in either chart: the mounts,
roles and policies both charts name are created by the program that calls
`pkg/apply` (or by hand), against the server that wave 5 started. A store
or a job that logs in before its role exists fails until it is retried —
which is why wave 20 is last and why the first restore check is triggered
by hand rather than waited for.

**Proving it.** On one cluster the proof is the same as anywhere: turn on
`snapshot`, run one by hand, then turn on `restoreCheck` with
`canary.namespaces` naming the one environment (or empty, to read back
every namespace the restored copy lists) and `pki.namespaces` naming it
too, and run it by hand. The pass line names the snapshot it opened, the
canaries it read and the chain it walked; until it has printed one, the
install has backups nobody has opened.

## Adopting objects that already run

Every object name is a value and none carries the release name or Helm's
own labels, so objects an estate renders from its own templates today can
be rendered by the charts without a rename:

| Chart | Names to set to the live ones |
|---|---|
| openbao-ops | `snapshot.serviceAccountName`, `snapshot.jobs[].name`, `restoreCheck.serviceAccountName`, `certificateExpiry.name`, `networkPolicy.names.*`, `networkPolicy.isolated[].name`, `networkPolicy.egress.rules[].name`, `server.tlsSecretName` |
| openbao-consumers | `stores[].name` with `storeSuffix`, `writers[].name`, `pki.issuerServiceAccount`, `pki.trustAnchors[].name`, `pki.issuers[].name`, `pki.bundle.name`, `certificates[].name` and `secretName` |

A renamed object is a delete and a create — for a store, every
ExternalSecret using it fails in between; for an issuer, every Certificate
stops renewing; for the serving certificate's Secret, the server loses its
key.

Render both, compare them object by object (parsed, so comments do not
count), and move them in ONE deployment change. With Argo CD that means
adding the chart as a **source of the same Application** that renders the
objects today, in the same Application spec that stops rendering them —
gate the old templates on a parameter the Application passes. A source in
a second Application, or removal and addition on two different clocks
(the repository the templates live in, and the Application spec), gives
automated pruning a window in which the objects are in neither: it
deletes them, and they are recreated only afterwards.

## Adopting an existing ceremony and custody

A root that already exists keeps its artifacts and its key; nothing is
signed to adopt it.

- **The artifacts.** The root and intermediate artifacts, and their
  `.attempt` reservations, are the files `pkg/ceremony` writes and reads:
  keep them where they are and point the hierarchy (or your own specs) at
  them. Set `serialNamespace` to the label prefix the root was created
  with -- the serial is derived from it, and a root created under another
  prefix fails verification rather than being silently re-derived.
  `openbaoctl pki create-root` then verifies the root and signs nothing,
  and `pki sign-intermediate --print-template` against the same CSR must
  print the template, and the hash, the previous tooling printed, byte
  for byte.
- **The custody.** Call `custody.Deploy` from the program that manages the
  custody today, with the role names, prefixes, description prefix,
  provider name and tags that program uses, so every Pulumi name and every
  input comes out the same ([custody.md](custody.md#adopting-existing-custody)).
  The preview must show no change to any key, alias, role or alarm; the
  keys are protected and retained, so a URN change would show as a
  replacement and must never be applied.

## Adopting a running OpenBAO configuration

A server already configured by a Pulumi program is adopted by `pkg/apply`
with an empty preview; nothing is recreated to adopt it.

1. **Derive the model from what the program declares today**, and write
   it out as a golden file. Every value the program spelled as a constant
   -- a mount's description, a role's claim mappings, an identity group's
   metadata, an issuer's organization -- becomes data in the model.
2. **Keep every resource name.** `pkg/apply` registers on the caller's
   context, not in a component, so a name the scheme in
   [model.md](model.md#resource-names) already produces needs nothing.
   Map every other one with `Options.Rename`, from the name the scheme
   gives to the name the state holds. Derive the map from the model rather
   than listing names by hand: a missed entry is a create beside a live
   object, and on a protected CA key a refusal.
3. **Prove it before any preview.** Register both programs under Pulumi's
   mocks and compare what each declares -- type, name, every input,
   protection, provider -- resource by resource. Dependencies may only
   grow: the apply waits for more than a hand-written program may have
   (a signature waits for its signer's pinned default and its mount's
   URLs), and a dependency is not part of a diff.
4. **Preview against the real server.** The only change allowed is the
   provider's per-run login token. Protected resources make a mistake a
   refusal rather than a replacement, but a replacement proposed on an
   unprotected role is still a delete, so read the preview.

## The zero-diff gate

Adopt a release only when your render is byte-identical to what runs, or
differs by exactly the change the release announces in
[CHANGELOG.md](../CHANGELOG.md).

Moving from hand-written objects to these charts is one change whose
render diff is empty: set the names above first.

For the Go module the render is the Pulumi preview of the program that
calls `pkg/custody` (no change but provider metadata), the preview of the
program that calls `pkg/apply` (no change but the provider's login token)
and, for the ceremony, `--print-template` against the committed root and a
known CSR (byte-identical to what the previous version printed).
