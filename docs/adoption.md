# Adoption

## Prerequisites

- The server, from upstream's `openbao/openbao` chart, with Raft storage
  and auto-unseal — [server.md](server.md) is the shape these charts
  assume.
- cert-manager, for the serving certificate and the PKI issuers, and
  trust-manager for the trust bundle.
- External Secrets, for the stores.
- A JWT auth mount per consuming cluster that trusts that cluster's
  ServiceAccount issuer, and the roles and policies the charts name
  (`snapshot.baoRole`, `restoreCheck.baoRole`, `stores[].role`,
  `writers[].name`, `pki.issuers[].role`). Those are the estate's: the
  charts assume them and never create them
  ([doctrine.md](doctrine.md#ownership-contract) lists what each needs).
- For the restore check's canary: in every namespace it reads,
  `<canary.kvMount>/<canary.path>` holding exactly
  `{namespace: <that namespace>}`.

## Install order

1. `openbao-ops` beside the server. Splice the `tlsReload` fragment into
   the upstream chart's `server.extraContainers` and set
   `shareProcessNamespace: true` there.
2. Turn on `snapshot` and let one run; then turn on `restoreCheck` and
   let one pass before relying on either. Trigger a first run by hand
   (`kubectl create job --from=cronjob/<name>`) rather than waiting a week.
3. Turn on `certificateExpiry` once the serving certificate is issued.
4. `openbao-consumers` on each consuming cluster. With `pki.enabled`,
   issue one disposable certificate per issuer (`certificates:`) to prove
   the login, the chain and renewal before any existing workload changes
   its `issuerRef`.

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

## The zero-diff gate

Adopt a release only when your render is byte-identical to what runs, or
differs by exactly the change the release announces in
[CHANGELOG.md](../CHANGELOG.md).

Moving from hand-written objects to these charts is one change whose
render diff is empty: set the names above first.
