# Adoption

## Prerequisites

- The server, from upstream's `openbao/openbao` chart, with Raft storage.
- cert-manager, for the serving certificate and the PKI issuer, and
  trust-manager for the trust bundle.
- External Secrets, for the stores.
- A JWT auth mount per consuming cluster that trusts that cluster's
  ServiceAccount issuer, and the roles and policies the charts name
  (`snapshot.baoRole`, `restoreCheck.baoRole`, `stores[].role`,
  `pki.role`). Those are the estate's: the charts assume them and never
  create them.

## Install order

1. `openbao-ops` beside the server. Splice the `tlsReload` fragment into
   the upstream chart's `server.extraContainers` and set
   `shareProcessNamespace: true` there.
2. Turn on `snapshot` and let one run; then turn on `restoreCheck` and
   let one pass before relying on either.
3. `openbao-consumers` on each consuming cluster. With `pki.enabled`,
   issue one disposable certificate (`certificates:`) to prove the issuer,
   the chain and renewal before any existing workload changes its
   `issuerRef`, then delete it.

## The zero-diff gate

Adopt a release only when your render is byte-identical to what runs, or
differs by exactly the change the release announces in
[CHANGELOG.md](../CHANGELOG.md).

Moving from hand-written objects to these charts is one change whose
render diff is empty: set the object names the charts expose
(`serviceAccountName`, `networkPolicy.names`, `pki.issuerName`,
`pki.bundle.name`, the store names and `storeSuffix`) to the live names
first. A renamed object is a delete and a create — for a store, every
ExternalSecret using it fails in between; for the issuer, every
Certificate stops renewing.
