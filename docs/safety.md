# Safety — what can break, and what the charts do about it

A secret store fails quietly. Backups that were never opened, a restore
judged on an exit code, a renewed certificate nobody loaded, a store any
namespace can read: each looks healthy until the day it is needed. The
charts take a position on each, and refuse at render time the values that
would reproduce one. Every refusal has a fixture under
`tests/invalid/<chart>/` that must fail; `just lint` renders each one and
refuses a fixture that renders.

## A backup regime, not the appearance of one

- **A snapshot is verified before it is stored.** Taking it is an
  initContainer, uploading is the main container, and between them the
  archive is extracted and checked against the `SHA256SUMS` it carries. A
  truncated snapshot therefore never becomes an object, and never counts.
- **The restore check reads data back.** It fetches the newest snapshot
  into a throwaway loopback-only server, restores it, then logs in **as
  the snapshot's own identity** — the scratch root token dies with the
  restore — and reads a canary per namespace. Judging a restore on the
  process exiting zero proves only that a process ran.
- **A stale newest snapshot fails the check.** If the snapshot job stopped
  three days ago nothing else notices, and a restore would happily pass on
  old data. That is exactly the failure the check is for.
- **The restore-check pod admits no ingress at all.** For the life of one
  pod it holds a full plaintext copy of the store.
- **Optionally, the restored PKI issues a certificate** (`verifyIssue`):
  proof it survived as an authority — keys, issuers, roles — not only as
  bytes.

## Three things that are easy to get subtly wrong

- **Two different CAs.** `caBundle` verifies the server a client is about
  to send a token to. `pki.trustRootCaBundle` verifies the certificates
  OpenBAO **issues**. They are usually different authorities and there is
  no reason for them to agree; confusing them produces an issuer that
  works and a chain nobody trusts.
- **A writer presents its own token.** A reader store authenticates as
  External Secrets; a writer store authenticates as the writer's own
  ServiceAccount, so nothing else on the cluster can write through it. The
  **auth mount** is this cluster's, the **OpenBAO namespace** is the
  target environment's: one identity, minted here, admitted there.
- **The bundle can carry two roots.** During a root migration, trusting
  the old and the new at once is what lets leaves be reissued in any
  order. A single-source bundle makes it a flag day.

## A renewed certificate that nothing loads

The upstream chart runs `bao server` under a `/bin/sh -ec` wrapper, so
PID 1 is the shell and a SIGHUP sent to the pod is swallowed. cert-manager
renews the certificate on disk, nothing reloads it, and the server keeps
presenting the old one until something restarts it — usually an expiry
outage. The `tlsReload` sidecar watches the file and signals the `bao`
process itself; it needs `shareProcessNamespace: true` on the server pod.

## Refused at render time

| Refusal | What it prevents |
|---|---|
| snapshots enabled with no jobs | an enabled backup that runs on no schedule |
| a snapshot upload or restore fetch with neither the S3 preset nor a command | the chart inventing where backups go, or guessing where they are |
| the S3 preset with no bucket | the same, one level down |
| a restore check with canary verification and no canary namespaces | a restore judged on nothing |
| a network policy with no client CIDRs | an ingress policy that admits nobody |
| a serving certificate with no issuer | a chart that picks an issuer; the issuer is always the estate's |
| a store or issuer with no `server`, or a store with no `caBundle` | a store that cannot reach OpenBAO, or cannot verify it before sending a token |
| a reader store with no `conditions` | a ClusterSecretStore readable from every namespace |
| a writer with no ServiceAccount, namespace or environments | a writer that would borrow the shared identity, or write nowhere |
| the PKI with no trust root | an issuer whose chain nothing trusts |
| a certificate with no issuer or no host | a certificate that identifies nothing |
| two entries claiming one object name | the second silently overwriting the first |
| any unknown key (`values.schema.json`) | a typo read as "use the default" |
