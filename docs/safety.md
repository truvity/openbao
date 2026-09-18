# Safety — what can break, and what the charts do about it

A secret store fails quietly. Backups that were never opened, a restore
judged on an exit code, a renewed certificate nobody loaded, a certificate
that stopped renewing, a store any namespace can read: each looks healthy
until the day it is needed. The charts take a position on each, and refuse
at render time the values that would reproduce one. Every refusal has a
fixture under `tests/invalid/<chart>/` that must fail; `just lint` renders
each one and refuses a fixture that renders.

## A backup regime, not the appearance of one

- **A snapshot is verified before it is stored.** Taking it is an
  initContainer, uploading is the main container, and between them the
  archive is extracted and checked against the `SHA256SUMS` it carries. A
  truncated snapshot therefore never becomes an object, and never counts.
- **The restore check reads data back.** It fetches the newest snapshot
  into a throwaway loopback-only server under the production seal (or a
  replica of its key), restores it, then logs in **as the snapshot's own
  identity** — the scratch root token dies with the restore — and reads a
  canary in every namespace. Each canary must name its own namespace, so
  a restore that mixed namespaces up fails too. Judging a restore on the
  process exiting zero proves only that a process ran.
- **The restored PKI is walked from the root you hold** (`pki`), link by
  link to every namespace's issuing CA — never from the restored copy's
  own root, because a copy always agrees with itself. The check then
  proves the restricted role refuses a wildcard, a subdomain, IP, URI and
  e-mail SANs, issues one leaf per namespace, checks the issuer stored it
  and walks it to its CA: proof the PKI survived as an authority, not only
  as bytes.
- **A stale newest snapshot fails the check.** If the snapshot job stopped
  three days ago nothing else notices, and a restore would happily pass on
  old data. That is exactly the failure the check is for.
- **The restore-check pod admits no ingress at all.** For the life of one
  pod it holds a full plaintext copy of the store. `networkPolicy.isolated`
  extends the same to anything else that holds one, such as a hand-run
  rebuild drill.

## A certificate renewed through the server it serves

When the serving certificate is issued by OpenBAO's own PKI, cert-manager
renews it THROUGH OpenBAO, over TLS verified against the certificate being
renewed. That works for as long as the current one is valid, and renewal
starts `renewBefore` ahead of the end, so a failing renewal has weeks of
retries — silently. Past the end nothing can renew it through OpenBAO, and
every client stops at once. `certificateExpiry` reads the Certificate's
`status.notAfter` daily and alerts once fewer than `alertBeforeSeconds`
are left — after renewal has been failing for a while, well before the
end — and fails the run while it lasts. Reading it needs `get` on one
Certificate and no Secret.

## A renewed certificate that nothing loads

The upstream chart runs `bao server` under a `/bin/sh -ec` wrapper, so
PID 1 is the shell and a SIGHUP sent to the pod is swallowed. cert-manager
renews the certificate on disk, nothing reloads it, and the server keeps
presenting the old one until something restarts it — usually an expiry
outage. The `tlsReload` sidecar watches the file and signals the `bao`
process itself; it needs `shareProcessNamespace: true` on the server pod.

## A name-constrained chain and the in-cluster names

A certificate from an intermediate constrained to the estate's domains
cannot carry the short in-cluster names, and a verifier checks every SAN
against the constraint — a certificate that lists them is refused
outright. `serverCertificate.serviceDnsNames: false` puts the endpoint
alone on it, and every client verifies that name while dialling another:
`server.tlsServerName` for the jobs, `BAO_TLS_SERVER_NAME` and
`leader_tls_servername` for the server ([server.md](server.md#verifying-one-name)).

## Reads on a standby

Since OpenBAO 2.5 a standby serves reads itself, eventually consistent.
Behind a load balancer that targets every pod — which is what keeps a
leader election from being an outage — a client's next call can land on a
standby that has not applied its last write: a configuration tool reads
back nothing for a mount it has just created. The server shape in
[server.md](server.md) sets `disable_standby_reads = true`.

## Three things that are easy to get subtly wrong

- **Two different CAs.** `caBundle` verifies the server a client is about
  to send a token to. `pki.trustAnchors` verify the certificates OpenBAO
  **issues**. They are usually different authorities and there is no
  reason for them to agree; confusing them produces an issuer that works
  and a chain nobody trusts.
- **A writer presents its own token.** A reader store authenticates as
  External Secrets; a writer store authenticates as the writer's own
  ServiceAccount, so nothing else on the cluster can write through it. The
  **auth mount** is this cluster's, the **OpenBAO namespace** is the
  target environment's: one identity, minted here, admitted there.
- **The bundle carries every root.** During a root migration, trusting
  the old and the new at once is what lets leaves be reissued in any
  order. A single-source bundle makes it a flag day.

## Refused at render time

| Refusal | What it prevents |
|---|---|
| snapshots enabled with no jobs | an enabled backup that runs on no schedule |
| a snapshot upload or restore fetch with neither the S3 preset nor a command | the chart inventing where backups go, or guessing where they are |
| the S3 preset with no bucket or no region | the same, one level down |
| a restore check with no `sealConfig` | a scratch server that cannot open a snapshot sealed by a key |
| a restore check with neither `canary` nor `pki` on | a restore judged on nothing |
| the PKI walk with no trust anchor, intermediate, issuer prefix, namespaces or domain | a walk that starts from the restored copy, or proves no issuing CA |
| a canary or PKI namespace that is not a plain name (schema) | a name spliced into the check's script |
| an expiry check with neither the SNS preset nor a command, or SNS with no topic or region | an expiry check that tells nobody |
| `alertBeforeSeconds` not below the renewal lead time | an alert before renewal has even started |
| no `renewBeforeSeconds` and a `serverCertificate.renewBefore` that is not whole hours | an alert text that cannot say how long renewal has been failing |
| a network policy with no client CIDRs | an ingress policy that admits nobody |
| an `isolated` entry or egress rule with no name or pod selector | an empty selector that isolates, or opens, every pod in the namespace |
| a serving certificate with no issuer | a chart that picks an issuer; the issuer is always the estate's |
| a serving certificate that names no host | a certificate that identifies nothing |
| a projected token path that is not absolute, or a token lifetime outside 600–86400 s (schema) | a mount the kubelet refuses, or a login token that outlives its purpose |
| a store with no `server` or no `caBundle`; issuers with no `server` or no `caBundle` | a store or issuer that cannot reach OpenBAO, or cannot verify it before sending a token |
| a reader store with no `conditions` | a ClusterSecretStore readable from every namespace |
| a writer with no ServiceAccount, namespace or environments | a writer that would borrow the shared identity, or write nowhere |
| PKI with no trust anchors, an anchor with no certificate, an issuer with no sign path (schema) or an unknown kind (schema) | an issuer whose chain nothing trusts |
| a certificate with no issuer or no host | a certificate that identifies nothing |
| two entries claiming one object name | the second silently overwriting the first |
| any unknown key (`values.schema.json`) | a typo read as "use the default" |
