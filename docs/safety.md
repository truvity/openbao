# Safety — what can break, and what the charts and the module do about it

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

## The apply: a configuration that cannot lock itself out

`pkg/apply` converges a whole server, so the ways it can hurt are the ways a
configuration tool always has -- plus the ones OpenBAO adds. Each is
answered in the model or the apply ([model.md](model.md)), and each answer
has a test.

- **Never the door it logs in through.** The operators' auth mount in root
  is the model's `bootstrap`: declared for review and never applied. An
  apply that owned it could change or remove it halfway through a run, and
  the rest of the run -- and every run after -- would have no way in.
- **A snapshot before anything changes.** `SnapshotJob` runs a Job from the
  snapshot CronJob and waits for it, before the login. It steps aside only
  for a named reason or on a fresh install; a failed snapshot stops the
  apply.
- **One alias per identity group.** OpenBAO keeps one alias per group and
  silently replaces it on a second write, so one group aliased on the CLI's
  mount and then the UI's would move its first alias to the second and lock
  every CLI login out. Each door gets its own identity group.
- **A role that binds nobody.** A JWT role with neither a bound subject nor
  a groups claim admits every token issued for its audience. `Validate`
  refuses it.
- **A policy that names a path twice.** OpenBAO keeps the second stanza, so
  such a policy grants whichever of the two nobody reviewed. Refused, as is
  every other name declared twice in one namespace: the second write would
  replace the first without a diff anyone reads.
- **A certificate that points nowhere.** A certificate carries the issuer,
  CRL and OCSP URLs its issuing mount had when it was signed, for its whole
  life. Every signature waits for the signer mount's URL and CRL
  configuration, and a signer must be an issuer of a mount declared before
  the one it signs into.
- **A constraint nobody declared.** An empty constraint list is left out,
  never sent empty, and an issuer with no `nameConstraints` carries no
  extension at all -- even one that only excludes IP ranges would be a
  constraint the chain above does not have.
- **A replaced CA.** Every key, certificate, import, issuer and mount
  configuration is protected: a Pulumi replacement of a CA is a refusal,
  never a new key. Retiring a CA is a migration -- a second issuer beside
  the first, roles moved one by one, the old one drained -- not an update.
- **Adopting under new names.** The apply registers on the caller's
  context, never inside a component whose type would enter every URN; its
  names never change in a minor, and `Options.Rename` keeps a running
  state's own names. A name that changes is a delete and a create.
- **Reads on a standby** ([above](#reads-on-a-standby)): the apply reads
  back each object it writes, so the server forwards every request to the
  active node.

## Refused before anything is applied

`model.Desired.Validate` runs first in `apply.Deploy`, and an estate runs
it wherever it derives a model; `Deploy` adds the checks only its options
can answer. Nothing is registered before a refusal.

| Refusal | What it prevents |
|---|---|
| a nested namespace name, a namespace declared twice, a named root | a tree the one-level design does not have, or one namespace written twice |
| a mount path, policy, group, role or issuer declared twice where it must be unique | the second write silently replacing the first |
| a group through a door that is no auth mount in its namespace, or with no door or no policy | a group that exists without ever being reached, or grants nothing |
| a JWT role with no audience, no user claim, no lifetime, or neither a bound subject nor a groups claim | a role that admits every token for its audience, or whose tokens never expire |
| an oidc mount with no client, or an oidc role with no redirect URI | a sign-in that fails at the issuer |
| a default role the mount does not declare | a login with no role |
| a policy that grants nothing, names a path twice, climbs out with `..` or grants an unknown capability | a policy that grants what nobody reviewed |
| a PKI mount with no issuer, or a default issuer it does not hold | a mount with nothing to sign with |
| an issuer with no or two signers, an unknown curve, a negative path length, or no lifetime when OpenBAO signs it | an unbounded CA, or one nobody signs |
| an issuer signed by one not declared in an earlier mount | a signature made before the signer's URLs exist |
| a role on an issuer its mount does not hold, with no domain, a templated domain, no usage, or a default beyond its maximum | a role that signs with the wrong key, signs nothing, or signs for anyone |
| a credential role reading its subject from no auth mount here | a role whose only name can never match |
| an SSH role for `root`, for a pattern, defaulting outside its list, with no key id, no key type, or a default beyond its maximum | a certificate for anyone, or one that names nobody |
| any SSH or credential role above `credentialMaxTtl` | a credential that outlives the ceiling |
| identity with no primary door, or metadata writing the `door` key | identity groups named inconsistently |
| (`Deploy`) an address that is not `https://`, a login with no mount, role or token | a token sent in clear, or no login |
| (`Deploy`) an oidc mount whose client secret is not in `OIDCClientSecrets` | a sign-in configured with an empty secret |
| (`Deploy`) an external issuer and no `SignedChain` | an intermediate the apply would have to invent |
| (`Deploy`) an issuer name used twice across the server | two issuers under one resource name |

## The ceremony: one signature, reviewed, never twice

A root key that signs something by accident cannot take it back: the root
publishes no revocation, and every client trusts what it signs. The
ceremony ([ceremony.md](ceremony.md)) takes a position on each way that
happens, and its tests run every refusal against a KMS double.

- **An ambiguous signature fails closed.** Before the one KMS call,
  `<artifact>.attempt` is created exclusively and fsynced, and it is never
  removed. A crash, a timeout or an unwritable artifact after that point
  leaves the reservation without an artifact, and every rerun refuses:
  the generation (for a root) or the CSR (for an intermediate) is burnt,
  instead of the key being asked for a second signature whose first may
  exist.
- **Only a reviewed template is signed.** Signing needs the SHA-256 of the
  exact TBSCertificate, derived offline by `--print-template`; a mismatch
  is refused before the reservation, so it costs nothing. The signed body
  is checked against the hash afterwards.
- **Only the committed root's key signs below it.** The KMS public key
  must be the committed root's, or nothing is reserved and nothing signed.
- **The CSR contributes its key and nothing else.** P-384, self-signed,
  exactly the authored subject, no alternative name, not the root's own
  key; everything else in the certificate comes from the spec.
- **A break-glass leaf is one name for days.** No wildcard, one DNS name,
  server auth only, at most 30 days (default 7), inside the root's
  validity and name constraint; `--out` is checked before the signature,
  because a signature whose output cannot be written is an alarm for
  nothing.
- **An installer proves before it installs.** `LoadSignedIntermediate`
  re-derives the template from the spec and checks the committed artifact
  against it and the root; a swapped or edited file is refused.
- **Custody cannot sign or delete.** The admin role has neither; the
  ceremony role signs only `ECDSA_SHA_384`; every Sign raises an alarm in
  both regions ([custody.md](custody.md)).

## Refused at render time

| Refusal | What it prevents |
|---|---|
| snapshots enabled with no jobs | an enabled backup that runs on no schedule |
| a snapshot upload or restore fetch with neither the S3 preset nor a command | the chart inventing where backups go, or guessing where they are |
| the S3 preset with no bucket or no region | the same, one level down |
| the S3 preset with an `endpoint` that is not an `http(s)` URL | a job that dials nothing on every run; empty is not an endpoint, it is AWS |
| a restore check with no `sealConfig` | a scratch server that cannot open a snapshot sealed by a key |
| a restore check with neither `canary` nor `pki` on | a restore judged on nothing |
| the PKI walk with no trust anchor, intermediate, issuer prefix, namespaces or domain | a walk that starts from the restored copy, or proves no issuing CA |
| a canary or PKI namespace that is not a plain name (schema) | a name spliced into the check's script |
| an expiry check with no preset and no command, SNS with no topic or region, or Alertmanager with no url or one that is not an `http(s)` origin | an expiry check that tells nobody |
| both alert presets at once | a second channel silently dropped by a job that alerts once |
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
