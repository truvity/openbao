# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. Both charts are released at every version, and
from v0.2.0 on the Go module and `openbaoctl` with them.

## v0.2.0

Not yet tagged. The Go module and `openbaoctl` arrive; both charts render
exactly what v0.1.0 rendered.

- **`pkg/ceremony`**: the CA ceremony with the root key in AWS KMS (P-384,
  `ECDSA_SHA_384`). The root's self-signature (or the import of an
  existing root), domain intermediates signed from an OpenBAO-held key's
  CSR in two steps (the template and its SHA-256, reviewed offline; then
  the signature, only for that hash), and a break-glass server leaf
  straight from the root. Every signature is reserved by an `.attempt`
  file first and never repeated; every result is proven and recorded as a
  public artifact. `LoadSignedIntermediate` proves a committed
  intermediate and returns the chain OpenBAO's `set-signed` takes.
  Deterministic serials are derived under `SerialNamespace`.
- **`pkg/custody`**: the root key's custody as a Pulumi Go module: per
  generation a protected, retained multi-region P-384 key and replica with
  aliases; a key policy that separates break-glass recovery,
  administration without signing or deletion, and ceremony read/sign
  (`kms:SigningAlgorithm`); the admin and ceremony roles; and a Sign alarm
  (CloudTrail → EventBridge → SNS, plus a CloudWatch alarm) in each region.
  Resources register on the caller's context, so existing custody is
  adopted with an empty preview.
- **`pkg/kmssigner`**: a `crypto.Signer` over a KMS P-384 key.
- **`openbaoctl`**: `pki create-root`, `pki sign-intermediate`,
  `pki verify-intermediate` and `pki sign-emergency-server`, from a
  hierarchy file.

## v0.1.0

Not yet tagged. The first release; entries for changes that land before
the tag go here.

- **`openbao-ops`**: snapshots verified against their own `SHA256SUMS`
  before they are stored, in retention tiers; a weekly restore check that
  restores the newest snapshot into a throwaway server under the
  production seal, logs in as the snapshot's own identity, reads a canary
  in every namespace (listed, or every one the copy lists) that must name
  its own namespace, and fails on a stale snapshot; optionally the same
  check walks the restored PKI from a committed root to every namespace's
  issuing CA, proves the role's refusals and issues a fresh leaf in each
  (`restoreCheck.pki`); a daily serving-certificate expiry check that
  alerts before the end (`certificateExpiry`, SNS preset); network
  policies, with isolated pods and egress rules of any kind; a serving
  certificate with generated SANs, or the endpoint alone for a
  name-constrained chain (`serviceDnsNames: false`), verified by the jobs
  through `server.tlsServerName`; the `tlsReload` sidecar fragment for the
  upstream chart.
- **`openbao-consumers`**: reader ClusterSecretStores bounded by namespace
  conditions, writer stores that present the writer's own
  ServiceAccount token, cert-manager issuers backed by OpenBAO's PKI (one
  per signing path, with extra token audiences), trust anchors distributed
  by a trust bundle that carries every root, and certificates.
- Object storage and alerting as container contracts, with S3 and SNS
  presets. Every object name is a value and nothing carries Helm's own
  labels, so objects rendered by other means can be adopted in place.
