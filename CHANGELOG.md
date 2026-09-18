# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. Both charts are released at every version.

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
