# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. Both charts are released at every version.

## v0.1.0

Not yet tagged. The first release; entries for changes that land before
the tag go here.

- **`openbao-ops`**: snapshots verified against their own `SHA256SUMS`
  before they are stored, in retention tiers; a weekly restore check that
  restores the newest snapshot into a throwaway server, logs in as the
  snapshot's own identity and reads a canary per namespace, and fails on a
  stale snapshot; network policies; a serving certificate with generated
  SANs; the `tlsReload` sidecar fragment for the upstream chart.
- **`openbao-consumers`**: reader ClusterSecretStores bounded by namespace
  conditions, writer stores that present the writer's own
  ServiceAccount token, a cert-manager issuer backed by OpenBAO's PKI, a
  trust bundle that can carry two roots, and workload certificates.
- Object storage as a container contract, with an S3 preset.
