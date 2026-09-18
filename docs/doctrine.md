# Doctrine — the design rules

## Two halves the upstream chart leaves out

The **server** is upstream's `openbao/openbao` chart and is not here.
These charts are what an install is judged on when it fails:

- **openbao-ops** runs beside the server: snapshots, the restore check,
  network policies, the serving certificate and the sidecar that reloads
  it.
- **openbao-consumers** runs on every cluster that consumes the server:
  External Secrets stores for readers and writers, a cert-manager issuer
  backed by OpenBAO's PKI, the trust bundle, and workload certificates.

## Object storage is a container with a contract

The chart does not know S3. It knows a **container with a contract**, and
ships an S3 preset as one implementation of it. The contract is the one
thing a replacement must honour:

| Job | Reads | Must produce |
|---|---|---|
| `snapshot.upload` | `/work/openbao.snap`, `/work/taken-at` | the object stored at `<prefix><taken-at>.snap` |
| `restoreCheck.fetch` | the store | `/work/openbao.snap` and `/work/key`, failing if the newest is older than `maxSnapshotAgeSeconds` |

## Ownership contract

| This repository | The consuming estate |
|---|---|
| the jobs, their order, and what counts as a pass | where backups live, which key seals them, which region |
| the auth shape: audience-scoped, short-lived, projected tokens | mounts, roles, policies, namespaces |
| that a snapshot is verified before it is stored and read back after | the schedule and retention that suit its risk |
| the object and container contracts | the images, the CNI, the issuer, the trust root |

The chart assumes, and does not create, a least-privilege split: the
snapshot identity can write to the store but not list or read it back;
the restore identity can read but not write. Both are the estate's to
grant.

## Rules a change must keep

- **Identities hold no stored token.** Every login is a projected,
  audience-scoped, short-lived ServiceAccount token.
- **Names are derived, not listed.** A certificate's SANs come from the
  Services; a store's role defaults to its name, so the policy bounding it
  is findable from it.
- **A refusal comes with its fixture** in `tests/invalid/<chart>/`.
- **A new capability renders nothing until asked for**, so an existing
  values file renders byte-for-byte the same after an upgrade unless the
  release says otherwise.
