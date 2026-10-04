# The worked example

One made-up organisation, built up in six capability levels. This is the
repository's worked example: every name in it is a placeholder, every level
is checked in CI with **no cluster and no cloud account**, and an adopter
copies the levels it needs and no more.

## The levels

Each level adds one capability to the one below it, and a level is complete
without the ones above: a level-N install needs nothing a level above N
provides. The tests prove both halves.

| Level | Directory | Adds | Needs besides the library |
|---|---|---|---|
| 0 | [00-server](00-server) | the server preset (Raft, optional awskms seal), its serving certificate, expiry alert and network policy | the upstream `openbao` chart, a serving certificate from any issuer |
| 1 | [01-secrets](01-secrets) | a KV mount per environment, a JWT auth mount per cluster, groups and policies, the External Secrets stores, snapshot and restore check | an OIDC issuer for people and jobs, External Secrets |
| 2 | [02-ssh](02-ssh) | SSH user and host CAs, hosts that sign their own host certificate (aws auth plugin), the plugin catalog watch | the plugin registered on the server, an instance role per fleet |
| 3 | [03-pki](03-pki) | the private-PKI contract (KMS root, DNS trust domain), cert-manager issuers, the trust bundle, the restore check's PKI proof | an AWS account for the root key, cert-manager, trust-manager |
| 4 | [04-workload-identity](04-workload-identity) | a URI trust domain with an environment CA (root-signed, two-phase), the identity issuer, the approver layer | csi-driver-spiffe, approver-policy, the blanket approver switched off |
| 5 | [05-enforcement](05-enforcement) | a project namespace below an environment, and the admission policy for namespaces at the enforced mTLS level | Kubernetes 1.30 or later |

A level directory holds **complete** files, not patches. A file a level does
not change is not repeated: the nearest level below it that has the file
supplies it.

| File | What it is |
|---|---|
| `spec.yaml` | the authored, non-PKI contract ([`pkg/builder`](../../docs/builder.md)): roster, jobs, environments, trusts, SSH, grants |
| `contract.yaml` | the private-PKI contract ([`pkg/pki`](../../docs/pki.md)); from level 3 |
| `ops.values.yaml` | values for the `openbao-ops` chart |
| `consumers.values.yaml` | values for the `openbao-consumers` chart, as the dev cluster runs it |
| `golden/` | what the level derives: the apply's resources, the server's HCL, the charts' renders |

The server preset is Go ([`org.go`](org.go), over [`../server`](../server)).

## What CI proves, per level

All of it runs from `just examples` (and the Go half again in `just test`):

- **Contract and desired state validate.** `spec.yaml` builds, the contract
  loads strictly and validates, the contract's PKI is derived and joined, and
  the whole `model.Desired` validates.
- **The apply previews under Pulumi's mocks.** The resources `apply.Deploy`
  registers are committed in `golden/resources.txt`; a preview registers what
  an apply does; each level registers nothing of the levels above it, and
  nothing a lower level registers is dropped or renamed.
- **The charts render.** `helm template` of each level's values against
  `golden/openbao-*.yaml` (`hack/golden.sh examples`).
- **The values and the model agree.** Every store and every cert-manager
  issuer in the values logs in as a role the desired state declares, on the
  mount the values name, with the audience cert-manager asks for, and may sign
  on the path the issuer signs through. The jobs' roles exist in root, the
  restore check's PKI proof names issuers the derivation produces, and the
  plugin the catalog watch names is the one the server preset registers.
- **Level 4's two-phase CA.** Phase A (`apply.BootstrapEnvironmentCA`) registers
  its key and request under the names the full apply gives them.
- **No organisation specifics.** `just leak-canary` holds this directory to
  made-up names and the reserved example domains.

What no level proves is a running cluster: that is the adopter's first
install (docs/adoption.md), in the order the levels give.

## Regenerating

```
just golden          # review the diff before committing
just examples
```
