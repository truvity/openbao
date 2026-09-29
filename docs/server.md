# The server, from upstream's chart

This repository does not install the server: upstream's `openbao/openbao`
chart does. What follows is the shape these charts assume of it — an HA
Raft cluster that auto-unseals, serves a certificate cert-manager renews,
is reached by clients that verify one name, and runs whatever external
plugin its auth or secrets methods need — as values for that chart. Every
particular (the endpoint, the key, the region, the image registry) is a
placeholder.

The plugin catalog's HCL and the values fragment around it (the emptyDir
it needs, the sidecar that finishes a download a fresh pod's own egress
raced) are rendered, not hand-typed: [`pkg/serverpreset`](../pkg/serverpreset)
is a **values preset**, not a wrapper chart — see
["Why a values preset, not a wrapper chart"](#why-a-values-preset-not-a-wrapper-chart)
below. [`examples/server`](../examples/server) is a complete, neutral
example, [`values.yaml`](../examples/server/values.yaml) beside it its
golden, and [`conformance/server_preset_test.go`](../conformance/server_preset_test.go)
boots a real `bao server` from exactly that rendered HCL to prove the
three faults below stay fixed.

```yaml
global:
  tlsDisable: false
injector:
  enabled: false
server:
  # With the JWT auth method nothing calls TokenReview.
  authDelegator:
    enabled: false
  # All pods start together and retry-join until one is initialised;
  # OrderedReady would stall the others behind an uninitialised first pod.
  podManagementPolicy: Parallel
  extraEnvironmentVars:
    BAO_CACERT: /openbao/userconfig/openbao-tls/ca.crt
    # The in-pod CLI dials 127.0.0.1. Verify the endpoint's name instead of
    # the address: with a name-constrained chain the endpoint is the one
    # name the certificate is certain to carry.
    BAO_TLS_SERVER_NAME: openbao.example.internal
    AWS_REGION: eu-example-1
  extraVolumes:
    - type: secret
      name: openbao-tls           # serverCertificate, from openbao-ops
  # tls-reload (below) signals the bao process across containers.
  shareProcessNamespace: true
  extraContainers: []            # the tls-reload fragment, below
  ha:
    enabled: true
    replicas: 3
    raft:
      enabled: true
      setNodeId: true
      config: |
        ui = true
        # Standbys forward every request to the active node. Since 2.5
        # standbys serve reads, eventually consistent: behind a load
        # balancer that targets every pod, a client's next call can land on
        # a standby that has not applied its last write yet.
        disable_standby_reads = true
        listener "tcp" {
          address         = "[::]:8200"
          cluster_address = "[::]:8201"
          tls_cert_file   = "/openbao/userconfig/openbao-tls/tls.crt"
          tls_key_file    = "/openbao/userconfig/openbao-tls/tls.key"
        }
        storage "raft" {
          path = "/openbao/data"
          # Dial the pod, verify the endpoint's name.
          retry_join {
            leader_api_addr       = "https://openbao-0.openbao-internal:8200"
            leader_ca_cert_file   = "/openbao/userconfig/openbao-tls/ca.crt"
            leader_tls_servername = "openbao.example.internal"
          }
          # ... one retry_join per replica
        }
        seal "awskms" {
          region     = "eu-example-1"
          kms_key_id = "alias/openbao-unseal"
        }
        service_registration "kubernetes" {}
        # Declared, because OpenBAO refuses API-created audit devices. The
        # restore check's scratch server declares the same (auditConfig).
        audit "file" "to-stdout" {
          options {
            file_path = "stdout"
          }
        }
```

## The seal's health check is a KMS budget

`seal "awskms"` is not only used to unseal. Every replica keeps checking
that it still can, by round-tripping an `Encrypt` and a `Decrypt` against
the key on a timer, for as long as it runs — so the request count follows
the number of replicas and the clock, not the traffic.

Measured on a five-replica cluster: about **960 KMS requests a day**,
which is about 192 per replica per day. Three replicas are therefore
about 17,000 requests a month and five about 29,000. AWS's free tier is
20,000 requests a month, so five replicas cross it around the 21st and
the account is billed for the rest of the month, every month.

So `replicas: 3` above is the reference for two reasons, not one: it is
the smallest Raft quorum that survives losing a node, and it is the
seal's budget. A replica added for headroom keeps spending its 192
requests a day for as long as it exists, whether or not anything reads
from it.

## Verifying one name

A certificate issued from a name-constrained intermediate cannot carry the
short in-cluster names (`openbao`, `openbao-active.<ns>.svc`, the peers'
pod names) unless the constraint admits them, and every SAN of a leaf is
checked against it. The alternative to widening the constraint is to put
ONE name on the certificate — the endpoint — and have every in-cluster
client verify that name while dialling whatever address it dials:

| Client | Setting |
|---|---|
| the server's own CLI | `BAO_TLS_SERVER_NAME` |
| Raft peers | `retry_join { leader_tls_servername }` |
| the openbao-ops jobs | `server.tlsServerName` |
| the certificate | `serverCertificate.serviceDnsNames: false`, `ipAddresses: []` |

## Reloading a renewed certificate

The upstream chart runs `bao server` under a `/bin/sh -ec` wrapper, so PID
1 is the shell and a SIGHUP sent to the pod is swallowed. cert-manager
renews the certificate on disk, nothing reloads it, and the server keeps
presenting the old one until something restarts it — usually an expiry
outage. The tls-reload sidecar watches the file and signals the `bao`
process itself; it needs `shareProcessNamespace: true`.

When openbao-ops is a subchart of the chart that installs the server, the
fragment splices in directly:

```yaml
server:
  shareProcessNamespace: true
  extraContainers: |
    {{- include "ops.tlsReloadContainer" . | nindent 2 }}
```

Otherwise copy the container from `ops.tlsReloadContainer` in
`charts/openbao-ops/templates/_helpers.tpl` into `server.extraContainers`,
with the `tlsReload` values filled in.

## Before the first sync: bootstrapping the Secret

`extraVolumes` above names one Secret, `openbao-tls`, that this
repository never creates: cert-manager's `serverCertificate` does, once
OpenBAO can answer its PKI mount. On a new cluster, or a restore onto
one, nothing has answered yet, so that Secret does not exist the first
time a GitOps controller syncs whatever installs the server -- and
whatever issuer normally requests through OpenBAO cannot issue until
something does. [docs/ceremony.md](ceremony.md#4-the-break-glass-server-certificate)'s
`openbaoctl pki sign-emergency-server` then `install-emergency-server
--kube-context <context>` (required -- no current-context fallback, so
the plan it prints names the cluster it resolved, not just the name
typed) is what creates that Secret by hand, from the KMS root directly,
before that first sync; a consuming estate's cluster-bootstrap runbook
should place it as an explicit, numbered step. Once cert-manager can reach
OpenBAO it reissues and takes the Secret over normally -- nothing here
needs to know it was ever bootstrapped by hand.

Every rehearsal of that path in this repository (`just
rehearse-bootstrap-tls`, run as part of `just test`/`just check` in CI)
signs with a local stand-in for the KMS root, never a real key; the real
KMS root signs this path only in the yearly drill `ceremony.md`
describes, run by hand and recorded in the consuming estate's restore
runbook.

## Rolling a configuration change

The upstream StatefulSet uses `OnDelete`: a change to the server's
configuration reaches a pod only when that pod is deleted. Roll by hand,
one pod at a time, **standbys first and the active node last**, waiting
for Raft to report every voter healthy between pods — deleting the active
node forces an election, and the goal is one election at the end, not one
per pod.

Find the leader from any pod: `bao status` reads `HA Mode` (`active` or
`standby`) and, on a standby, `Active Node Address` names the one to
delete last. Address it explicitly (`-address=https://<pod>.<internal
service>:8200`, `BAO_TLS_SERVER_NAME` still set to the endpoint) rather
than the address every client dials, which always resolves to the active
node and so always answers `active` regardless of which pod is actually
asked.

Raft's own endpoints (`sys/storage/raft/configuration`,
`sys/storage/raft/snapshot`, …) are ROOT-only: they refuse a namespaced
request even as `-ns=root` or `-ns=/` — omit the flag, or unset
`BAO_NAMESPACE` first if a shell already carries one from an environment
namespace.

## The plugin catalog: three faults, fixed once

OpenBAO, unlike Vault, ships no cloud auth or secrets method built in:
every one is an external plugin, downloaded from an OCI image and
verified against a checksum before the server ever runs it. Getting a
plugin declared safely on a real, multi-pod server ran into three faults
that do not show up reading the documentation, each fixed by
[`pkg/serverpreset`](../pkg/serverpreset) rather than left for the next
install to rediscover:

1. **`plugin_directory` must exist before `bao server` starts**, whether
   or not the download that follows succeeds. A failed download never
   creates it, and a missing directory makes the server EXIT —
   `Error creating KMS plugin catalog: expand plugin directory: lstat
   ...: no such file or directory` — never warn and continue.
   `Config.PluginVolume`/`Config.PluginVolumeMount` are the emptyDir that
   makes this true on every pod, on every restart, unconditionally.
2. **`plugin_download_behavior` accepts exactly `"fail"` or
   `"continue"`.** Any other value, including the word `"warn"`, is
   accepted by the server's config parser and silently ignored — read
   back with `bao read` (or a rendered diff) it looks set, but it behaves
   as whichever of the two real values the server happens to default to.
   `Config.Validate` refuses anything else at RENDER time, before it ever
   reaches a server that would not complain either.
3. **A fresh pod's first download races whatever admits its egress.**
   The very first attempt on a new pod times out because the network
   policy (or whatever else gates that pod's egress) has not yet caught
   up with its address, and nothing retries it on its own —
   `plugin_download_behavior = "continue"` (the default) starts the
   server anyway, with that plugin simply missing until something tries
   again. `Config.RetrySidecarContainer` is that something: it waits for
   the server's OWN listener to answer (SIGHUP's default disposition
   terminates a process that has not installed a handler for it yet, so
   signalling too early restarts the container instead of retrying
   anything) and then SIGHUPs `bao server` on a timer — which re-runs the
   SAME declarative download and registration from the server's current
   config, and succeeds once egress has caught up.

`Config.HCL()` renders the whole configuration in one deterministic pass,
and [`conformance/server_preset_test.go`](../conformance/server_preset_test.go)
boots a real, non-dev `bao server` from it — with a local plugin directory
and no route to the plugin's registry — to prove faults 1 and 3 stay
fixed: a missing directory still exits, and a `"continue"` failure still
leaves the server serving.

Two things this package does NOT try to derive, because the repository's
own guessing would be the next particular to leak: `Plugin.EgressHosts` is
data (a registry's blob layers can live on a second host — ghcr.io's do,
at `pkg-containers.githubusercontent.com` — and that split is the
registry's own property, not a pattern this package could infer from the
image reference alone), and `Config.Arch` is never derived from a node
selector — `ResolveArch` exists to refuse a selection that could resolve
to more than one architecture explicitly, before a checksum is ever
picked for it.

### Egress

`Config.EgressDomains()` returns every hostname a rendered `Config`
needs, derived from what is actually enabled: each plugin's
`EgressHosts`, AWS STS (global and regional) for a plugin whose
`RequiresSTS` is true, and the seal's KMS host. It is not a
`NetworkPolicy` — whether an egress allowlist is CIDR-based, an
`ApplicationNetworkPolicy`'s domain names, or a service mesh's egress
rule is the platform's shape, not this package's — but it is exactly the
list either one is built from, so it feeds `openbao-ops`'s own
`networkPolicy.egress.rules` (a list of whole policies, in whatever shape
the platform needs) or a consumer's own policy, without re-deriving what
"plugins on" actually requires reaching.

### Plugin rollout runbook

Rolling a NEW or changed plugin block is a configuration change (`OnDelete`
above), with one more thing to verify before trusting it: the download
happened on the node it was supposed to, and the catalog holds the exact
version a mount will ask for.

1. **Canary one standby first.** Delete the pod, wait for it to become a
   healthy standby again (`bao status` on it directly, not through the
   endpoint every client dials — see "Rolling a configuration change"),
   then check its own logs for
   `plugins: OCI plugin downloading completed` with no
   `failed to download plugin` beside it, and the retry sidecar's log
   line (`plugin-retry: <path> present`) if the first attempt raced
   egress the way fault 3 above describes.
2. **Confirm the catalog entry, on that same pod's namespace:**
   `bao read sys/plugins/catalog/<Kind>/<Name>` shows `version` equal to
   `Plugin.Version`, `oci = true` and `deregistration_params.plugin_version`
   (or the equivalent field this OpenBAO release reports) — the
   declarative path is the ONLY one that can register a catalog entry
   pointing into the OCI cache; an API registration of the same entry is
   refused (`cannot execute files outside of configured plugin
   directory`), so a catalog entry that exists at all here is proof the
   declarative path ran, not proof a human ran it correctly.
3. **Only then roll the rest**, standby by standby, **leader last** — the
   same order as any other configuration change, so a plugin that turns
   out to be wrong strands the fewest voters on it.
4. **A mount that uses the plugin must pin `plugin_version` to the same
   string** (`Plugin.Version`) as the catalog entry, or it resolves the
   unversioned key and then a builtin — never this entry — which reads as
   "the plugin isn't there" from the mount's side even once the catalog
   itself is correct.

Step 2 above is also `charts/openbao-ops`'s `pluginCatalog` watch, run on a
schedule rather than by hand: it re-reads `sys/plugins/catalog/<type>/<name>`
for every plugin an estate configures and alerts the moment one is missing,
at the wrong version, or — with `oci`/`declarative` checked — reports an
entry an API call could have created rather than one the declarative
download actually registered. It complements a log-based alert on `failed
to download plugin`: that needs a pipeline watching the server's own log
lines, where this asks the catalog itself, the same ground truth step 2
reads by hand. Reading the catalog needs a policy granting **both** `read`
and `sudo` on `sys/plugins/catalog/<type>/<name>`, per entry, in the root
namespace — this chart never creates that policy or the role bound to it
(docs/doctrine.md's ownership contract); see [docs/reference.md](reference.md#plugincatalog)
for the values.

## Image

Keep the server's image, `snapshot.image`, `restoreCheck.image` and
`tlsReload.image` on the same tag: a restore check that restores with an
older `bao` than took the snapshot is proving the wrong pairing. The
plugin-retry sidecar (`Config.RetrySidecarContainer`) follows the same
rule — its `RetrySidecarOptions.Image` should be the server's own image,
for the same reason `tlsReload` is.

## Why a values preset, not a wrapper chart

Two shapes were on the table for `pkg/serverpreset`: a Helm chart that
depends on upstream's `openbao/openbao-helm` and installs the server
itself, or a values preset a caller merges into that chart's own
`valuesObject`. This repository's own opening line settled it: **"This
repository does not install the server: upstream's chart does."** A
wrapper chart that itself gets installed would be exactly the thing that
sentence says this repository is not — a SECOND chart between an
estate's GitOps tool and the server, owning a release upstream's chart
already owns, for no reason the plugin catalog itself needs.

A values preset also matches how every other part of this shape already
ships: `tlsReload` (`charts/openbao-ops`) has been "a fragment for the
upstream chart, not an object of its own" since before this package
existed, spliced into `server.extraContainers` by hand or by a subchart
`include`; `Config.Values` and `Config.RetrySidecarContainer` are the
same kind of fragment, rendered in Go instead of Helm because the
validation they need — the mixed-architecture refusal, the HCL-safety
check on every plugin field, the download-behavior refusal — is
render-time logic a values file has no way to express, and a Go type is
exactly what an estate that wants that validation reused rather than
copied is already set up to `go get`.

## Migration note: adopting the preset with an empty diff

An install that already hand-authors this HCL — the shape this very
document's reference example has shown since before the plugin catalog
existed — adopts `pkg/serverpreset` by construction, not by rewrite: give
`Config` the same values the hand-written HCL already has (the same
`Arch` resolved from the same node selector, the same `Seal.Region` and
`KMSKeyID`, the same `Raft.Peers`, the same `Plugin` entries with the
same checksums) and `Config.HCL()` renders the identical text, because it
renders the reference shape in the reference order (see
`TestHCLOrderMatchesReferenceShape`,
[`pkg/serverpreset`](../pkg/serverpreset)) — the same `ui`,
`disable_standby_reads`, listener, Raft, seal, `service_registration`,
plugin block, audit device sequence this document's own example has
always used. Diffing the two is the adoption check: a real difference
means an input was carried over wrong, not that the preset renders
something new.

What moves out of the hand-authored values at the same time:
`server.volumes`/`server.volumeMounts` for the plugin directory become
`Config.Values(volumeName)`'s output, merged in the same place; and the
plugin-retry loop, wherever it was hand-copied into an existing sidecar
script, becomes its own container from `Config.RetrySidecarContainer` —
which needs nothing from an existing `tlsReload` container it replaces
beyond the `shareProcessNamespace: true` both already required.

Nothing about `bao operator init`, the recovery-key ceremony, or an
already-running cluster's data changes: this is a values-file migration
on the NEXT config roll (`OnDelete`, above), not a data migration, and
the plugin rollout runbook's canary-one-standby-first order applies to it
exactly as it would to a hand-edited HCL change.
