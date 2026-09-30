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
        # Up to OpenBAO 2.6 the seal is built in. From 2.7 it is an external
        # plugin, installed before the server starts: see "The seal as a
        # plugin (OpenBAO 2.7)" below for the extra stanza and init container.
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

## The seal as a plugin (OpenBAO 2.7)

From OpenBAO 2.7.0 the `awskms` seal is no longer built into the binary. It
is an external KMS plugin (`kms-aws` in
[openbao-plugins](https://github.com/openbao/openbao-plugins)), and a server
whose config still says `seal "awskms" {}` alone exits at startup with
`Error configuring seal "awskms": unknown wrapper: awskms`. 2.6 already
supports the plugin form (a plugin shadows the built-in seal), so the change
can be staged.

A seal is different from every other plugin in one way that decides the
design: **it cannot wait for the server to be Ready.** The auth plugin's
download can fail, be retried by a sidecar and land minutes after the pod
started; the server is sealed, unusable and never becomes Ready until the seal
plugin's binary is on disk and running. So the binary must be in
`plugin_directory` before `bao server` starts, and nothing about getting it
there may depend on the network, on a retry, or on the server being up.

### What the preset renders

`Seal.Plugin` (a `serverpreset.SealPlugin`) switches the mode. It is
explicit, not inferred from a version: `Config.ServerVersion` is only a guard
(from 2.7 a seal with no `Plugin` is refused; below 2.6 a `Plugin` is
refused). With `Seal.Plugin` nil the 2.6 rendering is byte for byte what it
was. With it set, the HCL gains a `plugin "kms"` block (plus
`plugin_directory`, once, whatever else declares plugins), and the values
gain an init container and an image volume:

```hcl
seal "awskms" {
  region     = "eu-example-1"
  kms_key_id = "alias/openbao-unseal"
}
plugin "kms" "awskms" {
  command = "kms-awskms-v0.1.0"      # a file in plugin_directory; <kind>-<seal>-<version>
  version = "v0.1.0"
}
plugin_directory = "/openbao/plugins"
```

```yaml
server:
  extraInitContainers:
    - name: seal-plugin-install
      image: openbao/openbao:2.7.0          # the server's own image: it has sh, cp, chmod, mv
      command: [/bin/sh, -c]
      args: [ "...copy, verify, rename..." ]  # see examples/server/values-2.7.yaml
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
      volumeMounts:
        - { name: openbao-plugins, mountPath: /openbao/plugins }               # the emptyDir the server also mounts
        - { name: seal-plugin-src, mountPath: /seal-plugin-src, readOnly: true }
  volumes:
    - name: openbao-plugins
      emptyDir: {}
    - name: seal-plugin-src                 # mounted by the init container only
      image:
        reference: ghcr.io/openbao/openbao-plugin-kms-aws@sha256:<manifest-list digest>
        pullPolicy: IfNotPresent
```

[`examples/server`](../examples/server) has the whole thing
(`Config27`, `Values27`), with
[`values-2.7.yaml`](../examples/server/values-2.7.yaml) as its golden, and
`values.yaml` (2.6) unchanged beside it.

### Why an init container over an image volume, and not the alternatives

The plugin's image is `FROM scratch`: the binary and nothing else, no shell.
So the init container cannot run *from* it; it runs from the server's own
image and reads the plugin image through an **image volume** that only it
mounts. The kubelet pulls that image by digest, through whatever mirror the
node is configured with, and the pod itself needs no egress for it.

| Delivery | Verdict |
|---|---|
| **Init container copying from an image volume** (the default, `DeliveryInitCopy`) | No network from the pod, so the network-policy-agent race that broke the first OCI download of the auth plugin cannot happen; pinned by manifest-list digest (the kubelet resolves the node's architecture); runs on every pod start against a fresh `emptyDir`; leaves a writable plugin directory the OCI-downloaded auth plugins can share. |
| Image volume mounted **as the plugin directory itself** | Rejected, and shown wrong on a real kubelet: the image ships the binary as mode `0644`, so `exec` fails with `Permission denied`; the volume is read-only, so it cannot share `plugin_directory` with the auth plugin's downloads (there is one directory); and it fixes the on-disk name to the image's own. (A single-FILE `subPath` from an image volume is refused by containerd outright.) |
| The server downloads it (`plugin "kms" { image = ... }`, `plugin_auto_download`) | Rejected: it needs pod egress to a registry at the one moment the network policy has not caught up, and a failed download with `plugin_download_behavior = "continue"` starts a server that can never unseal, while `"fail"` crash-loops it. There is nothing to retry into: the retry sidecar signals a server that must already be running. `Config.Validate` refuses a `kms` entry in `Plugins`. |
| An init container running `bao plugin init` | Would work (not rehearsed), but needs pod egress to the registry (or an in-cluster mirror) at start, which is what the default deliberately avoids. |
| The binary baked into a custom server image (`DeliveryPreinstalled`) | Supported: the preset renders only the HCL and the plugin directory, and the server refuses to start if the file is not there. Nothing here verifies it; the adopter owns that. |

The init container writes the copy beside its destination and renames it,
sets it executable (the image's mode is `0644`), and, when
`SealPlugin.SHA256ByArch` is set, verifies the checksum before it installs
anything. It exits non-zero if the image lacks the binary; the pod then never
starts a server that could not unseal.

**Cluster requirement.** Image volumes: a Kubernetes release with the
`ImageVolume` feature (beta since 1.33, off by default until it is enabled by
default in later releases; check `kubectl explain pod.spec.volumes.image`)
and a container runtime that supports it (containerd 2.1 or later). On a cluster without it the pod is not admitted, which is the loud,
early failure a seal wants; use `DeliveryPreinstalled` there.

### Startup requirements the preset refuses to violate

`Config.Validate`, `HCL`, `Values` and `SealHCL` refuse, at render time, a
seal plugin that cannot be satisfied at startup:

- a plugin directory that is not an absolute path (it must exist when the
  server starts; the emptyDir plus the init container guarantee it);
- an image with a tag, a digest inside it, or none; a digest that is not
  `sha256:<64 hex>` (a tag alone is never enough);
- no `CopyImage` (the init container's image), no `Version`;
- a `Plugins` entry of kind `kms` (a KMS plugin is never downloaded by the
  server);
- a server below 2.7 with no checksum for `Config.Arch` (2.6 refuses a
  manually installed plugin with no checksum: `error verifying checksum: no
  checksum provided`), and any checksum map that lacks `Config.Arch`;
- `ServerVersion` 2.7 or later with a seal and no `Plugin`.

`plugin_download_behavior` is unchanged and applies to the auth plugins only;
the seal plugin is not in the download set, so `"continue"` cannot hide a
missing seal plugin. The retry sidecar does not watch it either, for the same
reason: it would signal a server that has to be running already.

### Egress and configuration reload

- The pod's egress does not change: KMS (`Seal.Endpoint`'s host when set,
  else `kms.<region>.amazonaws.com`), plus whatever the auth plugins need.
  The plugin image is pulled by the kubelet. Point `SealPlugin.Image` at your
  own mirror or pull-through cache if the nodes cannot reach the public
  registry; nothing else changes. `Config.EgressDomains()` therefore adds
  nothing for the seal plugin.
- The upstream chart copies the rendered HCL to a scratch file at start, and
  the StatefulSet is `OnDelete`: a change to the seal plugin's `Version`,
  `Digest` or `Image` reaches a pod only when it is deleted. (2.7 reloads KMS
  plugin stanzas on `SIGHUP`, but that reads the copy, not the ConfigMap;
  roll the pod.) The plugin file name carries the version, so a new version is
  a new file, not an in-place overwrite of a running binary.

### Other 2.7 changes that touch this shape

| 2.7 change | Here |
|---|---|
| `file` storage removed | Not used by the preset (Raft). The conformance tests that booted `file` storage now use single-node Raft. |
| Raft `path` created if missing | Nothing to do; the preset's emptyDir/volume paths already exist. |
| Declarative `plugin` no longer needs `sha256sum` for a manually installed binary | Optional for the seal plugin from 2.7; required on 2.6.x (see above). |
| `plugin_auto_register` defaults to `true` | The preset already renders it explicitly for the auth plugins. |
| Built-in `ldap`, `kerberos`, `radius` auth and `ldap` secrets removed | Not used by this repository's model. An estate that mounts one installs the plugin from openbao-plugins. |
| PKI refuses FQDNs ending in `.` | This repository's roles and certificates carry no trailing dot. |
| Go module `github.com/openbao/openbao/v2` | This module imports no OpenBAO Go module; nothing to change. |

### Proof

`just rehearse-seal-plugin` ([`conformance/seal_plugin_test.go`](../conformance/seal_plugin_test.go);
needs Docker 28 or later and network for the image pulls, so not part of `just
test`) boots real `bao server`s from the exact rendered HCL on a Docker
network with **no route out** (no internet, no registry, no DNS) and the KMS
emulated by a sibling container only they can reach, with the plugin installed
by the init container the preset renders, run as rendered (its image, script,
mounts and user), a Docker image mount standing in for the kubelet's image
volume. It proves:

- a 2.7.0 server given the 2.6 rendering exits (`unknown wrapper: awskms`), and
  one given the plugin form but no binary exits (`no such file or
  directory`), never serving sealed;
- a **cold start** initializes and unseals; a **container restart** and a
  **pod restart** (empty plugin directory, init container again) unseal with
  no help;
- 2.6.3 runs the same plugin (`builtin: false`) and then 2.7.0 on the same
  data, so the seal change and the version change can be two rolls;
- a **three-voter Raft cluster rolls 2.6.3 to 2.7.0**, standbys first, the
  active node last, snapshot first: after every node all three are unsealed,
  Raft shows three voters and a write commits; a standby reverted to 2.6.3
  and the 2.6 rendering rejoins and unseals; a full restart of all three at
  once unseals unaided.

The rendered pod shape was also run once on a throwaway kind cluster
(Kubernetes 1.36, `ImageVolume` on) to confirm the kubelet mounts the image
volume, the init container installs an executable binary as uid 100, and the
plugin runs; that run is manual, not part of the recipe.

### Runbook: 2.6 to 2.7 with the KMS seal plugin

Order matters and every step has a stop condition. The StatefulSet is
`OnDelete`, so nothing rolls until you delete a pod.

**Before anything**

1. Confirm the cluster supports image volumes: run a throwaway pod that
   mounts any small image as a volume, or use `DeliveryPreinstalled`.
2. Resolve the pins. From the plugin release
   (`kms-aws-v<version>` in openbao-plugins) take the version, the
   manifest-list digest of `ghcr.io/openbao/openbao-plugin-kms-aws:<version>`
   (mirror the image if the nodes cannot reach the registry, and pin the
   mirror's digest, which is identical for a bit-for-bit copy), and, if you
   stage on 2.6.x, the raw-binary checksum for every architecture from
   `checksums-kms-aws.txt`. Render `Config` with `ServerVersion` set.
3. Read the 2.7 removals above against your configuration.
4. **Snapshot first.** `bao operator raft snapshot save` from the active node
   and copy it off the cluster (the snapshot job of `openbao-ops` does the
   same); confirm the restore check is green. This is the only way back once
   a 2.7 node has been the active node.
5. Confirm you hold the recovery keys and that KMS access is unchanged (the
   seal's key and IAM are untouched by this change).

**Optional stage: the plugin on 2.6.x, no version change.** Merge the values
with `Seal.Plugin` (and checksums) with the image still 2.6.x, then roll as
below. A server that came up with the plugin logs `Auto Seal: awskms
(builtin: false, ...)`. This proves the plugin path on the version you run
before the version changes; the direct roll is also rehearsed, so this is
extra caution, not a requirement.

**The roll** (repeat for each pod):

1. Merge the change: the 2.7 image on the server and on the init container's
   `CopyImage`, and the seal plugin values (`extraInitContainers`, the two
   volumes, the HCL with the plugin block).
2. **Standbys first, the active node last.** Find the active node with
   `bao status` (`HA Mode`); address each pod directly. Delete one standby.
3. Wait until **all** hold, and only then go on:
   - the init container completed: its log ends
     `seal-plugin-install: installed /openbao/plugins/kms-awskms-<version>`;
   - the server is unsealed by itself: `bao status` shows `Sealed false`,
     `Seal Type awskms`, `Version 2.7.x`, and the server log has `Auto Seal:
     awskms (builtin: false ...)`;
   - `bao operator raft list-peers` shows every voter healthy, and a write
     commits (`bao kv put` then `get` through another node).
4. **Stop at the first pod that is not Ready.** Do not delete the next one.
   What the symptoms mean:
   | Symptom | Cause |
   |---|---|
   | pod stuck `Init:0/1` or `ContainerCreating`, event `ErrImagePull` or unsupported volume type | the kubelet cannot pull the plugin image (mirror, digest) or has no image volumes |
   | init container `Error`: `does not match the pinned checksum` | the checksum belongs to another version or architecture |
   | init container `Error`: `missing or empty` | the image has no binary at its root (wrong image) |
   | server exits: `unknown wrapper: awskms` | the HCL was rendered for 2.6 (no `Seal.Plugin`) |
   | server exits: `lstat ...: no such file or directory` | the plugin file or `plugin_directory` is missing (init container removed, or a different mount) |
   | server exits: `no checksum provided` | a 2.6.x server and no `sha256sum` |
   | unsealed but the KMS health check warns | KMS reachability or IAM, unchanged by this change; it is not the plugin |
5. Roll the second standby the same way, then the active node last (one
   election at the end).
6. After the last pod: a full pass of step 3 on every node, and the alerts
   that page on a sealed node are quiet.

**Revert.** Before the active node has run 2.7, a node that misbehaves goes
back by itself: restore the previous values (the 2.6 rendering is unchanged:
built-in seal, 2.6 image, no init container) and delete its pod; it rejoins on
its own data and unseals (rehearsed for a standby). Once the active node has
run 2.7, do not run a 2.6 binary against that data: restore the snapshot into
a fresh 2.6.x cluster (or roll forward). Stopping at the first not-Ready pod
is what keeps the first case the only one you meet.

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

`Config.HCL()` and `Config.Values()` refuse an empty `Listener.Address`, a
Raft with peers but no `Path` or a peer with no `LeaderAPIAddr`, and a
Config with no Raft peers unless `ExternalStorage` is set (the storage
backend is configured outside the preset): a server with no storage block
does not start. `PluginHCL`, `SealHCL` and `EgressDomains` need neither and
stay usable on a bare Config. `Config.CheckMounts(desired)` is an opt-in
cross-check of the two plugin registration paths: a mount's `pluginVersion`
must be a declarative `Plugin`'s `Version`, and an unpinned mount needs a
`Desired.Plugins` entry (those are registered unversioned, so they cannot
satisfy a pin).

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
