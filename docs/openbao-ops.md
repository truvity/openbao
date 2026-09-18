# openbao-ops

The operational half of an OpenBAO install, beside the upstream server
chart. Every part is off until enabled, so one install can carry any subset
— including a second install that renders only the serving certificate,
when the certificate belongs to a different deployment than the jobs.

| Part | Objects | What it proves or prevents |
|---|---|---|
| `snapshot` | ServiceAccount, one CronJob per tier | a backup exists, and it opened before it was stored |
| `restoreCheck` | ServiceAccount, ConfigMap, CronJob | the newest backup restores, its data reads back, and its PKI still issues on the chain you trust |
| `certificateExpiry` | ServiceAccount, Role, RoleBinding, CronJob | a serving certificate that stopped renewing is noticed weeks before it ends |
| `networkPolicy` | NetworkPolicies, egress policies | clients reach the API only, peers reach Raft only, the jobs are reachable by nothing |
| `serverCertificate` | Certificate | the serving certificate, with the names clients verify |
| `tlsReload` | *(a fragment for the upstream chart)* | a renewed certificate is served without a restart — see [server.md](server.md) |

Object names are values, never derived from the release name, so an estate
that already runs these objects can adopt the chart without renaming —
and without a delete and recreate — anything.

## Contracts

Object storage and alerting are containers with a contract. Each has a
preset (S3, SNS) and takes any image that honours the contract instead.

| Container | Reads | Environment | Must |
|---|---|---|---|
| `snapshot.upload` | `/work/openbao.snap`, `/work/taken-at` | `SNAPSHOT_PREFIX`, `HOME` | store the bytes at `$SNAPSHOT_PREFIX<taken-at>.snap` |
| `restoreCheck.fetch` | the store | `MAX_SNAPSHOT_AGE_SECONDS`, `HOME` | write the newest snapshot to `/work/openbao.snap` and its name to `/work/key`, and **fail** when it is older than the limit |
| `certificateExpiry.alert` | `/work/status`: notAfter, the Ready status, its message, one per line | `ALERT_BEFORE_SECONDS`, `HOME` | alert and exit non-zero when fewer seconds than that are left |

Identities are the estate's to grant, least privilege each:

| Identity | OpenBAO | Object storage / alerting | Kubernetes |
|---|---|---|---|
| `snapshot` | read `sys/storage/raft/snapshot` | write under the prefixes; no list, no read | none (no token automounted) |
| `restoreCheck` | on the RESTORED copy: read the canaries, issue from `pki.role` | read the newest snapshot; decrypt with the seal's key | none |
| `certificateExpiry` | none | publish to one topic | `get` on one Certificate (the chart's Role) |

The jobs log in with a projected ServiceAccount token for `auth.audience`,
at most `auth.expirationSeconds` old, on the JWT mount `auth.mountPath`.

## The restore check

One pod, three containers:

1. `fetch` (init) — the newest snapshot, refused when older than
   `maxSnapshotAgeSeconds`: a stale newest snapshot means the snapshot job
   stopped, which is the failure this check exists to find.
2. `server` (native sidecar) — a scratch OpenBAO on `127.0.0.1` only, TLS
   off, storage on an emptyDir, under `sealConfig`. It holds a full
   plaintext copy of production for the life of the pod, so it admits no
   ingress (`networkPolicy`) and dies with the check.
3. `check` — initialises the scratch, restores the snapshot over it, and
   logs in **as the snapshot's own identity** (the scratch root token dies
   with the restore). Then:
   - **canary**: in every namespace (listed, or every one the restored copy
     lists), `<kvMount>/<path>` must read exactly
     `{namespace: <that namespace>}`;
   - **pki** (optional): stages your committed root in the token's
     cubbyhole and walks `bao pki verify-sign` from it to the domain
     intermediate and to every namespace's issuing CA — signature, path,
     key id, subject and trust, which also checks path length and name
     constraints. It proves the restricted role refuses a wildcard, a
     subdomain, IP, URI and e-mail SANs, then issues one leaf per namespace,
     checks the issuer stored it, and walks it to its issuing CA.

The PKI walk expects a two-tier hierarchy under an offline root:

```
<trustAnchor>                                  your committed root (never the restored copy's)
└── <intermediate.mount>/issuer/<intermediate.issuer>          root namespace
    └── <ns>/<issuing.mount>/issuer/<issuing.issuerPrefix>-<ns>  one per namespace
        └── <role>.<ns>.<domain>                                 a fresh leaf, from <ns>/<issuing.mount>/issue/<role>
```

## Values

### Common

| Value | Default | Description |
|---|---|---|
| `commonAnnotations` | `{}` | Added to every object. Each part's `annotations` are merged over it. |
| `namespace` | `""` | Where every object lives. Empty: the release namespace. |
| `server.address` | `""` | The API address the jobs dial. Empty: `https://<activeService>.<namespace>.svc:<apiPort>`. |
| `server.activeService` | `openbao-active` | The Service that resolves to the active pod. Writes must not land on a standby. |
| `server.service` | `openbao` | The main Service; one of the certificate's in-cluster names. |
| `server.headlessService` | `openbao-internal` | The Service peers dial each other through; the certificate carries a wildcard over it. |
| `server.apiPort` | `8200` | API port, in the default address and the policies. |
| `server.clusterPort` | `8201` | Raft port, open between peers only. |
| `server.tlsSecretName` | `openbao-tls` | The serving certificate's Secret — and the Certificate's name. |
| `server.caKey` | `ca.crt` | The key in that Secret the snapshot job verifies the server with. |
| `server.tlsServerName` | `""` | The name the jobs verify the server against when it is not the name they dial (`BAO_TLS_SERVER_NAME`). Set it when the certificate names only the endpoint. |
| `server.podLabels` | `app.kubernetes.io/name: openbao`, `component: server` | How the server pods are selected by the policies. |
| `auth.mountPath` | `jwt` | The JWT auth mount the jobs log in to. |
| `auth.audience` | `openbao` | The audience of the jobs' projected token. A token for this audience cannot be replayed against the Kubernetes API. |
| `auth.expirationSeconds` | `600` | The projected token's lifetime (600–86400). |
| `auth.tokenMountPath` | `/var/run/openbao` | Where the token is mounted; the jobs read `<tokenMountPath>/token`. |

### snapshot

| Value | Default | Description |
|---|---|---|
| `enabled` | `false` | Render the snapshot jobs. |
| `serviceAccountName` | `openbao-snapshot` | The ServiceAccount, and the pods' `app.kubernetes.io/name` label the policies select. |
| `serviceAccountAnnotations` | `{}` | On the ServiceAccount only, over `annotations` (e.g. a cloud role binding). |
| `annotations` | `{}` | On every object of the part. |
| `baoRole` | `openbao-snapshot` | The OpenBAO role the job logs in as. |
| `jobs` | 6-hourly `raft/`, weekly `weekly/` | One CronJob per entry: `name`, `schedule`, `prefix`. A prefix per tier lets a lifecycle rule expire tiers differently. The weekly copy is a snapshot of its own, never a copy of an object: the writer cannot read. |
| `timeZone` | `Etc/UTC` | The CronJobs' time zone. |
| `startingDeadlineSeconds` | `3600` | A run that starts late is still worth taking. |
| `activeDeadlineSeconds` | `900` | Per run. |
| `backoffLimit` | `2` | Retries per run. |
| `workSizeLimit` | `2Gi` | The emptyDir the snapshot is written to. |
| `nodeSelector`, `tolerations` | none | Pod placement. |
| `image` | `openbao/openbao:2.6.2` | Takes and verifies the snapshot. Keep it equal to the server's image. `repository`, `tag`, `digest` (wins over the tag), `pullPolicy` (empty: the cluster default). |
| `resources` | 10m / 64Mi, limit 256Mi | The snapshot container. |
| `upload.image` | `amazon/aws-cli:2.36.44` | The uploader. |
| `upload.command`, `upload.args`, `upload.env` | none | A replacement uploader (the contract above). |
| `upload.resources` | 10m / 128Mi, limit 512Mi | |
| `upload.s3.enabled` | `false` | The S3 preset: `aws s3 cp` with a checksum. |
| `upload.s3.bucket`, `upload.s3.region` | `""` | Required with the preset. |
| `upload.s3.checksumAlgorithm` | `SHA256` | Sent with every object. |

### restoreCheck

| Value | Default | Description |
|---|---|---|
| `enabled` | `false` | Render the weekly restore check. |
| `serviceAccountName` | `openbao-restore-check` | The ServiceAccount, ConfigMap and CronJob, and the pods' label. |
| `serviceAccountAnnotations`, `annotations` | `{}` | As for `snapshot`. |
| `baoRole` | `openbao-restore-check` | The role the check logs in as on the restored copy. |
| `schedule` | `37 5 * * 0` | Sundays, after the snapshots. |
| `timeZone`, `startingDeadlineSeconds` | `Etc/UTC`, `3600` | |
| `activeDeadlineSeconds` | `1200` | |
| `backoffLimit` | `1` | |
| `workSizeLimit` | `2Gi` | The snapshot's and the scratch server's emptyDirs. |
| `nodeId` | `restore-check` | The scratch server's Raft node id. |
| `nodeSelector`, `tolerations` | none | |
| `maxSnapshotAgeSeconds` | `43200` | A newest snapshot older than this fails the check. |
| `image` | `openbao/openbao:2.6.2` | The scratch server and the check. Keep it equal to the server's image. |
| `sealConfig` | *required* | Raw HCL of the scratch server's seal. A snapshot opens only under the seal that wrapped its keyring — the same key, or a replica of it; a replica in another region proves a snapshot opens without the primary region. |
| `sealDescription` | `""` | How the pass line names that seal. |
| `auditConfig` | a `file` device to stdout | Raw HCL of the scratch server's audit devices. OpenBAO refuses API-created audit devices, so declare them exactly as production does. |
| `serverEnv` | none | The scratch server's environment (e.g. the seal's region). |
| `serverResources` | 50m / 128Mi, limit 512Mi | |
| `resources` | 10m / 64Mi, limit 256Mi | The check container. |
| `fetch.*` | as `snapshot.upload` | The fetcher: `image`, `command`, `args`, `env`, `resources`, and the S3 preset `s3.enabled`, `s3.bucket`, `s3.region`, `s3.prefix` (`raft/`: the tier it restores from). |
| `canary.enabled` | `true` | Read a canary back in every namespace. At least one of `canary` and `pki` must be on. |
| `canary.kvMount` | `kv` | The KV v2 mount holding the canary. |
| `canary.path` | `restore-canary` | Its path. Its data must be exactly `{namespace: <the namespace's name>}`. |
| `canary.namespaces` | `[]` | Empty: every namespace the restored copy lists, and none listed is a failure. |
| `pki.enabled` | `false` | Walk and exercise the restored PKI. |
| `pki.trustAnchor.certificate` | *required* | Base64 PEM of the root you committed. |
| `pki.trustAnchor.name` | `""` | Its name, for the pass line. |
| `pki.intermediate.mount`, `pki.intermediate.issuer` | `pki-int`, *required* | The domain intermediate the root signed, in the root namespace. |
| `pki.issuing.mount`, `pki.issuing.issuerPrefix` | `pki`, *required* | Each namespace's issuing CA: `<ns>/<mount>/issuer/<issuerPrefix>-<ns>`. |
| `pki.namespaces` | *required* | The namespaces with an issuing CA; one leaf is issued in each. |
| `pki.role` | `restore-check` | The issuing role; it should allow exactly `<role>.<ns>.<domain>`. |
| `pki.domain` | *required* | |
| `pki.ttl` | `1h` | The leaves' lifetime. |
| `pki.refusals.enabled` | `true` | Prove the role refuses a wildcard, a subdomain, IP, URI and e-mail SANs. |
| `pki.refusals.namespace` | `""` | Where; empty: the first of `pki.namespaces`. |

### certificateExpiry

| Value | Default | Description |
|---|---|---|
| `enabled` | `false` | Render the daily expiry check. |
| `name` | `openbao-tls-expiry` | The ServiceAccount, Role, RoleBinding and CronJob, and the pods' label. |
| `annotations` | `{}` | On every object of the part. |
| `certificateName` | `""` | The Certificate to read. Empty: `server.tlsSecretName`. |
| `clusterName` | `""` | Named in the alert. |
| `certManagerNamespace` | `cert-manager` | Named in the alert's "look at" line. |
| `schedule`, `timeZone` | `23 7 * * *`, `Etc/UTC` | Daily: one alert a day while it lasts. |
| `startingDeadlineSeconds`, `activeDeadlineSeconds`, `backoffLimit` | `3600`, `300`, `0` | |
| `alertBeforeSeconds` | `1814400` | 21 days. Must be less than the renewal lead time: an alert before renewal has started is noise. |
| `renewBeforeSeconds` | `0` | The renewal lead time, for the alert text. `0`: `serverCertificate.renewBefore`, which must then be whole hours. |
| `nodeSelector`, `tolerations` | none | |
| `read.image`, `read.resources` | `alpine/kubectl:1.34.2`, 10m / 32Mi | Reads the Certificate's status. |
| `alert.image` | `amazon/aws-cli:2.36.44` | |
| `alert.command`, `alert.args`, `alert.env`, `alert.resources` | none | A replacement alert (the contract above). |
| `alert.sns.enabled` | `false` | The SNS preset: publish, then fail the run. |
| `alert.sns.topicArn`, `alert.sns.region` | `""` | Required with the preset. |
| `alert.sns.runbook` | `""` | A last line of the message: where the way back is written down. |

### networkPolicy

| Value | Default | Description |
|---|---|---|
| `enabled` | `false` | Render the policies. |
| `annotations` | `{}` | On every policy. |
| `names.serverIngress` | `openbao-ingress` | The server's ingress policy. |
| `names.restoreCheckIngress` | `openbao-restore-check-ingress` | Rendered with `restoreCheck`: nothing may connect in. |
| `names.certificateExpiryIngress` | `openbao-tls-expiry-ingress` | Rendered with `certificateExpiry`: nothing may connect in. |
| `clientCidrs` | *required* | The ranges that may reach the API port. |
| `extraClientSelectors` | `[]` | More API clients, as raw NetworkPolicyPeer entries. |
| `isolated` | `[]` | More pods nothing may connect to (`name`, `podSelector`), e.g. a hand-run rebuild drill that holds a restored copy. |
| `egress.enabled` | `false` | Render `egress.rules`. |
| `egress.rules` | `[]` | Whole egress policies: `name`, `podSelector`, `egress` (passed through), and optionally `apiVersion` and `kind` — a standard NetworkPolicy is CIDR-based, and a CNI extension that names hosts has its own kind. |

The server's ingress admits `clientCidrs` and `extraClientSelectors` to the
API port, the server's own pods to the API and Raft ports, and — with
`snapshot` — the snapshot pods to the API port.

### serverCertificate

| Value | Default | Description |
|---|---|---|
| `enabled` | `false` | Render the Certificate (named `server.tlsSecretName`). |
| `externalDnsName` | `""` | The endpoint clients outside the cluster use; first in the SAN list. |
| `commonName` | `""` | Empty: `externalDnsName`. |
| `serviceDnsNames` | `true` | Add the Services' in-cluster names and a wildcard over the peers. Turn it off for a name-constrained chain that cannot carry them; clients then verify the endpoint (see [server.md](server.md)). |
| `extraDnsNames` | `[]` | More names. The chart deliberately never names a load balancer, so a replaced one needs no reissue. |
| `ipAddresses` | `[127.0.0.1]` | IP SANs, for the in-pod CLI. `[]` with a name-constrained chain. |
| `duration`, `renewBefore` | `2160h`, `720h` | 90 days, renewed a month before the end. |
| `privateKey` | ECDSA 256, rotation Always | Must match what the issuer's role signs: a CSR that disagrees is refused, not downgraded. |
| `issuerRef` | *name required* | The estate's issuer. |
| `annotations` | `{}` | On the Certificate. |

### tlsReload

The sidecar fragment `ops.tlsReloadContainer`, for the upstream chart —
see [server.md](server.md).

| Value | Default | Description |
|---|---|---|
| `intervalSeconds` | `60` | How often the certificate file is compared. |
| `certPath` | `/openbao/userconfig/openbao-tls/tls.crt` | The file watched. |
| `volumeName`, `mountPath` | `userconfig-openbao-tls`, `/openbao/userconfig/openbao-tls` | The upstream chart's volume for the TLS Secret. |
| `image` | `openbao/openbao:2.6.2` | Needs `sh`, `cksum`, `tr` and `kill`: the server image has them. |
| `resources` | 5m / 8Mi, limit 32Mi | |
