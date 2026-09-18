# Reference

Every value of both charts. `charts/<chart>/values.yaml` carries the same
keys with their defaults and a comment each, and `values.schema.json` is
the authority on types: an unknown key fails the render.

Every object name is a value, and none carries the release name or Helm's
own labels — the names below are what an existing install adopts
([adoption.md](adoption.md#adopting-objects-that-already-run)).

## openbao-ops

Every part is off until enabled, so one install can carry any subset.

| Part | Objects |
|---|---|
| `snapshot` | ServiceAccount, one CronJob per tier |
| `restoreCheck` | ServiceAccount, ConfigMap, CronJob |
| `certificateExpiry` | ServiceAccount, Role, RoleBinding, CronJob |
| `networkPolicy` | the server's ingress, an ingress deny per job pod and per `isolated` entry, `egress.rules` |
| `serverCertificate` | Certificate |
| `tlsReload` | nothing: a fragment for the upstream chart |

### Top level, `server`, `auth`

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
| `serviceDnsNames` | `true` | Add the Services' in-cluster names and a wildcard over the peers. Turn it off for a name-constrained chain that cannot carry them; clients then verify the endpoint (see [server.md](server.md#verifying-one-name)). |
| `extraDnsNames` | `[]` | More names. The chart deliberately never names a load balancer, so a replaced one needs no reissue. |
| `ipAddresses` | `[127.0.0.1]` | IP SANs, for the in-pod CLI. `[]` with a name-constrained chain. |
| `duration`, `renewBefore` | `2160h`, `720h` | 90 days, renewed a month before the end. |
| `privateKey` | ECDSA 256, rotation Always | Must match what the issuer's role signs: a CSR that disagrees is refused, not downgraded. |
| `issuerRef` | *name required* | The estate's issuer. |
| `annotations` | `{}` | On the Certificate. |

### tlsReload

The sidecar fragment `ops.tlsReloadContainer`, for the upstream chart —
see [server.md](server.md#reloading-a-renewed-certificate).

| Value | Default | Description |
|---|---|---|
| `intervalSeconds` | `60` | How often the certificate file is compared. |
| `certPath` | `/openbao/userconfig/openbao-tls/tls.crt` | The file watched. |
| `volumeName`, `mountPath` | `userconfig-openbao-tls`, `/openbao/userconfig/openbao-tls` | The upstream chart's volume for the TLS Secret. |
| `image` | `openbao/openbao:2.6.2` | Needs `sh`, `cksum`, `tr` and `kill`: the server image has them. |
| `resources` | 5m / 8Mi, limit 32Mi | |

## openbao-consumers

Stores and PKI are independent: an install may render either or both.

| Part | Objects |
|---|---|
| `stores` | one ClusterSecretStore per kind, `<name>-<storeSuffix>` |
| `writers` | one ClusterSecretStore per (writer, environment), `<name>-<environment>` |
| `pki.trustAnchors` | one ConfigMap per root, in `pki.certManager.namespace` |
| `pki.issuers` | the login's ServiceAccount, Role and RoleBinding (`<issuerServiceAccount>-token`), and one issuer per entry |
| `pki.bundle` | a trust-manager Bundle |
| `certificates` | one Certificate per entry |

| Value | Default | Description |
|---|---|---|
| `commonAnnotations` | `{}` | Added to every object; per-object `annotations` are merged over it. |
| `server` | `""` | The OpenBAO endpoint. Required when a store or an issuer renders. |
| `caBundle` | `""` | Base64 PEM of the CA that signed the server's certificate. Required when a store or an issuer renders. |
| `vaultNamespace` | `""` | The OpenBAO namespace stores and issuers address. Empty on an install without namespaces. |
| `kvMount` | `kv` | The KV v2 mount every store reads and writes. |
| `storeSuffix` | `openbao` | A reader store is `<name>-<storeSuffix>`, distinguishable from a same-named store on another provider during a migration. |
| `auth.mountPath` | `jwt` | This cluster's JWT auth mount — usually named after the cluster. Issuers log in on it as `/v1/auth/<mountPath>`. |
| `auth.audience` | `openbao` | The stores' token audience. |
| `auth.expirationSeconds` | `600` | The stores' token lifetime (600–86400). |
| `auth.serviceAccount.name`, `.namespace` | `external-secrets`, `external-secrets` | The identity reader stores present. |
| `writerAuthMount` | `""` | The mount writer stores log in on. Empty: `auth.mountPath`. |
| `stores[].name` | *required* | The kind. The store is `<name>-<storeSuffix>`. |
| `stores[].role` | the name | The OpenBAO role, so the policy that bounds a store is findable from the store. |
| `stores[].vaultNamespace` | `vaultNamespace` | |
| `stores[].conditions` | *required* | The namespaces that may use the store. Without them it is readable from every namespace on the cluster. |
| `stores[].annotations` | `{}` | |
| `writers[].name` | *required* | The writer; also its OpenBAO role. |
| `writers[].namespace` | *required* | Where its ServiceAccount lives — the one namespace the store admits. |
| `writers[].serviceAccount` | *required* | The identity the store presents. |
| `writers[].environments` | *required* | One store `<name>-<environment>` per entry, addressing that OpenBAO namespace. |
| `writers[].annotations` | `{}` | |
| `pki.enabled` | `false` | Render the anchors, the issuers and the bundle. |
| `pki.annotations` | `{}` | On the anchors and on the login's ServiceAccount, Role and RoleBinding. |
| `pki.certManager.namespace` | `cert-manager` | Where the anchors, the login and namespaced issuers live; the default namespace of `certificates`. |
| `pki.certManager.serviceAccountName` | `cert-manager` | cert-manager's own identity, bound to mint the login's tokens. |
| `pki.issuerServiceAccount` | `openbao-issuer` | The identity issuers log in as; its Role and RoleBinding are `<name>-token`. |
| `pki.vaultNamespace` | `""` | Default for every issuer; empty: `vaultNamespace`. |
| `pki.trustAnchors` | *required* | Each: `name` (the ConfigMap), `certificate` (base64 PEM), optional `labels`, `annotations`. Public certificates only. |
| `pki.rootKey` | `ca.crt` | The key each anchor's ConfigMap holds its certificate under. |
| `pki.issuers` | `[]` | Each: `name`, `signPath` (the role that bounds what it signs), `role` (the auth role), optional `kind` (`ClusterIssuer` or `Issuer`), `audiences`, `vaultNamespace`, `annotations`. A Vault issuer's path is fixed, so a second chain or role is a second issuer. |
| `pki.bundle.enabled` | `true` | Render the Bundle. |
| `pki.bundle.name` | `openbao-private-ca` | |
| `pki.bundle.annotations` | `{}` | |
| `pki.bundle.extraSources` | `[]` | Sources placed BEFORE the anchors — during a migration, the old root or a Secret-held CA. |
| `pki.bundle.target.key` | `ca-certificates.crt` | The key of the ConfigMap trust-manager writes in each namespace. |
| `pki.bundle.target.namespaceSelector` | `{}` | Where it writes; `{}` is every namespace. |
| `certificateDefaults.duration`, `.renewBefore` | `720h`, `240h` | Renewal at a third of the lifetime: two chances before anything expires. |
| `certificateDefaults.privateKey` | ECDSA 256, rotation Always | Must match what the role signs. |
| `certificates[].name` | *required* | |
| `certificates[].namespace` | `pki.certManager.namespace` | |
| `certificates[].commonName`, `.dnsNames` | one required | `dnsNames` defaults to `[commonName]`. |
| `certificates[].secretName` | `<name>-tls` | |
| `certificates[].issuerRef` | the first of `pki.issuers` | |
| `certificates[].uris`, `.usages` | none | |
| `certificates[].duration`, `.renewBefore`, `.privateKey` | `certificateDefaults` | |
| `certificates[].annotations`, `.labels` | `{}` | |

Two entries that would render the same object — two stores, a store and a
writer, two anchors, two issuers, two certificates or their Secrets — fail
the render instead of overwriting each other.
