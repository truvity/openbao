# Reference

Every value of both charts, then the ceremony's
[hierarchy file](#hierarchy-file), [`openbaoctl`](#openbaoctl), the
[`pkg/custody`](#pkgcustody) inputs, and the desired-state
[`pkg/model`](#pkgmodel) and its [`pkg/apply`](#pkgapply). `charts/<chart>/values.yaml` carries the same
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
| `upload.s3.endpoint` | `""` | Any store that speaks the S3 API. Empty keeps the AWS endpoint; set, it is `AWS_ENDPOINT_URL_S3`, and the CLI's default request and response checksums are turned down to `when_required`, which a store that is not AWS may not implement. Must be an `http(s)` URL. MinIO and Ceph RGW: the store's own URL; Cloudflare R2: `https://<account>.r2.cloudflarestorage.com` with `region: auto`. |
| `upload.s3.pathStyle` | `false` | Address the bucket as `endpoint/bucket/key` rather than `bucket.endpoint/key`: a property of the store's certificate, so its own switch. The CLI reads it from its config file alone; the script writes that one line and `AWS_CONFIG_FILE` names it. |
| `upload.s3.existingSecret` | `""` | A Secret holding `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (and optionally `AWS_SESSION_TOKEN`), given through `envFrom`, for a store with no pod identity. Empty keeps the pod's ambient identity. |
| `upload.s3.checksumAlgorithm` | `SHA256` | Sent with every object, whatever the store. |

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
| `fetch.*` | as `snapshot.upload` | The fetcher: `image`, `command`, `args`, `env`, `resources`, and the S3 preset `s3.enabled`, `s3.bucket`, `s3.region`, `s3.endpoint`, `s3.pathStyle`, `s3.existingSecret`, `s3.prefix` (`raft/`: the tier it restores from). |
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
| `alert.sns.enabled` | `false` | The SNS preset: publish, then fail the run. At most one preset may be on. |
| `alert.sns.topicArn`, `alert.sns.region` | `""` | Required with the preset. |
| `alert.sns.runbook` | `""` | A last line of the message: where the way back is written down. |
| `alert.alertmanager.enabled` | `false` | The Alertmanager preset: one POST, then fail the run. At most one preset may be on. |
| `alert.alertmanager.url` | `""` | Required with the preset: where Alertmanager answers, e.g. `http://alertmanager.example.svc:9093`. The chart appends `/api/v2/alerts`, so a value that is not an `http(s)` origin fails the render. |
| `alert.alertmanager.alertname` | `OpenBAOCertificateExpiring` | The `alertname` label. |
| `alert.alertmanager.severity` | `warning` | The `severity` label. |
| `alert.alertmanager.release` | `""` | The `release` label, which tells two installs apart; empty leaves the label out. A value like every other name here, never Helm's release name. |
| `alert.alertmanager.runbook` | `""` | The `runbook` annotation: where the way back is written down. |
| `alert.alertmanager.image` | `curlimages/curl:8.22.0` | This preset's image, because `alert.image` defaults to the AWS CLI. Anything with a POSIX shell and curl does. |

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

## Hierarchy file

What `openbaoctl pki` reads ([ceremony.md](ceremony.md#the-hierarchy-file)).
Strict: an unknown key is an error. Paths are relative to the file.

| Key | Type | Required | What |
|---|---|---|---|
| `serialNamespace` | string | no, `private-pki` | prefix of every deterministic serial's label (`<ns>-root-serial-v1`, `<ns>-intermediate-serial-v1`, `<ns>-emergency-server-serial-v1`); never change it for an existing root |
| `root.generationId` | string | yes | the generation; part of the root's serial and of every artifact |
| `root.subject.commonName`, `.organization` | string | CN yes | the root's subject; an empty organization is left out |
| `root.notBefore` | RFC 3339 | yes | start of validity; fixed, so the template is reproducible |
| `root.lifetime` | Go duration | yes | e.g. `175200h` |
| `root.maxPathLen` | int ≥ 0 | yes | CA layers below the root; 0 is "leaves only", never unbounded |
| `root.permittedDnsDomains` | list | no | a critical name constraint on the root; omit for none |
| `root.artifact` | path | yes | where the root artifact is written, and `<artifact>.attempt` beside it |
| `intermediates[].trustDomain` | string | yes | the intermediate's name (no spaces or slashes), unique; part of its serial |
| `intermediates[].subject` | as above | CN yes | must equal the CSR's subject exactly |
| `intermediates[].lifetime` | Go duration | yes | from the root's `notBefore`; must end inside the root |
| `intermediates[].permittedDnsDomains` | list | no | a critical constraint that also excludes every IP; each name must sit inside the root's constraint, if any |
| `intermediates[].artifact` | path | yes | the intermediate artifact, and its `.attempt` |
| `emergencyServer.dnsName` | DNS name | for `sign-emergency-server` | the one name a break-glass leaf serves; no wildcard |
| `emergencyServer.lifetime` | Go duration | no, `168h` | at most `720h` |

## openbaoctl

Every signing command asks the KMS key for at most one signature. The
region is read from the key ARN; `--aws-profile` (default: the SDK's
chain) is the identity to start from and `--role-arn` the ceremony role
assumed on top of it.

| Command | Flags | Signs |
|---|---|---|
| `pki create-root` | `--hierarchy`, `--key-arn` (required), `--import-certificate`, `--aws-profile`, `--role-arn` | once, unless the artifact exists or a certificate is imported |
| `pki sign-intermediate` | `--hierarchy`, `--trust-domain`, `--csr` (required); exactly one of `--print-template` or `--confirm-template <sha256>`; `--key-arn` (default: the root artifact's), `--aws-profile`, `--role-arn` | only with `--confirm-template`, once, unless the artifact exists |
| `pki verify-intermediate` | `--hierarchy`, `--trust-domain` (required), `--chain-out` (must not exist; default prints the chain) | never; needs no credential |
| `pki sign-emergency-server` | `--hierarchy`, `--csr` (required); exactly one of `--print-template` or `--confirm-template`; `--not-before` (required to sign: the value `--print-template` printed), `--out` (default `openbao-emergency.crt`, must not exist), `--key-arn`, `--aws-profile`, `--role-arn` | only with `--confirm-template`, once per run; nothing is committed |

## pkg/custody

`custody.Deploy(ctx, custody.Args{...}, opts...)`; `opts` are appended to
every resource and provider ([custody.md](custody.md)).

| Field | Default | What |
|---|---|---|
| `AccountID` | required | the custody account; also every provider's only allowed account |
| `Partition` | `aws` | the partition every ARN is composed in |
| `Profile` | none | the AWS shared-config profile of every provider |
| `TrustedPrincipalARNPattern` | required | `ArnLike` pattern of the human administrators: assume both roles, administer the keys directly |
| `AdminRoleName`, `CeremonyRoleName` | required, distinct | the two roles |
| `PermissionsBoundaryPolicyName` | none | a customer-managed policy in the account, attached to both roles as their boundary |
| `Generations[]` | at least one | `ID`, `Region` (primary), `ReplicaRegion` (must differ); oldest first, additive |
| `Notify` | none | e-mail addresses subscribed to every generation's Sign alarm, in both regions |
| `AliasPrefix` | `alias/private-pki/root/` | alias `<prefix><ID>`, the same in both regions |
| `SignAlertPrefix` | `private-pki-root-sign-` | topic, rule and alarm `<prefix><ID>` |
| `DescriptionPrefix` | `Private PKI root` | key description `<prefix> <ID> (multi-region primary)` / `(DR replica)` |
| `RolesProviderName` | `private-pki-root-primary` | the roles' provider, `provider/aws/<name>`, in the first generation's primary region |
| `DeletionWindowDays` | `30` | 7–30 |
| `Tags` | none | `func(TagScope) map[string]string`, called for `roles`, each generation's `key` and each generation's `sign-alert` |

`Deploy` returns the roles and, per generation, the alias, the regions,
the key and the replica, for the caller's exports.

## pkg/model

The fields of `model.Desired` and what each engine holds; yaml keys in
brackets. [model.md](model.md) explains the shape,
[`desired-one-env.yaml`](../pkg/model/testdata/desired-one-env.yaml) is
the small case and
[`desired.yaml`](../pkg/model/testdata/desired.yaml) spells every field.
Durations are Go durations (`15m`, `720h`).

| Type | Field | Required | What |
|---|---|---|---|
| `Desired` | `Bootstrap` (`bootstrap`) | yes | the root door the apply logs in through; validated, never applied |
| | `Root` (`root`) | yes | what the apply owns in root; no name |
| | `Namespaces` (`namespaces`) | no | one per environment, a plain name each |
| | `Identity` (`identity`) | yes | `primaryDoor`, and `metadata` every identity group carries |
| | `CredentialMaxTTL` (`credentialMaxTtl`) | no | the ceiling on every SSH and credential role |
| `Namespace` | `Name`, `KV`, `PKI`, `SSH`, `Auth`, `Policies`, `Groups` | name outside root | the engines below |
| `KVMount` | `Path`, `Description`, `Canary` | path | a KV v2 mount; the canary is written as `{"namespace": <name>}` |
| `JWTMount` | `Path`, `Type` (empty or `oidc`), `Description`, `ClientID` (oidc), `DefaultRole`, `DiscoveryURL`, `Roles` | path, issuer | one auth mount; the discovery URL is also the bound issuer |
| `Role` | `Name`, `Type`, `BoundAudiences`, `BoundSubject`, `UserClaim`, `GroupsClaim`, `ClaimMappings`, `AllowedRedirectURIs`, `OIDCScopes` (oidc), `Policies`, `TTL` | name, audience, user claim, TTL, and a subject or a groups claim | `TTL` is also the maximum |
| `Group` | `Name`, `Policies`, `Doors` | all | one identity group per door, aliased there by `Name` |
| `Policy`, `Rule` | `Name`, `Rules`; `Path`, `Capabilities` | all | rendered in rule order (`Policy.HCL`) |
| `PKIMount` | `Path`, `Description`, `DefaultLeaseTTL`, `MaxLeaseTTL`, `DefaultIssuer`, `Issuers`, `Roles`, `CredentialRoles` | all but description and roles | the default issuer is pinned |
| `PKIIssuer` | `Name`, `CommonName`, `Organization`, `KeyCurve` (`P-256`, `P-384`, `P-521`), `TTL`, `MaxPathLength`, `NameConstraints`, and one of `SelfSigned`, `SignedBy`, `External` | name, common name, curve, signer; TTL unless external | issuer names are unique across the server |
| `IssuerRef` | `Namespace` (empty for root), `Mount`, `Issuer` | mount, issuer | an issuer of an earlier mount |
| `NameConstraints` | `PermittedDNSDomains`, `ExcludedIPRanges`, `PermittedEmailAddresses`, `PermittedURIDomains` | no | an empty list is left out |
| `PKIRole` | `Name`, `Issuer`, `AllowedDomains`, `AllowBareDomains`, `AllowSubdomains`, `AllowWildcards` (`allowWildcardCertificates`), `Server`, `Client`, `KeyCurve`, `TTL`, `MaxTTL`, `RenewBefore` | all but `RenewBefore` | `RenewBefore` is for the consumers, not OpenBAO |
| `CredentialRole` | `Name`, `Issuer`, `SubjectMount`, `CNValidations` (`email`, `hostname`), `Server`, `Client`, `KeyCurve`, `TTL`, `MaxTTL` | all but validations | signs only the caller's own alias name on `SubjectMount` |
| `SSHMount` | `Path`, `Description`, `KeyType`, `Roles` | path, key type, a role | the CA key is generated inside OpenBAO |
| `SSHRole` | `Name`, `AllowedUsers`, `DefaultUser`, `KeyTypes`, `KeyIDFormat`, `Extensions`, `TTL`, `MaxTTL` | all but extensions | principals spelled out; never root |
| `KVLayout` | rows of `Kind`, `Key`, `Properties`, `Writer` | kind, key, properties | `Validate`, `SecretsFor(kind)`, `SecretForKey(key)`, `Kinds()`; `{name}` placeholders |

The access-roster preset ([integrations/access-roster.md](integrations/access-roster.md#the-preset)):

| Type | Field | Default | What |
|---|---|---|---|
| `Roster` | `Issuer` | required | discovery URL and bound issuer of both doors |
| | `TTL` | required | a login token's whole life, on both doors |
| | `Audience` | `openbao` | the roster role's bound audience: the issuer's exchange client |
| | `GroupsClaim`, `UserClaim` | `groups`, `sub` | the claims both roles map |
| | `ClaimMappings` | none | claim -> alias metadata, on both roles |
| | `Mount`, `Role` | `jwt-roster`, `roster` | the people-and-jobs door and its one role |
| | `Description` | none | the door's description |
| | `UI` | none | adds the web UI's door |
| `RosterUI` | `RedirectURIs` | required | the UI's callback, `UICallback(address, mount)` |
| | `Mount`, `ClientID` | `oidc`, `openbao-ui` | the UI's door and the issuer client it signs in as |
| | `Scopes` | `profile`, `email` | the OIDC scopes asked for |
| | `Description` | none | the door's description |

Methods: `Door()`, `UIDoor()`, `Doors()`, `DoorPaths()`, `Identity(metadata)`
(the roster door primary), `Grant(group, rules...)` and
`JobGrant(group, rules...)` (a policy named after the group, admitted
through every door or the roster door alone), `Bootstrap(operators)` (the
operators' door in root, for `Desired.Bootstrap`), `RootUI(operators)`
(the UI's door into root). `OperatorPolicy(name)` is every capability on
`*`. The names are constants: `RosterMount`, `RosterRole`,
`RosterAudience`, `RosterGroupsClaim`, `RosterUserClaim`, `RosterUIMount`,
`RosterUIClient`.

Helpers: `ServiceAccountSubject(namespace, serviceAccount)`,
`Identity.GroupName(group, door)`, `Identity.GroupMetadata(door)`,
`DurationSeconds(duration)`, `Desired.Applied()` (root, then the
namespaces), `Namespace.Label()` (`root` for root).

## pkg/apply

`apply.Deploy(ctx, &desired, apply.Options{...})` validates, runs
`BeforeApply` (apply only), logs in, and registers every namespace the
model owns on `ctx` ([model.md](model.md#applying-it)).

| Option | Default | What |
|---|---|---|
| `Address` | required | `https://` URL clients reach; the provider's address and the base of every PKI mount's issuer, CRL and OCSP URLs (`<Address>/v1/<ns>/<mount>/...`) |
| `Login.Mount`, `Login.Role` | required | the auth mount and role in root the provider logs in with |
| `Login.Token` | required | returns the JWT; called once, after `BeforeApply`, and marked secret |
| `Login.CACertFile` | none | the PEM file the server's certificate is verified against |
| `ProviderName` | `openbao` | the provider's logical name |
| `BeforeApply` | none | runs on an apply, never on a preview; an error stops the apply |
| `OIDCClientSecrets` | none | client secret by client id; required for every oidc mount's client |
| `SignedChain` | none | returns an external issuer's PEM chain, the issuer's certificate first; required when the model has one. Verify it before returning it |
| `Rename` | none | maps a derived logical name to the name a running state holds; the adoption hook |
| `ResourceOptions` | none | appended to every resource and the provider (a parent, for instance) |

`Deploy` returns `Result`: `Provider`, `Namespaces`, `Certificates`
(self-signed issuers' certificates by issuer name), `CertificateRequests`
(external issuers' requests by issuer name) and `SSHCAPublicKeys` (by
`MountRef{Namespace, Path}`). `apply.NewProvider(ctx, name, address, login)`
creates the same provider for another program that writes into OpenBAO as
the same operator.

`apply.SnapshotJob` is the pre-apply snapshot; pass its `Run` as
`BeforeApply`.

| Field | Default | What |
|---|---|---|
| `Kubectl` | required | runs kubectl (`apply.KubectlWith(kubeconfig)`) |
| `Namespace`, `CronJob` | required | the snapshot CronJob (`openbao-ops` renders one); the Job is `<CronJob>-pre-apply-<UTC timestamp>` |
| `SkipEnv` | none | an environment variable that, set to a reason, applies without a snapshot |
| `Wait`, `Poll` | `16m`, `5s` | how long to wait for the Job, and how often to look |
| `Logger`, `Now` | `slog.Default()`, `time.Now` | |
