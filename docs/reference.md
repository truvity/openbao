# Reference

Every value of both charts. `charts/<chart>/values.yaml` carries the same
keys with their defaults and a comment each, and `values.schema.json` is
the authority on types: an unknown key fails the render.

## openbao-ops

### Top level

| Value | Default | Notes |
|---|---|---|
| `commonAnnotations` | `{}` | on every rendered object |
| `namespace` | the release namespace | where the server and these jobs live |

### `server` — how the jobs and policies find the server

| Value | Default | Notes |
|---|---|---|
| `server.address` | derived from `activeService` | the API address the jobs talk to |
| `server.activeService` | `openbao-active` | resolves to whichever pod is active; writes must not land on a standby |
| `server.service` | `openbao` | |
| `server.headlessService` | `openbao-internal` | the Service peers dial each other through |
| `server.apiPort` / `server.clusterPort` | `8200` / `8201` | |
| `server.tlsSecretName` | `openbao-tls` | the Secret holding the serving certificate |
| `server.caKey` | `ca.crt` | the key in it a client verifies the server with |
| `server.podLabels` | `app.kubernetes.io/name: openbao`, `component: server` | for the network policies |

### `auth` — how the jobs log in

| Value | Default | Notes |
|---|---|---|
| `auth.mountPath` | `jwt` | the JWT auth mount |
| `auth.audience` | `openbao` | a token minted for this audience cannot be replayed against the Kubernetes API |
| `auth.expirationSeconds` | `600` | |

### `snapshot`

| Value | Default | Notes |
|---|---|---|
| `snapshot.enabled` | `false` | |
| `snapshot.serviceAccountName` | `openbao-snapshot` | |
| `snapshot.serviceAccountAnnotations`, `.annotations` | `{}` | a cloud identity binding belongs in the ServiceAccount annotations |
| `snapshot.baoRole` | `openbao-snapshot` | should read `sys/storage/raft/snapshot` and nothing else |
| `snapshot.jobs` | two tiers: `openbao-snapshot` 6-hourly into `raft/`, `openbao-snapshot-weekly` into `weekly/` | `{name, schedule, prefix}`; `prefix` per tier, so a lifecycle rule can expire them differently; must not be empty |
| `snapshot.timeZone` | `Etc/UTC` | |
| `snapshot.startingDeadlineSeconds` | `3600` | |
| `snapshot.activeDeadlineSeconds` | `900` | |
| `snapshot.backoffLimit` | `2` | |
| `snapshot.workSizeLimit` | `2Gi` | the scratch volume the snapshot is verified in |
| `snapshot.nodeSelector`, `.tolerations` | empty | |
| `snapshot.image` | `openbao/openbao` at the chart's pinned tag | `{repository, tag, digest, pullPolicy}` |
| `snapshot.resources` | 10m / 64Mi requests, 256Mi limit | |
| `snapshot.upload.image` | `amazon/aws-cli` at the chart's pinned tag | |
| `snapshot.upload.command`, `.args`, `.env` | empty | any store: read `/work/openbao.snap` and `/work/taken-at`, store the bytes at `<SNAPSHOT_PREFIX><taken-at>.snap` |
| `snapshot.upload.resources` | 10m / 128Mi requests, 512Mi limit | |
| `snapshot.upload.s3.enabled` | `false` | the S3 preset; either it or `command` is required |
| `snapshot.upload.s3.bucket` | *required* with the preset | |
| `snapshot.upload.s3.region` | `""` | |
| `snapshot.upload.s3.checksumAlgorithm` | `SHA256` | |

### `restoreCheck`

| Value | Default | Notes |
|---|---|---|
| `restoreCheck.enabled` | `false` | |
| `restoreCheck.serviceAccountName` | `openbao-restore-check` | |
| `restoreCheck.serviceAccountAnnotations`, `.annotations` | `{}` | |
| `restoreCheck.baoRole` | `openbao-restore-check` | |
| `restoreCheck.schedule` | `37 5 * * 0` | weekly |
| `restoreCheck.timeZone` | `Etc/UTC` | |
| `restoreCheck.activeDeadlineSeconds` | `1200` | |
| `restoreCheck.workSizeLimit` | `2Gi` | |
| `restoreCheck.nodeId` | `restore-check` | the scratch server's Raft node id |
| `restoreCheck.nodeSelector`, `.tolerations` | empty | |
| `restoreCheck.maxSnapshotAgeSeconds` | `43200` | twelve hours; a newer snapshot is required, or the check fails |
| `restoreCheck.image` | `openbao/openbao` at the chart's pinned tag | |
| `restoreCheck.sealConfig` | `""` | raw HCL for the scratch server's seal; a snapshot from an auto-unsealed cluster needs the same seal, or a replica of its key |
| `restoreCheck.serverEnv` | `[]` | environment for the scratch server, e.g. the seal's credentials |
| `restoreCheck.serverResources` | 50m / 128Mi requests, 512Mi limit | the scratch server |
| `restoreCheck.resources` | 50m / 128Mi requests, 256Mi limit | the checking container |
| `restoreCheck.fetch.image` | `amazon/aws-cli` at the chart's pinned tag | |
| `restoreCheck.fetch.command`, `.args`, `.env` | empty | any store: write the newest snapshot to `/work/openbao.snap` and its name to `/work/key`, and fail if it is older than `maxSnapshotAgeSeconds` |
| `restoreCheck.fetch.resources` | 10m / 128Mi requests, 512Mi limit | |
| `restoreCheck.fetch.s3.enabled` | `false` | the S3 preset; either it or `command` is required |
| `restoreCheck.fetch.s3.bucket` | *required* with the preset | |
| `restoreCheck.fetch.s3.region` | `""` | |
| `restoreCheck.fetch.s3.prefix` | `raft/` | which tier the check restores |
| `restoreCheck.verifyCanary` | `true` | read a known value back per namespace |
| `restoreCheck.canary.kvMount`, `.path`, `.field` | `kv`, `restore-canary`, `data` | |
| `restoreCheck.canary.namespaces` | *required* when `verifyCanary` | the OpenBAO namespaces whose canary must survive |
| `restoreCheck.verifyIssue` | `false` | also issue a certificate from the restored PKI |
| `restoreCheck.issue.namespaces` | `[]` | |
| `restoreCheck.issue.path` | `pki/issue/restore-check` | |
| `restoreCheck.issue.commonNamePrefix` | `restore-check` | |
| `restoreCheck.issue.domain` | `""` | |
| `restoreCheck.issue.ttl` | `1h` | |

### `networkPolicy`

| Value | Default | Notes |
|---|---|---|
| `networkPolicy.enabled` | `false` | |
| `networkPolicy.annotations` | `{}` | |
| `networkPolicy.names.serverIngress` | `openbao-ingress` | |
| `networkPolicy.names.restoreCheckIngress` | `openbao-restore-check-ingress` | admits nothing |
| `networkPolicy.clientCidrs` | *required* when enabled | where clients live |
| `networkPolicy.extraClientSelectors` | `[]` | raw NetworkPolicyPeer entries |
| `networkPolicy.egress.enabled` | `false` | |
| `networkPolicy.egress.rules` | `[]` | `{name, podSelector, egress}`; CIDR-based, because naming hostnames needs a CNI extension whose shape differs by provider |

### `serverCertificate`

| Value | Default | Notes |
|---|---|---|
| `serverCertificate.enabled` | `false` | |
| `serverCertificate.externalDnsName` | `""` | the name a client outside the cluster uses; prepended to the SANs |
| `serverCertificate.commonName` | `""` | |
| `serverCertificate.extraDnsNames` | `[]` | the Service names are generated, never listed |
| `serverCertificate.ipAddresses` | `[127.0.0.1]` | |
| `serverCertificate.duration` / `.renewBefore` | `2160h` / `720h` | |
| `serverCertificate.privateKey` | ECDSA 256, `rotationPolicy: Always` | |
| `serverCertificate.issuerRef` | `{name: "", kind: ClusterIssuer, group: cert-manager.io}` | `name` *required* when enabled |
| `serverCertificate.annotations` | `{}` | |

### `tlsReload` — a fragment for the upstream chart

| Value | Default | Notes |
|---|---|---|
| `tlsReload.intervalSeconds` | `60` | how often the sidecar compares the certificate on disk |
| `tlsReload.certPath` | `/openbao/userconfig/openbao-tls/tls.crt` | |
| `tlsReload.volumeName` | `userconfig-openbao-tls` | the upstream chart's volume for the TLS Secret |
| `tlsReload.mountPath` | `/openbao/userconfig/openbao-tls` | |
| `tlsReload.image` | `openbao/openbao` at the chart's pinned tag | |
| `tlsReload.resources` | 5m / 8Mi requests, 32Mi limit | |

## openbao-consumers

| Value | Default | Notes |
|---|---|---|
| `commonAnnotations` | `{}` | |
| `server` | `""` | the OpenBAO endpoint; *required* before any store or the issuer renders |
| `caBundle` | `""` | base64 PEM of the CA that signed the **server's** certificate; *required* whenever a store renders |
| `vaultNamespace` | `""` | the OpenBAO namespace these objects address; empty on an install with no namespaces |
| `kvMount` | `kv` | the KV v2 mount every reader store reads from |
| `storeSuffix` | `openbao` | appended to a reader store's name, so it is distinguishable from a same-named store on another provider during a migration |
| `auth.mountPath` | `jwt` | this cluster's JWT auth mount |
| `auth.audience` | `openbao` | |
| `auth.expirationSeconds` | `600` | |
| `auth.serviceAccount` | `external-secrets` in `external-secrets` | the identity External Secrets presents for reader stores |
| `writerAuthMount` | `""` | the auth mount writer stores log in to; default `auth.mountPath` |
| `stores[].name` | *required* | one ClusterSecretStore per entry, unique |
| `stores[].role` | the name | the OpenBAO role, so the policy bounding a store is findable from it |
| `stores[].conditions` | *required* | which namespaces may use the store |
| `stores[].vaultNamespace` | the top-level `vaultNamespace` | |
| `stores[].annotations` | `{}` | |
| `writers[].name` | *required* | |
| `writers[].namespace` | *required* | where its ServiceAccount lives |
| `writers[].serviceAccount` | *required* | the writer presents its own token |
| `writers[].environments` | *required*, non-empty | one store per target OpenBAO namespace |
| `writers[].annotations` | `{}` | |
| `pki.enabled` | `false` | the cert-manager issuer, the trust bundle and the certificates below |
| `pki.trustRootCaBundle` | *required* when enabled | base64 PEM of the **root** that signs what OpenBAO issues |
| `pki.rootConfigMapName` / `pki.rootKey` | `openbao-private-root` / `ca.crt` | |
| `pki.annotations` | `{}` | |
| `pki.certManager.namespace` / `.serviceAccountName` | `cert-manager` / `cert-manager` | cert-manager's own identity, which mints the issuer's tokens |
| `pki.issuerServiceAccount` | `openbao-issuer` | the identity cert-manager presents to OpenBAO; it holds no token |
| `pki.issuerName` | `openbao-private` | |
| `pki.issuerKind` | `ClusterIssuer` | or `Issuer`, to scope it to one namespace |
| `pki.signPath` | `pki/sign/cert-manager` | |
| `pki.role` | `cert-manager` | |
| `pki.vaultNamespace` | the top-level `vaultNamespace` | |
| `pki.bundle.enabled` | `true` | a trust-manager Bundle distributing the root |
| `pki.bundle.name` | `openbao-private-ca` | |
| `pki.bundle.extraSources` | `[]` | during a root migration, the old root as well |
| `pki.bundle.target.key` | `ca-certificates.crt` | |
| `pki.bundle.target.namespaceSelector` | `{}` | every namespace |
| `certificateDefaults.duration` / `.renewBefore` | `720h` / `240h` | renewal at a third of the lifetime |
| `certificateDefaults.privateKey` | ECDSA 256, `rotationPolicy: Always` | |
| `certificates[].name` | *required* | |
| `certificates[].namespace` | `pki.certManager.namespace` | |
| `certificates[].commonName`, `.dnsNames` | one of them *required* | |
| `certificates[].issuerRef` | the chart's issuer | |
| `certificates[].uris` | `[]` | URI SANs |
| `certificates[].secretName` | `<name>-tls` | |
| `certificates[].usages` | cert-manager's default | |
| `certificates[].duration`, `.renewBefore`, `.privateKey` | `certificateDefaults` | |
| `certificates[].annotations`, `.labels` | `{}` | |
