# openbao-consumers

The cluster side of an OpenBAO install: runs on every cluster that
consumes one. Stores and PKI are independent — an install may render
either or both, so each can sit in the deployment, and at the point in its
ordering, where it belongs.

| Part | Objects |
|---|---|
| `stores` | one External Secrets ClusterSecretStore per kind, reading as External Secrets |
| `writers` | one ClusterSecretStore per (writer, environment), writing as the writer's own ServiceAccount |
| `pki.trustAnchors` | one ConfigMap per root that verifies what OpenBAO issues |
| `pki.issuers` | the ServiceAccount cert-manager logs in as, its token Role and RoleBinding, and one cert-manager issuer per signing path |
| `pki.bundle` | a trust-manager Bundle of every anchor, distributed to every namespace |
| `certificates` | cert-manager Certificates — typically one disposable smoke certificate per issuer |

Object names are values, never derived from the release name, so objects
that already exist are adopted as they are.

## Three things easy to get subtly wrong

- **Two different CAs.** `caBundle` verifies the SERVER a client is about
  to send a token to. `pki.trustAnchors` verify the certificates OpenBAO
  ISSUES. They are usually different authorities; confusing them produces
  an issuer that works and a chain nobody trusts.
- **A writer presents its own token.** A reader store authenticates as
  External Secrets; a writer store authenticates as the writer's own
  ServiceAccount, so nothing else on the cluster can write through it. The
  auth mount is this cluster's, the Vault namespace the target
  environment's: one identity, minted here, admitted there.
- **The bundle carries every root.** During a root migration, trusting the
  old and the new at once is what lets leaves be reissued in any order. A
  single-source bundle makes it a flag day.

## Issuer logins

Every issuer logs in as `pki.issuerServiceAccount` on the `auth.mountPath`
mount, with a token cert-manager mints per request — there is no stored
credential. cert-manager always requests the audience `vault://<name>`
(`vault://<namespace>/<name>` for an `Issuer`), so the OpenBAO role can be
bound to exactly one issuer. `audiences` adds more: a second issuer that
signs on another path of the SAME chain can reach the first issuer's role
by asking for its audience too, instead of a login of its own that would
be the same ServiceAccount under another name.

## Values

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
