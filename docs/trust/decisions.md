# Decision log

One entry per decision that shapes the trust and access model, in the order it
was taken. Each states the **choice**, the **alternatives with pros and cons**,
and the **consequences**. This is the *shape* log; the repository's numbered
design records in [decisions/](../decisions/README.md) remain the long-form
reasoning for the ones they cover, and are linked where they do.

Rules, the same as the numbered records: **an entry is never edited to reverse a
decision.** A changed mind is a new entry that supersedes the old one, and the
old one keeps its text and gains a `Superseded by` line. Dates are when the
decision was taken.

| Id | Decision | Status |
|---|---|---|
| [T-01](#t-01-certificate-families-are-decided-by-what-the-name-is) | Certificate families are decided by what the name is | accepted |
| [T-02](#t-02-one-kms-root-two-domain-intermediates) | One KMS root, two domain intermediates | accepted |
| [T-03](#t-03-the-root-is-a-signer-and-the-ceremony-is-not-a-resource) | The root is a signer; the ceremony is not a resource | accepted |
| [T-04](#t-04-per-environment-identity-cas-signed-by-the-root) | Per-environment identity CAs signed by the root | accepted |
| [T-05](#t-05-a-service-role-and-an-identity-role) | A `service` role and an `identity` role | accepted |
| [T-06](#t-06-spiffe-has-a-narrow-mandate) | SPIFFE has a narrow mandate | accepted |
| [T-07](#t-07-the-blanket-approver-is-off-approvers-are-per-issuer) | The blanket approver is off; approvers are per issuer | accepted |
| [T-08](#t-08-namespaced-issuers-are-allowed-and-one-policy-covers-them) | Namespaced issuers are allowed; one policy covers them | accepted |
| [T-09](#t-09-one-serviceaccount-per-component-is-mandatory) | One ServiceAccount per component is mandatory | accepted |
| [T-10](#t-10-gateway-fronted-components-stay-permissive) | Gateway-fronted components stay permissive | accepted |
| [T-11](#t-11-no-mesh-mutual-tls-at-application-level) | No mesh; mutual TLS at application level | accepted |
| [T-12](#t-12-verify-full-everywhere) | `verify-full` everywhere | accepted |
| [T-13](#t-13-a-databases-own-clients-get-that-databases-own-ca) | A database's own clients get that database's own CA | accepted; supersedes T-13a |
| [T-13a](#t-13a-application-database-certificates-from-an-openbao-clusterissuer) | Application database certificates from an OpenBAO `ClusterIssuer` | **superseded by T-13** |
| [T-14](#t-14-people-reach-a-database-with-a-db-client-certificate-and-a-map) | People reach a database with a `db-client` certificate and a map | accepted |
| [T-15](#t-15-no-local-database-proxy) | No local database proxy | accepted |
| [T-16](#t-16-ssh-people-on-opkssh-machines-and-hosts-on-our-cas) | SSH: people on opkssh; machines and hosts on our CAs | accepted |
| [T-17](#t-17-opkssh-groups-use-a-dot-delimiter-for-now) | opkssh groups use a dot delimiter, for now | accepted, temporary |
| [T-18](#t-18-es384-by-default-per-audience-exceptions) | ES384 by default; per-audience exceptions | accepted |
| [T-19](#t-19-the-origin-chain-is-separate-and-unconstrained) | The origin chain is separate and unconstrained | accepted |
| [T-20](#t-20-cloudflare-a-root-token-mints-least-privilege-children) | Cloudflare: a root token mints least-privilege children | accepted |
| [T-21](#t-21-the-gateway-signs-people-in) | The gateway signs people in | accepted |
| [T-22](#t-22-storage-credentials-come-from-a-broker) | Storage credentials come from a broker | accepted |
| [T-23](#t-23-passwords-are-an-explicit-fallback) | Passwords are an explicit fallback | accepted |
| [T-24](#t-24-cnpg-secrets-always-carry-cnpgioreload) | CNPG Secrets always carry `cnpg.io/reload` | accepted |
| [T-25](#t-25-people-ladder-roles-avoid-the-reserved-pg_-prefix) | People ladder roles avoid the reserved `pg_` prefix | accepted, names to be decided |
| [T-26](#t-26-heavy-lifting-lives-in-the-library-consumers-keep-rows-values-and-thin-adapters) | Heavy lifting lives in the library; consumers keep rows, values and thin adapters | accepted |
| [T-27](#t-27-the-kms-seal-plugin-arrives-by-init-container-from-a-digest-pinned-image-volume) | The KMS seal plugin arrives by init container from a digest-pinned image volume | accepted |

---

### T-01: Certificate families are decided by what the name is

**Date:** 2026-09-29. **Status:** accepted.

**Choice.** A host name gets the private hostname chain; a workload
(ServiceAccount) gets its environment's SPIFFE identity CA; a person gets an
OpenBAO credential role (database) or opkssh / the SSH CA (SSH); a database's own
clients get that database's own CA. A self-signed namespaced `Issuer` is the
bootstrap exception.

| Alternative | Pros | Cons |
|---|---|---|
| one CA for everything | one policy, one trust bundle | one mistake lets a certificate of one meaning pass as another; no name or URI constraint fits all four meanings |
| one CA per environment for everything | environment wall | same confusion inside an environment |
| a mesh's CA | uniform | per-node data plane; see T-11 |

**Consequences.** Each family has its own trust bundle and its own review. A new
kind of name is a new family decision, recorded here first.

---

### T-02: One KMS root, two domain intermediates

**Date:** 2026-09-16. **Status:** accepted.

**Choice.** One root generation, in a KMS. Two domain intermediates under it: the
**private** one, DNS-constrained to the private zone and the cluster domain, and the
**origin** one, unconstrained and limited by its role's host list. They share the root
and nothing else.

| Alternative | Pros | Cons |
|---|---|---|
| a self-signed root inside OpenBAO | no ceremony | the root key is reachable by whoever reaches the server; no separation of "administer" from "sign" |
| one intermediate for both | fewer CAs | a cluster that can mint origin names could mint private ones; a constrained origin CA needs a new one per new zone |
| a root per environment | strong wall | a trust bundle per environment for every client; a ceremony per environment |

**Consequences.** Adding a public zone needs no new CA; the origin role's host list is
the wall, and it is configuration. The origin chain is trusted only by the tunnel daemon.

---

### T-03: The root is a signer, and the ceremony is not a resource

**Date:** 2026-09-15. **Status:** accepted.

**Choice.** The KMS key signs a handful of reviewed templates, once each, recorded as
committed artifacts; the ceremony is an operator command, never a Pulumi resource or a
controller. Custody (key, policy, roles, alarm) is declarative and signs nothing.

| Alternative | Pros | Cons |
|---|---|---|
| sign from a controller | no operator step | an imperative once-only signature has no safe create/read lifecycle; a refresh or retry can sign again |
| sign in CI | reviewable | a credential able to sign lives in CI |

**Consequences.** See [hierarchy.md](hierarchy.md#two-phase-creation-of-a-ca). The Sign
alarm fires on every signature; a signature nobody expected is an incident.

---

### T-04: Per-environment identity CAs signed by the root

**Date:** 2026-09-28. **Status:** accepted; supersedes the per-project issuing CA shape of
[ADR 0002](../decisions/0002-workload-mtls-service-and-identity-roles.md).

**Choice.** Each environment's identity CA is signed *directly by the root* by the Go
ceremony, with an exact URI constraint for that environment's trust domain and path
length 0. There is no shared identity intermediate.

| Alternative | Pros | Cons |
|---|---|---|
| a shared identity intermediate signing per-environment CAs inside OpenBAO | one CA to ceremony | OpenBAO drops `permitted_uri_domains` when it signs a CA, so the environment CAs carry no URI constraint and trust each other's SPIFFE IDs; only role configuration keeps them apart |
| per-project issuing CAs | the CA boundary is the project boundary | same OpenBAO limitation; many CAs to run |
| rely on the approver alone | no CA design | the approver is issuance-time and can be misconfigured; a constraint is checked by every verifier |

**Consequences.** One ceremony per environment. An environment's CA cryptographically
cannot mint another's identity. Peers still check the trust domain (defence in depth).

---

### T-05: A `service` role and an `identity` role

**Date:** 2026-09-27. **Status:** accepted.

**Choice.** `service`: DNS SANs, server usage, for anything reached by name. `identity`:
one URI SAN, no DNS or IP, client and server usage, `use_csr_sans` false, P-256.

| Alternative | Pros | Cons |
|---|---|---|
| one wider role | one role | a certificate's role should say which promise it makes; every consumer would have to inspect SANs |
| templating the URI to the caller | per-pod enforcement in OpenBAO | works, but the caller OpenBAO sees is the issuer's login, not the pod, so it cannot bind to the pod |

**Consequences.** Per-pod attestation is the approver's job, never OpenBAO's
([workload-identity.md](workload-identity.md#how-a-pod-gets-one)).

---

### T-06: SPIFFE has a narrow mandate

**Date:** 2026-09-29. **Status:** accepted.

**Choice.** Workload identity is used where it pays -- calls across clusters, brokers,
and sensitive services -- and **not** as a universal requirement. The baseline for
in-cluster traffic is default-deny NetworkPolicy plus server TLS. Databases use their
own CA; browsers use the gateway.

| Alternative | Pros | Cons |
|---|---|---|
| SPIFFE everywhere | uniform identity | a per-component ServiceAccount, allow-list and rotation path in every client and every third-party server; cannot authenticate a database role; a browser cannot hold one |
| network policy alone | simple | an address is whoever holds it today |
| a mesh | transparent | see T-11 |

**Consequences.** A project chooses a level per environment
(`off`, `identity`, `enforced`); the default is `off`. Federation is planned, not built.

---

### T-07: The blanket approver is off; approvers are per issuer

**Date:** 2026-09-28. **Status:** accepted.

**Choice.** cert-manager's blanket approver is disabled. Approval is per issuer: one exact
`CertificateRequestPolicy` for each OpenBAO-backed issuer, csi-driver-spiffe's own
approver for the identity issuer alone, and one allow-all policy for namespaced `Issuer`s.
`approvercheck` proves it (shape, live RBAC, flag).

| Alternative | Pros | Cons |
|---|---|---|
| leave it on | nothing to do | the identity is decoration: any requester gets any name (measured) |
| approver-policy for the identity issuer too | one approver | a policy cannot express "the requester's own ServiceAccount"; it would approve any allowed URI |
| turn it off without a proven replacement | fast | every certificate and every renewal stops silently |

**Consequences.** The cutover is a runbook with an order; a green live run is not proof
(it does not see short-lived tenants or fields no policy names). The proof is the
**refusal**.

---

### T-08: Namespaced issuers are allowed, and one policy covers them

**Date:** 2026-09-28. **Status:** accepted.

**Choice.** One allow-all policy for every namespaced `Issuer`. Never for an
OpenBAO-backed issuer; the render refuses the combination.

| Alternative | Pros | Cons |
|---|---|---|
| exact policy per tenant issuer | tight | tenants mint issuers under a fresh name every run; no policy can name them in advance; installs hang silently |
| forbid namespaced issuers | tight | a database's own CA (T-13) and the bootstrap need one |

**Consequences.** A namespaced self-signed or CA issuer confers no trust outside its
namespace, so approving it grants nothing that was not held.

---

### T-09: One ServiceAccount per component is mandatory

**Date:** 2026-09-29. **Status:** accepted.

**Choice.** Every component runs as its own ServiceAccount. No shared-account mode, no
toggle.

| Alternative | Pros | Cons |
|---|---|---|
| a shared account per release | fewer objects | components become indistinguishable; every allow-list collapses to the project boundary |
| an opt-in per-component mode | gradual | a default of "shared" defeats the identity; two code paths to maintain |

**Consequences.** A component-contract rule with a render check. A shared account is
flagged wherever found.

---

### T-10: Gateway-fronted components stay permissive

**Date:** 2026-09-29. **Status:** accepted.

**Choice.** A component the gateway forwards browser traffic to may be `permissive` and
never `strict`. The gateway does not present a workload identity today.

| Alternative | Pros | Cons |
|---|---|---|
| give the gateway its own SPIFFE identity and re-encrypt | authenticates the hop | not decided; needs confirming that gateway backend TLS can present a client certificate, and each backend a second listener |
| `strict` behind the gateway | uniform | refuses its only caller |

**Consequences.** The gateway-to-app hop is authenticated by network policy and the
cluster boundary. Revisit if a driver appears.

---

### T-11: No mesh; mutual TLS at application level

**Date:** 2026-09-16 (identity in process: 2026-09). **Status:** accepted.

**Choice.** No service mesh. Three hops, three mechanisms (client to gateway, gateway to
backend, service to service), all on the same PKI; service-to-service identity is
terminated in process by a small library.

| Alternative | Pros | Cons |
|---|---|---|
| a mesh | transparent | a data plane on every node or pod; no single mesh works cleanly on both cluster kinds in use; ordering defects with the network plugin; a vendor line above the free one |
| a terminating proxy beside each workload | no per-language work | a second container per pod to pin, scan and render; explicit addressing; the caller's identity must be forwarded |
| in process | three small functions per language | per-language work |

**Consequences.** A terminating proxy remains the escape hatch for a container we do not
build, declared in the chart as an ordinary sidecar, never injected. Revisit when a
concrete driver appears.

---

### T-12: `verify-full` everywhere

**Date:** 2026-09-29. **Status:** accepted.

**Choice.** Every client verifies the server's chain *and* name. No steady state of
`require`. In-cluster clients dial the fully qualified name the certificate carries.

| Alternative | Pros | Cons |
|---|---|---|
| `require` | works with any certificate | accepts any certificate; a name-constrained private chain buys nothing |
| `verify-ca` | chain checked | any certificate from the CA passes for any name |

**Consequences.** Short in-cluster forms fail. A client moves its host and root first,
then flips the mode; rollback is one connection string.

---

### T-13: A database's own clients get that database's own CA

**Date:** 2026-09-29. **Status:** accepted. Supersedes [T-13a](#t-13a-application-database-certificates-from-an-openbao-clusterissuer).

**Choice.** Owner, migration, runtime and replication certificates come from a
cert-manager self-signed CA in the database's namespace. The client-CA file holds that CA
(and the private root only when people connect). The operator does not hold the CA key.

| Alternative | Pros | Cons |
|---|---|---|
| per-database CA (chosen) | namespace and environment bound by construction; no new OpenBAO role or approver shape; cert-manager owns issuance | operator no longer mints role certificates; a CA per database |
| the operator's CA | zero work | operator owns issuance; SEC1 keys; outside cert-manager |
| OpenBAO `ClusterIssuer` | one family | see T-13a |
| combined bundle keeping the operator's key | additive | renewal of a CA the operator no longer renews becomes ours; relies on operator internals |

**Consequences.** [databases.md](databases.md#the-per-database-ca).

---

### T-13a: Application database certificates from an OpenBAO `ClusterIssuer`

**Date:** 2026-09-29 (earlier the same day). **Status:** **superseded by [T-13](#t-13-a-databases-own-clients-get-that-databases-own-ca).**

**Choice (as it was).** Application client certificates for a database from a `ClusterIssuer`
on the private chain, with a new OpenBAO role for a bare common name and a matching approver
policy.

**Why it was reversed.** libpq needs a self-signed anchor, so a database trusting the private
root as a client anchor accepts every certificate under it, and a `ClusterIssuer` lets any
namespace mint `CN=<role>`. The wide anchor is now admitted for people only, guarded by an
invariant. The old text is kept so the timeline is true.

---

### T-14: People reach a database with a `db-client` certificate and a map

**Date:** 2026-09-29. **Status:** accepted.

**Choice.** The OpenBAO `db-client` credential role signs a person's CSR (CN = e-mail, 1 hour);
`pg_hba` has a people line before the catch-all with a map; `pg_ident` has explicit
e-mail-to-role rows; roles are a ladder minus superuser (names to be decided, see [T-25](#t-25-people-ladder-roles-avoid-the-reserved-pg_-prefix)); the private root is in
the client-CA file, guarded by the tested CN invariant.

| Alternative | Pros | Cons |
|---|---|---|
| OpenBAO database secrets engine | instant revocation, per-person users | `CREATEROLE` on every database; network reach into every cluster; reverses "OpenBAO stays out of the data plane"; similar effort |
| PostgreSQL 18 OAuth | native token check | device-flow grant is not implemented by the issuer; business apps must not take an OIDC dependency for the database |
| shared passwords | trivial | none of the properties above |

**Consequences.** [databases.md](databases.md#people). `accessctl` gains `--as` and `--target`.

---

### T-15: No local database proxy

**Date:** 2026-09-29. **Status:** accepted.

**Choice.** `accessctl` does not run a local proxy. libpq connects directly; reach is a
`hostaddr`.

| Alternative | Pros | Cons |
|---|---|---|
| a loopback proxy | hides certificate handling | a long-lived local process holding the certificate; a second TLS termination; nothing libpq lacks |

**Consequences.** Reach is the network's problem ([people.md](people.md#network-reach)).

---

### T-16: SSH: people on opkssh; machines and hosts on our CAs

**Date:** 2026-09-27. **Status:** accepted. See [decision 0003](../decisions/0003-ssh-people-external-machines-and-hosts-on-our-cas.md).

**Choice.** People use opkssh (no CA); machines use the SSH user CA; hosts use a separate SSH
host CA. Two CAs are never the same key.

| Alternative | Pros | Cons |
|---|---|---|
| a CA for people too | one mechanism | a CA to revoke, distribute and audit for a population with a working OIDC path |
| one CA for users and hosts | one key | one compromise costs both |
| static keys | no infrastructure | no expiry, no audit, per-host `authorized_keys` |

**Consequences.** A host that takes only people trusts no user CA. Machine roles with a forced
command need a policy-level denial of `critical_options`.

---

### T-17: opkssh groups use a dot delimiter, for now

**Date:** 2026-09-28. **Status:** accepted, **temporary**.

**Choice.** A per-audience `groups_delimiter` of `.` for the opkssh client, with dot-form
`auth_id` lines. Removed when upstream fixes its parser.

| Alternative | Pros | Cons |
|---|---|---|
| rename groups issuer-wide | no shim | breaks every other consumer of the group names |
| patch and run a fork | immediate | a fork to keep |
| wait | none | the ladder cannot be expressed |

**Consequences.** A colon-spelled `auth_id` line silently denies everyone.

---

### T-18: ES384 by default; per-audience exceptions

**Date:** 2026-09-25 (flip 2026-09-28). **Status:** accepted.

**Choice.** The issuer's default is ECDSA P-384 (ES384). An RSA key signs only the audiences whose
relying parties verify RS256 only; the JWKS carries both. Every OpenBAO JWT/OIDC mount states its
accepted algorithms.

| Alternative | Pros | Cons |
|---|---|---|
| RSA everywhere | universally verified | larger, slower; inconsistent with a P-384 estate |
| ES256 everywhere | broadly accepted | some verifiers still refuse EC; not the fleet default |

**Consequences.** Never flip a default without the exception pins first
([people.md](people.md#sign-in)).

---

### T-19: The origin chain is separate and unconstrained

**Date:** 2026-09-16. **Status:** accepted. Part of T-02; kept as its own entry because it is
the reason a public zone costs no CA.

**Choice.** See [hierarchy.md](hierarchy.md#the-domain-intermediates).

| Alternative | Pros | Cons |
|---|---|---|
| a constrained origin CA | wall in the certificate | a new intermediate per new zone or account |
| each cluster's own self-signed CA | simple | a second PKI; trust distribution by hand |
| skip origin verification | none | the tunnel would accept any origin |

---

### T-20: Cloudflare: a root token mints least-privilege children

**Date:** 2026-09-28. **Status:** accepted.

**Choice.** One root account token that holds only the permission to create account tokens; every
stack gets a child token scoped to its zone, bucket or the tunnel. Children never mint tokens.

| Alternative | Pros | Cons |
|---|---|---|
| one broad user token | one credential | broad blast radius; a user token cannot hold token-creation anyway |
| a token per person | attribution | not what a stack needs |

**Consequences.** Renaming a stack must preserve resource identities; tokens have no expiry and
rotate by a changed `rotation` string.

---

### T-21: The gateway signs people in

**Date:** 2026-09-13. **Status:** accepted.

**Choice.** Envoy Gateway's OIDC and JWT filters, one client per application, no per-application proxy
and no shared single-sign-on proxy.

| Alternative | Pros | Cons |
|---|---|---|
| a proxy per application | isolated | a release, a cache and a cookie key per application |
| one shared proxy | one release | one client id, so per-client gating is lost |
| the application signs itself in | flexible | per-application code |

**Consequences.** Three silent failure modes documented in
[servers-and-edge.md](servers-and-edge.md#sign-in-at-the-gateway).

---

### T-22: Storage credentials come from a broker

**Date:** 2026-09-27. **Status:** accepted.

**Choice.** A broker in the Cloudflare component mints temporary, bucket-scoped storage credentials from a
plain OIDC token, mapping a group only. The issuer mints third-party credentials only for systems whose
membership it governs.

| Alternative | Pros | Cons |
|---|---|---|
| mint in the issuer | one service | the parent key sits in the issuer; storage is not a system the issuer governs |
| long-lived keys in CI | trivial | no expiry |

---

### T-23: Passwords are an explicit fallback

**Date:** 2026-09-29. **Status:** accepted.

**Choice.** A password role is an explicit `auth: password` toggle, off by default, for a tool that
cannot present a client certificate. It is not the design.

**Consequences.** Terminal state for applications is certificates; a soft step
(`scram-sha-256 clientcert=verify-full`) eases migration.

---

### T-24: CNPG Secrets always carry `cnpg.io/reload`

**Date:** 2026-09-29. **Status:** accepted.

**Choice.** Every user-provided CloudNativePG Secret (server TLS, server CA, client CA,
replication) carries `cnpg.io/reload: "true"`. cert-manager Certificates set it through
`secretTemplate.labels`; trust-manager targets through `target.secret.metadata.labels`.

| Alternative | Pros | Cons |
|---|---|---|
| no label, reload by hand | nothing to remember | measured: a renewed server certificate was not served after more than 8 minutes; the failure is silent until expiry |
| restart instances on renewal | works | a restart per renewal, per instance |

**Consequences.** [issuance.md](issuance.md#reloading-what-actually-picks-up-a-renewed-file).
With the label a renewal was served in under 10 seconds, with no restart.

---

### T-25: People ladder roles avoid the reserved `pg_` prefix

**Date:** 2026-09-29. **Status:** accepted; the final names are to be decided.

**Choice.** The database roles people map to (the ladder) must not start with `pg_`.

**Why.** PostgreSQL reserves the prefix for its predefined roles and refuses to create
one, so a ladder named with it cannot exist. **Consequences.**
[databases.md](databases.md#people).

---

### T-26: Heavy lifting lives in the library; consumers keep rows, values and thin adapters

**Date:** 2026-09-30. **Status:** accepted.

**Choice.** Logic that more than one estate would otherwise copy (the PKI contract
in `pkg/pki`, approver policies rendered by `openbao-consumers`, `approvercheck`,
the server preset, the custody cross-check) lives in this library and is consumed
as published. A consuming estate keeps its own rows (which environments, which
hosts), its values, and thin adapters that call the library.

| Alternative | Pros | Cons |
|---|---|---|
| each consumer keeps its own copy | no coordination | copies drift; a fix has to be found and made in each; a hand-written policy is the first to miss a request shape |
| a wrapper chart or framework in the consumer | one place per estate | the logic is still not shared, and the estate owns a second interface |

**Consequences.** A move onto the library must not change what exists: the PKI
contract move was proved by a name-set golden and a zero-diff preview. See [issuance.md](issuance.md#the-policies).

---

### T-27: The KMS seal plugin arrives by init container from a digest-pinned image volume

**Date:** 2026-09-30. **Status:** accepted.

**Choice.** On OpenBAO 2.7 the KMS seal is an external plugin. An init container
installs it from an OCI image volume pinned by digest before the server starts. It
is never downloaded at startup.

| Alternative | Pros | Cons |
|---|---|---|
| download at startup | no image to build | needs egress from the pod, trusts the network at the moment the seal must open, and a failed fetch is an outage |
| bake the plugin into a custom server image | one artefact | a rebuild of the server image per plugin change; the server is no longer the upstream image |
| mount from a tag | readable | a tag moves; the bytes that unseal the cluster are not the bytes reviewed |

**Consequences.** Pods need no route out. The digest is a reviewed pin, changed by
pull request. Rehearsed in the library (v0.23.0); runbook in
[server.md](../server.md#runbook-26-to-27-with-the-kms-seal-plugin).
