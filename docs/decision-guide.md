# Decision guide: which capability level, and why the shape is what it is

This library is modular by construction. The desired-state model and its
apply, the PKI contract and ceremony, the server preset and the two charts
share no code, so an organisation adopts the **lowest level that answers its
problem** and stops. This page is the map: the ladder, what each rung needs
and costs, the two structural decisions underneath it (the namespace split
and the PKI chains), the approver layer, and the model for adopting mutual
TLS in workloads.

It explains and recommends; it does not repeat mechanism. For each rung's
platform checklist, with a command that verifies every item, see
[prerequisites.md](prerequisites.md). For the full account of every
certificate family and access path, see [trust/](trust/README.md).

Examples below use `example.org`, an environment `dev`, a project `shop` and
a cluster `east`. Every one is an input in a real install.

## The capability ladder

Each level adds to the one below it. A level never silently pulls in the
level above, and each is runnable on its own: the matching directory under
`examples/org/` renders it with no cloud access.

| Level | You get | Worked example |
|---|---|---|
| 0 | a server | [examples/org/level-0](../examples/org/level-0/) |
| 1 | secrets: KV per environment, ESO stores, JWT login per cluster | [examples/org/level-1](../examples/org/level-1/) |
| 2 | an SSH certificate authority and host-certificate renewal | [examples/org/level-2](../examples/org/level-2/) |
| 3 | an internal PKI: KMS-held root, issuers, trust bundles | [examples/org/level-3](../examples/org/level-3/) |
| 4 | workload identity: a CA per environment, SPIFFE leaves | [examples/org/level-4](../examples/org/level-4/) |
| 5 | enforcement: namespaces opted in, admission refuses a pod without an identity | [examples/org/level-5](../examples/org/level-5/) |

Level 2 and level 3 are independent of each other (SSH needs no PKI, and PKI
needs no SSH); both need level 1's door. Level 4 needs level 3. Level 5
needs level 4.

### Level 0: a server

**Prerequisites.** Kubernetes with persistent volumes for Raft; the upstream
`openbao/openbao` chart; a serving certificate from *some* CA (cert-manager
or any Secret); for auto-unseal, a KMS key and a pod identity allowed to use
it.

**Toggles.** `pkg/serverpreset` (`Seal`, `Plugins`, `UI`, and the listener
and Raft shape) and the `openbao-ops` parts: `serverCertificate`,
`tlsReload`, `snapshot`, `restoreCheck`, `certificateExpiry`,
`networkPolicy`, `rootGeneration`, `pluginCatalog`, `snapshotAge`,
`jobSuccess`. Every part is off by default and renders alone.

**Consequences.**

- Without a seal stanza the server is a Shamir server unsealed by hand after
  every restart, and `restoreCheck` is unusable (it needs a seal config to
  open a snapshot).
- With an AWS KMS seal the key is a hard dependency of every restart.
  Losing it, or its region, loses the cluster. The library never creates it;
  [awsserver.md](awsserver.md) offers components for it.
- The serving certificate has a chicken-and-egg: if OpenBAO's own PKI issues
  its serving certificate, the break-glass leaf is the bootstrap, which pulls
  level 3 into level 0. A level-0 install takes its serving certificate from
  another CA.
- `rootGeneration` in the ops chart is the root-token generation watch, not a
  PKI root generation.

Read: [server.md](server.md), [bootstrap.md](bootstrap.md), [safety.md](safety.md).

### Level 1: secrets

**Prerequisites.** Level 0; an operator door in the root namespace (the
bootstrap: [bootstrap.md](bootstrap.md)); External Secrets Operator; each
consuming cluster's ServiceAccount issuer reachable from OpenBAO at its
discovery URL; Pulumi with the Vault provider to run `pkg/apply`.

**Toggles.** The model: environments (`Namespaces`), a `KV` mount with its
canary, a `JWT` auth mount per cluster with workload roles, `Policies`,
`Groups`, `Projects`. The consumers chart: `stores`, `writers`, `auth.*`.

**Consequences.**

- Each store's `conditions` (bound audience and subject) are the only
  per-store boundary; the chart makes them mandatory.
- One JWT mount per cluster, in each namespace where something logs in. A
  second cluster means a second mount and a second issuer to keep reachable;
  a new namespace never does.
- No cert-manager and no trust-manager are involved.

Read: [model.md](model.md), [team-secrets.md](team-secrets.md),
[adoption.md](adoption.md#single-cluster).

### Level 2: SSH

**Prerequisites.** Level 1; the AWS auth plugin registered on the server
(declaratively through the server preset, or as a command already on disk:
choose one path); egress to the STS endpoint; hosts that can reach OpenBAO
and run the `openbao-hostcert` renewer.

**Toggles.** The model's `SSH`, `SSHHost` and `AWSAuth` mounts,
`CredentialMaxTTL`; the server preset's `Plugins` and retry sidecar; the ops
chart's `pluginCatalog` watch.

**Consequences.** Hosts trust the SSH CA public key: a compromise of the SSH
mount key is estate-wide, which is why user and host CAs are separate keys.
The host renewer depends on the plugin being present at every pod start.
Roles refuse a root principal and wildcard principals.

Read: [hostcert-renew.md](hostcert-renew.md),
[decisions/0003](decisions/0003-ssh-people-external-machines-and-hosts-on-our-cas.md).

### Level 3: an internal PKI

**Prerequisites.** Level 1; a cloud account for the root key (multi-region
asymmetric KMS key) and an audit trail on it; an operator machine for the
offline ceremony; cert-manager (with its Vault issuer); trust-manager if the
chart renders the bundle.

**Toggles.** `pkg/pki` `Contract` (the whole file is optional), trust
domains (DNS and URI lists, each may be empty), root generations; the
model's PKI mounts and roles; `pkg/custody`; `openbaoctl pki`; the
consumers chart's `pki.*`.

**Consequences.** This is the highest operational burden of the ladder.

- The contract is **immutable**: a root is never re-signed, only
  additional generations are added.
- Every root signature is a reviewed template, recorded as a public
  artifact, and announced by an alarm. A root that signs an unexpected
  thing is an incident.
- A yearly break-glass drill is part of owning it.
- Name constraints live in the intermediates and are permanent in them.

Read: [ceremony.md](ceremony.md), [custody.md](custody.md), [pki.md](pki.md),
[trust/hierarchy.md](trust/hierarchy.md), [trust/issuance.md](trust/issuance.md).

### Level 4: workload identity

**Prerequisites.** Level 3 with a URI trust domain; csi-driver-spiffe;
approver-policy; the **blanket approver turned off** (a one-way door,
below).

**Toggles.** Contract `trustDomains.uri` with `environmentCA`; the identity
role's URI SAN shape; the consumers chart's `pki.issuers[].identity`,
`approverPolicy`, and an identity `bundles[]` entry; the driver's own values.

**Consequences.**

- Turning the blanket approver off changes **every** `CertificateRequest` on
  the cluster. Anything not covered by an approver rule stops being issued,
  silently.
- The identity role bounds only the URI trust domain
  (`spiffe://<domain>/*`); the per-namespace, per-ServiceAccount check is the
  driver's approver's job, not OpenBAO's.
- The driver always generates ECDSA P-256 keys, so the identity role must
  accept P-256 ([pki.md](pki.md#two-curves)).
- Every component needs its own ServiceAccount: the identity *is*
  namespace plus ServiceAccount.

Read: [approver.md](approver.md), [trust/workload-identity.md](trust/workload-identity.md),
[decisions/0002](decisions/0002-workload-mtls-service-and-identity-roles.md).

### Level 5: enforcement

**Prerequisites.** Level 4 proven by the refusal test; Kubernetes 1.30 or
later for `ValidatingAdmissionPolicy`; a platform that labels the namespaces
it moves to `enforced`.

**Toggles.** The consumers chart's `admissionPolicy.*` (off by default); the
per-project, per-environment `mtls` level; the calls catalogue's `strict`
rows.

**Consequences.** `failurePolicy` is `Fail`: an admission policy that cannot
be evaluated refuses the request. Roll it out with `[Warn, Audit]` first.
There is no namespace-level exemption; a namespace that should not be
enforced is simply not labelled. Existing pods keep running; they are judged
when their template next changes.

Read: [trust/workload-identity.md](trust/workload-identity.md#the-admission-policy).

## The namespace split

OpenBAO namespaces are `<environment>` and `<environment>/<project>`.
[ADR 0001](decisions/0001-namespaces-are-environment-project.md) is the full
record; the reasons in short:

| Namespace | Holds | Never holds |
|---|---|---|
| root | the operators' door, the snapshot and restore-check logins, namespace creation | environment workloads |
| `dev` (environment) | logins (JWT mounts per cluster), policies, identity groups, and the platform's own mounts: KV, the issuing CAs, SSH | a project's data |
| `dev/shop` (project) | mounts only: a KV mount and an issuing CA signed by the environment's CA | logins, policies, groups, admins |

- **Logins live at the environment.** A token that logs in at `dev` and holds
  a policy naming `shop/kv/data/...` reads the project namespace without a
  second login. An identity group in a child namespace cannot contain an
  entity that logged in at the parent, so logins at the project level would
  need one auth mount per project: the multiplication this split avoids.
- **No per-project admins.** A namespace-scoped admin reaches only downward;
  an environment admin already reaches every project, so a project admin
  could do nothing an environment admin cannot. A partner's self-service is
  rows in desired state, reviewed before every apply, never OpenBAO's `sys`
  API.
- **A project namespace exists for a different organisation's sake.** A
  policy path's isolation depends on nobody who writes policy being careless;
  a project namespace gives a mount table and an issuing CA of its own.
- **The environment is the platform.** The operator's own infrastructure is
  not a project; it is what the environment namespace already is.
- **Cost.** One namespace per environment and project pair, cheap now that
  mount tables are namespace-scoped.
- **Environments are the blast-radius unit** for PKI too: each has its own
  issuing CA and its own identity CA (below).

## The PKI chains

One KMS-held root signs a handful of certificates in its life. Everything
else hangs from it in separate chains, because **each family answers a
different question** and one CA issuing all of them would need one policy
able to express all of them.

| Chain | Shape | Why |
|---|---|---|
| **private** (hosts) | root, a DNS-constrained domain intermediate, an issuing CA per environment | a certificate says "you reached the machine you meant"; the constraint covers the private zone and the cluster domain, and nothing outside it can be named |
| **origin** (a tunnel's origin) | root, an unconstrained domain intermediate, an origin CA per environment | public zones come and go, and a DNS constraint lives in the CA certificate; the role's explicit host list is the limit, and only the tunnel daemon trusts it |
| **identity** (workloads) | root, **directly** an identity CA per environment, exact URI constraint | see below |
| **per-database** | a self-signed `Issuer` in the database's namespace, outside the tree | PostgreSQL's TLS library anchors only on a self-signed certificate, so a server that trusted the private root as a client anchor would accept everything under it |

**Why the identity CA is signed by the root, not an intermediate.**
OpenBAO drops `permitted_uri_domains` when it signs a CA certificate
([openbao/openbao#4104](https://github.com/openbao/openbao/issues/4104)). A
CA signed *inside* OpenBAO would carry no URI constraint, and every
environment would trust every other environment's SPIFFE IDs, held apart only
by role configuration. The ceremony (Go's `x509`) sets the constraint
correctly, so each environment's identity CA is signed by the root with an
**exact** URI constraint and path length 0: it cannot mint another
environment's identity, by construction, regardless of any policy.

**Why the root has no name constraint.** A 20-year certificate must not
encode today's zone list. Constraints go on the intermediates, which are
re-issuable.

**Why the bundles are separate.** The private root bundle goes to every
namespace; an environment's identity bundle holds **only that environment's
CA** and goes only to opted-in namespaces. A verifier must not need to lean on
a CA constraint to stay inside its environment.

Mechanism: [pki.md](pki.md), [ceremony.md](ceremony.md),
[trust/hierarchy.md](trust/hierarchy.md), [trust/databases.md](trust/databases.md).

## The approver layer

cert-manager decides whether a `CertificateRequest` may be signed *before* it
reaches an issuer. OpenBAO signs; it never decides who may ask.

- **The blanket approver must be off** wherever an identity issuer exists. On,
  whoever can create a request gets any name from any issuer whose backend
  allows it, so the SPIFFE attestation is decoration. Measured: a hand-made
  request naming another workload's URI came back approved and issued.
- **Off is a one-way door and fails silent.** An unapproved request is not
  denied, it just never gets a certificate; Helm waits time out and renewals
  quietly stop. So something must approve in its place, and be proven to
  *before* the switch.
- **Three approvers, three disjoint sets of signers.** cert-manager's blanket
  approver (everything, until off); approver-policy (its
  `approveSignerNames`, gated by a `CertificateRequestPolicy` and RBAC `use`);
  csi-driver-spiffe's own approver (exactly the identity issuer).
- **approver-policy is never given the identity issuer.** A policy cannot say
  "the requester's own ServiceAccount", so it would either approve nothing
  or approve any URI it allows, which is the blanket approver again.
- **Prove the refusal, not the issuance.** Submit a request for another
  workload's URI; it must end `Denied`. Never accept "certificates are
  issued": with the blanket approver on they are, forgeries included.
- **Prove every request shape**, not the requests alive at one instant:
  short-lived tenants and subject fields are invisible to a live check.
  `approvercheck` is the offline evaluator that does this, and fails closed.

Runbook, policies and `approvercheck`: [approver.md](approver.md);
the rationale and alerts: [trust/issuance.md](trust/issuance.md).

## The mTLS adoption model

How much of workload identity is on is two independent switches.

**Per component, in the application's configuration (`tls.mode`).**

| Mode | Serves |
|---|---|
| `off` | cleartext only |
| `permissive` | cleartext and authenticated, on two ports |
| `strict` | the authenticated port only |

A chart's default is `off`, always: a chart must be installable where the
platform provides none of this. A component behind a gateway may be
`permissive` but never `strict`, because the edge terminates TLS. Migration is
three changes with no coordinated window: the server adds its authenticated
port, its clients move to it, the server drops cleartext.

**Per project and per environment, on the platform (`mtls`).**

| Level | What is rendered | What is injected per pod |
|---|---|---|
| `off` (default) | nothing | nothing |
| `identity` | the namespace opts in to the identity bundle and receives the request permission; apps run `permissive` | a CSI volume holding `tls.crt`, `tls.key`, `ca.crt`; the pod's own ServiceAccount; no sidecar |
| `enforced` | `identity`, plus `strict` for components the catalogue marks, plus the admission policy | the same; a pod without the volume or on the `default` account is refused at admission |

A project moves `off`, `identity`, `enforced` per environment and does not
regress.

**What is injected per pod, exactly.** One CSI volume from
`spiffe.csi.cert-manager.io`, mounted as a directory, never a `subPath` (a
`subPath` mount never refreshes). The certificate lives one hour and is never
written to a Secret. Nothing else: no proxy and no agent.

**No sidecars for our own workloads.** The transport libraries (in
[truvity/policy](https://github.com/truvity/policy)) build the TLS
configuration, re-read the files on change, verify the peer's chain and
SPIFFE name, and check the caller against the allow-list. A mesh was
rejected: it adds a proxy per pod for a decision the application can make
itself ([trust/decisions.md](trust/decisions.md#t-11-no-mesh-mutual-tls-at-application-level)).

**A reload helper only for third-party products that cannot reload.** A
product that reads its certificate once at start (a broker, a database
operator that needs a label, a server holding its own certificate) gets a
reload sidecar or its native reloader, scoped to that product. Do not tie a
reload to an hourly leaf: a reload can re-run authentication for every
connected client. Where the product cannot verify identity at all, the
options are a terminating proxy in its pod or a written exception naming the
reason.

The workload-side page, with the transport libraries and the catalogue, is the
truvity/policy mTLS guide (see truvity/policy mTLS guide). The platform side
that this model requires is [prerequisites.md](prerequisites.md).

## Choosing a level

| Your problem | Stop at | Do not take on |
|---|---|---|
| a team's secrets in Kubernetes, no static credentials | 1 | PKI |
| the above, plus SSH access without distributing keys | 2 | PKI |
| certificates for your own hosts and services under a root you control | 3 | workload identity |
| services that must know *who* is calling, across clusters or at a broker | 4 | enforcement before the refusal test passes |
| a guarantee that no pod skips its identity | 5 | a namespace-wide switch: opt in per namespace |

If in doubt, stay one level lower than you think you need: each level adds an
operating burden that its predecessor does not have, and none can be removed
cheaply once other things trust it.
