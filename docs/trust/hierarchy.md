# The PKI hierarchy and its ceremonies

One root, held in a KMS, that signs a handful of certificates in its life.
Below it, three kinds of chain, each with a different constraint and a
different set of relying parties. This page is the shape and the reasons;
[ceremony.md](../ceremony.md) is the step-by-step, [custody.md](../custody.md)
is the key's policy, and [pki.md](../pki.md) is the authored contract
(`pkg/pki`) that encodes the invariants below and derives everything OpenBAO
holds from them: the domain intermediates, each environment's issuing CAs,
their leaf and credential roles, and the mounts they live in.

```
<root generation>                        KMS key, self-signed, 20 years, no name constraint
|-- private domain intermediate          10 years, DNS name constraint: the private zone + the cluster domain
|   `-- <env> issuing CA                 3 years, key inside OpenBAO, one per environment
|       `-- host leaves                  30 days (90 at most): servers, gateway client cert, service certs
|       `-- credential leaves            1 hour: a person's database client certificate
|-- origin domain intermediate           10 years, NO DNS constraint, limited by the role's host list
|   `-- <env> origin CA                  3 years
|       `-- origin leaves                30 days (90 at most): listeners the tunnel daemon connects to
|-- <env> identity CA  (one per env)     3 years, signed BY THE ROOT, exact URI constraint, path length 0
|   `-- SPIFFE leaves                    1 hour (24 at most)
`-- break-glass server leaf              a week at most; never committed; only when OpenBAO cannot issue its own
```

## The root

**A KMS key that is used as a signer and nothing else.** The root's private
key is generated inside a KMS (P-384, multi-region so that the loss of one
region does not lose the root) and never leaves it. It signs, over its life:
itself, one certificate per domain intermediate, one per environment
identity CA, and the break-glass leaf. Every signature is a reviewed
template, signed once, recorded as a public artifact that is committed, and
announced by an alarm (an alert on the KMS `Sign` event in every region).
A root that signs a fourth kind of thing is an incident, not a change.

The **key policy is the whole authority** ([custody.md](../custody.md)): the
administrator role can manage the key but cannot sign, schedule deletion,
or rewrite the policy; the ceremony role can sign and read the public key
and nothing else. Separating "administer" from "sign" is what makes the key
governable without making it usable.

**No name constraint on the root, deliberately.** A 20-year certificate must
not encode today's zone list: a new environment or public zone would need a
new root generation. Constraints live on the intermediates, which are
re-issuable under the root. `pkg/pki` refuses a root that carries one.

**Path length 3.** Root, domain intermediate, environment CA, project CA,
leaf: three CA certificates may sit below the root, so a project can later
hold its own issuing CA under an environment's.

## The domain intermediates

A **trust domain** is one intermediate under the root. Two share the root and
nothing else, so one can be rotated or lost without the other.

| Domain | Constraint on the CA | What actually limits the leaves | Trusted by |
|---|---|---|---|
| **private** | DNS: the private zone and the cluster domain | the CA's constraint, plus per-role name patterns | every workload and every person |
| **origin** | none | the role's `allowed_domains`, rendered from the catalogue of hostnames the tunnel is configured for | the tunnel daemon only |

The private intermediate **includes the cluster domain** (`cluster.local` by
default) because in-cluster service certificates carry
`<service>.<namespace>.svc.<cluster-domain>`. A name constraint applies to
the whole chain below the constrained certificate, so a domain missing from
the intermediate can never be issued anywhere beneath it. Only that shape is
offered: a shorter form (`<service>.<namespace>.svc`, or a bare service name)
has no place under the constraint, and the approver denies it
([issuance.md](issuance.md#the-policies)).

The origin intermediate is unconstrained **on purpose**. Environments will
serve many public zones from many Cloudflare accounts, and a DNS constraint
lives in the CA *certificate*: a constrained origin chain would need a new
intermediate per new zone. Role policy is configuration and can change in an
apply; a CA certificate cannot. The role's host list is the only limit, and
that list is derived from the gateway catalogue, so a new hostname needs an
OpenBAO configuration apply before its listener can get a certificate. Wildcards
are refused, except on the one role where the catalogue declares a wildcard
group whose names are generated (CI installs, per-employee installs): a
wildcard must still be a declared group domain, so nothing can ask for a
wildcard no listener declares.

### The identity CA is signed by the root, not by an intermediate

Workload identity uses a **URI** name constraint (the trust domain of the
SPIFFE ID), not a DNS one. The obvious design is a shared identity
intermediate under the root that signs one issuing CA per environment. That
design fails on a real limitation: **OpenBAO drops `permitted_uri_domains`
when it signs a CA certificate**
([openbao/openbao#4104](https://github.com/openbao/openbao/issues/4104)) --
and it ignores the parameter on root generation too, with an "unrecognized
parameter" warning that a lenient client will not notice. An issuing CA
signed *inside* OpenBAO therefore carries **no URI constraint**, and every
environment's CA would trust every other environment's SPIFFE IDs, with only
the OpenBAO *role* (configuration, not certificate) keeping an environment to
its own trust domain.

The ceremony is this repository's own Go code, and Go's `x509` builds URI
constraints correctly. So each environment's identity CA is signed
**directly by the root** by the ceremony, with an *exact* URI constraint (its
own trust domain, no leading dot: an exact host match) and path length 0. The
CA cryptographically cannot mint another environment's identity. There is no
shared identity intermediate (the contract's `domainIntermediate` for a URI
domain is optional for exactly this reason). Full mechanism:
[pki.md](../pki.md#per-environment-identity-cas-and-why).

The same finding shapes what you may rely on OpenBAO to enforce: **only DNS
name constraints can be set through OpenBAO's own endpoints**; `excluded_ip_ranges`
is also ignored on root generation. Anything else comes from the ceremony.

## Lifetimes and algorithms

| Certificate | Lifetime | Renew | Notes |
|---|---|---|---|
| root generation | 20 years, never re-signed | -- | a new generation, never a re-signature |
| domain intermediate | 10 years | prepare 2 years ahead | |
| environment CA (issuing, origin, identity) | 3 years | prepare 180 days ahead | the origin and private ones are OpenBAO-held keys |
| host and origin leaf | 30 days default, 90 at most | 10 days before | cert-manager renews |
| SPIFFE leaf | 1 hour default, 24 at most | re-requested, never renewed in place | never persisted to a Secret |
| person's database client certificate | 1 hour | on the next command | key generated on the laptop; role has `sign` only |
| break-glass leaf | a week at most | signed by hand | each is one more Sign alarm |

The expiry thresholds are authored in the contract (`alerts.thresholds`) but
the alert is **off until an alert consumer exists** (the contract refuses
`alerts.enabled: true` before then). Until then the weekly restore check and
a look before every PKI change are the watch.

**Algorithms.** Every CA signs P-384 with ECDSA-SHA-384; `global.immutable`
fixes this fleet-wide. A **leaf** role may accept a second curve, and the
distinction matters:

- OpenBAO treats a role's `key_bits` as a **minimum** for an EC role. A P-256
  request against a role holding 384 is refused outright ("role requires a
  minimum of a 384-bit key"), never downgraded. So `pkg/apply` writes a P-384
  leaf role with `key_bits` 256, and it signs both.
- The workload-identity CSI driver **always generates P-256** and has no
  option for another, so the identity role is declared P-256. The refusal
  arrives *after* the approver has approved, which reads as a signing failure,
  not a policy one.
- RSA is refused everywhere. `global.additionalLeafKeyCurves` allow-lists an
  exception explicitly; nothing else admits a curve.

Tighten leaves to P-384 only once nothing asks for P-256.

## Two-phase creation of a CA

Every domain intermediate and every environment identity CA is signed
**exactly once, offline**, from a CSR OpenBAO produced. The key stays in
OpenBAO; the certificate comes back. It is two phases because the CSR must
exist before anything can be signed, and nothing downstream may treat the CA
as live until its signed certificate is committed.

**Phase A: additive only.**

1. Create the mount and the unsigned key in OpenBAO, and export the CSR.
   The desired-state apply cannot declare an `external` issuer that has
   nothing to import yet, so this first step is a dedicated bootstrap
   (`apply.BootstrapEnvironmentCA` for an environment CA) that registers the
   mount and the request under the names the normal apply will later use, so
   phase B adopts both with no create and no delete.
2. Stop. Nothing has been signed.

**The ceremony.** Someone derives the certificate template from the contract
and reviews it; a second person repeats the dry run.

1. `openbaoctl pki sign-intermediate ... --print-template` needs no
   credential and prints every field and a `template sha256`: the hash of the
   exact TBSCertificate the root key would sign. Nothing in it depends on the
   signer, so two people on the same branch and CSR get the same hash. With
   `--contract` it also prints the **custody cross-check**: the key, its
   region and replica, the generation, the ceremony role and the profile,
   verified against the custody outputs the custody side published
   (`--custody-outputs`), or the reason it was skipped
   (`--skip-custody-check`). A key that is not the published one, a wrong
   region or generation, or a role that is not the ceremony role is refused
   before anything is reserved or signed; see
   [pki.md](../pki.md#the-custody-cross-check).
2. Both check the subject, the issuer, the name constraints and the validity,
   and write the hash down; the second person also reads the custody lines
   (or the skip reason).
3. The signing run accepts **only that hash**, and repeats the custody
   check. It rebuilds the template and
   refuses a mismatch *before* reserving anything, checks the KMS key is the
   one behind the committed root, creates an exclusive `<artifact>.attempt`
   reservation (so nothing signs twice for one artifact), signs once, proves
   the result (signature, chain, public key equals the CSR's, path length,
   key usage, constraints exactly as authored) and writes the artifact without
   overwrite.
4. The artifact and its reservation are committed. The Sign alarm has fired;
   whoever receives it is told first.

**Phase B: the artifact gates everything downstream.** The committed
artifact is proven offline against the contract and the committed root, and
its chain is imported through the normal apply. `IntermediateSigned(spec)` is
the gate: nothing that depends on the CA -- an environment CA below it, a
leaf role, a trust bundle entry -- renders until it reports true. After
installing, the certificate OpenBAO reports for the issuer must be the
artifact's, byte for byte.

The ceremony is not a Pulumi resource or a controller on purpose: an
imperative, once-only signature has no safe create/read lifecycle, and an
apply callback can run again on a refresh or a retry.

## Root generation and rotation

A new root **generation** is prepared without touching the active one.
Rotation is a walk, and the order is the safety:

1. Create the KMS custody for the new generation (key, replica, policy, alarm)
   and run its ceremony; commit the public artifact.
2. Add the generation to `migration.trustedGenerations`, beside the old one.
   That, and nothing else, puts the new root in every bundle. The list only
   accepts a generation whose artifact is present and re-verified (fingerprint,
   key identifier, subject, self-signature).
3. Wait until every trust bundle reports synced on every cluster and every
   non-Kubernetes consumer (laptops, the tunnel daemon's roots file) confirms
   the new root. The origin domain has no bundle: the tunnel daemon's roots
   file is widened in its own change **before** any origin leaf is issued
   from the new root.
4. Prepare a new domain intermediate under the new root, then one new
   environment CA under it for **every** environment. Activate and drain
   environments independently.
5. Keep the old root trusted until every old chain has retired. Overlap can
   last years and is intentionally conservative.
6. Retire the old root only in a separate, approved change
   ([Retiring a CA](#retiring-a-ca-safely)).

**A bundle holding two roots has an operating-system consequence.** Some
trust-store tools import every certificate in a file; others are reliable
with exactly one per file. Split the bundle per certificate before telling
people to re-run a trust step.

**Rotating an environment CA** follows the same shape one level down: a
second, separately named, protected resource set for the successor; a
preparation preview that may create only the successor key, CSR, signed
certificate, import and named issuer, and contains no delete or replacement;
a smoke certificate addressed explicitly to the successor; then an activation
change that points the mount default and every issuance role at the
successor and sets the old issuer's usage to `crl-signing,read-only`. Leaves
renew through the active role. When forcing a renewal, renew by namespace or
by name and **never every certificate in the cluster**: some Certificates
hold another system's *signing key*, and renewing one rotates that key.

Rollback before retirement is selector-only: point the roles and the mount
default back at the old issuer and renew. Never delete the successor during
an incident.

## Retiring a CA safely

Expiry alone never authorizes deletion, and neither does a successor being
live. Retirement is a **separate reviewed change**, bottom-up, once everything
below the CA has drained:

1. Confirm the last leaf's `NotAfter` (plus a margin) has passed. Do not infer
   a parent's retirement from the leaf lifetime alone: environment CAs live for
   three years.
2. In the change that retires it, **explicitly unprotect** the old
   generation. Every CA key, certificate, signature, import, named issuer,
   pinned default and mount configuration is `protect`ed by the apply, because
   replacing a CA is an overlapping-issuer migration, not an edit, and a
   signing role that disappears in a replace is a window in which nobody can
   sign. Unprotecting is the visible, reviewable act.
3. Delete the old resources, leaves' parents last. Record the approval and
   evidence in the change.
4. Never edit a protected generation in place. A successor uses a new logical
   name, key name and issuer name; issuer names are unique across the server
   because resources are named after them.

**Issuer-scoped names are a trap.** A role's logical resource name is derived
from the issuer it signs with. Pointing a role at a new issuer -- with nothing
else changed -- changes that logical name, so the state registers a new role
and *deletes the old one*, and the delete reaches the very OpenBAO path the
create just wrote, because the role's own name never changed. Whenever a role
moves between issuers (an environment moving from a shared intermediate's
issuing CA to its own root-signed CA is the case that exists), merge
`apply.EnvironmentCARoleRename(oldIssuer, newIssuer, roles...)` into the
apply's `Rename` map. Reading a preview, *any* delete of a role is a stop.

## The break-glass leaf

OpenBAO's own serving certificate normally comes from its own hierarchy,
renewed by cert-manager through OpenBAO. If that certificate expires,
cert-manager can no longer reach OpenBAO to renew it, and a restored or new
cluster has no OpenBAO yet. For those two moments the root signs one leaf by
hand (`openbaoctl pki` break-glass), never committed, with the Sign alarm.
A break-glass leaf exists so OpenBAO does not need a *second* PKI kept aside
for the day it cannot issue. A yearly drill runs the real KMS root once, by
hand.

## Certificate roles at a glance

| Role | Domain | Names | Usage | Notes |
|---|---|---|---|---|
| `private` | private | any name in the environment's private zone, the zone itself included | server, client | what servers and gateways use |
| `client` | private | a name below the zone, never the zone | client only | the machine exposure's client certificates |
| `gateway` | private | one fixed name | client only | what the gateway presents to a backend that asks |
| `service` | private | `<service>.<namespace>.svc.<cluster-domain>` only | server, client | per-service certificates where a name is checked |
| `origin` | origin | the catalogue's hosts | server only | wildcards only where the catalogue declares them |
| `identity` | per-environment identity CA | one URI SAN `spiffe://<trust domain>/*`, no DNS, no IP | server, client | P-256; `use_csr_sans` false |
| `db-client` (a *credential* role) | private | the caller's own e-mail alias | client only | CN validated as an e-mail; `sign` only; not stored |
| restore check | private | one fixed harmless name | server | 1-hour leaves; proves the weekly restore can sign |

`use_csr_sans` matters: OpenBAO defaults it to `true`, and when true the
request's own URI SANs are silently dropped, so an identity role without
`use_csr_sans: false` signs a certificate that *looks* scoped and carries no
URI name at all.

## SSH certificate authorities

SSH is a second, separate hierarchy in OpenBAO: a **user CA** per
environment (machine users) and a **host CA** on a mount of its own. They are
never the same key: the two things a CA does for SSH -- telling clients which
hosts to trust, telling hosts which users to admit -- are different promises,
and one compromised key must not cost both. People do not use the user CA at
all in the target shape (they use opkssh); see [people.md](people.md#ssh) and
[decision 0003](../decisions/0003-ssh-people-external-machines-and-hosts-on-our-cas.md).

## The seal key and the seal plugin

The KMS root above signs and nothing else. A **second** KMS key belongs to
the server: the auto-unseal (seal) key, which wraps the barrier key OpenBAO
encrypts everything with. They are different keys with different policies,
and neither can do the other's job: the seal key only encrypts, decrypts and
describes (its grants are `Encrypt`, `Decrypt`, `DescribeKey`) and cannot
sign a certificate; the root can sign and is never used to unseal. Losing the
seal key's access seals every node at its next restart; the recovery keys and
the raft snapshot are the way back, so both are kept where the estate keeps
its other recovery material.

From OpenBAO 2.7 the code that talks to that key is an **external plugin
binary** the server runs as a child process, with the server's own KMS
credentials. It therefore sits inside the trust boundary in a way an auth
plugin does not: whoever controls that binary can decrypt the barrier key. So
the binary is pinned, never fetched by the server at runtime: by the
manifest-list digest of its OCI image (and optionally its raw-binary
checksum), installed before the server starts by an init container that
pulls nothing itself (the kubelet pulls the digest, through the estate's own
mirror if the nodes cannot reach the public registry), into a per-pod
directory that is thrown away with the pod. A bump of the plugin is a
reviewed change to a digest, rolled standby first like any configuration
change. Why the delivery is shaped this way, what the render refuses, the
rehearsal that proves it and the 2.6 to 2.7 runbook are in
[server.md](../server.md#the-seal-as-a-plugin-openbao-27).
The weekly restore check opens a snapshot with its own scratch server, so it
installs the same pinned plugin the same way
([server.md](../server.md#the-restore-check-needs-the-plugin-too)); a restore
check that cannot start on 2.7 proves nothing.

## Where each part is used

| You need to change | Read |
|---|---|
| the root, its custody, the yearly drill | [ceremony.md](../ceremony.md), [custody.md](../custody.md) |
| the server's seal (auto-unseal key, seal plugin), rolling to 2.7 | [server.md](../server.md#the-seal-as-a-plugin-openbao-27) |
| which trust domains, roles, lifetimes exist | [pki.md](../pki.md) |
| what OpenBAO is asked to hold | [model.md](../model.md#pki-mounts-issuers-roles) |
| who may ask cert-manager for a certificate | [issuance.md](issuance.md) |
| an existing hierarchy that predates this library | [adoption.md](../adoption.md) |
