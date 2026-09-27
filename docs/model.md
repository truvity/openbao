# The desired-state model and its apply

`pkg/model` describes everything an OpenBAO server is configured with, per
namespace and per engine. `pkg/apply` converges a server onto it with the
Pulumi vault provider. The model has no loader and no configuration format:
a platform derives a `model.Desired` from its own sources (whatever
decides who reads which secret, which clusters exist, which names a PKI
role may sign), writes it out as a golden file for review, and hands it to
the apply.

```
your sources ──derive──▶ model.Desired ──Validate──▶ apply.Deploy ──▶ OpenBAO
                              │
                              └── yaml golden, reviewed in every change
```

## The shape

```
Desired
├── bootstrap      the door the apply logs in through — declared, never applied
├── root           what the apply owns in the root namespace
├── namespaces[]   one per environment, directly below root
├── identity       how groups become identity groups
└── credentialMaxTtl
```

Each namespace (`root` included) holds the same engines:

| Field | Engine | What |
|---|---|---|
| `kv[]` | KV v2 | a mount, its description, and an optional restore canary |
| `pki[]` | PKI | a mount, the issuers whose keys it holds, host-name roles and credential roles |
| `ssh[]` | SSH | a user CA whose key OpenBAO generates, and its roles |
| `auth[]` | JWT/OIDC | who issues the tokens a mount accepts, and its roles |
| `projects[]` | -- | this namespace's own [`ProjectNamespace`](#projects-environmentproject)s, an environment only |
| `policies[]` | ACL | named policies, rule by rule, in order |
| `groups[]` | identity | a group's policies and the doors it is admitted through |

**The namespace tree is `<environment>/<project>`.** Root, one namespace
per environment directly below it, and, below each environment, one
namespace per project ([ADR 0001](decisions/0001-namespaces-are-environment-project.md)).
`Validate` refuses a namespace or project name with a `/`, a space, `..`,
`*` or `+` — a single, plain path segment or nothing.

Two worked examples, the small one first:

- [`desired-one-env.yaml`](../pkg/model/testdata/desired-one-env.yaml) —
  **one environment**, on the cluster that also runs the server: a root
  CA and an intermediate in root, that cluster's door in root for the
  backup job and the same door in the environment for its stores and its
  issuer, the environment's issuing CA and its service role, a KV mount
  with a restore canary, and people's door. It is the single-cluster
  install ([adoption.md](adoption.md#single-cluster)) as desired state,
  and `conformance/` applies it to a real server.
- [`desired.yaml`](../pkg/model/testdata/desired.yaml) — **the whole
  shape**: the same root and intermediate, a second intermediate signed
  outside OpenBAO, an SSH user CA, the web UI's door, credential roles,
  two environments, and one project (`billing`, in `dev`) beside `dev`'s
  own KV mount.

Neither is a template to copy: an estate derives its own model from its
own sources. They are what every field looks like when it is filled in.

### Projects: `<environment>/<project>`

A [`ProjectNamespace`](../pkg/model/project.go) is one project, nested one
level below its environment. It holds mounts and nothing that admits
anybody: `kv[]` and `pki[]` today, Transit later — never `auth[]`,
`policies[]`, `groups[]`, `ssh[]`, `sshHost[]`, or a nested `projects[]` of
its own. It is a type of its own, not [`Namespace`](../pkg/model/desired.go)
reused with a runtime flag, for the same reason [`SSHHostMount`](#ssh) is a
sibling type of `SSHMount` rather than a `kind` on it: most of what ADR
0001 refuses, this refuses simply by having no field to write it in, which
`Validate` never needs to check at all.

**An environment holds its own platform mounts *and* its projects, side by
side.** `dev`'s own `kv[]` is the operators' own KV mount — their secrets,
their environment's issuing CA, their SSH CAs — exactly as before this
record; `dev.projects[]` is where a tenant's, a team's or a partner's own
mounts live instead. Nothing about adding a project forces platform data
into one, and nothing stops an environment with no projects at all from
looking exactly as it always has.

**A project's issuing CA is signed by its own environment's issuer, and
only that.** `PKIIssuer.SignedBy` inside a `ProjectNamespace` must name a
mount and issuer the SAME environment declares directly — never root's,
never a sibling project's, never the project's own root or an external
signer. `Validate` refuses any of those; a project's chain is always root
→ ... → the environment's issuing CA → the project's issuing CA → its
leaves.

**An environment's own issuing CA needs `MaxPathLength` at least 1 once
it signs a project's.** A path-length constraint counts the WHOLE
remaining chain below an issuer, not just the next hop (RFC 5280
4.2.1.9): root → a domain intermediate → an environment's issuing CA → a
project's issuing CA is four levels, and every issuer above the bottom
one needs a budget wide enough for everything still beneath it —
`Validate` (`Desired.validateSignerDepth`) refuses an issuer whose
`MaxPathLength` is too short for the deepest chain the model actually
puts below it, naming both the issuer and the descendant it cannot cover,
before anything is applied. `MaxPathLength: 0` still means exactly what
it always has — this issuer signs no further CA at all — so adding a
project to an environment whose own issuing CA was declared with 0 is a
model change this record's own validation refuses until that issuer's
`MaxPathLength` is raised.

**Raising an existing environment CA's `MaxPathLength` is not something
OpenBAO lets you do in place.** The value is set once, when the issuer is
created (`selfSigned`/an intermediate's certificate request), and is part
of what makes the certificate the certificate it is — changing it means
generating a new issuer (a new key, or the same key re-signed under a new
name) and migrating every role and project below the old one across, the
same shape [ADR 0001](decisions/0001-namespaces-are-environment-project.md)'s
own migration section describes for a KV path. An environment CA that
will ever sign a project should therefore be given `MaxPathLength: 1` (or
more, for a deeper hierarchy still to come) from the day it is created,
even before its first project exists — cheaper than a CA migration later.

**A policy at the environment reaches a project's mount by path.**
[`model.ProjectPath(project, mount, subpath)`](../pkg/model/project.go)
builds `<project>/<mount>/<subpath>`; a token that logs in at the
environment and holds a policy naming it reads
`<environment>/<project>/<mount>/<subpath>` with no second login (ADR
0001, proved against a real server in `conformance/project_test.go`).
`Validate` refuses a rule that names a project the environment does not
actually declare, or a mount inside it the project does not hold, and —
because the SAME path shape is how a rule reaches the environment's own
mounts (`kv/data/*`) and a project's (`billing/kv/data/*`) alike, with no
namespace hop to tell them apart — it also refuses any environment-level
rule whose FIRST path segment carries a glob (`*` or `+`) rather than one
literal name: `*` and a prefix glob such as `bill*` reach every project
the environment declares (a partner's among them) exactly as readily as
the environment's own mounts, whether or not a project happens to collide
with the glob today. A rule that means one project names it in full
(`ProjectPath` or its equivalent); a rule that means only the
environment's own mount already spells that mount out first
(`kv/data/*`, `pki/sign/service`, `ssh/sign/runner`) and is untouched,
since the glob there sits after the first segment, never in it.

Deleting a project deletes its mounts, then its namespace: OpenBAO refuses
to delete a namespace that still has children, so nothing here is a
one-step operation.

### The bootstrap

The apply logs in through an auth mount in root, as a role that grants it
everything. If the apply owned that mount it could lock itself out halfway
through a run, so it never touches it: the server's initialisation creates
it, and `bootstrap` declares it only so a review sees the whole picture.
Policies the bootstrap declares may be referenced by name from `root`
(a second door into root carrying the operators' policy, say).

### Auth: workloads and people

A `jwt` mount accepts tokens from one issuer (`discoveryUrl`, also the
bound issuer). Two kinds of role live on it:

- **A workload role** binds one token subject — for a Kubernetes workload,
  `model.ServiceAccountSubject(namespace, serviceAccount)` — and carries
  its `policies` on the token.
- **A people role** maps the issuer's `groupsClaim` onto identity groups
  and carries no policies itself: the groups' aliases on the mount do.
  `claimMappings` copy claims into the alias metadata, so an audit entry
  says who a login was.

A role that does neither admits every token for its audience, and
`Validate` refuses it.

`supportedAlgorithms` is the signing algorithms the mount accepts, jwt
role or oidc role alike. Empty resolves to `model.DefaultSupportedAlgorithms`
(RS256, ES256, ES384) -- the plugin's own default is RS256 alone for an
oidc role (`all` for a jwt role), which would refuse an issuer that signs
ES256 or ES384, so the apply always states the resolved list explicitly.
`Validate` refuses a name the JWT plugin does not sign with (so no HS* or
`none`, ever) and a name repeated.

An `oidc` mount (`type: oidc`) is the web UI's door: a browser sign-in as
`clientId`, whose secret is an input of the apply and never desired state.
It keeps the namespace in the OIDC state, so one redirect URI serves every
namespace, and it is listed on the sign-in page.

For an issuer whose tokens carry a flat groups claim -- access-roster's,
or one shaped like it -- `model.Roster` builds both doors, the grants that
turn a group name into a policy, and the operators' bootstrap door from
one value. [integrations/access-roster.md](integrations/access-roster.md)
is that contract end to end, and
[`examples/roster`](../examples/roster/roster.go) a whole server built
with it, which the conformance test applies to a real server.

### Groups and doors

OpenBAO gives an identity group **one** alias: writing a second alias for
the same group silently replaces the first. So a group admitted through two
doors — the CLI's `jwt` mount and the UI's `oidc` mount — becomes two
identity groups, one aliased on each mount, carrying the same policies.
Through `identity.primaryDoor` the identity group keeps the group's bare
name; through any other door it is `<name>@<door>`, and records the door in
its metadata.

### PKI: mounts, issuers, roles

A PKI mount holds one or more issuers. Each issuer's key is generated
inside the mount (`internal`) and never leaves it, and exactly one of
three says who signs its certificate:

| Issuer | Signed by | The apply |
|---|---|---|
| `selfSigned: true` | itself | makes a root inside OpenBAO |
| `signedBy: {namespace, mount, issuer}` | an issuer of a mount declared **earlier** | has that mount sign the request, after its URLs exist |
| `external: true` | a signer outside OpenBAO — a root whose key is in a KMS ([ceremony.md](ceremony.md)) | exports the request and imports the chain you supply |

`defaultIssuer` is pinned as the mount's default and never follows the
latest issuer. Every role names its own `issuer`, so the default never
decides what a role signs — which is what lets an old and a new CA share a
mount through a migration. Once the default issuer exists the apply
configures the mount's issuer, CRL and OCSP URLs (under `Options.Address`),
its CRL and its auto-tidy, and every signature on the mount waits for them:
a certificate carries the URLs its issuing mount had when it was signed.

`nameConstraints` are what the signer puts on the certificate. An empty
list is left out rather than sent empty, and an issuer with none carries no
name-constraints extension at all: an unconstrained parent gives an
unconstrained child. For an `external` issuer they record what the
external signer is expected to put there. OpenBAO 2.6.2 does not
recognise `excludedIpRanges` when it generates a root inside the mount —
it ignores the parameter and says so in a warning — which is why the
one-environment example, the one applied to a real server, constrains
domains only.

A host-name role (`roles[]`) signs the names it lists; everything else is
off whatever is written: no templates, globs, any-name, IP, URI or other
SANs, localhost or e-mail protection, and a common name, when present, must
be a host name. An exact wildcard entry matches as a bare domain, so
`allowWildcardCertificates` signs exactly the wildcards the role lists.

A credential role (`credentialRoles[]`) signs a CSR for the caller and
nobody else: the only common name it accepts is the caller's own alias name
on `subjectMount`. It offers `sign` only, so the key is always the
caller's, and it stores nothing: its revocation model is its short life.

### SSH

Trust for SSH has three parts, and this model covers two of them. People
sign in through opkssh, straight against an OIDC issuer, with no CA and no
part in this model at all
([integrations/access-roster.md](integrations/access-roster.md#5-openbao-through-accessctl-bao-accessctl-pgpsql-and-opkssh-for-people)).
**Machines** — CI jobs, controllers, anything that is not a person at a
keyboard — get user certificates from `ssh[]`. **Hosts** get host
certificates from `sshHost[]`, so a client trusts one
`@cert-authority <domains> <key>` line instead of pinning every host's own
key.

`ssh[]` is one user CA per mount, generated inside OpenBAO; only its public
key leaves (`Result.SSHCAPublicKeys`). Each role lists its principals
outright — no `*`, no template, never `root` — writes the certificate's
key id itself, signs only the key types it lists, and grants exactly its
`extensions`. The mount caps every lease at the longest role maximum.

`sshHost[]` is a **host CA on a mount of its own, generated inside OpenBAO
the same way — never the same key as any `ssh[]` mount's**: a key clients
are told to trust for hosts must never also be a key sshd trusts for
users. `SSHHostMount`/`SSHHostRole` are a sibling type to
`SSHMount`/`SSHRole` rather than a `kind` flag on the existing one, because
the two roles share almost no field (principals and a default user, versus
domains and bare/subdomain flags): a shared type would carry fields that
mean nothing for the other kind, and `Validate` would need to branch on
which fields apply. As a sibling type, a host role can never even be
written onto a user mount — the compiler refuses it, not a runtime check —
and every existing `ssh[]` mount and role renders exactly as it did before
this type existed.

A host role's `allowedDomains` are literal host names — no `*`, no
identity template, exactly like a PKI host-name role's own `allowedDomains`
— and at least one of `allowBareDomains`/`allowSubdomains` must be true, or
the role signs nothing. Its lifetime is capped at 30 days, always — not by
`credentialMaxTtl`, which reaches only `ssh[]` and `credentialRoles[]` and
is an estate's own, lower ceiling on short-lived credentials. A host
certificate is trusted by whatever holds the CA's public key, with no
per-signing review, so it is deliberately allowed to outlive a short-lived
credential by a wide margin — and the 30-day cap on it is this
repository's own, not something a namespace's `credentialMaxTtl` raises or
lowers. `Result.SSHHostCAPublicKeys` carries the host CA's public key
per mount, the same way `Result.SSHCAPublicKeys` does for a user mount, for
a consumer to render into an `@cert-authority` line.

**Who may sign a host certificate:** this repository adds no new auth
method for it. A host proves itself the same way any other workload does
— a Kubernetes pod's projected ServiceAccount token, on a `jwt` mount role
bound to that ServiceAccount (`ServiceAccountSubject`) — whose policy
grants `update` on exactly `<host mount>/sign/<host role>` and nothing
else. `examples/roster` wires this up end to end (`HostAgentDoor`,
`HostAgentRole`), and `conformance/roster_test.go` signs a host
certificate through it against a real server.

**A machine role can force one command.** `SSHRole.ForceCommand`, when
set, is the one command every certificate that role signs carries as its
`force-command` critical option — a machine identity that should only ever
run one thing, such as a backup agent, never an interactive shell.
`Validate` refuses `ForceCommand` alongside `permit-pty` or any forwarding
extension: a forced command that can still open a terminal or forward a
port is not forced.

Making the forced command actually unconditional took more than the SSH
role's own configuration. OpenBAO 2.6.2's SSH secrets engine applies a
role's `default_critical_options` only when the **request's own**
`critical_options` is entirely absent; when the request carries one,
however small, OpenBAO uses the request's map exactly as given, in place
of the role's default, rather than merging the two.
`allowed_critical_options` only limits which keys such a request may name
— it does not stop the caller from naming one, whether the list is empty
(which means "any key", not "none": a factory-default convention shared
with `allowed_extensions`) or names something else entirely, since the
default is dropped regardless of which key survived the check. Confirmed
against a real server while building this: with `allowed_critical_options`
left empty, a request that supplied its own `force-command` critical
option **succeeded and replaced** the role's default. There is no role
setting that fixes this — it is the request-versus-default trade-off the
engine makes, not a bug this library can validate around from inside the
SSH mount.

The grant that reaches a force-command role's sign path must therefore
deny the `critical_options` parameter outright at the **ACL layer**,
which does stop it: `path "…" { … denied_parameters = { "critical_options"
= [] } }` refuses any request that carries the parameter at all, before
the SSH backend ever sees it, whatever key or value it names.
`Rule.DeniedParameters` is that clause, `Namespace.Validate` refuses a
policy that grants a force-command role's sign path without denying
`critical_options` there, and `examples/roster`'s `signForced` helper is
the pattern a grant should follow. See
[safety.md](safety.md#a-forced-command-that-a-caller-can-still-replace)
for the refusal this closes and the test that proved it.

### KV and the canary

A KV mount is version 2. Its `canary` is a secret the apply writes as
`{"namespace": "<namespace>"}`, which `openbao-ops`' restore check reads
back from a restored snapshot to prove it decrypts data in every namespace.

`model.KVLayout` is the contract between whoever writes a secret and
whoever reads it — kind, key under `<kind>/`, properties, writer — with
`{name}` placeholders. The apply writes no secrets, so a layout is
validated and consulted by an estate's own checks, never applied.

## Applying it

```go
result, err := apply.Deploy(c, desired, apply.Options{ // c is the *pulumi.Context
    Address: "https://openbao.example.com",
    Login: apply.Login{
        Mount: "jwt-people", Role: "people", CACertFile: caFile,
        Token: func(ctx context.Context) (string, error) { return operatorJWT(ctx) },
    },
    BeforeApply: apply.SnapshotJob{
        Kubectl: apply.KubectlWith(kubeconfig), Namespace: "openbao",
        CronJob: "openbao-snapshot", SkipEnv: "EXAMPLE_SKIP_SNAPSHOT",
    }.Run,
    OIDCClientSecrets: map[string]pulumi.StringInput{"openbao-ui": uiSecret},
    SignedChain:       verifiedChainFromYourCeremony,
})
```

In order, `Deploy`:

1. validates the model, and refuses what only the options can decide: an
   oidc mount without its client secret, an external issuer without
   `SignedChain`, an issuer name used twice across the server;
2. runs `BeforeApply` — on an apply, never on a preview;
3. fetches the login token and creates the provider, which uses the login
   token as is (no child token: a short-lived token cannot mint one that
   outlives it);
4. registers root, then each namespace: PKI, KV, policies, auth mounts
   and roles, groups and aliases, SSH, credential roles.

`Result` carries the provider, the namespaces, every self-signed issuer's
certificate (a trust anchor), every external issuer's request (what the
external signer signs), and every SSH CA's public key, for the caller's
exports.

**The snapshot comes before the token.** `apply.SnapshotJob` creates a Job
from the snapshot CronJob `openbao-ops` renders and waits until it
completes; it steps aside only when `SkipEnv` names a reason, or when the
CronJob has never succeeded (a fresh install, where this very apply creates
the job's role). A slow snapshot therefore never eats into a short-lived
login.

**The server must not serve reads from a standby.** The apply reads back
every object it writes. Behind a load balancer that targets every pod, a
standby that has not applied the write answers with nothing; the server
shape in [server.md](server.md) sets `disable_standby_reads = true`.

### Resource names

`Deploy` registers every resource directly on the caller's Pulumi context,
not inside a component resource: a component type would put itself into
every child's URN, and a state that already runs these objects — hundreds
of mounts, roles and protected CA keys — would preview as a replacement of
all of it. The logical names are derived from the model, and **a derived
name never changes in a minor version**:

| Resource | Logical name (`<ns>` is the namespace; `root` for root) |
|---|---|
| namespace | `ns-<ns>`; a project's is `ns-<environment>-<project>` |
| KV, PKI, SSH and SSH host mounts | `<path>` in root, `<ns>-<path>` in a namespace -- `<environment>-<project>-<path>` inside a project |
| canary | `<ns>-<canary>` |
| policy | `<ns>-policy-<name>` (`:` becomes `-`) |
| auth mount | `<ns>-auth-<path>` |
| auth role | `<ns>-role-<mount>-<role>` |
| identity group, alias | `<ns>-group-<name>`, `<ns>-alias-<name>`; `-<door>` appended off the primary door |
| self-signed root | `<issuer>-certificate` |
| request, signature, import, named issuer | `<issuer>-csr`, `<issuer>-signed`, `<issuer>-import`, `<issuer>-issuer` |
| pinned default, URLs, CRL, auto-tidy | `<mount name>-default`, `-urls`, `-crl`, `-auto-tidy` |
| host-name role, credential role | `<issuer>-role-<name>`, `<issuer>-credential-role-<name>` |
| SSH CA, SSH role (user or host mount alike) | `<mount name>-ca`, `<mount name>-sshrole-<name>` |
| provider | `ProviderName`, default `openbao` |

Issuer names are unique across the server because resources are named
after them. `Options.Rename` maps any of these to the name an existing
state holds the object under ([adoption.md](adoption.md#adopting-a-running-openbao-configuration)).
[`pkg/apply/testdata/resources.yaml`](../pkg/apply/testdata/resources.yaml)
is every resource the worked example registers, with its inputs.

### What is protected

Every CA key, certificate, signature, import, named issuer, pinned
default and mount configuration, every SSH mount, CA and role -- host or
user alike -- and every credential role is `protect`ed: replacing a CA is
an explicit, overlapping-issuer migration, and a signing role that
disappears in a replace is a window in which nobody can sign. PKI
host-name roles hold no key and are not protected; SSH roles, unlike
those, always are, because an SSH role's own principals or domains are
what a certificate is trusted for -- there is no issuer underneath it to
re-derive the same trust from. Expired issuers are never tidied: retiring
a CA is a separate, bottom-up operation once everything below it has
drained.
