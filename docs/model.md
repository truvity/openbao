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
| `policies[]` | ACL | named policies, rule by rule, in order |
| `groups[]` | identity | a group's policies and the doors it is admitted through |

**The namespace tree is one level.** Root, and one namespace per
environment. A project, a team or a tenant is a policy path
(`kv/data/<project>/*`) and an identity group inside its environment's
namespace, never a namespace of its own: a namespace per project multiplies
mounts, issuing CAs and logins for no isolation a policy does not already
give. `Validate` refuses a namespace name with a `/`.

A worked example of the whole shape is
[`pkg/model/testdata/desired.yaml`](../pkg/model/testdata/desired.yaml): a
root CA and an intermediate in root, an intermediate signed outside
OpenBAO, and two environments.

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
external signer is expected to put there.

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

One user CA per mount, generated inside OpenBAO; only its public key leaves
(`Result.SSHCAPublicKeys`). Each role lists its principals outright — no
`*`, no template, never `root` — writes the certificate's key id itself,
signs only the key types it lists, and grants exactly its `extensions`. The
mount caps every lease at the longest role maximum.

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
| namespace | `ns-<ns>` |
| KV, PKI and SSH mounts | `<path>` in root, `<ns>-<path>` in a namespace |
| canary | `<ns>-<canary>` |
| policy | `<ns>-policy-<name>` (`:` becomes `-`) |
| auth mount | `<ns>-auth-<path>` |
| auth role | `<ns>-role-<mount>-<role>` |
| identity group, alias | `<ns>-group-<name>`, `<ns>-alias-<name>`; `-<door>` appended off the primary door |
| self-signed root | `<issuer>-certificate` |
| request, signature, import, named issuer | `<issuer>-csr`, `<issuer>-signed`, `<issuer>-import`, `<issuer>-issuer` |
| pinned default, URLs, CRL, auto-tidy | `<mount name>-default`, `-urls`, `-crl`, `-auto-tidy` |
| host-name role, credential role | `<issuer>-role-<name>`, `<issuer>-credential-role-<name>` |
| SSH CA, SSH role | `<mount name>-ca`, `<mount name>-sshrole-<name>` |
| provider | `ProviderName`, default `openbao` |

Issuer names are unique across the server because resources are named
after them. `Options.Rename` maps any of these to the name an existing
state holds the object under ([adoption.md](adoption.md#adopting-a-running-openbao-configuration)).
[`pkg/apply/testdata/resources.yaml`](../pkg/apply/testdata/resources.yaml)
is every resource the worked example registers, with its inputs.

### What is protected

Every CA key, certificate, signature, import, named issuer, pinned
default and mount configuration, every SSH mount, CA and role, and every
credential role is `protect`ed: replacing a CA is an explicit,
overlapping-issuer migration, and a signing role that disappears in a
replace is a window in which nobody can sign. Host-name roles hold no key
and are not protected. Expired issuers are never tidied: retiring a CA is
a separate, bottom-up operation once everything below it has drained.
