# The desired-state builder

[`pkg/model`](model.md) says what an OpenBAO server is configured with, and
[`pkg/pki`](pki.md) derives the PKI half of it from an authored contract.
`pkg/builder` is the rest: it derives everything else -- the workloads'
logins, the SSH and host-certificate engines, the groups people hold, the
project namespaces, the jobs that live in root -- from declarative contracts,
one per engine, and writes it as a `model.Desired`.

```
your rows ──adapter──▶ builder.Spec ──Build──▶ model.Desired ◀──Apply── pki.Derivation
   (cfg/*.yaml, clusters,   (this page)              │
    access rows)                                     └── yaml golden, reviewed in every change
```

An estate keeps **its rows** (which clusters exist, which stores each runs,
who holds which group) and a thin **adapter** that maps them onto a `Spec`.
What a login, a grant or an SSH role *is* -- the role, the policy, the rules,
the order that makes the output stable, the checks that refuse a bad
contract -- is the library's, so every estate that adopts it gets the same
answer to the same question, and reviews a diff of the model rather than of
code that writes it.

A `Spec` is Go, and it is YAML too: every field carries a tag, `builder.Load`
reads one (refusing a key it does not know), and
[`pkg/builder/testdata/spec.yaml`](../pkg/builder/testdata/spec.yaml) is an
example whose whole derivation is the golden
[`testdata/desired.yaml`](../pkg/builder/testdata/desired.yaml).

Nothing here names an estate. Every mount, role, group, policy and
description is a field of the spec.

## The spec

| Field | What |
|---|---|
| `roster` | the issuer people and jobs sign in through ([`model.Roster`](model.md#groups-and-doors)): the two doors every environment gets, and the life of a token there |
| `operators`, `operatorsTtl` | the group that may change the server, and the life of its tokens in root (only operators log in there) |
| `metadata` | carried by every identity group |
| `credentialMaxTtl` | the ceiling on every short-lived credential ([`model.Desired.CredentialMaxTTL`](model.md)) |
| `audience` | the audience of every workload token; default `openbao` |
| `plugins` | the plugin catalog the apply registers, as [`model.Plugin`](model.md); none for a server that registers its own |
| `root` | what the apply owns in root beside the operators' door: the jobs and the operators-only mounts |
| `environments[]` | one namespace each, sorted by name in the output |

`Spec.Build` returns a `Built`: the validated `Model` (no PKI: `pki.Derivation.Apply`
joins it), and the parts a review wants separately -- `Bootstrap` (the
operators' door), `RootUI` (the web UI's door into root), `RootJobs` and one
namespace per environment. The two views share no memory.

## Access: the KV contract

A policy is an **`access`**: an ordered list of clauses, and a clause is one
`op`. The order is the order of the policy's stanzas.

| `op` | Fields | Grants |
|---|---|---|
| `read` | `prefix` | the secrets under a prefix (`data/<prefix>/*`) and their metadata, with `list`; empty prefix is the whole mount |
| `write` | `prefix` | read, create, update, patch and delete under a prefix |
| `push` | `prefix` | what a push job needs and no more: read and write the data and its metadata, never list, patch or delete |
| `key` | `path` | `read` on the data endpoint of one secret; a trailing `*` is OpenBAO's prefix match |
| `secrets` | `project`, `write` | one project's secrets: through the project's own namespace mount if the environment declares one (`projects`), through its prefix in the shared mount if not -- a grant written this way follows the project when it moves |
| `all` | -- | write the whole shared mount and every project namespace the environment declares |
| `sign` | `mount`, `role` | `update` on `<mount>/sign/<role>`, nothing else |
| `sign-forced` | `mount`, `role` | `sign` on a role that forces a command, and denies `critical_options` (the only way OpenBAO honours the forced command unconditionally, [safety.md](safety.md)) |
| `ca` | `namespace`, `mount`, `issuer` | read one CA's certificate and issuer record: what a restore check proves |
| `canary` | `namespace`, `mount`, `path` | read one KV canary in a namespace |
| `rules` | `rules[]` | stanzas as written, for a system path (`builder.SnapshotRule`, `NamespacesRule`, `RootGenerationRule`, `PluginCatalogRule` spell the ones a job of OpenBAO's own needs) |

A clause that sets a field its op does not read, or omits one it needs, is
refused. A later stanza that repeats an earlier one exactly is written once
(two issuers in one mount name the mount's certificate twice); one that
repeats a path with other capabilities is an error, because OpenBAO would
keep whichever came last.

## Auth: trusts and workloads

A **trust** is a cluster whose ServiceAccount tokens a namespace accepts: a
JWT mount on the cluster's issuer (`mount`, `description`, `issuer`). Its
**workloads** are the machine identities that log in on it, in declaration
order:

| Field | What |
|---|---|
| `role`, `subject` | the role's name, and the one `sub` it admits (`model.ServiceAccountSubject`) |
| `audience` | the token audience; default the spec's |
| `ttl` | the token's whole life |
| `policy` | the one policy the token carries; default the role's name |
| `access` | what the policy grants. Empty declares no policy: `policy` then names one declared elsewhere in the namespace (an SSH role's grant), and a name nothing declares is refused |

A workload has no group and no door. `optional: true` on a trust declares its
mount only if somebody logs in on it -- the mount a hub cluster's writers use
in every other namespace, say. The roster's doors follow the trusts.

## Identity: grants

A **grant** (`name`, `access`) is a policy named after an internal group and
the group admitted through the roster's doors (`model.Roster.Grant`);
`jobsOnly` admits it through the people-and-jobs door alone, for a group only
jobs hold. A **secret grant** (`policy`, `path`, `groups`) lets each group
read ONE secret -- `read` on its data endpoint, no metadata, no list, no
wildcard -- through the jobs' door alone; a group's policies are collected
and sorted. `reserved` names KV prefixes a secret grant may not reach (a
canary the restore check reads, what a push job owns), each with its owner
for the refusal.

## SSH

`ssh.shape` is what every role has in common (key types, key id format, the
one extension, lifetimes), so no two roles drift apart. `ssh.user` is a user
CA -- a key OpenBAO generates and never exports -- with roles that each sign
for ONE `principal`; `forceCommand` makes the role's certificates carry that
command and no extension, and `policy` declares the sign-only policy naming
the role, for a workload (`policy:`) or a group (`grant`) to hold.
`ssh.host` is a host CA on a mount of its own, never sharing a key with the
user CA; its roles list `domains` with `bare` and/or `subdomains`.

`hostAuth` and `hostLogins` let fleets of hosts with no Kubernetes identity
sign their own host certificates with an IAM instance role: one AWS auth
mount (`serverId` unique per namespace, `pluginVersion` naming a versioned
catalog entry, `ttl` one signature long), and for each fleet an auth role
bound to the instance role's ARN, a host role on the host CA for the fleet's
`domain`, and the policy joining them. Every fleet in one namespace shares
the mount and the host CA, and each has its own role and policy, so one
fleet can never ask for another's name. The instance role is matched by the
text of its ARN rather than resolved to AWS's unique id, because resolving it
needs a grant in the fleet's own account ([safety.md](safety.md)).

## Environments, projects and root

An **environment** composes the above for one namespace: `kv` (the shared
mount, with its restore canary), `projects[]` (each with a namespace of its
own holding a KV mount and nothing that admits anybody,
[ADR 0001](decisions/0001-namespaces-are-environment-project.md)), `trusts`,
`ssh`, `hostAuth`, `hostLogins`, `grants`, `secrets` and `reserved`. **Root**
is `jobs` -- one trust whose workloads are OpenBAO's own jobs (a Raft
snapshot is a root-namespace endpoint, and a restore check reads every
namespace, so neither can log in anywhere narrower) -- and `kv`, the mounts
kept out of every environment's reach because a policy declared inside an
environment cannot name a path in its parent. A job's access has no KV mount
to address, so a KV clause there is refused.

### Order

The output is stable, and the estate can rely on it. Auth mounts are the
trusts in order, then the roster's doors; a mount's roles are its workloads
in order; policies and groups are sorted by name, and the host logins'
policies follow them in declaration order. A change of contract is a small
diff of the model, and a reordering of the spec is not one.

## What it refuses

Beyond the model's own validation (`Built.Model.Validate`, run by `Build`):
an environment with no name or no KV mount, a trust with no issuer, a
workload with no role or subject, a workload naming a policy nothing
declares, a grant with no name, a clause with an unknown op or a field it does
not read, one path granted twice with different capabilities, a secret grant
inside a reserved prefix or not shaped `<prefix>/<key>`, and host logins with
no AWS auth mount, no host CA, no instance role ARN or no domain.

## The PKI

The PKI is [pkg/pki](pki.md)'s. A workload that carries a PKI role's sign path
(cert-manager's login, say) is an ordinary workload with a `sign` access, so
an estate derives those from `pki.Derivation` and appends them to the
cluster's trust before calling `Build`; the derivation's `Apply` then joins
the mounts to `Built.Model`.
