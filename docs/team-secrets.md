# A team's shared secrets

The credentials a team shares while it develops — the sandbox API token
every engineer's local stack needs, the test account's password, the key
for a third party's staging tenant — kept in OpenBAO, with an
[access-roster](integrations/access-roster.md) issuer deciding who reads
them and who writes them.

> A namespace is an environment. A project's engineers read its prefix;
> its deployers and approvers write it. A repository is a path under its
> project. Membership is the issuer's.

Nothing here is a new mechanism. It is the roster contract's grants
([access-roster.md §3](integrations/access-roster.md#3-groups-become-identity-groups-become-policies))
pointed at a KV prefix, and the only decisions are which groups get which
capabilities and what the paths look like. Both are below, and both are
executed: [`conformance/roster_test.go`](../conformance/roster_test.go)
applies [`examples/roster`](../examples/roster/roster.go) to a real
`bao server -dev`, writes a secret as a deployer, reads it back as a
viewer, and is refused every call this page says is refused. A tutorial
that has never executed is a tutorial that lies.

**What this is not for: production values.** [What never goes in](#8-what-never-goes-in)
says why, and it is the reason the pattern is allowed to be this simple.

## 1. Two sides of one name

The estate declares **groups**: who is on a project, in which role. The
issuer puts those names in the `groups` claim of every token it mints.
OpenBAO holds **policies of the same names**, and an identity group per
name aliased on each door, carrying the policy. The name is the whole
mapping; nothing re-maps it, and the two sides are kept in step by being
derived from one declaration rather than by agreement.

Two consequences worth knowing before the first grant:

- **A group OpenBAO knows nothing about is ignored.** The login succeeds
  — with the `default` policy alone — and the first real call is a 403. A
  project name misspelt on one side shows up as a refusal at the read, not
  at the sign-in, and reads like a person who is in no group. Compare
  `identity_policies` on the login answer against the groups in the token
  before looking anywhere else.
- **A person's group needs both doors.** `Roster.Grant` admits it through
  `jwt-roster` and through the UI's `oidc` mount (as `<group>@oidc`);
  `Roster.JobGrant` through `jwt-roster` alone. A project group made with
  `JobGrant` works from the CLI and leaves the web UI showing an empty
  namespace to the same person.

## 2. Three groups, one prefix

Per project and per environment namespace, three groups and three policies
of the same names:

| Group | `kv/data/{project}/*` | `kv/metadata/{project}/*` |
|---|---|---|
| `{env}:{project}:viewer` | `read` | `list`, `read` |
| `{env}:{project}:deployer` | `create`, `read`, `update` | `list`, `read` |
| `{env}:{project}:approver` | `create`, `read`, `update` | `list`, `read` |

- **Three, and not one `secrets` group**, because these three already
  exist: they are the project's roles at the issuer, held by the same
  people who deploy it and approve its releases. A fourth role would be a
  second membership list to keep in step with the first, and the whole
  point of the model is that there is exactly one.
- **The viewer's metadata line is not decoration.** `read` on the data
  path alone tells nobody what there is to read: without `list` on the
  metadata path a person must already know every variable's name.
- **No `delete`, and no destroy.** Writing a value is routine; retiring
  one is rare, and destroying a version does not come back. Both stay with
  whoever operates the namespace. A team that must retire its own keys
  adds `delete` on the data path — the soft delete, which an operator can
  undo — and leaves `kv/destroy/*` and the metadata delete where they are.

**The trap in the paths.** `data/` and `metadata/` are KV version 2's API
paths, not the paths `bao kv` prints. `bao kv put kv/orders/local-dev/...`
writes `kv/data/orders/local-dev/...`, and a policy written on
`kv/orders/*` — the path everyone reads off the command line — grants
nothing whatsoever. Its symptom is a 403 on every read by a person who is
plainly in the group, which sends people looking at the issuer.

## 3. The grant

From [`examples/roster`](../examples/roster/roster.go), which is the state
the conformance test applies:

```go
people := model.Roster{Issuer: "https://id.example.com", TTL: "1h", UI: ui}

read := []model.Rule{
    {Path: "kv/data/orders/*", Capabilities: []string{model.CapRead}},
    {Path: "kv/metadata/orders/*", Capabilities: []string{model.CapList, model.CapRead}},
}
write := []model.Rule{
    {Path: "kv/data/orders/*", Capabilities: []string{model.CapCreate, model.CapRead, model.CapUpdate}},
    {Path: "kv/metadata/orders/*", Capabilities: []string{model.CapList, model.CapRead}},
}

// Grant returns a policy named after the group, and the group admitted
// through every door, carrying it; grant appends the pair to the
// namespace's Policies and Groups.
grant(people.Grant("dev:orders:viewer", read...))
grant(people.Grant("dev:orders:deployer", write...))
grant(people.Grant("dev:orders:approver", write...))
```

A workload that reads one of these values is not one of the three. It gets
its own identity and its own grant, one `read` on one path, through the
one door a job has:

```go
grant(people.JobGrant("ci-release",
    model.Rule{Path: "kv/data/orders/ci/release", Capabilities: []string{model.CapRead}}))
```

The namespace is the environment: `dev`, `staging`, one each, with the
same three groups inside and their own values. A project that exists in
two environments is two grants in two namespaces, never one prefix shared
by both — the tree is one level deep for exactly this reason
([access-roster.md §2](integrations/access-roster.md#2-the-openbao-side-two-doors-per-namespace)).

## 4. What the paths look like

```
kv/data/{project}/{purpose}/{repository}/{VARIABLE}
         orders    local-dev  checkout    API_TOKEN
```

| Segment | What it is | Who decides it |
|---|---|---|
| `{project}` | the prefix the three groups are granted on | the estate's project list |
| `{purpose}` | what the values are for — `local-dev` for a laptop stack | the team |
| `{repository}` | one repository of the project | the team |
| `{VARIABLE}` | one variable, holding one field, `value` | the repository |

**A repository is a path segment, not a grant.** Onboarding the project's
second repository is a new segment under a prefix that is already granted:
no new group, no new policy, no change at the issuer, nothing to apply. It
is the property the whole layout is chosen for, and the one to check
first when somebody proposes a per-repository group.

**One variable per path**, rather than one secret holding every variable
of a repository. A rotation then touches exactly the path that rotated,
two people rotating two variables do not race each other through a
read-modify-write of one blob, and the list of variable names is the
metadata listing rather than something written down beside it.

## 5. How a person reads

Four calls, and nothing is stored: no OpenBAO token on the laptop, no
client secret, no long-lived key
([access-roster.md §5](integrations/access-roster.md#5-credentials-what-accessctl-credential-calls)
is the same shape for certificates).

1. **Exchange** the issuer's session for a token whose audience is
   `openbao`. The issuer refuses here, before OpenBAO is reached, anyone
   the `openbao` client's `requires` does not admit.
2. **Log in** at `auth/jwt-roster/login` with `role=roster`, in the
   namespace that is the environment. The token's `groups` become the
   policies; the answer's `identity_policies` is what was actually held.
3. **List and read** under `kv/metadata/{project}/{purpose}/{repository}`
   and `kv/data/...`.
4. **`auth/token/revoke-self`**, at the end, always — including after a
   failure. The login's TTL is the fallback, not the plan.

```sh
token=$(accessctl token --issuer "$ISSUER" --audience openbao)
login=$(jq -n --arg jwt "$token" '{role: "roster", jwt: $jwt}' |
  curl -fsS -H "X-Vault-Namespace: dev" -X POST --data @- "$BAO_ADDR/v1/auth/jwt-roster/login")
```

An issuer-side CLI is the right home for those four calls as one verb that
renders an `.env` file — this page describes the shape, not a command,
because at the time of writing no such verb is released and a documented
command that does not exist is worse than none. Whoever writes it: the
file is `0600` and ignored by git, only the **names** are printed, a
second run rewrites the file, and a run that reads **zero** keys fails
rather than writing an empty file. An empty `.env` is the failure mode
nobody notices; it looks like a stack that is merely misconfigured.

The same four calls are what a CI job makes, with the job's own identity
and its own one-path grant
([access-roster.md §6](integrations/access-roster.md#6-ci-jobs)).

## 6. How the owner writes and rotates

A deployer or an approver writes directly — the web UI in the right
namespace, or the CLI:

```sh
bao kv put -mount=kv orders/local-dev/checkout/API_TOKEN value=...
```

Rotating is writing again: KV version 2 keeps the previous version, every
reader has the new value on their next read, and nothing is granted,
applied or announced. Two things to keep straight:

- **Rotate at the source first, then write here.** A new value in OpenBAO
  is not a rotation of anything; the credential is still valid wherever it
  was issued until that system is told otherwise. Write the store last, so
  that what readers pick up is the value that works.
- **The old version is still readable.** Everyone holding the prefix can
  read back the version before the rotation until someone with the
  operator's capabilities destroys it. A value that must truly disappear
  needs that destroy — which is one of the reasons for the next section.

## 7. How revocation works

Membership is the issuer's, and only the issuer's. Taking a person off the
project there is the whole revocation: the next exchange mints a token
without that group, the login that follows holds no policy for the prefix,
and the read is a 403. OpenBAO is not edited, and no list is kept twice.

What it does not do:

- **It does not end a session already issued.** A token minted a minute
  before the change lives out its TTL — an hour in the reference
  environment. Short door TTLs are what bound that window, and they are
  the reason the reference sets 15 minutes in root.
- **It does not unread what was read.** Every value under the prefix was
  on that person's disk the moment they last fetched. Revocation stops the
  next read, never the last one, so a departure from a project is also a
  rotation of what the project's prefix held.

## 8. What never goes in

**Production values.** Not as an exception for one variable, not
temporarily: the pattern's gate is a single group membership, and
everything else about it is built for a team moving quickly.

- Every engineer on the project reads **every** value under the prefix.
  There is no per-path approval, no second person, and a read is not a
  request anybody sees before it succeeds.
- The reading end is a laptop and a file on it. That is what makes the
  fetch worth having, and it is not a place a production credential may be.
- A value written by mistake stays readable in its old version until an
  operator destroys it.

Production credentials go to a workload, not to a person: one identity,
one path, `JobGrant`, read by the thing that needs it and by nobody else.
The line is worth stating out loud in the estate's own words, because the
day somebody asks for an exception, the answer has to already exist.

## 9. It is tested

Two subtests of
[`conformance/roster_test.go`](../conformance/roster_test.go), against a
real `bao server -dev` and an issuer in access-issuer's shape:

- *a project's prefix: the deployers write it, the engineers read it* —
  the deployer writes the secret, the viewer reads that value back and
  lists the names, the viewer's write is refused, a read outside the
  prefix is refused, a missing path inside the prefix is a 404 (which is
  how the two are told apart: 403 means the policy never reached the
  path), a rotation is picked up by the next read, and the approver
  writes the same prefix the deployer does.
- *membership is the issuer's: the next token decides the next read* — the
  same person without the project group, then with no groups at all, then
  with a group name OpenBAO was never told about: a login every time, and
  a 403 on the read every time.

```sh
just check                                        # what CI runs
OPENBAO_CONFORMANCE=required go test ./conformance/ -run TestRosterContract
```

Without a `bao` binary the conformance test skips;
`OPENBAO_CONFORMANCE=required`, which `just test` sets, makes a missing
one a failure. The refusals this page describes are pinned there with
their statuses, and
[access-roster.md §7](integrations/access-roster.md#7-failure-modes) has
every other way a login or a call fails, with the message OpenBAO prints.
