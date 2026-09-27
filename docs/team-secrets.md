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
  metadata path a person must already know every repository's name.
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
by both — a KV prefix under the environment, exactly as
([access-roster.md §2](integrations/access-roster.md#2-the-openbao-side-two-doors-per-namespace))
describes it. This is the right shape while every project belongs to the
operators' own organisation: a policy path costs nothing extra and needs
no second mount. A project that is a different organisation's own --
sharing this installation, not just this environment -- gets a namespace
of its own instead ([ADR 0001](decisions/0001-namespaces-are-environment-project.md),
[model.md](model.md#projects-environmentproject)); nothing here changes
for the projects that stay policy paths.

## 4. What the paths look like

```
kv/data/{project}/{purpose}/{repository}
         orders    local-dev  checkout
```

| Segment | What it is | Who decides it |
|---|---|---|
| `{project}` | the prefix the three groups are granted on | the estate's project list |
| `{purpose}` | what the values are for — `local-dev` for a laptop stack | the team |
| `{repository}` | one repository of the project, and one KV secret: every one of its variables is a FIELD of it, named after the variable (`API_TOKEN`, `DB_URL`, ... — never a placeholder like `value`) | the repository |

**A repository is a path segment, not a grant.** Onboarding the project's
second repository is a new segment under a prefix that is already granted:
no new group, no new policy, no change at the issuer, nothing to apply. It
is the property the whole layout is chosen for, and the one to check
first when somebody proposes a per-repository group.

**One secret per repository, one field per variable**, rather than one
path per variable. `bao kv patch` merges a named field into a secret's
existing data server-side ([§6](#6-how-the-owner-writes-and-rotates)), so
two people rotating two different variables of the same repository do
not race each other through a read-modify-write of one blob — the race a
per-variable layout would otherwise exist to avoid is closed at the API
instead, by never reading the other fields to begin with.

**The trade, stated plainly rather than discovered at a rollback.** KV
version 2 still versions every rotation, but now per SECRET rather than
per variable: rotating one field advances the version every OTHER field
of the same repository is read at too. "Back to exactly before this one
variable changed" also means every sibling variable reverts to whatever
it held at that same version, which may not be what it holds today. A
repository whose variables genuinely rotate independently enough that
this matters is a repository that has outgrown "purpose" as the only
axis, and is a candidate for its own `{purpose}` segment, not a return to
one path per variable.

A single field's own name being the variable's name, and never a
placeholder, is what lets a plain `bao kv get -format=env` render an
entire repository straight into a dotenv file with no renaming step: see
[§5](#5-how-a-person-reads).

## 5. How a person reads

Nothing is stored beyond the login itself: no client secret, no
long-lived key, and no OpenBAO token accessctl does not already manage
`0600` on its own
([access-roster.md §5](integrations/access-roster.md#5-openbao-through-accessctl-bao-accessctl-pgpsql-and-opkssh-for-people)
is the same shape for certificates).

1. **Exchange** the issuer's session for a token whose audience is
   `openbao`. The issuer refuses here, before OpenBAO is reached, anyone
   the `openbao` client's `requires` does not admit.
2. **Log in** at `auth/jwt-roster/login` with `role=roster`, in the
   namespace that is the environment. The token's `groups` become the
   policies; the answer's `identity_policies` is what was actually held.
3. **Read** `kv/data/{project}/{purpose}/{repository}` — the repository's
   whole secret, every variable a field of it, in one call.
4. Nothing revokes the login by default: it is cached and reused until it
   nears its own expiry, the same as any other accessctl login.
   `--forget` revokes it early; whether that is worth doing is below.

`accessctl bao` makes steps 1 and 2 for you, then runs the real `bao`
unchanged for step 3:

```sh
accessctl bao kv get -ns=dev -mount=kv -format=env orders/local-dev/checkout > .env
chmod 0600 .env
```

One call, because the repository's whole secret is one call: every field
comes back at once, and `-format=env` renders each straight into a
correctly-named dotenv line, since a field's own name is the variable's
name ([§4](#4-what-the-paths-look-like)) — no listing, no loop, no
renaming step between OpenBAO's answer and the file. The properties to
keep, because a repository's `make secrets` target is this one line:

- write the file `0600` and keep it in `.gitignore`;
- redirecting with `>` already truncates, so a variable removed upstream
  never survives as a stale line — resist the urge to reach for `>>` here;
- never print a value, in whatever the target logs on success or
  failure;
- **a missing path, or a path with no fields left in it, must fail the
  target.** `bao` itself exits non-zero on a path that does not exist,
  which already fails the target if its own exit code is checked; a
  path that exists but holds zero fields is not a `bao` error at all —
  `-format=env` renders whatever fields there are, which for zero fields
  is nothing, and passes `bao`'s own (successful) exit code through
  unchanged — so the target must check that the file it wrote is
  non-empty itself, the same way the removed `accessctl secrets env`
  command used to fail on a listing of zero names. An empty `.env` is
  the failure mode nobody notices: the stack starts with every variable
  unset and reads as merely misconfigured, days later and never at the
  fetch;
- a `403` from `bao` already names the path; surface it as `bao` gives
  it, because "permission denied" on a path reads as a mistake in the
  path and almost never is.

**Listing still has a job, just a smaller one.** The viewer's metadata
grant now answers "which repositories does this purpose hold"
(`bao kv list -ns=dev -mount=kv orders/local-dev`), not "which variables
does this repository hold" — there is no sub-listing inside one secret.
A `make secrets` target that already knows its own repository's name
never needs to list at all.

The same read is what a CI job makes, with the job's own identity and its
own one-path grant
([access-roster.md §6](integrations/access-roster.md#6-ci-jobs)) — a job
exchanges its own token afresh every run and keeps no login cache to
`--forget` in the first place.

## 6. How the owner writes and rotates

A deployer or an approver writes directly — the web UI in the right
namespace, or `accessctl bao`, which authenticates and hands the call to
the real `bao` unchanged.

**The first write, creating the repository's secret**, is `kv put`:

```sh
accessctl bao kv put -ns=dev -mount=kv orders/local-dev/checkout API_TOKEN=... DB_URL=...
```

**`kv put` REPLACES every field of the path with exactly what this call
names — always, not only the first time.** Fine here, since there is
nothing yet to replace; run it again on a secret that already holds
other variables and it deletes them, because the second write's data
*is* the whole secret from then on, not a merge on top of what was
there. Every write after the first is `kv patch` instead, which merges
one field into whatever the secret already holds:

```sh
accessctl bao kv patch -ns=dev -mount=kv orders/local-dev/checkout API_TOKEN=...
```

**Adding a new variable to an existing repository is the same `kv
patch`**, naming the new field: no new path, no new grant, nothing to
apply — the repository's three groups already reach it, because they are
granted on the whole prefix, not on today's fields. Rotating one variable
of several never touches the others: `patch` tries an HTTP `PATCH`
first, and — since none of the three roles above grants `patch` on
`kv/data/*`, only `create`, `read` and `update` — falls back on its own
to a read, a local merge and a write, verified against `bao kv patch -h`
in this repository's own devbox (OpenBAO 2.6.2). Either way, the two
fields nobody named are read back unchanged.

**Removing one variable without touching the others** is `kv patch`'s
own `-remove-data`, confirmed against the same help text — not `kv put`
with the field left out, which would happen to produce the same result
here only because there is nothing else left to lose; `-remove-data`
says plainly what happened, and stays correct the day the repository
holds a third variable neither call should touch:

```sh
accessctl bao kv patch -ns=dev -mount=kv -remove-data=API_TOKEN orders/local-dev/checkout
```

Rotating is writing again: KV version 2 keeps the previous version, every
reader has the new value on their next read, and nothing is granted,
applied or announced. **The version is the repository's now, not a single
variable's** ([§4](#4-what-the-paths-look-like)): rotating or removing
one field advances the version every OTHER field of the same repository
is read at too. Two more things to keep straight:

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
  the deployer writes the repository's secret, the viewer reads it back
  and lists its purpose for the repository names inside it, the viewer's
  write is refused, a read outside the prefix is refused, a missing path
  inside the prefix is a 404 (which is how the two are told apart: 403
  means the policy never reached the path), a rotation is picked up by
  the next read, and the approver writes the same prefix the deployer
  does.
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
