# 0001 — Namespaces are `<environment>/<project>`

**Status:** Accepted; supersedes [doctrine.md](../doctrine.md)'s earlier
"one namespace level" law
**Date:** 2026-09-27

## Context

[doctrine.md](../doctrine.md) declared one namespace level: root, then
one namespace per environment; a project was a policy path and an
identity group, never a namespace of its own, because "a namespace per
project multiplies mounts, issuing CAs and logins for no isolation a
policy does not already give." That law fit an installation whose every
project belongs to one organisation: a policy path already gives a
project all the isolation it needs, at zero extra namespace cost, when
the only people who can write a policy are the operators themselves.

It stops fitting once an installation shares one OpenBAO with more than
one organisation — sharing the installation with a partner organisation
as one of its projects. A partner's mount tables, KV data and issuing CA
sitting beside every other project's, inside the same environment
namespace, is fine while every project belongs to the operators' own
organisation. It is a much weaker claim once a different organisation
owns some of the projects: a policy path's isolation depends entirely on
nobody with write access to policy being careless or compromised, and a
partner project widens who ends up depending on that guarantee without
widening who enforces it.

## Decision

Namespaces become `<environment>/<project>`. Every project — a business
project, a partner organisation's project — gets one, always, so there is
exactly one shape to reason about, rather than "namespaced for a partner,
policy-path for everyone else."

> **Amended 2026-09-28.** This sentence originally listed the operator's
> own infrastructure alongside a business project and a partner project as
> something that gets a project namespace too. It does not: see the
> amendment at the end of this record. The environment namespace is
> itself the operator's platform — it already holds the platform's own
> mounts, not only logins, policies and identity groups — so there is
> nothing left for a project namespace named for the operator's
> infrastructure to hold.

**Logins, policies and identity groups live only at `<environment>`.** A
project namespace holds mounts and nothing that admits anybody: a KV v2
mount, an issuing CA signed by the environment's own CA, and later a
Transit mount. Nobody logs in "at" a project; a token reaches a project
by logging in at the environment and holding a policy that names a path
under that project.

**Why logins stay at the environment** (tested against OpenBAO 2.6.2):

- A token that logs in at `<environment>/` and holds a policy naming
  `<project>/kv/data/...` reads `<environment>/<project>/kv/data/...`
  without a second login at the child namespace. Moving mounts one level
  down costs nothing extra at login time.
- An identity group inside a child namespace cannot contain an entity
  that logged in at the parent, unless the installation turns on the
  unsafe cross-namespace-identity flag. Put logins at the project level
  instead, and every group granting that project's own role would need
  its own auth mount there too — the multiplication the old law existed
  to avoid, now paid per project rather than avoided.
- A `sys/`-scoped admin bound to a namespace reaches only downward from
  it. An admin scoped to a project namespace could therefore never also
  administer the environment, while an admin scoped to the environment
  already reaches every project under it — so a project-level admin role
  would let nobody do anything an environment-level one cannot already
  do, and there is no reason to mint one.
- A child namespace's issuing CA can be signed by its parent's issuer,
  but only by a credential that spans both namespaces — the same
  credential the apply itself already uses to converge the whole tree,
  never a project's own.

**Consequence: no per-project logins, no per-project admins.**
Delegating OpenBAO administration to a partner would force a login mount
inside that partner's own project namespace — the exact multiplication
this decision avoids everywhere else — so it is not offered. A partner's
self-service happens in the desired-state rows an operator reviews
before every apply, never against OpenBAO's own `sys` API.

**Every project gets one, including the operators' own infrastructure.**
There is no project that stays outside this shape because it happens to
belong to the operators; the operators' own infrastructure is a project
like any other, so the rule has no silent exception to remember.

> **Amended 2026-09-28.** Superseded: the operator's own infrastructure is
> not a project and gets no project namespace. It is what the environment
> namespace itself already is — see the amendment at the end of this
> record.

**Deleting a project deletes its namespace**, after deleting its
children — OpenBAO refuses to delete a namespace that still has
children. Nothing under a retired project's mounts survives the delete;
a project that must keep data past retirement is migrated out first,
like any other decommission.

**Cost:** one namespace per `<environment> × <project>` pair, cheap now
that mount tables are namespace-scoped rather than server-wide — the
mount-table ceiling that once made "fewer namespaces" attractive no
longer applies past OpenBAO 2.1.

**Clients.** An ESO-style reader logs in at `<environment>` and reads
`<environment>/<project>/kv/data/...`: its target path gains one segment
and its login does not change. A CLI-shaped client already separates
"where I log in" from "where I act" — a login namespace, and a target
namespace passed with each call — and keeps doing exactly that, with the
target namespace now carrying the project segment too.

**Migration shape**, generic: for a KV path laid out today as
`{environment}/kv/{project}/...`, create the project namespace, copy each
secret to `{environment}/{project}/kv/...`, flip every reader's target
path to the new location, verify, then delete the old copy. The same
shape for an issuing CA: mint the project's issuing CA under the project
namespace, signed by the environment's CA, move roles across one at a
time, drain the old role, retire it.

## Consequences

- Every installation, including a single-organisation one with no
  partners, now pays one extra namespace hop per project. The old law's
  "for no isolation a policy does not already give" stops being true the
  moment more than one organisation writes policy in the same
  installation, but a single-organisation installation pays the same
  namespace cost for isolation it may not strictly need — accepted,
  because the alternative is two shapes to maintain and explain instead
  of one.
- `pkg/model` now carries this shape directly: `Namespace.Projects`, one
  `ProjectNamespace` per project ([model.md](../model.md#projects-environmentproject)).
  A consuming estate no longer derives it from a single-level model; it
  writes the project into the desired state like anything else the model
  expresses.
- A project is deleted along with everything in it; there is no
  soft-delete or export step this record specifies. An estate that needs
  one builds it in its own migration tooling.

## Alternatives considered

**Keep the one-level law and isolate a partner project by policy path
alone**, as the old law does for every project today. Rejected: a policy
path's isolation depends on every policy writer being careful, and a
different organisation's project widens the blast radius of one policy
writer's mistake from "one team's data" to "another organisation's
data," with nothing enforced by the server itself.

**Give a partner organisation its own OpenBAO installation.** Removes
the shared-installation risk entirely, at the cost of running, patching
and paying for a second server, a second root of trust, and everything
downstream of it, for every partner. Rejected for the reason a shared
installation was chosen at all: the isolation a dedicated installation
buys is not needed once the namespace and policy boundaries here hold.

**A namespace per project regardless of environment
(`<project>/<environment>`).** Rejected: an environment is the wall every
login, policy and identity group already respects, and putting the
project segment first would put one project's `stage` and `prod` data
one namespace-hop apart from each other, rather than one hop apart from
every other project's `stage` — the wrong thing to make cheap to
conflate.

## Amendment (2026-09-28)

An operator running this record's shape asked the question this record
had left implicit: what is the environment namespace itself, once every
project — including the operator's own infrastructure, by the original
wording above — has moved into a project namespace beneath it? The
answer decided here is that the environment namespace **is** the
operator's platform. Besides the logins, policies and identity groups
this record always kept there, it holds the platform's own mounts too:
its KV (platform secrets stay directly at `<environment>/kv/<kind>`, one
level up from where a tenant's would sit), the environment's own issuing
CAs, and the SSH user and host CAs. None of that is a project's mounts
sitting in a project namespace named for the operator; it is what the
environment namespace already is.

**Project namespaces are for tenants only** — a business project, a
partner organisation's project — never for the operator's own
infrastructure. There is therefore no project namespace carved out to
hold the platform's own mounts under some name chosen for it: doing so
would give the platform two homes for the same kind of thing (mounts
directly under the environment, and mounts under an environment/project
pair invented to mean "not a tenant"), where one is enough. The two
sentences amended above are wrong for exactly this reason: the operator's
own infrastructure was never a project waiting for a namespace, and
"every project" always meant every *tenant* project.

**Consequence.** Platform secrets do not migrate to a project namespace;
they were always at the right level. Only a tenant project that has its
own team secrets — its own KV, or later its own issuing CA for workload
mTLS — gets a project namespace at all; a tenant with nothing of its own
to hold gets none.

**Root stays the minimal trust anchor, and an environment is not
promoted to it.** A sibling environment namespace that happens to run the
operators' own management tooling is still an environment, not the
installation's root: anything granted at root reaches every namespace
below it by path, so root holds only what must reach everything —
operators, the domain intermediates, backup and restore-check logins, the
door the operators' own UI logs in through — and nothing that looks like
a workload, however central that workload is to running the platform.
Promoting such an environment to root would widen root's reach to every
other environment's projects for no isolation gained; keeping it a
sibling keeps the environment wall the one wall every login already
respects (see "Why logins stay at the environment" above).

**An environment-level policy names its projects; it does not glob
across them.** Because a project namespace is a wall the server enforces
and not only one a policy path draws, a policy declared at
`<environment>` must not use a wildcard or glob in the *first* path
segment below the environment where that segment could span more than
one project's namespace — such a policy would quietly reopen the very
boundary a project namespace exists to hold. A policy instead names its
declared projects explicitly, one path per project it is meant to reach;
the library that renders policies enforces this by refusing a policy
whose first segment is not a literal project name (or a path that stays
inside the environment's own mounts, never crossing into a project's).
