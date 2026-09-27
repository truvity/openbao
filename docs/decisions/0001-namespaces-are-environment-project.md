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

Namespaces become `<environment>/<project>`. Every project — the
operators' own infrastructure, a business project, a partner
organisation's project — gets one, always, so there is exactly one shape
to reason about, rather than "namespaced for a partner, policy-path for
everyone else."

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
- [model.md](../model.md)'s "the namespace tree is one level" statement
  describes the model's current behaviour and is not itself changed by
  this record: the model gains nested project namespaces in a later
  release. Until then, a consuming estate that wants this record's
  namespace shape derives it from a single-level model the same way it
  derives anything else the model does not yet express directly.
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
