# Architecture decisions

One record per decision that changes what this repository's model or
documentation commits to from the outside — a namespace shape a
consuming estate must derive its model around, a certificate SAN shape a
workload must present, a signing algorithm a mount must state.
[doctrine.md](../doctrine.md) states the design rules that hold across
records; a record here says why one of them is shaped the way it is, or
why an earlier one changed. When the two disagree, doctrine.md describes
what this repository actually ships and a record here is read as the
reasoning that got there.

A record is never edited to reverse a decision. A changed mind gets a new
record that supersedes the old one, so the index below stays a true
timeline and nothing is silently rewritten under an old date.

## Index

| ADR | Decision |
|---|---|
| [0001](0001-namespaces-are-environment-project.md) | Namespaces are `<environment>/<project>` |
| [0002](0002-workload-mtls-service-and-identity-roles.md) | Workload mTLS: a `service` role and an `identity` role, on per-project issuing CAs |
| [0003](0003-ssh-people-external-machines-and-hosts-on-our-cas.md) | SSH: people on an external OIDC flow, machines and hosts on this installation's own CAs |
| [0004](0004-jwt-oidc-mounts-state-supported-signing-algorithms.md) | Every JWT/OIDC mount states its supported signing algorithms |

## Template

Start a new record from this shape. Keep it tight — long enough to make
the reasoning checkable, short enough that the next reader finishes it.

```markdown
# NNNN — <a decision, stated as a decision>

**Status:** Proposed | Accepted | Superseded by [NNNN](NNNN-slug.md)
**Date:** YYYY-MM-DD

## Context

The situation that made a decision necessary, and the constraint that
ruled some answers out before the rest were compared.

## Decision

What was decided, stated so a reader could act on it without reading
anything else. Include the shape of the mechanism, not just its name.

## Consequences

What this costs, what it forecloses, and what a relying party or an
operator must now do differently. Say the honest boundary out loud —
the case this decision does not cover — rather than leaving it to be
discovered.

## Alternatives considered

Each one named, with the specific reason it was not chosen. "We didn't
think of it" is a fine thing to be able to write here later; do not
retrofit reasons no one had at the time.
```
