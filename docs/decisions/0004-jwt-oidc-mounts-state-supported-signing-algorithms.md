# 0004 — Every JWT/OIDC mount states its supported signing algorithms

**Status:** Accepted
**Date:** 2026-09-27

## Context

The JWT/OIDC secrets engine's own factory default for an `oidc`-type
role's supported signing algorithms is RS256 alone — nothing else is
accepted unless a mount says otherwise. An issuer that signs with more
than one algorithm, or that has moved its default away from RS256, is
silently refused at login by any mount that never stated its own list:
the failure looks like a token problem, not a mount-configuration gap,
because nothing about the mount's own state says which algorithms it
trusts.

## Decision

Every JWT and OIDC mount states `jwt_supported_algs` explicitly, naming
every algorithm this installation's issuer might sign either kind of
token with — never left to the plugin's own default, whatever that
default happens to be for the mount's type. This is a property of the
mount, set once and consulted the same way regardless of which algorithm
a particular login happens to use that day.

## Consequences

- A mount that previously relied on the plugin's implicit default now
  states its list out loud; this is a visible, reviewable line in the
  mount's own configuration rather than an assumption nobody wrote down.
- Moving the issuer's default signing algorithm, or adding a new one for
  a particular audience, is a mount-configuration change, not a silent
  expectation that every relying party already handles it — every relying
  party's mount already names, explicitly, everything it currently
  accepts.
- A mount that is not updated when a new algorithm comes into use fails
  at login with a signature-verification error that names the actual
  cause (an algorithm the mount does not list) rather than a login that
  has to be debugged by process of elimination.

## Alternatives considered

**Leave mounts unset and rely on the plugin's default.** Rejected: the
default differs by role type (every algorithm for a `jwt`-type role,
RS256 alone for an `oidc`-type role) and is not documented anywhere a
mount's own configuration shows — a reader auditing what a mount trusts
would have to know the plugin's source to find out, rather than reading
it off the mount.
