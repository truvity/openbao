# 0003 — SSH: people on an external OIDC flow, machines and hosts on this installation's own CAs

**Status:** Accepted
**Date:** 2026-09-27

## Context

SSH trust has three different populations, and treating them as one
problem produces a design that fits none of them well: a person at a
keyboard, a machine acting on its own identity (a CI job, a controller),
and a host proving it is the host a client thinks it is dialling. Each
already has, or can have, a better-fitting way to establish trust than a
single shared certificate authority signing every one of them the same
way.

## Decision

**People:** an OIDC-based flow against the installation's issuer
(opkssh) — an OpenID Connect ID token verified straight into `sshd`, with
no certificate authority in the path at all. This is outside this
repository's own scope (it involves no OpenBAO mount, no role, no
certificate this repository issues) and is mentioned here only as
context for why the SSH engine this repository ships models no "person"
role: that population is served entirely outside it.

**Machines** — a CI job, a controller, anything that is not a person at
a keyboard — get user certificates from this installation's SSH user CA,
the same engine and mechanism as before. A machine role may additionally
force one command on every certificate it signs (`force-command`), for a
restricted account that should never get an interactive shell: a backup
agent, a build daemon, anything that exists to run exactly one thing.

**Getting `force-command` to actually be forced needed one more piece
than the role's own configuration.** A caller's sign request may carry
its own `critical_options`, and when it does, the SSH secrets engine uses
the request's map exactly as given, in place of the role's own default —
never merged with it (verified against a real server). So a role with a
`force-command` default and no other protection can be asked to sign a
certificate whose `force-command` is something else entirely, or has
none at all, and the engine complies. The fix sits at the policy layer,
not the role's: a grant reaching a force-command role's sign path must
deny the `critical_options` parameter outright — a policy clause that
refuses any request carrying that parameter at all, whatever key or value
it names, checked before the request ever reaches the SSH backend. This
repository's own model validation now enforces that a force-command
role's sign path is never granted without this denial alongside it, so
the mistake this closes cannot ship silently a second time.

**Hosts** get certificates from a **separate host CA, on a mount of its
own** — never the same key as the user CA that signs machine
certificates. A key that clients are told to trust for hosts must never
also be a key `sshd` trusts for users: the two roles a CA plays for SSH
(which hosts to trust; which users to let in) are different promises, and
one compromised key should not cost both. A host role signs literal host
names — no wildcard, no template — and its certificates live at most 30
days, with daily renewal recommended so a host's certificate is never
close to its own expiry in normal operation. A host proves itself to get
a certificate the same way any other workload proves itself: an existing
workload login (a Kubernetes pod's projected ServiceAccount token) for a
host running as a pod, or a cloud identity — an instance role, through
the cloud provider's own auth method — for a host that is not (planned;
not yet built). A client that trusts the host CA needs exactly one
`@cert-authority <domains> <key>` line, rather than pinning every
individual host's own key and updating that pin every time a host is
replaced.

## Consequences

- This repository's SSH engine models two roles — machine user
  certificates and host certificates — and deliberately models no
  "person" role at all. A reader looking for how people authenticate over
  SSH will not find it here; that is intentional, not an omission.
- A host's certificate lifetime is capped structurally at 30 days
  regardless of any other credential ceiling an installation sets for
  shorter-lived things, because a host certificate is trusted by whatever
  holds the CA's public key with no per-signing review — it is
  deliberately allowed to outlive a short-lived machine credential by a
  wide margin, and the cap exists so that margin still has a ceiling.
- Any grant onto a force-command role's sign path that omits the
  `critical_options` denial is refused before it is applied; an
  installation cannot accidentally ship the mistake this record closes.
- A host that is not running as a Kubernetes pod (bare metal, a VM
  outside the cluster) has no host-certificate path yet in this
  repository: the cloud-identity route is planned, not shipped.

## Alternatives considered

**One CA for both users and hosts.** Rejected: the two roles a CA plays
for SSH — telling clients which hosts to trust, and telling hosts which
users to let in — are different promises to different parties, and
collapsing them into one key means a single compromise costs both at
once, with no way to rotate one trust relationship without touching the
other.

**Fixing `force-command` inside the SSH role's own configuration** (a
stricter `allowed_critical_options`, say). Rejected because it does not
work: the engine's own behaviour is to take the request's
`critical_options` map exactly as given whenever the request supplies one
at all, regardless of what the role's allowed-list names — the
role-level knobs gate which keys a present map may name, never whether
the caller may present one to begin with. Only a policy-level denial of
the parameter itself closes the gap.

**A CA-issued certificate for people too, instead of the external OIDC
flow.** Not this repository's decision to make: people's SSH
authentication is a different system's contract, entered here only as
the reason no "person" role exists in this engine.
