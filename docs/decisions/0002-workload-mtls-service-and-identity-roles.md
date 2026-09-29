# 0002 — Workload mTLS: a `service` role and an `identity` role, on per-project issuing CAs

**Status:** Accepted; the per-project issuing CA shape below is superseded
by per-environment identity CAs signed directly by the root
([pki.md](../pki.md#per-environment-identity-cas-and-why)). OpenBAO
drops URI name constraints when it signs an intermediate
([openbao/openbao#4104](https://github.com/openbao/openbao/issues/4104)),
so a CA signed by the shared domain intermediate carries no URI
constraint; each environment's identity CA is therefore signed by the
root, with the exact URI constraint written by the ceremony. The two
role shapes (`service`, `identity`) and the rest of this decision stand.
**Date:** 2026-09-27

## Context

A workload role today issues one shape of certificate: a DNS name,
server-auth only, for things reached by name — a database, a message
broker, OpenBAO's own serving certificate. That shape carries no notion
of the caller's own identity: a certificate proves "this is the
database," never "this is the workload calling it," so authorization
between workloads has nowhere to attach on the certificate itself and
ends up living wherever a chart's author happened to put it, one chart
at a time.

Workload identity — mutual TLS where both sides present a certificate
naming who they are, not just what they serve — needs a different SAN
shape (a URI, not a DNS name), a different key usage (client and server,
not server alone), and a different issuing discipline (only a workload's
own project should be able to mint a certificate claiming to be in that
project). Reusing the existing role for this means either widening it
until it accepts both shapes — one role signing both "this is a named
service" and "this is this workload's identity" certificates, with
nothing on the role itself saying which promise a given certificate
makes — or building a second mechanism. This record chooses the second.

## Decision

Two roles, doing two different jobs, on a mount that already knows how
to keep them apart because per-project issuing CAs exist
([0001](0001-namespaces-are-environment-project.md)):

**`service`** — the existing shape, unchanged. DNS SANs, server auth.
For anything reached by a name rather than by its own identity: a
database, a broker, OpenBAO itself.

**`identity`** — new. URI SAN only, no DNS SAN, no IP SAN. The URI is
`spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`: a SPIFFE
ID naming the workload by the Kubernetes identity it already has,
nothing an operator invents per workload. Client and server auth both,
because a workload calling another workload is a client in that call and
may be a server in the next one. Issued through cert-manager's CSI
SPIFFE driver, so a workload's identity certificate is a file on disk it
never had to ask for by name — the driver requests it on the pod's
behalf from its own ServiceAccount, and cert-manager's approver decides
whether to sign.

**Why a per-project issuing CA matters here specifically.** A project's
issuing CA is the only thing in the chain that can mint an `identity`
certificate claiming that project's namespace in its SPIFFE ID. An
installation where one shared issuing CA minted every project's identity
certificates would need every project's SAN checked by something outside
the CA itself — the CA's own signature would no longer be evidence of
which project a workload belongs to. With one issuing CA per project,
the CA boundary and the project boundary are the same boundary: a
project's CA cannot even be asked to sign an `identity` role naming
another project's namespace, because no role naming that namespace
exists on this CA.

**The chain: a URI-constrained domain intermediate.** The domain
intermediate above the per-project issuing CAs carries
`permittedURIDomains`, naming the trust domain every `identity`
certificate below it may use — the same name-constraint mechanism the
existing DNS-constrained domain intermediate already uses for
`permittedDNSDomains`, extended to URIs. This constraint is minted at
ceremony time, in a new generation of the domain intermediate, because
**the ceremony is this repository's own code** — Go's `x509` package
already builds and verifies URI name constraints — **and OpenBAO's own
`pki/root/generate/internal` and `pki/intermediate/generate/internal`
endpoints do not need to support them for this to work**: the ceremony
mints the intermediate outside OpenBAO entirely (the root in a KMS, the
intermediate's CSR signed by the root, [ceremony.md](../ceremony.md)'s
existing flow), so the constraint is baked into the intermediate's
certificate before OpenBAO ever holds the corresponding private key.
OpenBAO 2.6.2's own root-generation endpoint separately does not honour
every name-constraint field it accepts — it silently ignores
`excludedIpRanges`, as [model.md](../model.md) already documents — which
is exactly the kind of gap the ceremony's own code sidesteps by not
depending on OpenBAO to enforce a constraint OpenBAO itself minted.

**The blanket approver must go, and the SPIFFE driver's own approver
must arrive, in the same change.** cert-manager ships a blanket automatic
approver that approves every CertificateRequest, which is harmless as
long as nothing on the cluster asks for a SAN it should not get, and
turns into decoration — a certificate that looks scoped but is not — the
moment a workload can request any URI SAN it likes and get it signed
anyway. Turning the blanket approver off without something else approving
in its place hangs every certificate request, including the one the
CA's own bootstrap needs, so this is one change, not two: disable the
blanket approver, install the SPIFFE driver's own approver (which checks
that a request's SPIFFE URI matches the requesting pod's own namespace
and ServiceAccount), and an approver-policy that explicitly admits the CA
bootstrap's own request. That check exists: `approvercheck --live
--require-blanket-approver-off` (`cmd/approvercheck`, described in
[approver.md](../approver.md)) asserts the blanket-approver flag is off
and that every live request is approved by a policy or skipped as the
SPIFFE signer, and a refusal test proves the negative directly: a CertificateRequest naming a
foreign SAN — a namespace or ServiceAccount that is not the requesting
pod's own — gets no certificate.

**Trust domain per cluster; peers check it.** Each cluster's workloads
share one trust domain in their SPIFFE IDs, and the trust bundle a peer
verifies against trusts every environment's domain intermediate at
once — a bundle scoped to only one cluster would not let a workload
verify a peer meant to be reachable from a different cluster. That means
the certificate chain alone does not prove which cluster a peer runs in:
two workloads in two different environments can both present
certificates that chain to the same trusted root. **A peer must check the
trust domain in the SPIFFE URI it receives, not only that the chain
verifies**, or a certificate valid for one environment verifies just as
well presented from another.

**Authorization is a catalogue, not a chart-by-chart decision.** Who may
call whom is rows in one catalogue — caller identity, callee identity,
nothing else — rendered into each service's own allow-list at render
time. A chart author does not decide, by hand, which SPIFFE IDs may
reach their service; the chart consumes the allow-list the catalogue
renders for it. This is what lets "who calls whom" be reviewed as one
list rather than reconstructed by reading every chart's own values.

## Consequences

- Every workload wanting mutual TLS by identity needs the CSI SPIFFE
  driver mounted, and an `identity`-role certificate available where its
  client library expects one; a workload that only ever calls a
  `service`-shaped endpoint (a database, a broker) needs neither.
- Disabling the blanket approver is a one-way door for every certificate
  request on the cluster, not only identity ones: anything relying on the
  blanket approver's "approve everything" behaviour for an unrelated
  CertificateRequest needs its own approver-policy rule before this
  change ships, or its requests hang.
- A peer that only checks "does this chain verify," and not "is this the
  trust domain I expect," is silently accepting cross-environment
  identities. This is a review item for every consumer of the SPIFFE
  bundle, not something the bundle's own shape prevents by itself.
- The catalogue becomes the one place "who may call whom" is answered;
  a chart that grants itself an allow-list entry by hand, bypassing the
  catalogue, defeats the reason the catalogue exists and should be
  treated as a bug wherever it is found.

## Alternatives considered

**One workload role, wider SANs.** Widen the existing DNS-and-server-auth
role to also accept a URI SAN and client auth, rather than adding a
second role. Rejected: a certificate's role should say which promise it
makes, and a role that can issue either a "this is a named service"
certificate or a "this is this workload's identity" certificate makes
neither promise legible from the role name alone — every consumer would
need to inspect the certificate's own SANs to know which kind it
received.

**A shared issuing CA for identity certificates, with the project
boundary enforced elsewhere.** Keep one issuing CA per environment for
`identity` certificates, and check the namespace/ServiceAccount match
downstream — the approver, or the consuming service. Rejected as the
sole control: it works for the approver's own check at issuance time, but
it means the CA's signature is no longer, by itself, evidence of which
project a workload belongs to — anyone who gets a certificate request
past the approver once (a misconfiguration, a bypassed policy) gets a
certificate the CA itself cannot distinguish from a legitimate one. A
per-project CA makes that mistake structurally unavailable rather than
relying on the approver alone to catch it.

**Skip the name constraint on the domain intermediate and rely on the
approver alone.** Rejected for the same reason: the approver is a
control that runs at issuance time and can be misconfigured or bypassed;
a name-constrained intermediate is a property of the certificate chain
itself, checked by every verifier, that holds even if the approver's own
policy has a gap nobody has noticed yet.

## Amendment, 2026-09-28: templating works, but the CSI flow cannot use it

Building the `identity` role (step 1 of this record, library only)
answered the question this record left open: whether an `identity` role's
`allowedUriSans` can be templated to the caller's own SPIFFE ID rather
than authored per workload. Two findings, both confirmed against a real
OpenBAO 2.6.2 server, not read from documentation:

**The template syntax works, with one trap.** A role can bind its URI SAN
to the caller's own identity --
`spiffe://<trust domain>/ns/{{identity.entity.aliases.<jwt
accessor>.metadata.service_account_namespace}}/sa/{{identity.entity.aliases.<jwt
accessor>.metadata.service_account_name}}` -- exactly as
[pkg/model](../model.md#auth-workloads-and-people)'s existing
`claimMappings` support already lets a workload role copy those two
claims into its own login's alias metadata. Proved directly: a login
bound to one ServiceAccount gets a certificate for exactly its own SPIFFE
ID and is refused for another's. The trap is `use_csr_sans`, a role field
this record never mentioned: OpenBAO 2.6.2 defaults it to `true`, and when
true the request's own `uri_sans` parameter is silently dropped --
whatever the role's `allowedUriSans` says, the signed certificate carries
**no** URI SAN at all. That is not a refusal a caller notices; it is a
certificate that looks scoped and is simply empty. An identity role must
set `use_csr_sans: false`, which is also the more defensible default on
its own terms: an identity certificate's SAN should never come from
whatever the CSR itself happens to carry.

**The CSI flow cannot use this templating, because it is never the
workload that logs in.** This record's own "Issued through cert-manager's
CSI SPIFFE driver" already says who asks OpenBAO for the certificate --
and having now built the templated role, it is worth being explicit about
what that means for it: the driver requests a workload's certificate on
the workload's behalf, authenticating to OpenBAO with **cert-manager's
own** login (its controller's identity, or the issuer's configured
credential) -- not the pod's. `identity.entity.aliases.<accessor>.metadata.*`
would resolve to cert-manager's own claims, the same for every pod it
ever requests a certificate for, never the requesting pod's namespace or
ServiceAccount. Templating an `identity` role to "the caller's own
identity" is therefore a real capability this record confirms works, but
not one the CSI flow can reach: the caller OpenBAO sees is always
cert-manager, whichever pod is actually asking.

**The fallback this record already named is what the CSI flow uses.**
"the chain+role constraint is `spiffe://<trust domain>/*`" -- literal, not
templated, with the trust domain held fixed and only the path open.
`pkg/model`'s `PKIRole.Validate` treats this as a distinct, deliberate
case: a wildcard in the URI's **host** (`spiffe://*`, or a foreign trust
domain reachable through one) is refused unless templated, because that
would let a caller claim to be from any trust domain at all; a wildcard
held to one fixed, already-constrained trust domain is accepted
untemplated, because OpenBAO's own chain and role already hold that
boundary -- what is left open is exactly the per-workload namespace and
ServiceAccount this record already assigns to the SPIFFE driver's own
approver, not to OpenBAO. Nothing about this amendment changes that
assignment; it only confirms, with a real server, that OpenBAO could not
have enforced the narrower promise here even if the approver did not
exist.
