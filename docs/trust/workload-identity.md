# Workload identity (SPIFFE)

A workload's identity is **the ServiceAccount it runs as**, carried in a
short-lived certificate the platform mounts into the pod. Two workloads that
both present such a certificate can authenticate each other, and a service can
admit a caller by *who it is* instead of *where it is*.

This is a **narrow mandate**. It is a tool for the cases below, not a blanket
requirement, and the platform must be honest about where it stops.

## Where SPIFFE pays, and where it does not

The baseline for in-cluster traffic is **NetworkPolicy default-deny plus server
TLS on the callee** (a certificate from the private chain, verified by name).
A network policy answers "may this address reach that one"; TLS answers "did I
reach the machine I meant". Workload identity adds "who is calling", and costs a
CSI volume, a ServiceAccount per component, an allow-list to maintain, and a
rotation path in every client. So it is used where the extra question is worth
that:

| Use SPIFFE identity when... | Because |
|---|---|
| the call **crosses clusters** | an address in another network says nothing; a network policy cannot follow it |
| the callee is a **broker** (a message bus, a credential broker) | the broker maps an identity to permissions; a token or an address is weaker |
| the callee is a **sensitive service** whose allow-list you want reviewable as data | "who may call whom" as rows, not as scattered chart values |

| Do not use it when... | Use instead |
|---|---|
| the caller is a browser | the gateway signs the person in ([servers-and-edge.md](servers-and-edge.md#sign-in-at-the-gateway)) |
| the callee is a **database** | the database's own CA ([databases.md](databases.md)); a SPIFFE certificate has an empty common name and PostgreSQL's `cert` method reads only the CN, so it cannot authenticate a database role |
| the callee is a third-party server that cannot verify identity | a terminating proxy in its pod, or a written exception naming the reason |
| the port is a probe | probes present no identity; the probe listener is its own port |

Rejected: a service mesh ([decisions.md](decisions.md#t-11-no-mesh-mutual-tls-at-application-level)).

## The identity

```
spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>
```

`<trust-domain>` is **the environment's private zone**: one trust domain per
environment. The name uses the identity Kubernetes already has; nothing is
invented per workload. Certificates live **1 hour** (24 at most), are never
persisted to a Secret, and carry client *and* server usage (a workload calling
another is a client in that call and may be a server in the next).

**Trust domain before account.** Two environments can each have a `shop`
namespace and an `api` account. The account alone is not the identity; the trust
domain is what makes it one.

## How a pod gets one

1. The pod mounts a volume from the CSI driver (`spiffe.csi.cert-manager.io`) at a fixed path.
2. The driver creates a `CertificateRequest` **as the pod's own ServiceAccount**
   (that is the attestation) for the URI naming that ServiceAccount, on an
   annotated request to the environment's `identity` issuer, with an ECDSA P-256
   key.
3. **The driver's approver decides.** It approves only if the requested SPIFFE
   URI equals the requesting pod's own namespace and ServiceAccount. Any other
   request to that issuer is left undecided and never signed.
4. OpenBAO signs on the *issuer's* login (cert-manager's own), under the
   environment's root-signed identity CA.
5. The volume holds `tls.crt`, `tls.key` and `ca.crt` (from the identity bundle).

Consequences that are easy to miss:

- The pod's ServiceAccount needs `create certificaterequests` in its namespace
  (a namespace-wide role for the group of ServiceAccounts is enough). Without it
  **the pod is never created**, with the reason in an event nobody is watching.
- OpenBAO cannot enforce a *per-pod* URI: the caller it sees is always the
  issuer's login, never the pod. The identity role is therefore
  `spiffe://<trust-domain>/*` -- fixed trust domain, open path -- and per-pod
  attestation is the approver's job. The role also has `use_csr_sans: false`, so a
  request's own SANs are never trusted. The environment CA's exact URI constraint
  is what keeps the trust domain fixed cryptographically
  ([hierarchy.md](hierarchy.md#the-identity-ca-is-signed-by-the-root-not-by-an-intermediate)).
- **Ordering.** Apply the namespace's request permission *before* the change that
  turns the mount on, or the mount is forbidden and the rollout stalls while old
  pods keep serving.

## One ServiceAccount per component: mandatory

**Every component of every workload runs as its own ServiceAccount.** No two
components share one, and there is no toggle to allow it.

Why: the identity *is* `ns` plus `sa`. A shared account makes components
indistinguishable, so every allow-list -- the catalogue, the peer lists, the
`enforced` level -- collapses to the *project* boundary. A component that only
calls out and a component that holds a sensitive capability would be one
principal. The shared account is the failure this rule forecloses, and it cannot
be diagnosed from the outside, because everything works.

Charts render one account per component (default `<release>-<component>`). A
component with a cloud-role binding may keep a *named* account, but still its own.
The component contract carries this as a rule with a check that no two
Deployments or Jobs render the same account
([truvity/policy](https://github.com/truvity/policy/blob/master/docs/contracts/component.md),
C14). Flag any chart or project that shares an account.

## Modes and levels

Two independent switches decide how much of this is on.

**Per component, in the application's own configuration (`tls.mode`):**

| Mode | Serves |
|---|---|
| `off` | cleartext only |
| `permissive` | both, on **two ports** (cleartext and authenticated) |
| `strict` | the authenticated port only |

`permissive` is two ports because one listener cannot be both in every runtime.
A component migrates in three commits with no coordinated window: the server adds
its authenticated port, its clients move to it, the server drops the cleartext
one. A mode is **per serving component, not per release**. **A gateway-fronted
component may be `permissive` but never `strict`**: the edge terminates TLS and
forwards cleartext, a browser cannot present a workload certificate, and a strict
one would refuse its only caller. The chart's schema refuses the combination.
**A chart's default is `off`**, always: a chart is installable by someone whose
platform provides none of this.

**Per project and per environment, on the platform (`mtls`):**

| Level | What is rendered |
|---|---|
| `off` (default; an environment not listed is `off`) | nothing: no namespace label, no request permission, no `tls` block |
| `identity` | the namespace opts in to the identity bundle and the request permission; the app runs `permissive`. Cleartext callers still work |
| `enforced` | `identity`, plus every component the catalogue marks `strict: true` runs strict, the render-time checks below hold, and [the admission policy](#the-admission-policy) refuses a pod that skips its identity |

A project moves `off` to `identity` to `enforced` **per environment**, and a state
that has reached `enforced` must not regress. `strict` is inert below `enforced`,
so a row can be prepared ahead of the flip; the flip to strict is a separate
change from any catalogue change (data is not entangled with enforcement).

## The admission policy

Level `enforced` means nothing if a pod can simply not ask for its identity. The
`openbao-consumers` chart therefore ships an **optional** `ValidatingAdmissionPolicy`
and binding (`admissionregistration.k8s.io/v1`, Kubernetes 1.30 or later; values
`admissionPolicy.*`, **off by default**, and the default render is unchanged).

**Scope.** It applies only to namespaces carrying the opt-in label
(`admissionPolicy.namespaceLabel`, default `mtls-level=enforced`; put the key
under your own prefix). Every other namespace, system ones included, is out of
scope, so there is nothing to exempt them from. The platform that renders a
project's namespace at level `enforced` renders that label; the chart does not
label namespaces.

**Rules**, each independently switchable:

| Rule | Refused | CEL, in short |
|---|---|---|
| identity volume (`csi`) | a container that does not mount a volume of the CSI driver (`csi.driver`, default `spiffe.csi.cert-manager.io`) | every entry of `containers` (init containers are not required to) has a `volumeMount` naming a `volumes[]` entry whose `csi.driver` is the driver; `csi.ignoreContainers` lists names that are exempt, for a sidecar a mutating webhook injects |
| ServiceAccount (`serviceAccount`) | a pod on the `default` ServiceAccount, or naming none | `serviceAccountName` is set, not empty and not `default` (a pod is defaulted to `default` before validation, so it is caught) |
| plaintext ports (`services`) | a Service with a port that is plaintext | see below |

**Pods and workloads both.** The pod rules run on `Pod` create **and** on the
pod template of `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `Job` and
`CronJob` (create and update; `workloads: false` turns the template half off).
A rule on Pods alone surfaces as a ReplicaSet that never gets a pod, with the
reason in an event nobody reads; on the template it surfaces at `kubectl apply`,
naming the object. The Pod rule stays on either way as the backstop for pods made
any other way.

**What "plaintext" means for a Service.** A Service port is TLS when its
`appProtocol`, lower-cased, is in `services.tlsAppProtocols` (default `https`,
`tls`, `grpcs`, `kubernetes.io/wss`). Everything else is plaintext: a port with
**no** `appProtocol` (the field is how a Service says what its port speaks, and
the policy cannot see inside a port), `http`, `grpc`, `kubernetes.io/h2c` (h2c is
HTTP/2 *without* TLS) and `kubernetes.io/ws`. That is deliberately mechanical: the
policy reads a declaration, it does not probe the backend, so a Service that
declares `https` and serves plaintext is a lie only a test can find. To satisfy
it, serve TLS and say so in `appProtocol`. A Service that is fronted by a gateway
or edge, which terminates TLS and forwards cleartext (see [modes](#modes-and-levels)),
opts out in one of three ways:

- the annotation `admissionPolicy.services.gatewayFrontedAnnotation` (default
  `gateway-fronted`) set to exactly `"true"` on the Service;
- its name in `services.allow`, or `name/portName` to allow one port only (a
  metrics port, say);
- the per-object exemption below.

`ExternalName` Services have no ports and are not checked.

**Exemption.** An annotation (`exemptAnnotation`, default `mtls-exempt`) with a
**non-empty value, the reason**, exempts one object from every rule: on a Pod, on
the **pod template** of a workload (so the Pod it makes carries it too), or on a
Service. An empty value is not an exemption and the refusal says so. There is no
namespace-level exemption: a namespace that should not be enforced is not
labelled. Review the annotation like a grant: `kubectl get pods,svc -A -o json`
filtered on it lists every one and its reason.

**Updates and deletions.** A terminating object is never refused (a finalizer
removal is an update, and refusing it would wedge the deletion). An update is
judged only when it changes what the rules read (a workload's pod template, a
Service's ports or annotations), so an unrelated edit to an object made before the
flip does not fail.

**Messages** name the object, the container or port and the fix, for example
`Deployment/api in namespace shop: container "app" does not mount a volume of the
CSI driver spiffe.csi.cert-manager.io ... Add a csi volume with that driver and
mount it in the container.`

**`failurePolicy` is `Fail`**: a policy that cannot be evaluated refuses the
request. `validationActions` is `[Deny]`; `[Warn, Audit]` is the dry run.

### Rolling it out: dry run first

1. Install with `admissionPolicy.enabled=true` and
   `admissionPolicy.validationActions={Warn,Audit}`. Nothing is refused. Label the
   namespace.
2. `kubectl apply` (or your GitOps dry run) now prints a `Warning:` for every object
   that would be refused, and the API server's audit log carries the same
   verdicts under the policy's name (the audit annotation
   `validation.policy.admission.k8s.io/validation_failure`). Fix each: add the
   volume and a ServiceAccount, set `appProtocol`, annotate the gateway-fronted
   Services, or exempt the few that truly cannot, with a reason.
3. When a full apply of the namespace is quiet, set `validationActions={Deny}`.
   Objects already in the namespace keep running (a policy does not touch what
   exists); they are judged when their template or ports next change.
4. Enable it per namespace by labelling, never by widening the policy.

What it does not do: it cannot prove the volume is *used* (the workload reading the
certificate), that a port declared `https` really serves TLS, or that the driver's
own approver is healthy; those are the transport libraries' and the alerts' job.
It is defence in depth for the identity, not a replacement for the calls catalogue.

## The calls catalogue

**Who may call whom is rows in one catalogue**, not a decision each chart author
makes. Each row is one component in one environment with a list of peers; each
peer is a `{namespace, serviceAccount}` pair (never a bare address, never a
whole SPIFFE URI: the chart's transport library builds the URI itself) and a
`why`. The catalogue is rendered into each service's own allow-list at render
time, so "who calls whom" is reviewed as one list.

Rules the loader enforces:

- **No globs.** An allow-list entry is one account. A wildcard is refused.
- **`why` is required.** An entry with no reason is the shape a stale grant takes
  once its author has moved on.
- **An empty list renders `[]`, never null.** An omitted list renders YAML `null`,
  which crash-loops every service reading it. An environment declared with
  `peers: []` reads as "somebody looked and granted nobody outside the release";
  an environment never mentioned reads as "nobody has looked".
- **Both ends must have an identity.** A caller with no identity in that
  environment cannot present a certificate, so a grant naming it describes a
  certificate that can never exist. (A caller that is not a project -- the ingress
  gateway -- is exempt.)
- **`enforced` needs every known caller granted** on a component before it is
  marked `strict`.
- **A chart grants its own internal callers**; the catalogue carries only
  *external* grants. Duplicating the internal graph would only drift from what the
  chart does, and a chart whose default cannot talk to itself installs and then
  sits refused at the handshake.

## Peer verification

Every implementation, in every language, holds a peer to the same rules. A
client that verifies by identity has to turn the standard library's name check
**off** and do both halves by hand; skipping either half is the mistake the flag's
name warns about, and skipping the *name* is the point (a workload certificate
carries an identity and usually no host name at all).

1. **Build the chain** against the environment's identity bundle (the trust
   anchor), with the intermediates the peer sent. Check validity.
2. **The leaf must be exactly what a SPIFFE X509-SVID is.**
   - It is **not a certificate authority**: `CA` is false, and it may not sign
     certificates or revocation lists. A workload certificate that could would let
     any admitted peer mint further identities.
   - It carries **exactly one URI name**, of any scheme. With two, which one is the
     identity would be a guess, and a guess is a grant.
   - A leaf that fails either is refused **whole, before its account is considered.**
   - Delivered in truvity/policy's transport libraries (Go, Python) and its Kotlin
     example as of v1.32.0.
3. **Check the trust domain**, then the `ns`/`sa` pair, against the allow-list. The
   trust domain is checked *in addition to* the chain, as defence in depth: the
   chain is evidence of the environment, and the check makes it not the only
   evidence.
4. **An empty allow-list admits nobody.** It is the right default for a service
   nobody has been granted, and the one default that has to fail closed.
5. **Refuse loudly on the server, quietly to the caller.** The caller is told it was
   refused, nothing more; which rule rejected it describes the allow-list to
   whoever is probing. The reason belongs in the server's log. Test both halves,
   or a service refusing everyone for an unrelated reason looks correct.
6. **Re-read the certificate when the file changes.** These live about an hour; a
   process that cached the first one works through a whole afternoon of testing and
   fails everywhere at once. Keep serving the previous certificate through a
   half-done rotation.
7. **The group owns the mount** ([issuance.md](issuance.md#reloading-what-actually-picks-up-a-renewed-file)).

Where the implementations live: Go and Python in
[truvity/policy](https://github.com/truvity/policy) (`transport/`; Python's
`ssl` has no verification callback, so the account check is `verify_peer` after
the handshake).

## Proving it

**Prove the refusal, never the issuance.** The dangerous failure is a platform
where identities are issued correctly *and anyone can ask for anyone's*. The
refusal test is in [issuance.md](issuance.md#the-refusal-test-is-the-proof);
`approvercheck --require-blanket-approver-off` is the CI assertion.

## NATS: identity mapped to a user

A message broker is the clearest case where identity pays. NATS's
`verify_and_map` matches a client certificate's e-mail SANs, then DNS SANs, then
**URI SANs**, then the subject. So a broker user is named by the certificate's
SPIFFE URI, verbatim; no field is bent to fit.

- **Status.** LIVE as a pilot in a development environment: the publisher connects
  with its SPIFFE identity and no token, and is mapped to its NATS user over
  TLS 1.3. Its transitional shared-account entry has been removed.
- The broker's `ca_file` is **that environment's identity bundle and nothing
  else**; its own server certificate is a private-chain leaf.
- Mapped users get the exact subjects the catalogue lists for publishing and
  `_INBOX.>` for subscribing (the acknowledgement inbox), nothing else.
- Migration is additive: the broker still allows non-TLS clients, which go through
  the token-based authentication callout as before. A TLS client whose certificate
  maps to no user, a plaintext client and a client with a token all end at the
  callout; a TLS client with *no* certificate never gets that far.
- **Rotation.** The broker verifies a client at the handshake and holds no copy of
  the leaf, so an hourly rotation needs no reload; a connection already made is
  not re-checked. The client re-reads its files on every connect. The broker's own
  certificate is long-lived and is the only reloadable input.

## Federation (PLANNED)

Everything here is **per environment**: each environment's identity CA is
trusted only inside it. Calls across environments or clusters need the peer's CA
in the verifier's bundle *and* the caller's trust domain in its allow-list. The
shape is planned, not built: a federated bundle would list foreign identity CAs
**explicitly, by environment**, never a shared intermediate, and each entry
would be a reviewed grant. Until then a cross-environment call is a broker's
job (the broker maps identity to permission) or a person's.

## Rollout order, in one place

1. The identity CA for the environment exists (ceremony) and its bundle is
   delivered ([hierarchy.md](hierarchy.md), [issuance.md](issuance.md#trust-bundles)).
2. The approver layer is cut over and proven by the refusal test
   ([approver.md](../approver.md)).
3. The driver has its source bundle.
4. A project's namespace opts in (`identity`), request permission first.
5. Charts turn `permissive` on; callers move; then, per component, `strict` in
   a separate change once the catalogue names every caller.
