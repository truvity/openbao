# Issuance: cert-manager, approver-policy and trust-manager

Three controllers turn the hierarchy into files in pods:

| Controller | Job | The rule it enforces |
|---|---|---|
| **cert-manager** | asks an issuer to sign, renews, writes the Secret | nothing signs unless a request is *approved* |
| **approver-policy** (and, for identity, csi-driver-spiffe's own approver) | decides whether a request may proceed | a request is approved only if a policy for that issuer names its exact shape |
| **trust-manager** | distributes the trust anchors as `Bundle`s | a namespace receives only the anchors it should trust |

OpenBAO signs; it never decides *who may ask*. That split is the point: the
signer knows what it can sign, the approver knows who is asking.

## Issuers

| Issuer | Backed by | Used for | Approved by |
|---|---|---|---|
| a `ClusterIssuer` per OpenBAO role (`private`, `client`, `gateway`, `service`, `origin`) | OpenBAO, on the environment's issuing CA | hosts and services | one exact `CertificateRequestPolicy` per issuer |
| the `identity` `ClusterIssuer` | OpenBAO, on the environment's root-signed identity CA | workload identity | **csi-driver-spiffe's own approver only**; approver-policy is never given this signer |
| a namespaced `Issuer` (a self-signed root plus a CA issuer) | a Secret in that namespace | a database's own client certificates; short-lived CI tenants | one allow-all policy for namespaced `Issuer`s (never for an OpenBAO-backed issuer) |

### How issuers log in

Every OpenBAO-backed issuer logs in as one ServiceAccount with a token
cert-manager mints **per request**: projected, audience-scoped, short-lived.
There is no stored credential. cert-manager always requests the audience
`vault://<issuer-name>` (`vault://<namespace>/<name>` for a namespaced
`Issuer`), so an OpenBAO role can be bound to exactly one issuer; a second
issuer that signs on another path of the same chain asks for the first's
audience in addition, rather than being a second identity for the same
account. See [doctrine.md](../doctrine.md#issuer-logins).

### The bootstrap exception

A self-signed root expressed as a cert-manager `Certificate` needs its request
approved like any other. So the moment the blanket approver is turned off
(below), the bootstrap needs an approver too. The allowed shape is a
**namespaced** self-signed `Issuer` and CA `Issuer`: they confer no trust
outside the namespace (whoever can create the `Issuer` already holds its key),
so approving them grants nothing that was not held. The render **refuses** to
combine that allow-all policy with any OpenBAO-backed issuer, because such an
issuer would ride it and its own shape would never be enforced.

Why it exists: tenants such as CI namespaces mint `Issuer`s under a fresh name
every run, which no exact per-issuer policy can name in advance. It is also
how a database gets its own CA ([databases.md](databases.md#the-per-database-ca)).

## The approver: off by default, then per issuer

**The blanket approver must be off.** cert-manager ships
`certificaterequests-approver`, which approves *every* request for an issuer
it knows. While it is on, whoever can create a `CertificateRequest` gets any
name they ask for from any issuer whose backend allows it. For an identity
issuer that is the whole problem: the certificate looks scoped -- a SPIFFE URI
naming a namespace and a ServiceAccount -- and is not, because nothing checked
the requester owns that name. Measured: an account created a request by hand
naming another workload's URI, and it came back approved and issued, with
nothing failing anywhere. **The attestation is decoration.** Turning it off
(`--controllers=*,-certificaterequests-approver` on the cert-manager
controller) needs something else approving in its place, first. The
step-by-step cutover, with the ordering that keeps it from hanging every
certificate on the cluster, is [approver.md](../approver.md#cutover-runbook).

**Three approvers can coexist; each owns a different set of signers:**

| Approver | Owns |
|---|---|
| cert-manager's blanket approver | everything, until turned off |
| approver-policy | the signers in its `approveSignerNames`, gated by a `CertificateRequestPolicy` plus RBAC `use` |
| csi-driver-spiffe's own approver | exactly its identity issuer, checking the requested SPIFFE URI equals the requesting pod's own namespace and ServiceAccount |

Two approvers on one signer race and the loser silently skips. And a request
that already carries an Approved or Denied condition is *skipped* by the
other two, so with the blanket approver on, "Approved" says nothing about
whether a policy would have approved it.

### The refusal test is the proof

**Never accept "certificates are issued" as evidence.** With the blanket
approver on they are, forgeries included. The proof is the **refusal**: as an
account that may create `CertificateRequest`s in one namespace, submit a
request against the identity issuer whose URI names a *different* namespace or
ServiceAccount. It must end `Denied` by the driver's approver, with no
certificate; then submit one for the right identity, which must be issued.
Keep a namespace and ServiceAccount for it, and re-run after every change to
this layer. Assert the blanket-approver flag in CI as well: a healthy driver
looks identical either way.

### The policies

One **exact** policy per non-identity issuer, selecting that issuer alone,
allowing only the shapes the issuer should ever be asked for (`dnsNames`,
`uris`, `commonName`, `ipAddresses`, `emailAddresses`, `usages`, each a glob
with `*` only; `isCA` is always false). approver-policy **denies any request
field a policy does not name**, so an issuer with no entry fails the render
rather than yielding a policy that refuses everything. Shorter service-name
forms are absent by policy. Keys: ECDSA 256 to 384; RSA refused. Durations
default to 1 hour to 2160 hours.

Two consequences worth naming:

- **A subject field is a field.** A leaf that carries an `O=` or `C=` must have
  it listed, or it is denied at its first renewal. Anything that used to pass
  because "there is no policy" now needs one.
- **The identity issuer has no policy at all.** A policy cannot express "the
  requester's own ServiceAccount"; only the driver's approver can. If
  approver-policy also owned the signer it would either leave those requests
  unapproved or approve any URI its policy allows -- the blanket approver
  again, with extra steps.

### `approvercheck`

`approvercheck` (`cmd/approvercheck`) is an offline port of approver-policy's
evaluator, fail-closed: a policy field it does not evaluate, or a request
field no policy names, is a failure, never a pass.

- `--requests` proves the selector and shape half, offline.
- `--live` lists every `CertificateRequest` and asks the API server, by
  read-only `SubjectAccessReview`, whether the request's own requester may
  `use` each candidate policy -- the same call approver-policy makes: it is the
  **live RBAC** proof.
- `--require-blanket-approver-off` fails unless the controller runs without the
  blanket approver.

Two limits, learned by shipping a cutover a live run called green:

1. `--live` sees only requests that exist at that instant. Short-lived tenants
   are invisible. Prove every request **shape** that can ever arrive by building
   the `CertificateRequest`s those tenants would make and asserting they are
   approved, in a test.
2. Point it at the cluster you mean. It reports the context and server it used
   on its first line; read it.

## Trust bundles

trust-manager `Bundle`s distribute anchors. The bundles are deliberately
**not** one big list.

| Bundle | Holds | Delivered to | Why |
|---|---|---|---|
| **private root** | the root of every *trusted generation*, and nothing else | a ConfigMap (`ca-certificates.crt`) in every namespace of every cluster | every workload verifies host names; the server sends its chain, so the root alone is enough |
| **environment identity** | that environment's identity CA and **only** that one | the namespaces that opt in with a label, plus the workload-identity driver's namespace | a verifier of workload identities must not accept another environment's CA |
| **origin roots** | the root of every trusted generation | **not a Bundle**: one file mounted into the tunnel daemon | only the tunnel connects to origin listeners; there is nothing to distribute |

The anchors are not a hand-edited PEM list: each trusted generation is
resolved to the certificate its ceremony committed, re-deriving the
fingerprint, key identifier, subject and self-signature before rendering. A
generation named as trusted with no artifact, or an edited one, fails the
render. `migration.trustedGenerations` is therefore the only lever: a root
enters the fleet's trust by being listed, and leaves it by being removed.

**Why the identity bundle holds only its own environment's CA.** The earlier
shape trusted a shared identity intermediate (so every environment's leaves
verified everywhere) and required every peer to check the trust domain in the
URI *in addition to* verifying the chain. Now that each environment has its own
root-signed identity CA with an exact URI constraint, the bundle can match the
boundary: the chain is evidence of the environment. Peers still check the trust
domain ([workload-identity.md](workload-identity.md#peer-verification)) -- as
defence in depth, not as the only wall.

**The driver's volume gets `ca.crt` only from its source bundle.** The CSI
driver writes `ca.crt` into a pod's volume only from a bundle mounted into the
driver itself (`app.driver.sourceCABundle`); without one the volume has
`tls.crt` and `tls.key` and no trust, and the app dies on a missing file. The
driver's bundle is a second `Bundle` from the same source, targeted at the
driver's namespace. A volume created before the driver had it does not gain
`ca.crt` retroactively: restart the stuck pods after the driver rolls.

## Keys and encodings

| Setting | Recommendation | Reason |
|---|---|---|
| algorithm and size | ECDSA P-384 (P-256 where the client cannot be told otherwise) | fleet-wide default; see [hierarchy.md](hierarchy.md#lifetimes-and-algorithms) |
| `privateKey.rotationPolicy` | `Always` | a new key on every renewal; a leaked key ages out |
| `privateKey.encoding` | **PKCS#8** for every client | cert-manager's default EC encoding is SEC1 (`BEGIN EC PRIVATE KEY`), which a Java client refuses. PKCS#8 PEM is still not enough for the Java PostgreSQL driver: it needs **DER** PKCS#8 (see below and [databases.md](databases.md#per-driver-rotation-notes)) |
| `additionalOutputFormats` | `DER` for a Java PostgreSQL client (candidate, **to be verified**) | the driver cannot read a PEM PKCS#8 EC key but reads DER PKCS#8; cert-manager can write the DER form beside the PEM, which would avoid an init-container conversion that breaks native rotation |
| `duration` / `renewBefore` | 720h / 240h for hosts; the driver re-requests hourly identities | a renewal window many times the outage you want to survive |

## Alerts

When issuance breaks nothing fails loudly: a workload loses its certificate, or
keeps an old one until it ends. `charts/openbao-consumers` ships the rules that
notice, so each consumer does not write its own. They are **off by default**
(`alerts.enabled: false`) and the output is a value: `alerts.format` is
`vmrule` (VMRule), `prometheusrule` (PrometheusRule) or `configmap` (the plain
Prometheus rules file under one key, for a ruler that loads files). Object
labels for an operator's `ruleSelector` go in `alerts.labels`, labels for
routing on every rule in `alerts.ruleLabels`, and `alerts.selector` narrows the
certificate rules to some namespaces or names.

| Alert | Fires when | Default | Severity | Reads |
|---|---|---|---|---|
| `IssuanceCertificateNotReady` | a Certificate is not Ready | 30m | warning | cert-manager `certmanager_certificate_ready_status` |
| `IssuanceCertificateRequestDenied` (opt-in) | a CertificateRequest has the Denied condition | 5m | critical | kube-state-metrics custom resource state, see below |
| `IssuanceCsiDriverSpiffeUnavailable` | the csi-driver-spiffe DaemonSet or approver Deployment has unavailable pods | 10m | critical | kube-state-metrics `kube_daemonset_status_number_unavailable`, `kube_deployment_status_replicas_unavailable` |
| `IssuanceApproverPolicyUnavailable` | approver-policy has unavailable pods (on with `approverPolicy.enabled`) | 10m | critical | kube-state-metrics `kube_deployment_status_replicas_unavailable` |
| `IssuanceCertificateExpiringSoon` | fewer than 7 days (`thresholdSeconds`) left on a Certificate | 15m | warning | cert-manager `certmanager_certificate_expiration_timestamp_seconds` |
| `IssuanceCertificateRenewalOverdue` | the renewal time passed more than 2 hours (`graceSeconds`) ago | 15m | warning | cert-manager `certmanager_certificate_renewal_timestamp_seconds` |
| `IssuanceCaExpiring` (opt-in) | fewer than 30 days left on an issuing or identity CA | 1h | critical | a not-after timestamp you export, see below |
| `IssuanceMetricsAbsent` | no cert-manager metric is being scraped | 15m | warning | `absent(certmanager_clock_time_seconds)` |

Every rule takes `enabled`, `for`, `severity`, `labels` and `annotations`
(merged over the rule's own; `runbook_url` goes here), and the ones with a
threshold take it by name. `alerts.rules.<rule>` in
[reference.md](../reference.md#openbao-consumers) lists them.

### What the metrics cover, and the gaps

- **cert-manager exports Certificate metrics, not CertificateRequest
  metrics.** A request stuck Pending (the issuer is not Ready, approver-policy
  never answers) and a request an approver Denied both leave the Certificate
  not Ready, so `IssuanceCertificateNotReady` is the native signal for both. It
  cannot tell them apart, and it only fires for a first issuance or an expired
  Certificate: a renewal that is denied leaves the old certificate Ready until
  it ends, which is what `IssuanceCertificateRenewalOverdue` (first) and
  `IssuanceCertificateExpiringSoon` (last) are for.
- **approver-policy exports no denial metric.** Its metrics are
  controller-runtime's, and a denial is a condition on the CertificateRequest,
  not a counter. `IssuanceCertificateRequestDenied` reads that condition
  through kube-state-metrics' custom resource state, which the cluster must
  configure and which is why the rule is opt-in. The rule's contract, which
  the metric name and the `type` label values adapt: a gauge per
  CertificateRequest condition, labelled `namespace`, `name` and `type`
  (`Approved`, `Denied`, `Ready`), whose value is 1 while that condition's
  status is `True`. A condition's status is a string, so the custom resource
  state configuration has to map it to a number; how depends on the
  kube-state-metrics version, and this chart does not ship that configuration.
- **csi-driver-spiffe exports no health metric the rules rely on.** They read
  the workload status of its DaemonSet and approver Deployment; the defaults
  are the names of its Helm chart, and `daemonSetRegex` and `deploymentRegex`
  follow a renamed release. The pods being available says the driver is there,
  not that it issues: the refusal test in [the approver section](#the-approver-off-by-default-then-per-issuer)
  is what proves that.
- **The CAs live in OpenBAO, and cert-manager holds no Certificate for
  them,** so no cert-manager metric can tell that one is near its end.
  `IssuanceCaExpiring` reads the not-after timestamp of the CA certificates
  from an exporter you run; the default metric is `x509_cert_not_after` of
  [x509-certificate-exporter](https://github.com/enix/x509-certificate-exporter)
  pointed at the trust-anchor ConfigMaps and the bundle in cert-manager's
  namespace, with `matchers` selecting them. Until you run one it stays off, and
  the gap is real: the offline root's expiry is a calendar entry, not an alert
  (see [hierarchy.md](hierarchy.md#lifetimes-and-algorithms)). A Certificate the
  chart manages is covered by the native expiry rule.
- **Nothing here proves the rules load.** A ruler refuses an expression it
  cannot parse, and a refused rule blocks whatever syncs it. The chart's tests
  render every format and run `promtool check rules` over each result
  (`conformance/alert_rules_test.go`, part of `just test`), so an unparseable
  render fails CI first.

## Reloading: what actually picks up a renewed file

A renewed certificate that nothing loads is an outage on a timer. The rules:

- **Mount the Secret as a directory, never as a `subPath`.** The kubelet
  refreshes a projected Secret volume in place (by atomic symlink swap); a
  `subPath` mount is a bind of one file and *never* refreshes.
- **A rotation is not atomic across two files.** A reader that catches it
  half-done must keep serving the previous, still-valid certificate rather than
  refusing every connection for the moment it takes.
- **Label every Secret a database operator reads. This is a rule.** CloudNativePG
  reloads a user-provided TLS Secret only when it carries `cnpg.io/reload: "true"`.
  Measured on a small cluster: without the label a renewed server certificate was
  not served after more than eight minutes; with it, in under five seconds. The
  rule covers every user-provided Secret: server TLS, server CA, client CA and
  replication. A cert-manager `Certificate` sets it with
  `secretTemplate.labels`; a Secret written by trust-manager sets it with
  `target.secret.metadata.labels`. Absent the label, nothing fails: the old
  certificate is served until it expires.
- **Know which side re-reads.** A client that builds its TLS configuration per
  new connection (libpq; pgjdbc, per new connection, see
  [databases.md](databases.md#per-driver-rotation-notes)) picks up a rotated
  certificate at the next connect. A client that read the files once and cached
  a connector works for a whole afternoon and fails everywhere at once at expiry,
  with an error that names nothing.
- **Servers that hold their own certificate** run a reload sidecar or a native
  reloader (OpenBAO's serving certificate: [safety.md](../safety.md#a-renewed-certificate-that-nothing-loads);
  a broker's config reloader watching its `cert_file`, `key_file` and `ca_file`).
  A reload can re-run authentication for every connected client; do not tie one
  to an hourly leaf.
- **A directory's group owns the mount.** A driver writes what it mounts owned by
  root; a process running as anyone else cannot read its own certificate. Set the
  pod's group to the user the image runs as. The symptom is a permission error or
  "malformed certificate", never a word about identity.
