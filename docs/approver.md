# The approver layer

cert-manager decides whether a `CertificateRequest` may be signed before
it ever reaches an issuer. That decision is the layer between "someone
asked for a certificate" and "OpenBAO signed one", and this repository
ships the pieces that make it correct for OpenBAO-issued certificates:

| Piece | What it is |
| --- | --- |
| [`approverPolicy`](reference.md#openbao-consumers) in `charts/openbao-consumers` | Optional, off by default. One `CertificateRequestPolicy` per issuer the chart creates, an optional allow-all policy for namespaced `Issuer`s, and the RBAC that lets cert-manager `use` them. |
| `approvercheck` (`cmd/approvercheck`, Go package `pkg/approvercheck`) | An offline port of approver-policy's evaluator. Says, for a set of requests and a set of policies, whether some policy approves each request, and proves the blanket approver is off. |
| [The example values below](#csi-driver-spiffe-values) | csi-driver-spiffe wired to an issuer this chart creates, with its own approver the only one for it. |

## Why the blanket approver must be off

cert-manager ships `certificaterequests-approver`, which approves every
request for an issuer it knows. While it is on, whoever can create a
`CertificateRequest` gets any name they ask for from any issuer, provided
the issuer's own backend allows it. For an identity issuer that is the
whole problem: the certificate looks scoped (a SPIFFE URI naming a
namespace and a ServiceAccount) and is not, because nothing checked the
requester owns that name. Measured: an account created a request by hand
naming another workload's URI, and it came back approved and issued, with
nothing failing anywhere. **The attestation is decoration.**

Turning it off has two consequences, and both are why this is a runbook
and not a flag:

- It turns off approval for **everything**, including cert-manager's own
  bootstrap (a self-signed root expressed as a `Certificate` needs its
  request approved like any other) and every renewal of every certificate
  on the cluster. Something must approve in its place, and it must be
  proven to before the switch, not after.
- Failure is **silence**. A request nobody approves is not denied, it just
  never gets a certificate: a Helm `--wait` times out, or a renewal
  quietly does not happen. Nothing errors.

## Who approves what

Three approvers can be present at once, and each owns a different set of
signers:

| Approver | Owns | Configured by |
| --- | --- | --- |
| cert-manager's blanket approver | everything, until turned off | `--controllers=*,-certificaterequests-approver` on the controller |
| approver-policy | the signers in its `app.approveSignerNames`, gated by `CertificateRequestPolicy` + RBAC `use` | this chart's `approverPolicy` |
| csi-driver-spiffe's own approver | exactly its identity issuer, checking the requested SPIFFE URI is the requesting pod's own namespace and ServiceAccount | the driver's `app.approver.signerName` |

**approver-policy is never given the identity issuer.** Its signer name
must not appear in `approveSignerNames`, and the chart never renders a
policy for an issuer marked `identity: true` (and refuses a render that
names one, or a policy that allows a `spiffe:` URI). A policy cannot
express "the requester's own ServiceAccount"; only the driver's approver
can. If approver-policy also owned the signer it would either leave those
requests unapproved or approve any URI its policy allows, and the second
is the blanket approver again with extra steps. Two approvers on one
signer also race, and the loser silently skips.

Which approver decided a request is not evidence of anything. Both
approver-policy and csi-driver-spiffe **skip** a request that already
carries an Approved or Denied condition, so with the blanket approver on
they never evaluate it, and an "Approved" condition tells you nothing
about whether a policy would have approved it. That is why
`approvercheck` re-runs the evaluation itself.

## The policies

Enable the section next to the issuers it is written for:

```yaml
pki:
  issuers:
    - {name: example-private,  signPath: pki/sign/private,  role: example-private}
    - {name: example-identity, signPath: pki/sign/identity, role: example-identity, identity: true}
approverPolicy:
  enabled: true
  issuers:
    example-private:
      dnsNames: ["*.east.example.internal"]
  namespacedIssuers:
    enabled: true          # only if tenants mint their own Issuers
```

- **One exact policy per non-identity issuer**, named after it, selecting
  that issuer alone (a namespaced `Issuer` also by namespace). What is
  allowed comes from the issuer's entry under `approverPolicy.issuers`:
  `commonName`, `dnsNames`, `uris`, `ipAddresses`, `emailAddresses`,
  `usages`, each a glob (`*` only). `isCA` is always `false`.
- **Fail closed at render.** approver-policy denies any request field a
  policy does not name, so an issuer with no entry, or an entry naming no
  shape, fails the render instead of producing a policy that refuses
  everything. So does a certificate of this chart asking for a usage its
  issuer's policy does not list (it would be denied at its first renewal,
  not at install).
- **Keys.** `approverPolicy.defaults.privateKey` is ECDSA 256 to 384: P-384
  is the chart's default certificate key, and the leaf roles accept P-256
  too ([pki.md](pki.md#two-curves)), so a certificate that still asks for
  P-256 is not stranded mid-migration. Tighten to `minSize: 384` per issuer
  or in the defaults once nothing asks for P-256. RSA is refused.
  Durations default to 1h to 2160h.
- **Namespaced issuers.** `namespacedIssuers.enabled` renders ONE
  allow-all policy for every namespaced `Issuer`, in any namespace. A
  namespaced self-signed or CA `Issuer` confers no trust outside its own
  namespace: whoever can create it already holds its key, so approving its
  requests grants nothing they did not have. It exists because tenants
  (CI namespaces, above all) mint `Issuer`s under a fresh name each run,
  which no exact policy can name in advance. Never use it for an issuer
  backed by OpenBAO: the render refuses `kind: Issuer` entries in
  `pki.issuers` while it is on, since they would ride the allow-all policy
  and their own shape would never be enforced.
- **Policies for issuers outside `pki.issuers`.** A SelfSigned or CA
  `Issuer`, or a `ClusterIssuer` not backed by OpenBAO (a per-database CA,
  a bootstrap self-signer) has no entry in `pki.issuers`, so
  `approverPolicy.extraPolicies[]` names it directly. Each entry is written
  out as given: no `defaults`, no allow-all, and what it does not name is
  refused.

  ```yaml
  approverPolicy:
    extraPolicies:
      - name: example-db-ca
        issuerRef: {group: cert-manager.io, kind: Issuer, name: example-db-ca}
        selector:
          namespace: {matchNames: [example-db]}     # or matchLabels
        allowed:
          commonName: {value: "example-db-*", required: true}   # a commonName alone is enough
          # dnsNames / uris / ipAddresses / emailAddresses: {values: [...], required: false}
          isCA: false
          usages: [digital signature, key encipherment]
        constraints:
          privateKey: {algorithm: ECDSA, minSize: 256, maxSize: 384}
          maxDuration: 2160h
        syncWave: 32          # optional; annotations: {} and roleName: "" too
  ```

  `name`, `issuerRef` (all of `group`, `kind`, `name`) and an `allowed` that
  names a commonName, dnsNames, uris, ipAddresses or emailAddresses are
  required; a `spiffe:` URI is refused as everywhere else. Each entry gets
  its **own** `ClusterRole` and `ClusterRoleBinding` granting `use` on that
  policy alone, named `<roleName>-<name>` (`<release>-approver-use-<name>`
  by default; the entry's `roleName` overrides), bound to the same
  requesters as the shared role. With `syncWave` set the policy carries that
  Argo CD wave and its role and binding the wave before, so the grant exists
  before the policy does. `approverPolicy.enabled` may then be used with no
  `pki.issuers` at all. `approvercheck` evaluates these policies like any
  other. List the issuer's signer in approver-policy's
  `app.approveSignerNames` too.
- **RBAC.** A `ClusterRole` granting `use` on exactly these policies and a
  binding to whoever creates the requests: cert-manager's own
  ServiceAccount, for every `Certificate` (`approverPolicy.requesters`
  overrides). csi-driver-spiffe's requests come from a workload's own
  ServiceAccount and are approved by the driver, never through a policy,
  so they need no entry.

approver-policy itself is installed separately. List every rendered
policy's signer in its `app.approveSignerNames`, and nothing else:

```yaml
app:
  approveSignerNames:
    - clusterissuers.cert-manager.io/example-private
    - issuers.cert-manager.io/*          # only with namespacedIssuers
    # NOT clusterissuers.cert-manager.io/example-identity
```

A policy whose signer is not in that list can never fire.

## approvercheck

```
approvercheck --policies policies.yaml --requests crs.yaml
approvercheck --policies policies.yaml --live --context NAME \
  --identity-signer clusterissuers.cert-manager.io/example-identity \
  --require-blanket-approver-off
```

`policies.yaml` is the rendered chart (`helm template ... | tee`) or
`kubectl get certificaterequestpolicies -o yaml`. The evaluator is
approver-policy's own logic, ported (it lives under approver-policy's
`internal/` tree and cannot be imported), and fail-closed: a policy field
it does not evaluate, or a request field no policy names, is a failure,
never a pass. Outcomes per request: `approved`, `denied` (with every
candidate policy's violations), `unprocessed` (no policy selects it, or
the requester is not RBAC-bound), `skipped` (an `--identity-signer`),
`error`. Exit 0 only if nothing is denied, unprocessed or in error; 1
otherwise; 2 a usage or load error.

- **`--requests`** is offline and proves the selector and shape half. It
  cannot prove RBAC (there is no cluster to ask).
- **`--live`** lists every `CertificateRequest`, and for each candidate
  policy asks the API server, by a read-only `SubjectAccessReview`
  (nothing is persisted), whether the request's own requester may `use`
  it: the same call approver-policy makes. Needs `list` on
  `certificaterequests` and `namespaces` and `create` on
  `subjectaccessreviews`.
- **`--require-blanket-approver-off`** (with `--live`) also fails unless
  cert-manager's controller Deployment (`--cert-manager-namespace`,
  default `cert-manager`) runs with `--controllers=*,-certificaterequests-approver`.
  This is the check ADR 0002 promises: run it in CI or on a schedule
  wherever the SPIFFE approver is meant to be the only one.
- **`--identity-signer`** (repeatable) names signers csi-driver-spiffe
  owns; they are reported `skipped`. Without it a request to the identity
  issuer is `unprocessed`, which is correct: no policy approves it.

### The kubeconfig trap

`--kubeconfig` (default: the standard client-go rules) is used at its
**current-context**, which is whatever the last `kubectl config use-context`
left. A green `--live` run against the wrong cluster proves nothing about
the right one. Pass `--context NAME` whenever the file holds more than one
cluster; the run's first line states the context and server it actually
used, so read it.

### What a live run cannot see

`--live` sees only the requests that exist at that instant. Short-lived
tenants (a CI namespace that mints its own `Issuer`s under a fresh
release name) are invisible to it, so a cutover proven against live
requests alone can still leave every such install hanging with nothing
failing. Prove every request **shape** that can ever arrive: build the
`CertificateRequest`s those tenants would make (the package's
`Review` takes any `CertificateRequest`) and assert they are approved, in
a test. The same goes for subject fields: approver-policy denies an
`O=` or `C=` no policy names, so a leaf that carries one needs it listed.

## Cutover runbook

Order matters: the blanket approver goes off **last**, and only after the
proof.

1. **Install approver-policy beside the blanket approver**, with
   `approveSignerNames` listing every policy's signer and not the
   identity issuer. Install csi-driver-spiffe with its approver scoped to
   the identity issuer (below). Nothing changes yet: the blanket approver
   still answers first.
2. **Enable `approverPolicy`** and apply. The policies and RBAC exist
   but decide nothing while the blanket approver still wins.
3. **Renew everything**: `cmctl renew --all --all-namespaces`. Some
   renewals are won by the blanket approver, some by approver-policy (the
   race), which is why step 4 does not trust their conditions.
4. **Prove coverage**:
   `approvercheck --live --context <cluster> --policies <policies> --identity-signer <the identity signer>`
   must exit 0 with every request `approved` or `skipped`. Fix a `denied`
   by widening the issuer's entry (or the certificate), an `unprocessed`
   by the RBAC or by a missing policy, and re-run. Also prove the shapes a
   live run cannot see (previous section).
5. **Turn the blanket approver off**: cert-manager's
   `extraArgs: ["--controllers=*,-certificaterequests-approver"]`. Renew
   everything again and re-run step 4 with
   `--require-blanket-approver-off`.
6. **The refusal test, the actual proof.** As an account that may create
   `CertificateRequest`s in one namespace, create a request against the
   identity issuer whose URI names a **different** namespace or
   ServiceAccount. It must end `Denied` by the driver's approver
   (`unexpected SPIFFE ID requested`), with no `.status.certificate`.
   Then one for the right identity, which must be approved and issued.
   Never accept "certificates are issued" as evidence: with the blanket
   approver on they are, forgeries included. Only the refusal shows the
   attestation is real. Keep a namespace and ServiceAccount for it so it
   can be re-run after every change to the layer.

Rolling back is step 5 reversed; the policies stay. If a renewal hangs
after step 5, re-enable the blanket approver first and investigate second.

Two things the runbook depends on:

- csi-driver-spiffe creates its requests **as the pod's own
  ServiceAccount**, so that account needs `create` on
  `certificaterequests` in its namespace. Without it the pod is never
  created (`error looking up service account`).
- The driver decides only requests carrying its identity annotation
  (`spiffe.csi.cert-manager.io/identity`). Any other request to its issuer
  stays undecided and is never signed, which is what you want.

## csi-driver-spiffe values

The driver requests from an issuer this chart creates (`identity: true`)
and its approver is scoped to that one signer:

```yaml
app:
  trustDomain: east.example.internal        # the identity role's URI SAN domain
  issuer:
    name: example-identity                   # the pki.issuers entry with identity: true
    kind: ClusterIssuer
    group: cert-manager.io
  # A short life; the role's own maximum is the outer bound.
  certificateRequestDuration: 1h
  driver:
    # ca.crt in every SPIFFE volume: without it the volume has tls.crt and
    # tls.key but no ca.crt and an mTLS app cannot start. The file comes
    # from a ConfigMap holding the trust bundle (the chart's Bundle,
    # delivered into cert-manager's namespace) mounted into the driver.
    sourceCABundle: /etc/csi-spiffe-trust/ca.pem
    volumes:
      - name: identity-trust
        configMap:
          name: example-identity-ca
    volumeMounts:
      - name: identity-trust
        mountPath: /etc/csi-spiffe-trust
        readOnly: true
  approver:
    # Scopes the driver's OWN `signers` RBAC to this issuer alone.
    signerName: clusterissuers.cert-manager.io/example-identity
    # OFF. On, the driver's approver would gain approval authority over
    # every non-SPIFFE request in the cluster too.
    autoApproveNonSPIFFE: false
```

The driver always generates an ECDSA **P-256** key and has no option for
another. The identity role must therefore accept P-256 (a P-384 role
written by `pkg/apply` does, see [pki.md](pki.md#two-curves)); a role
that requires 384 refuses the driver's request with a 400 after the
approver has already approved it, which reads as a signing failure and
not a policy one.
