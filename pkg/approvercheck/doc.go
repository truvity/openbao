// Package approvercheck is an offline port of cert-manager approver-policy's
// evaluator: it answers, for a set of CertificateRequests and a set of
// CertificateRequestPolicy objects, whether some policy would approve each
// request -- independent of which approver happened to decide it first.
//
// # Why this exists (the race)
//
// While approver-policy, csi-driver-spiffe's own approver and cert-manager's
// built-in blanket approver are all active on one cluster, whichever
// approves a CertificateRequest first wins, and the blanket approver is
// fast. Both approver-policy and csi-driver-spiffe SKIP any
// CertificateRequest that already carries an Approved or Denied condition:
// they never evaluate it, so no event and no record of policy coverage
// exists for a request the blanket approver decided. An "Approved"
// condition therefore proves nothing about whether approver-policy WOULD
// have approved it; the only way to know is to run its evaluation logic
// against every request. That is this package, and it is the proof the
// blanket approver can be switched off without stranding a renewal.
//
// # Why a reimplementation
//
// approver-policy's selector matching and evaluators live under its own
// pkg/internal/ tree. Go enforces the internal/ import boundary on the
// import path alone, so nothing outside approver-policy can import them,
// and no public package exposes the same logic (pkg/approver only defines
// the plugin interface). This package therefore ports, from
// approver-policy v0.28.0:
//
//   - wildcard.go: pkg/internal/util/wildcard.go, the glob every
//     comparison uses;
//   - selector.go: the SelectorIssuerRef and SelectorNamespace predicates;
//   - allowed.go: the allowed evaluator (commonName, dnsNames, uris,
//     ipAddresses, emailAddresses, isCA, usages, and the named subject
//     fields);
//   - constraints.go: the constraints evaluator, in full;
//   - rbac.go: the RBACBound predicate, as the same read-only
//     SubjectAccessReview the real controller issues.
//
// Fields the port does not evaluate (allowed.otherNames,
// allowed.subject.otherAttributes, CEL validations) make Review return an
// error outcome rather than a silent pass, and the REQUEST side of the
// unnamed fields is ported fail-closed: approver-policy denies any
// request field its policy does not name, and so does this package. A
// ported evaluator must never approve what the original would refuse.
//
// # What a run cannot see
//
// A live run sees only the CertificateRequests that exist at that
// instant. Short-lived tenants (CI namespaces that mint their own Issuers
// under a fresh name each run) are invisible to it, so a cutover proven
// against live requests alone can still strand them. Prove every request
// SHAPE that can ever arrive: feed the shapes of those tenants through
// Review as fixtures, in a test.
package approvercheck
