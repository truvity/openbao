package approvercheck

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/client-go/kubernetes"
)

// The outcomes a Result reports.
const (
	OutcomeApproved    = "approved"
	OutcomeDenied      = "denied"
	OutcomeUnprocessed = "unprocessed"
	OutcomeSkipped     = "skipped"
	OutcomeError       = "error"
)

type (
	// Result is one CertificateRequest's outcome.
	Result struct {
		Namespace string
		Name      string
		Issuer    string // the signer name, see SignerName
		Outcome   string // one of the Outcome* constants
		Detail    string // the approving policy, or why it was denied/errored
	}

	// Options tunes Review.
	Options struct {
		// RequireRBAC also asks the API server, per candidate policy,
		// whether the request's own requester may `use` it. Needs a live
		// client; without it a policy file alone cannot answer whether the
		// RBAC binding is right.
		RequireRBAC bool
		// SkipSigners are signer names (see SignerName) whose requests a
		// different approver owns and approver-policy is never consulted
		// for -- csi-driver-spiffe's SPIFFE identity issuer above all.
		// They are reported skipped, never evaluated.
		SkipSigners []string
	}
)

// Failed reports whether the outcome means a request would not be approved.
func (r Result) Failed() bool {
	return r.Outcome == OutcomeDenied || r.Outcome == OutcomeUnprocessed || r.Outcome == OutcomeError
}

func (r Result) String() string {
	return fmt.Sprintf("%-11s %-45s issuer=%-45s %s", r.Outcome, r.Namespace+"/"+r.Name, r.Issuer, r.Detail)
}

// Review ports pkg/internal/approver/manager/review.go's Review()
// (v0.28.0) for one CertificateRequest against the given candidate
// policies: filter by selector, filter by RBAC binding (live client
// required), then run both evaluators against everything left. Approved on
// the first policy that raises no violation; Denied with every candidate
// policy's violations if none does; Unprocessed if no policy's selector
// even matched.
func Review(
	ctx context.Context,
	client kubernetes.Interface,
	policies []policyapi.CertificateRequestPolicy,
	cr *cmapi.CertificateRequest,
	opts Options,
) Result {
	res := Result{Namespace: cr.Namespace, Name: cr.Name, Issuer: SignerName(cr)}

	for _, skip := range opts.SkipSigners {
		if res.Issuer == skip {
			res.Outcome = OutcomeSkipped
			res.Detail = "another approver owns this signer (csi-driver-spiffe's, for an identity issuer), not approver-policy"
			return res
		}
	}

	var selected []policyapi.CertificateRequestPolicy
	for i := range policies {
		matched, err := selectorMatches(ctx, client, &policies[i], cr)
		if err != nil {
			res.Outcome = OutcomeError
			res.Detail = err.Error()
			return res
		}
		if matched {
			selected = append(selected, policies[i])
		}
	}

	if len(selected) == 0 {
		res.Outcome = OutcomeUnprocessed
		res.Detail = "no CertificateRequestPolicy selector matches this issuerRef/namespace"
		return res
	}

	if opts.RequireRBAC {
		var bound []policyapi.CertificateRequestPolicy
		for i := range selected {
			ok, err := rbacBound(ctx, client, &selected[i], cr)
			if err != nil {
				res.Outcome = OutcomeError
				res.Detail = err.Error()
				return res
			}
			if ok {
				bound = append(bound, selected[i])
			}
		}
		selected = bound
		if len(selected) == 0 {
			res.Outcome = OutcomeUnprocessed
			res.Detail = "selector matched but the requester (spec.username) is not RBAC-bound (`use`) to any matching policy"
			return res
		}
	}

	type failure struct {
		policy     string
		violations []string
	}
	var failures []failure

	for i := range selected {
		policy := &selected[i]

		allowedViolations, err := evaluateAllowed(policy, cr)
		if err != nil {
			res.Outcome = OutcomeError
			res.Detail = fmt.Sprintf("policy %q: %v", policy.Name, err)
			return res
		}

		constraintsViolations, err := evaluateConstraints(policy, cr)
		if err != nil {
			res.Outcome = OutcomeError
			res.Detail = fmt.Sprintf("policy %q: %v", policy.Name, err)
			return res
		}

		violations := slices.Concat(allowedViolations, constraintsViolations)
		if len(violations) == 0 {
			res.Outcome = OutcomeApproved
			res.Detail = fmt.Sprintf("policy %q", policy.Name)
			return res
		}

		failures = append(failures, failure{policy: policy.Name, violations: violations})
	}

	sort.Slice(failures, func(i, j int) bool { return failures[i].policy < failures[j].policy })
	var parts []string
	for _, f := range failures {
		parts = append(parts, fmt.Sprintf("[%s: %s]", f.policy, strings.Join(f.violations, "; ")))
	}
	res.Outcome = OutcomeDenied
	res.Detail = strings.Join(parts, " ")

	return res
}

// SignerName is the fully-qualified signer string approver-policy's own
// approveSignerNames/RBAC scoping uses:
// "<plural-resource>.<group>/<name>" for the request's issuerRef, with
// cert-manager's defaulted kind/group applied the same way selectorMatches
// does. A ClusterIssuer named "example" is
// "clusterissuers.cert-manager.io/example"; a namespaced Issuer is
// "issuers.cert-manager.io/example".
func SignerName(cr *cmapi.CertificateRequest) string {
	kind := nonEmptyOrDefault(cr.Spec.IssuerRef.Kind, cmapi.IssuerKind)
	group := nonEmptyOrDefault(cr.Spec.IssuerRef.Group, "cert-manager.io")

	plural := "issuers"
	if kind == "ClusterIssuer" {
		plural = "clusterissuers"
	}

	return fmt.Sprintf("%s.%s/%s", plural, group, cr.Spec.IssuerRef.Name)
}
