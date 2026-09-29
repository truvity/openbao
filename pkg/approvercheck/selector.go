package approvercheck

import (
	"context"
	"fmt"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// selectorMatches ports pkg/internal/approver/manager/predicate's
// SelectorIssuerRef and SelectorNamespace (v0.28.0) into one call: whether
// policy's selector applies to cr at all, before either evaluator runs. A
// nil client is fine as long as the policy sets no matchLabels (the common
// case for every policy the chart renders) -- namespace label lookups only
// happen when a policy actually asks for one.
func selectorMatches(ctx context.Context, client kubernetes.Interface, policy *policyapi.CertificateRequestPolicy, cr *cmapi.CertificateRequest) (bool, error) {
	if !selectorIssuerRefMatches(policy, cr) {
		return false, nil
	}

	return selectorNamespaceMatches(ctx, client, policy, cr)
}

func selectorIssuerRefMatches(policy *policyapi.CertificateRequestPolicy, cr *cmapi.CertificateRequest) bool {
	sel := policy.Spec.Selector.IssuerRef
	if sel == nil {
		return true
	}

	// cert-manager's webhook defaults issuerRef.kind to "Issuer" and
	// .group to "cert-manager.io" when the request omits them, so the
	// selector must compare against the SAME defaulted values
	// approver-policy's predicate does, not the raw (possibly empty)
	// request fields.
	kind := nonEmptyOrDefault(cr.Spec.IssuerRef.Kind, cmapi.IssuerKind)
	group := nonEmptyOrDefault(cr.Spec.IssuerRef.Group, "cert-manager.io")
	name := cr.Spec.IssuerRef.Name

	if sel.Name != nil && !wildcardMatches(*sel.Name, name) {
		return false
	}
	if sel.Kind != nil && !wildcardMatches(*sel.Kind, kind) {
		return false
	}
	if sel.Group != nil && !wildcardMatches(*sel.Group, group) {
		return false
	}

	return true
}

func selectorNamespaceMatches(
	ctx context.Context,
	client kubernetes.Interface,
	policy *policyapi.CertificateRequestPolicy,
	cr *cmapi.CertificateRequest,
) (bool, error) {
	sel := policy.Spec.Selector.Namespace
	if sel == nil {
		return true, nil
	}

	matched := len(sel.MatchNames) == 0
	for _, pattern := range sel.MatchNames {
		if wildcardMatches(pattern, cr.Namespace) {
			matched = true
			break
		}
	}
	if !matched {
		return false, nil
	}

	if sel.MatchLabels == nil {
		return true, nil
	}

	if client == nil {
		return false, fmt.Errorf("policy %q selects on namespace labels but no live client is available to read them", policy.Name)
	}

	ns, err := client.CoreV1().Namespaces().Get(ctx, cr.Namespace, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("get namespace %s: %w", cr.Namespace, err)
	}

	selector, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: sel.MatchLabels})
	if err != nil {
		return false, fmt.Errorf("policy %q namespace.matchLabels: %w", policy.Name, err)
	}

	return selector.Matches(labels.Set(ns.Labels)), nil
}

func nonEmptyOrDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
