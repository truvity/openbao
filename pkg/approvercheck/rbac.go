package approvercheck

import (
	"context"
	"fmt"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// rbacBound ports pkg/internal/approver/manager/predicate's RBACBound
// (v0.28.0): a live, read-only SubjectAccessReview asking whether the
// CR's own requester (spec.username/groups/uid/extra -- the identity
// cert-manager's webhook recorded at creation, not this tool's own
// identity) is allowed the `use` verb on this CertificateRequestPolicy.
// This is the SAME check and the SAME API call approver-policy's real
// controller makes; a SubjectAccessReview is non-mutating (nothing is
// created or persisted), so this is safe under read-only access.
//
// Requires a live client -- there is no way to answer "is this RBAC
// binding correct" from a policy file alone.
func rbacBound(ctx context.Context, client kubernetes.Interface, policy *policyapi.CertificateRequestPolicy, cr *cmapi.CertificateRequest) (bool, error) {
	if client == nil {
		return false, fmt.Errorf("policy %q: RBAC binding can only be checked with a live client (--live)", policy.Name)
	}

	extra := make(map[string]authzv1.ExtraValue, len(cr.Spec.Extra))
	for k, v := range cr.Spec.Extra {
		extra[k] = authzv1.ExtraValue(v)
	}

	review := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   cr.Spec.Username,
			Groups: cr.Spec.Groups,
			Extra:  extra,
			UID:    cr.Spec.UID,
			ResourceAttributes: &authzv1.ResourceAttributes{
				Group:     "policy.cert-manager.io",
				Resource:  "certificaterequestpolicies",
				Name:      policy.Name,
				Namespace: cr.Namespace,
				Verb:      "use",
			},
		},
	}

	result, err := client.AuthorizationV1().SubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("SubjectAccessReview for policy %q: %w", policy.Name, err)
	}

	return result.Status.Allowed, nil
}
