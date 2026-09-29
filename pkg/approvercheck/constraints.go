package approvercheck

import (
	"fmt"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// evaluateConstraints ports pkg/internal/approver/constraints's Evaluate
// (v0.28.0) in full -- minDuration, maxDuration, privateKey.{algorithm,
// minSize,maxSize} are the whole of that evaluator, so there is nothing
// left unported here (unlike allowed.go).
func evaluateConstraints(policy *policyapi.CertificateRequestPolicy, cr *cmapi.CertificateRequest) ([]string, error) {
	consts := policy.Spec.Constraints
	if consts == nil {
		return nil, nil
	}

	var violations []string

	if consts.MaxDuration != nil {
		if cr.Spec.Duration == nil {
			violations = append(violations, fmt.Sprintf("maxDuration: request sets no duration, policy requires <= %s", consts.MaxDuration.Duration))
		} else if consts.MaxDuration.Duration < cr.Spec.Duration.Duration {
			violations = append(violations, fmt.Sprintf("maxDuration: requested %s exceeds policy's %s", cr.Spec.Duration.Duration, consts.MaxDuration.Duration))
		}
	}

	if consts.MinDuration != nil {
		if cr.Spec.Duration == nil {
			violations = append(violations, fmt.Sprintf("minDuration: request sets no duration, policy requires >= %s", consts.MinDuration.Duration))
		} else if consts.MinDuration.Duration > cr.Spec.Duration.Duration {
			violations = append(violations, fmt.Sprintf("minDuration: requested %s is below policy's %s", cr.Spec.Duration.Duration, consts.MinDuration.Duration))
		}
	}

	if consts.PrivateKey != nil {
		csr, err := decodeCSR(cr.Spec.Request)
		if err != nil {
			return nil, err
		}

		alg, size, err := publicKeyAlgorithmAndSize(csr.PublicKey)
		if err != nil {
			return nil, err
		}

		if consts.PrivateKey.Algorithm != nil && *consts.PrivateKey.Algorithm != alg {
			violations = append(violations, fmt.Sprintf("privateKey.algorithm: requested %s, policy requires %s", alg, *consts.PrivateKey.Algorithm))
		}
		if consts.PrivateKey.MaxSize != nil && *consts.PrivateKey.MaxSize < size {
			violations = append(violations, fmt.Sprintf("privateKey.maxSize: requested key size %d exceeds policy's %d", size, *consts.PrivateKey.MaxSize))
		}
		if consts.PrivateKey.MinSize != nil && *consts.PrivateKey.MinSize > size {
			violations = append(violations, fmt.Sprintf("privateKey.minSize: requested key size %d is below policy's %d", size, *consts.PrivateKey.MinSize))
		}
	}

	return violations, nil
}
