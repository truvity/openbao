package approvercheck

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// blanketApprover is the name of cert-manager's built-in controller that
// approves EVERY CertificateRequest for an issuer it knows.
const blanketApprover = "certificaterequests-approver"

// BlanketApproverOff reports whether a cert-manager controller's command
// line turns the built-in blanket approver off. The flag is
// `--controllers=*,-certificaterequests-approver` (the Helm chart's
// `extraArgs`): a `-name` entry removes a controller from the default set,
// and a list with no `*` runs only what it names. Absent the flag the
// approver is ON, which is the default.
func BlanketApproverOff(args []string) bool {
	for _, raw := range args {
		list, ok := strings.CutPrefix(raw, "--controllers=")
		if !ok {
			continue
		}
		entries := strings.Split(list, ",")
		hasStar, named := false, false
		for _, e := range entries {
			switch strings.TrimSpace(e) {
			case "-" + blanketApprover:
				return true
			case "*":
				hasStar = true
			case blanketApprover:
				named = true
			}
		}
		if !hasStar && !named {
			return true
		}
	}
	return false
}

// CheckBlanketApproverOff asserts, live, that cert-manager's controller in
// namespace runs with the blanket approver off. The proof of a cutover is a
// REFUSAL, not an issued certificate (a healthy cluster with the blanket
// approver on looks identical); this is the cheap half that catches the
// flag being reverted. It looks at every Deployment in namespace labelled
// app.kubernetes.io/name=cert-manager, app.kubernetes.io/component=controller
// and returns an error naming the one that still has the approver on, or if
// none is found (a check that inspected nothing must not pass).
func CheckBlanketApproverOff(ctx context.Context, client kubernetes.Interface, namespace string) error {
	list, err := client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=cert-manager,app.kubernetes.io/component=controller",
	})
	if err != nil {
		return fmt.Errorf("list cert-manager controller deployments in %q: %w", namespace, err)
	}
	if len(list.Items) == 0 {
		return fmt.Errorf("no cert-manager controller Deployment (labels app.kubernetes.io/name=cert-manager, "+
			"app.kubernetes.io/component=controller) in namespace %q", namespace)
	}
	for i := range list.Items {
		if !deploymentHasBlanketApproverOff(&list.Items[i]) {
			return fmt.Errorf("deployment %s/%s still runs cert-manager's blanket approver: add --controllers=*,-%s", namespace, list.Items[i].Name, blanketApprover)
		}
	}
	return nil
}

func deploymentHasBlanketApproverOff(d *appsv1.Deployment) bool {
	for i := range d.Spec.Template.Spec.Containers {
		c := &d.Spec.Template.Spec.Containers[i]
		if BlanketApproverOff(append(append([]string{}, c.Command...), c.Args...)) {
			return true
		}
	}
	return false
}
