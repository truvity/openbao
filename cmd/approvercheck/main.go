// Command approvercheck proves whether a set of cert-manager
// CertificateRequestPolicy objects actually covers a set of
// CertificateRequests -- the check that the blanket approver can be turned
// off without stranding a renewal, and that the approver layer for
// OpenBAO-issued certificates is in place.
//
// Whichever of cert-manager's blanket approver, approver-policy and
// csi-driver-spiffe's own approver decides a CertificateRequest first wins,
// and the losers never evaluate it, so an "Approved" condition alone proves
// nothing about policy coverage. This tool runs the same selector-matching
// and evaluator logic approver-policy's controller runs (see package
// approvercheck) so its verdict is independent of who decided.
//
// Two modes:
//
//	approvercheck --policies policies.yaml --requests crs.yaml
//	approvercheck --policies policies.yaml --certificates certs.yaml
//	approvercheck --policies policies.yaml --live [--context NAME]
//
// The first two are offline and check the selector and shape half; the
// second builds the requests cert-manager would make for a rendered set of
// Certificates, so a tenant that does not exist yet is proven too.
// --policies may be given more than once, for a set rendered in pieces.
// --live lists
// the cluster's CertificateRequests and additionally proves the RBAC half
// with one read-only SubjectAccessReview per candidate policy per request.
//
// Exit status: 0 every request is approved by some policy (or skipped as
// an identity signer), 1 at least one is not, 2 a usage or load error.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/truvity/secrets/pkg/approvercheck"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Version is stamped by the release.
var Version = "dev"

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approvercheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var policyPaths stringList
	fs.Var(&policyPaths, "policies", "YAML/JSON file with one or more CertificateRequestPolicy objects, e.g. the rendered openbao-consumers chart. "+
		"Repeatable: the policies of every file are checked together (a file with none is tolerated if another has some)")
	requestsPath := fs.String("requests", "", "YAML/JSON file with a CertificateRequestList (kubectl get certificaterequests -A -o yaml > file)")
	certificatesPath := fs.String("certificates", "", "YAML/JSON file with cert-manager Certificates "+
		"(e.g. `helm template ... --show-only templates/certificates.yaml`): "+
		"checks the CertificateRequest cert-manager would create for each, offline. May be combined with --requests")
	namespace := fs.String("namespace", "", "with --certificates, the namespace the requests are made in, replacing the Certificates' own")
	live := fs.Bool("live", false, "list live CertificateRequests and check the RBAC binding live instead of --requests (read-only)")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig path; defaults to the standard client-go loading rules. Used at its CURRENT-CONTEXT: see --context")
	kubeContext := fs.String("context", "", "kubeconfig context to use instead of the current-context. Pass it whenever the kubeconfig holds more than one "+
		"cluster: the current-context is whatever the last `kubectl config use-context` left, and a green run against "+
		"the wrong cluster proves nothing")
	requireBlanketOff := fs.Bool("require-blanket-approver-off", false, "with --live, also fail unless cert-manager's controller runs with "+
		"--controllers=*,-certificaterequests-approver")
	certManagerNS := fs.String("cert-manager-namespace", "cert-manager", "namespace of cert-manager's controller, for --require-blanket-approver-off")
	version := fs.Bool("version", false, "print the version and exit")
	var identitySigners stringList
	fs.Var(&identitySigners, "identity-signer", "signer name (e.g. clusterissuers.cert-manager.io/<name>) whose requests csi-driver-spiffe's own approver owns; "+
		"reported skipped, never evaluated. Repeatable")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *version {
		logf(stdout, "approvercheck %s", Version)
		return 0
	}

	if len(policyPaths) == 0 {
		logf(stderr, "approvercheck: --policies is required")
		return 2
	}
	offline := *requestsPath != "" || *certificatesPath != ""
	if !*live && !offline {
		logf(stderr, "approvercheck: one of --requests, --certificates or --live is required")
		return 2
	}
	if *live && offline {
		logf(stderr, "approvercheck: --live is an alternative to --requests and --certificates")
		return 2
	}
	if *namespace != "" && *certificatesPath == "" {
		logf(stderr, "approvercheck: --namespace needs --certificates")
		return 2
	}
	if !*live && (*requireBlanketOff || *kubeContext != "") {
		logf(stderr, "approvercheck: --require-blanket-approver-off and --context need --live")
		return 2
	}

	policies, err := approvercheck.LoadPolicyFiles(policyPaths...)
	if err != nil {
		logf(stderr, "approvercheck: load policies: %v", err)
		return 2
	}

	var clientset kubernetes.Interface
	var dynClient dynamic.Interface
	if *live || approvercheck.HasNamespaceLabelSelector(policies) {
		var target string
		clientset, dynClient, target, err = buildClients(*kubeconfig, *kubeContext)
		if err != nil {
			logf(stderr, "approvercheck: build kube client: %v", err)
			return 2
		}
		logf(stdout, "approvercheck: cluster %s", target)
	}

	var requests []cmapi.CertificateRequest
	if *live {
		requests, err = approvercheck.ListLiveCertificateRequests(ctx, dynClient)
	} else {
		requests, err = loadOffline(*requestsPath, *certificatesPath, *namespace)
	}
	if err != nil {
		logf(stderr, "approvercheck: load CertificateRequests: %v", err)
		return 2
	}

	logf(stdout, "approvercheck: %d policies, %d CertificateRequests", len(policies), len(requests))

	opts := approvercheck.Options{RequireRBAC: *live, SkipSigners: identitySigners}
	counts := map[string]int{}
	failed := false
	for i := range requests {
		res := approvercheck.Review(ctx, clientset, policies, &requests[i], opts)
		counts[res.Outcome]++
		failed = failed || res.Failed()
		logf(stdout, "%s", res.String())
	}

	logf(stdout, "---")
	for _, outcome := range []string{
		approvercheck.OutcomeApproved, approvercheck.OutcomeDenied, approvercheck.OutcomeUnprocessed,
		approvercheck.OutcomeSkipped, approvercheck.OutcomeError,
	} {
		if counts[outcome] > 0 {
			logf(stdout, "%s: %d", outcome, counts[outcome])
		}
	}

	if *requireBlanketOff {
		if err := approvercheck.CheckBlanketApproverOff(ctx, clientset, *certManagerNS); err != nil {
			logf(stdout, "FAIL: blanket approver: %v", err)
			failed = true
		} else {
			logf(stdout, "blanket approver: off")
		}
	}

	if failed {
		logf(stdout, "FAIL: a check above did not pass (a CertificateRequest with no approving policy, or the blanket approver still on)")
		return 1
	}

	logf(stdout, "OK: every CertificateRequest is approved by some policy (or skipped as an identity signer)")
	return 0
}

// loadOffline reads the requests of --requests and the requests built from
// --certificates, in that order.
func loadOffline(requestsPath, certificatesPath, namespace string) ([]cmapi.CertificateRequest, error) {
	var requests []cmapi.CertificateRequest
	if requestsPath != "" {
		loaded, err := approvercheck.LoadCertificateRequests(requestsPath)
		if err != nil {
			return nil, err
		}
		requests = loaded
	}
	if certificatesPath != "" {
		certs, err := approvercheck.LoadCertificates(certificatesPath)
		if err != nil {
			return nil, err
		}
		built, err := approvercheck.RequestsForCertificates(certs, namespace)
		if err != nil {
			return nil, err
		}
		requests = append(requests, built...)
	}

	return requests, nil
}

// logf writes a formatted line to w, ignoring the write error: w is
// always os.Stdout/os.Stderr (or a test's io.Writer), and a CLI has
// nowhere useful to report a failed write to its own output to.
func logf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format+"\n", args...)
}

// buildClients loads the kubeconfig at its current-context unless
// kubeContext names another, and reports which context and server it
// resolved so a run's output says which cluster it checked.
func buildClients(kubeconfigPath, kubeContext string) (clientset kubernetes.Interface, dynClient dynamic.Interface, target string, err error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: kubeContext}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)

	raw, err := cc.RawConfig()
	if err != nil {
		return nil, nil, "", fmt.Errorf("load kubeconfig: %w", err)
	}
	name := raw.CurrentContext
	if kubeContext != "" {
		name = kubeContext
		if _, ok := raw.Contexts[kubeContext]; !ok {
			return nil, nil, "", fmt.Errorf("kubeconfig has no context %q", kubeContext)
		}
	}

	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, nil, "", fmt.Errorf("load kubeconfig: %w", err)
	}
	target = fmt.Sprintf("context %q, server %s", name, cfg.Host)

	clientset, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, "", err
	}
	dynClient, err = dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, "", err
	}

	return clientset, dynClient, target, nil
}
