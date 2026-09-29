package conformance_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kubeconfigVariable names a kubeconfig of a THROWAWAY cluster (a kind
// cluster, Kubernetes 1.30 or later) the admission test may install a
// policy into and create namespaces in. It is deliberately not the
// ordinary KUBECONFIG: a test that writes to whatever the shell points at
// is a test that eventually writes to a real cluster. `just
// admission-conformance` creates the cluster, runs this test and deletes
// it. Unset, the test skips, even under OPENBAO_CONFORMANCE=required, since
// `just test` runs where there is no cluster; set
// OPENBAO_ADMISSION_CONFORMANCE=required to make an unset variable a
// failure.
const kubeconfigVariable = "OPENBAO_ADMISSION_KUBECONFIG"

const (
	enforcedNS = "enforced"
	freeNS     = "unlabelled"
	csiDriver  = "spiffe.csi.cert-manager.io"
)

// kubectl runs kubectl against the throwaway cluster, with stdin as given.
func kubectl(t *testing.T, kubeconfig, stdin string, args ...string) (string, error) {
	t.Helper()

	command := exec.Command("kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...)
	command.Stdin = strings.NewReader(stdin)

	var out bytes.Buffer
	command.Stdout, command.Stderr = &out, &out
	err := command.Run()

	return out.String(), err
}

// install renders the chart with the admission policy on (and whatever
// `set` adds) and applies it.
func installPolicy(t *testing.T, kubeconfig string, set ...string) {
	t.Helper()

	args := []string{"template", "admission", consumersChart, "--namespace", "default", "--set", "admissionPolicy.enabled=true"}
	for _, s := range set {
		args = append(args, "--set", s)
	}

	rendered, err := exec.Command(tool(t, "helm"), args...).CombinedOutput()
	require.NoError(t, err, string(rendered))

	out, err := kubectl(t, kubeconfig, string(rendered), "apply", "-f", "-")
	require.NoError(t, err, out)
}

// admit is what the API server said to one manifest, as a server-side dry
// run: it goes through every admission plugin and stores nothing.
func admit(t *testing.T, kubeconfig, namespace, manifest string) (string, bool) {
	t.Helper()

	out, err := kubectl(t, kubeconfig, manifest, "-n", namespace, "create", "--dry-run=server", "-f", "-")

	return out, err == nil
}

func pod(name string, extra string) string {
	return fmt.Sprintf("apiVersion: v1\nkind: Pod\nmetadata:\n  name: %s\n%sspec:\n", name, extra)
}

// compliantSpec is a pod spec that meets every pod rule.
func compliantSpec(indent string) string {
	spec := `serviceAccountName: app
containers:
  - name: app
    image: registry.example/app:1
    volumeMounts:
      - {name: identity, mountPath: /var/run/secrets/identity}
volumes:
  - name: identity
    csi: {driver: ` + csiDriver + `, readOnly: true}
`

	return indentBlock(spec, indent)
}

func indentBlock(s, indent string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = indent + lines[i]
	}

	return strings.Join(lines, "\n") + "\n"
}

func deployment(name, podMeta, podSpec string) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata: {name: %s}
spec:
  selector: {matchLabels: {app: %s}}
  template:
    metadata:
      labels: {app: %s}
%s    spec:
%s`, name, name, name, podMeta, podSpec)
}

func service(name, extra, ports string) string {
	return fmt.Sprintf("apiVersion: v1\nkind: Service\nmetadata:\n  name: %s\n%sspec:\n  selector: {app: x}\n%s", name, extra, ports)
}

// waitFor retries until the policy is enforcing: the API server compiles a
// new policy asynchronously, so the first request can race it.
func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}

		time.Sleep(time.Second)
	}
}

// TestAdmissionPolicy installs the rendered ValidatingAdmissionPolicy into
// a real API server and asserts what it admits and refuses: the rules'
// CEL is only proved by a server that compiles and runs it.
func TestAdmissionPolicy(t *testing.T) {
	kubeconfig := os.Getenv(kubeconfigVariable)
	if kubeconfig == "" {
		if os.Getenv("OPENBAO_ADMISSION_CONFORMANCE") == "required" {
			t.Fatalf("OPENBAO_ADMISSION_CONFORMANCE=required and no %s: run `just admission-conformance`", kubeconfigVariable)
		}

		t.Skipf("no %s (a throwaway cluster's kubeconfig): `just admission-conformance` creates a kind cluster and sets it", kubeconfigVariable)
	}

	tool(t, "kubectl")

	installPolicy(t, kubeconfig,
		"admissionPolicy.services.allow={allowed-svc,metrics-svc/metrics}",
		"admissionPolicy.csi.ignoreContainers={injected}")

	for _, ns := range []string{enforcedNS, freeNS} {
		out, err := kubectl(t, kubeconfig, "", "create", "namespace", ns)
		require.NoError(t, err, out)
	}

	out, err := kubectl(t, kubeconfig, "", "label", "namespace", enforcedNS, "mtls-level=enforced")
	require.NoError(t, err, out)

	out, err = kubectl(t, kubeconfig, "", "-n", enforcedNS, "create", "serviceaccount", "app")
	require.NoError(t, err, out)

	// The policy must have compiled with no type-check warning: a warning
	// is an expression that reads a field its kind does not have.
	waitFor(t, "the policy to type-check", func() bool {
		status, err := kubectl(t, kubeconfig, "", "get", "validatingadmissionpolicy", "admission-mtls-enforced", "-o", "jsonpath={.status.typeChecking}")

		return err == nil && strings.Contains(status, "{}")
	})

	// Each namespace needs its default ServiceAccount before a pod is
	// admitted at all.
	for _, ns := range []string{enforcedNS, freeNS} {
		waitFor(t, "the default ServiceAccount of "+ns, func() bool {
			_, err := kubectl(t, kubeconfig, "", "-n", ns, "get", "serviceaccount", "default")

			return err == nil
		})
	}

	waitFor(t, "the policy to enforce", func() bool {
		_, ok := admit(t, kubeconfig, enforcedNS, pod("probe", "")+"  containers: [{name: c, image: i}]\n")

		return !ok
	})

	type testCase struct {
		name      string
		namespace string
		manifest  string
		// refused: the substrings the refusal must carry; empty: admitted.
		refused []string
	}

	tlsPort := "  ports:\n    - {name: web, port: 443, appProtocol: https}\n"
	cases := []testCase{
		{name: "compliant pod", namespace: enforcedNS, manifest: pod("ok", "") + compliantSpec("  ")},
		{
			name: "pod with no identity volume", namespace: enforcedNS,
			manifest: pod("no-csi", "") + "  serviceAccountName: app\n  containers: [{name: app, image: i}]\n",
			refused:  []string{"Pod/no-csi in namespace " + enforcedNS, `container "app"`, csiDriver},
		},
		{
			name: "second container does not mount it", namespace: enforcedNS,
			manifest: "placeholder",
		},
		{
			name: "pod on the default ServiceAccount", namespace: enforcedNS,
			manifest: pod("default-sa", "") + strings.Replace(compliantSpec("  "), "  serviceAccountName: app\n", "", 1),
			refused:  []string{"default ServiceAccount", "one ServiceAccount per component"},
		},
		{
			name: "exempt with a reason", namespace: enforcedNS,
			manifest: pod("exempt", "  annotations: {mtls-exempt: \"node agent, no identity\"}\n") + "  containers: [{name: c, image: i}]\n",
		},
		{
			name: "exempt without a reason", namespace: enforcedNS,
			manifest: pod("empty-reason", "  annotations: {mtls-exempt: \"\"}\n") + "  containers: [{name: c, image: i}]\n",
			refused:  []string{"non-empty reason"},
		},
		{
			name: "injected container is ignored by name", namespace: enforcedNS,
			manifest: pod("injected", "") + strings.Replace(compliantSpec("  "), "containers:\n", "containers:\n    - {name: injected, image: proxy}\n", 1),
		},
		{name: "good Deployment", namespace: enforcedNS, manifest: deployment("good", "", compliantSpec("      "))},
		{
			name: "Deployment refused at apply time", namespace: enforcedNS,
			manifest: deployment("bad", "", "      containers: [{name: app, image: i}]\n"),
			refused:  []string{"Deployment/bad in namespace " + enforcedNS, `container "app"`},
		},
		{
			name: "Deployment on the default ServiceAccount", namespace: enforcedNS,
			manifest: deployment("bad-sa", "", strings.Replace(compliantSpec("      "), "      serviceAccountName: app\n", "", 1)),
			refused:  []string{"Deployment/bad-sa", "default ServiceAccount"},
		},
		{
			name: "exempt Deployment (annotation on the pod template)", namespace: enforcedNS,
			manifest: deployment("exempt-d", "      annotations: {mtls-exempt: \"legacy, tracked\"}\n", "      containers: [{name: app, image: i}]\n"),
		},
		{
			name: "CronJob refused", namespace: enforcedNS,
			manifest: `apiVersion: batch/v1
kind: CronJob
metadata: {name: bad-cron}
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers: [{name: job, image: i}]
`,
			refused: []string{"CronJob/bad-cron", `container "job"`},
		},
		{
			name: "compliant CronJob", namespace: enforcedNS,
			manifest: `apiVersion: batch/v1
kind: CronJob
metadata: {name: good-cron}
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
` + compliantSpec("          "),
		},
		{
			name: "Service with no appProtocol", namespace: enforcedNS,
			manifest: service("plain", "", "  ports:\n    - {name: web, port: 80}\n"),
			refused:  []string{"Service/plain", "port web", "no appProtocol", "https, tls, grpcs, kubernetes.io/wss"},
		},
		{
			name: "Service h2c is not TLS", namespace: enforcedNS,
			manifest: service("h2c", "", "  ports:\n    - {name: rpc, port: 80, appProtocol: kubernetes.io/h2c}\n"),
			refused:  []string{"port rpc", "appProtocol kubernetes.io/h2c"},
		},
		{
			name: "one plaintext port among TLS ports", namespace: enforcedNS,
			manifest: service("mixed", "", "  ports:\n    - {name: web, port: 443, appProtocol: https}\n    - {name: debug, port: 8080, appProtocol: http}\n"),
			refused:  []string{"port debug"},
		},
		{
			name: "Service with TLS ports", namespace: enforcedNS,
			manifest: service("tls", "", tlsPort+"    - {name: rpc, port: 444, appProtocol: GRPCS}\n    - {name: t, port: 445, appProtocol: tls}\n"),
		},
		{
			name: "gateway-fronted annotation", namespace: enforcedNS,
			manifest: service("fronted", "  annotations: {gateway-fronted: \"true\"}\n", "  ports:\n    - {name: web, port: 80}\n"),
		},
		{
			name: "gateway-fronted annotation is exactly true", namespace: enforcedNS,
			manifest: service("fronted-no", "  annotations: {gateway-fronted: \"yes\"}\n", "  ports:\n    - {name: web, port: 80}\n"),
			refused:  []string{"port web"},
		},
		{name: "Service on the allow list", namespace: enforcedNS, manifest: service("allowed-svc", "", "  ports:\n    - {name: web, port: 80}\n")},
		{name: "port on the allow list", namespace: enforcedNS, manifest: service("metrics-svc", "", tlsPort+"    - {name: metrics, port: 9090}\n")},
		{
			name: "another port of that Service is not", namespace: enforcedNS,
			manifest: service("metrics-svc", "", "  ports:\n    - {name: other, port: 9091}\n"),
			refused:  []string{"port other"},
		},
		{
			name: "exempt Service", namespace: enforcedNS,
			manifest: service("exempt-svc", "  annotations: {mtls-exempt: \"third-party client\"}\n", "  ports:\n    - {name: web, port: 80}\n"),
		},
		{
			name: "ExternalName Service", namespace: enforcedNS,
			manifest: "apiVersion: v1\nkind: Service\nmetadata: {name: ext}\nspec: {type: ExternalName, externalName: example.org}\n",
		},
		{
			name: "everything is allowed in a namespace without the label", namespace: freeNS,
			manifest: pod("free", "") + "  containers: [{name: c, image: i}]\n",
		},
		{name: "a plaintext Service is allowed there too", namespace: freeNS, manifest: service("free", "", "  ports:\n    - {port: 80}\n")},
	}

	// A pod cannot repeat the containers key: build the second-container
	// case directly.
	for i := range cases {
		if cases[i].name == "second container does not mount it" {
			cases[i].manifest = pod("second", "") + strings.Replace(compliantSpec("  "), "containers:\n", "containers:\n    - {name: sidecar, image: i}\n", 1)
			cases[i].refused = []string{`container "sidecar"`}
		}
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, ok := admit(t, kubeconfig, c.namespace, c.manifest)
			if len(c.refused) == 0 {
				assert.True(t, ok, out)
				assert.NotContains(t, out, "Warning")

				return
			}

			require.False(t, ok, "admitted, should have been refused: %s", out)
			assert.Contains(t, out, "denied request")

			for _, want := range c.refused {
				assert.Contains(t, out, want)
			}
		})
	}

	t.Run("dry run warns and admits", func(t *testing.T) {
		installPolicy(t, kubeconfig, "admissionPolicy.validationActions={Warn,Audit}")

		bad := pod("dry", "") + "  containers: [{name: app, image: i}]\n"

		waitFor(t, "the binding to switch to warn", func() bool {
			out, ok := admit(t, kubeconfig, enforcedNS, bad)

			return ok && strings.Contains(out, "Warning")
		})

		out, ok := admit(t, kubeconfig, enforcedNS, bad)
		assert.True(t, ok, out)
		assert.Contains(t, out, `container "app"`)
		assert.Contains(t, out, "default ServiceAccount")
	})

	t.Run("an object made before the flip keeps working until its own rules change", func(t *testing.T) {
		// Still in warn mode: create a plaintext Service, as one from before
		// the label existed would be, then turn the policy on.
		out, err := kubectl(t, kubeconfig, service("legacy", "", "  ports:\n    - {name: web, port: 80}\n"), "-n", enforcedNS, "create", "-f", "-")
		require.NoError(t, err, out)

		installPolicy(t, kubeconfig, "admissionPolicy.validationActions={Deny}")
		waitFor(t, "the binding to switch back to deny", func() bool {
			_, ok := admit(t, kubeconfig, enforcedNS, pod("probe2", "")+"  containers: [{name: c, image: i}]\n")

			return !ok
		})

		// An edit that changes nothing the rules read is not refused ...
		out, err = kubectl(t, kubeconfig, "", "-n", enforcedNS, "label", "service", "legacy", "team=x")
		assert.NoError(t, err, out)

		// ... a change to the ports is judged ...
		out, err = kubectl(t, kubeconfig, "", "-n", enforcedNS, "patch", "service", "legacy", "--type=json",
			"-p", `[{"op":"replace","path":"/spec/ports/0/port","value":81}]`)
		assert.Error(t, err, out)
		assert.Contains(t, out, "port web")

		// ... and so is dropping the way out.
		out, err = kubectl(t, kubeconfig, "", "-n", enforcedNS, "annotate", "service", "legacy", "gateway-fronted=true")
		assert.NoError(t, err, out)
		out, err = kubectl(t, kubeconfig, "", "-n", enforcedNS, "annotate", "service", "legacy", "gateway-fronted-")
		assert.Error(t, err, out)

		// A terminating object is never refused: deleting it must work.
		out, err = kubectl(t, kubeconfig, "", "-n", enforcedNS, "delete", "service", "legacy")
		assert.NoError(t, err, out)
	})
}
