package conformance_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// esoCRDs is the External Secrets CRD bundle the AWS policy is proved
// against: the real schemas, so an expression that reads a field the way
// the API server does not is a failure here. OPENBAO_ESO_CRDS overrides it
// with a path or URL (offline, or another release).
const esoCRDs = "https://raw.githubusercontent.com/external-secrets/external-secrets/v2.12.0/deploy/crds/bundle.yaml"

const awsPolicyValues = `aws:
  identity: podIdentity
awsStores:
  - name: example-app-config
    region: eu-example-1
    role: arn:aws:iam::444455556666:role/a-app-config
    conditions:
      - namespaces: [tenant]
`

// TestAdmissionPolicyAWS proves the AWS store policy of openbao-consumers
// (aws.admissionPolicy, on by default in podIdentity mode) on a real API
// server: what borrows the External Secrets controller's AWS identity is
// refused, and what names its own auth, or is not on AWS, or is one of the
// release's stores, is admitted. Same throwaway cluster as
// TestAdmissionPolicy; `just admission-conformance` runs both.
func TestAdmissionPolicyAWS(t *testing.T) {
	kubeconfig := os.Getenv(kubeconfigVariable)
	if kubeconfig == "" {
		if os.Getenv("OPENBAO_ADMISSION_CONFORMANCE") == "required" {
			t.Fatalf("OPENBAO_ADMISSION_CONFORMANCE=required and no %s: run `just admission-conformance`", kubeconfigVariable)
		}

		t.Skipf("no %s (a throwaway cluster's kubeconfig): `just admission-conformance` creates a kind cluster and sets it", kubeconfigVariable)
	}

	tool(t, "kubectl")

	crds := os.Getenv("OPENBAO_ESO_CRDS")
	if crds == "" {
		crds = esoCRDs
	}

	// Server-side: the bundle's annotations are too large for a client-side
	// apply's last-applied annotation.
	out, err := kubectl(t, kubeconfig, "", "apply", "--server-side", "-f", crds)
	require.NoError(t, err, out)

	out, err = kubectl(t, kubeconfig, "", "wait", "--for=condition=Established", "--timeout=120s",
		"crd/secretstores.external-secrets.io", "crd/clustersecretstores.external-secrets.io",
		"crd/ecrauthorizationtokens.generators.external-secrets.io", "crd/stssessiontokens.generators.external-secrets.io")
	require.NoError(t, err, out)

	values := filepath.Join(t.TempDir(), "values.yaml")
	require.NoError(t, os.WriteFile(values, []byte(awsPolicyValues), 0o600))

	rendered, err := exec.Command(tool(t, "helm"), "template", "aws", consumersChart, "--namespace", "default",
		"-f", values, "--show-only", "templates/aws-admission.yaml").CombinedOutput()
	require.NoError(t, err, string(rendered))
	require.Contains(t, string(rendered), "kind: ValidatingAdmissionPolicy", "the policy is on by default in podIdentity mode")

	out, err = kubectl(t, kubeconfig, string(rendered), "apply", "-f", "-")
	require.NoError(t, err, out)

	out, err = kubectl(t, kubeconfig, "", "create", "namespace", "tenant")
	require.NoError(t, err, out)

	waitFor(t, "the AWS policy to type-check", func() bool {
		status, err := kubectl(t, kubeconfig, "", "get", "validatingadmissionpolicy", "aws-aws-stores", "-o", "jsonpath={.status.typeChecking}")

		return err == nil && strings.Contains(status, "{}")
	})

	awsStore := func(kind, name, auth string) string {
		return "apiVersion: external-secrets.io/v1\nkind: " + kind + "\nmetadata:\n  name: " + name +
			"\nspec:\n  provider:\n    aws:\n      service: ParameterStore\n      region: eu-example-1\n" +
			"      role: arn:aws:iam::444455556666:role/a-app-config\n" + auth
	}
	jwt := "      auth:\n        jwt:\n          serviceAccountRef: {name: own}\n"
	secretRef := "      auth:\n        secretRef:\n          accessKeyIDSecretRef: {name: keys, key: id}\n" +
		"          secretAccessKeySecretRef: {name: keys, key: secret}\n"
	fake := func(kind, name string) string {
		return "apiVersion: external-secrets.io/v1\nkind: " + kind + "\nmetadata:\n  name: " + name +
			"\nspec:\n  provider:\n    fake:\n      data: []\n"
	}
	generator := func(kind, name, auth string) string {
		return "apiVersion: generators.external-secrets.io/v1alpha1\nkind: " + kind + "\nmetadata:\n  name: " + name +
			"\nspec:\n  region: eu-example-1\n  role: arn:aws:iam::444455556666:role/a-app-config\n" + strings.ReplaceAll(auth, "      ", "  ")
	}

	waitFor(t, "the AWS policy to enforce", func() bool {
		_, ok := admit(t, kubeconfig, "tenant", awsStore("SecretStore", "probe", ""))

		return !ok
	})

	for _, tc := range []struct {
		name, namespace, manifest string
		// refused: the substrings the refusal must carry; empty: admitted.
		refused []string
	}{
		{"a SecretStore on aws with no auth", "tenant", awsStore("SecretStore", "borrow", ""),
			[]string{"SecretStore borrow in namespace tenant", "no auth of its own"}},
		{"a SecretStore on aws with an empty auth", "tenant", awsStore("SecretStore", "empty", "      auth: {}\n"),
			[]string{"no auth of its own"}},
		{"a SecretStore on aws with its own ServiceAccount", "tenant", awsStore("SecretStore", "jwt", jwt), nil},
		{"a SecretStore on aws with its own keys", "tenant", awsStore("SecretStore", "keys", secretRef), nil},
		{"a SecretStore not on aws", "tenant", fake("SecretStore", "fake"), nil},
		{"the release's ClusterSecretStore", "", awsStore("ClusterSecretStore", "example-app-config", ""), nil},
		{"another ClusterSecretStore on aws", "", awsStore("ClusterSecretStore", "other", ""),
			[]string{"ClusterSecretStore other", "not one of the stores release aws renders"}},
		{"another ClusterSecretStore on aws, even with auth", "", awsStore("ClusterSecretStore", "other-jwt", jwt),
			[]string{"not one of the stores release aws renders"}},
		{"a ClusterSecretStore not on aws", "", fake("ClusterSecretStore", "fake"), nil},
		{"an ECR generator with no auth", "tenant", generator("ECRAuthorizationToken", "ecr", ""),
			[]string{"ECRAuthorizationToken ecr", "names no auth of its own"}},
		{"an ECR generator with its own ServiceAccount", "tenant", generator("ECRAuthorizationToken", "ecr-jwt", jwt), nil},
		{"an STS generator with no auth", "tenant", generator("STSSessionToken", "sts", ""),
			[]string{"STSSessionToken sts", "names no auth of its own"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{}
			if tc.namespace != "" {
				args = append(args, "-n", tc.namespace)
			}

			out, err := kubectl(t, kubeconfig, tc.manifest, append(args, "create", "--dry-run=server", "-f", "-")...)
			if len(tc.refused) == 0 {
				assert.NoError(t, err, out)

				return
			}

			require.Error(t, err, "admitted, but must be refused:\n%s", tc.manifest)

			for _, want := range tc.refused {
				assert.Contains(t, out, want)
			}
		})
	}
}
