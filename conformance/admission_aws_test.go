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

const (
	readerRole = "arn:aws:iam::444455556666:role/a-app-config"

	podValues = `aws:
  identity: podIdentity
awsStores:
  - name: example-app-config
    region: eu-example-1
    role: ` + readerRole + `
    conditions:
      - namespaces: [tenant]
`

	// podValuesNext is the pod release one change later: the store's role
	// moved, and a store added.
	podValuesNext = `aws:
  identity: podIdentity
awsStores:
  - name: example-app-config
    region: eu-example-1
    role: ` + nextRole + `
    conditions:
      - namespaces: [tenant]
  - name: example-app-added
    region: eu-example-1
    role: ` + readerRole + `
    conditions:
      - namespaces: [tenant]
`
	nextRole = "arn:aws:iam::444455556666:role/a-app-config-next"

	// auditFilter is docs/esoaws.md's audit, verbatim: every AWS SecretStore
	// and generator that names no auth of its own, which a policy installed
	// after them never judged.
	auditFilter = `.items[] | (if .kind == "SecretStore" then .spec.provider.aws ` +
		`elif .kind == "ClusterGenerator" then (.spec.generator.ecrAuthorizationTokenSpec // .spec.generator.stsSessionTokenSpec) ` +
		`else .spec end) as $a | select($a != null and $a.auth.secretRef == null and $a.auth.jwt == null) | ` +
		`"\(.kind) \(.metadata.namespace // "-")/\(.metadata.name)"`

	webValues = `aws:
  identity: webIdentity
  admissionPolicy:
    enabled: true
awsStores:
  - name: example-web-config
    region: eu-example-1
    role: ` + readerRole + `
    auth:
      jwt:
        serviceAccountRef: {name: eso-web-config, namespace: external-secrets}
    conditions:
      - namespaces: [tenant]
`
)

// awsCase is one manifest and what the API server must say to it.
type awsCase struct {
	name, namespace, manifest string
	// refused: the substrings the refusal must carry; empty: admitted.
	refused []string
}

func awsStore(kind, name, provider string) string {
	return "apiVersion: external-secrets.io/v1\nkind: " + kind + "\nmetadata:\n  name: " + name +
		"\nspec:\n  provider:\n    aws:\n      service: ParameterStore\n      region: eu-example-1\n" + provider
}

func withRole(rest string) string { return "      role: " + readerRole + "\n" + rest }

const (
	jwtAuth = "      auth:\n        jwt:\n          serviceAccountRef: {name: own}\n"
	keyAuth = "      auth:\n        secretRef:\n          accessKeyIDSecretRef: {name: keys, key: id}\n" +
		"          secretAccessKeySecretRef: {name: keys, key: secret}\n"
	webAuth = "      auth:\n        jwt:\n          serviceAccountRef: {name: eso-web-config, namespace: external-secrets}\n"
	// A ClusterGenerator is cluster-scoped: its ServiceAccount names a
	// namespace.
	clusterJWTAuth = "      auth:\n        jwt:\n          serviceAccountRef: {name: own, namespace: tenant}\n"
)

func fakeStore(kind, name string) string {
	return "apiVersion: external-secrets.io/v1\nkind: " + kind + "\nmetadata:\n  name: " + name +
		"\nspec:\n  provider:\n    fake:\n      data: []\n"
}

func generator(kind, name, auth string) string {
	return "apiVersion: generators.external-secrets.io/v1alpha1\nkind: " + kind + "\nmetadata:\n  name: " + name +
		"\nspec:\n  region: eu-example-1\n  role: " + readerRole + "\n" + strings.ReplaceAll(auth, "      ", "  ")
}

// clusterGenerator wraps an ECR or STS spec, the way ESO v2's
// ClusterGenerator does; kind UUID wraps nothing of AWS.
func clusterGenerator(kind, name, auth string) string {
	spec := map[string]string{"ECRAuthorizationToken": "ecrAuthorizationTokenSpec", "STSSessionToken": "stsSessionTokenSpec"}[kind]
	body := "  generator:\n    uuidSpec: {}\n"

	if spec != "" {
		// auth is written at the depth of the wrapped spec's fields.
		body = "  generator:\n    " + spec + ":\n      region: eu-example-1\n      role: " + readerRole + "\n" + auth
	}

	return "apiVersion: generators.external-secrets.io/v1alpha1\nkind: ClusterGenerator\nmetadata:\n  name: " + name +
		"\nspec:\n  kind: " + kind + "\n" + body
}

// installAWSPolicy renders the chart's AWS policy for values under release
// and applies it, then waits until it type-checks clean and enforces.
func installAWSPolicy(t *testing.T, kubeconfig, release, values string) {
	t.Helper()

	file := filepath.Join(t.TempDir(), "values.yaml")
	require.NoError(t, os.WriteFile(file, []byte(values), 0o600))

	rendered, err := exec.Command(tool(t, "helm"), "template", release, consumersChart, "--namespace", "default",
		"-f", file, "--show-only", "templates/aws-admission.yaml").CombinedOutput()
	require.NoError(t, err, string(rendered))
	require.Contains(t, string(rendered), "kind: ValidatingAdmissionPolicy")

	out, err := kubectl(t, kubeconfig, string(rendered), "apply", "-f", "-")
	require.NoError(t, err, out)

	waitFor(t, "the "+release+" AWS policy to type-check", func() bool {
		status, err := kubectl(t, kubeconfig, "", "get", "validatingadmissionpolicy", release+"-aws-stores", "-o", "jsonpath={.status.typeChecking}")

		return err == nil && strings.Contains(status, "{}")
	})

	waitFor(t, "the "+release+" AWS policy to enforce", func() bool {
		_, ok := admit(t, kubeconfig, "", awsStore("ClusterSecretStore", "probe", withRole("")))

		return !ok
	})
}

func runAWSCases(t *testing.T, kubeconfig string, cases []awsCase) {
	t.Helper()

	for _, tc := range cases {
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

// TestAdmissionPolicyAWS proves the AWS store policy of openbao-consumers
// (aws.admissionPolicy) on a real API server: in podIdentity mode, what
// would borrow the External Secrets controller's AWS identity is refused,
// even while held in deletion by a finalizer, and so is a release store
// that drifted from what the release renders; in webIdentity mode, a
// release store reads as its one ServiceAccount. Same throwaway cluster as
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
		"crd/ecrauthorizationtokens.generators.external-secrets.io", "crd/stssessiontokens.generators.external-secrets.io",
		"crd/clustergenerators.generators.external-secrets.io")
	require.NoError(t, err, out)

	out, err = kubectl(t, kubeconfig, "", "create", "namespace", "tenant")
	require.NoError(t, err, out)

	// What exists before the policy is never judged by it: the audit is
	// what finds it.
	for _, manifest := range []struct{ namespace, body string }{
		{"tenant", awsStore("SecretStore", "pre-existing", withRole(""))},
		{"tenant", awsStore("SecretStore", "pre-existing-jwt", withRole(jwtAuth))},
		{"", clusterGenerator("ECRAuthorizationToken", "pre-existing-ecr", "")},
	} {
		args := []string{"create", "-f", "-"}
		if manifest.namespace != "" {
			args = append([]string{"-n", manifest.namespace}, args...)
		}

		out, err = kubectl(t, kubeconfig, manifest.body, args...)
		require.NoError(t, err, out)
	}

	installAWSPolicy(t, kubeconfig, "pod", podValues)

	t.Run("the audit lists what predates the policy", func(t *testing.T) {
		jq, err := exec.LookPath("jq")
		if err != nil {
			t.Skip("no `jq` on PATH; the audit in docs/esoaws.md needs it")
		}

		list, err := kubectl(t, kubeconfig, "", "get", "secretstores,ecrauthorizationtokens,stssessiontokens,clustergenerators", "-A", "-o", "json")
		require.NoError(t, err, list)

		command := exec.Command(jq, "-r", auditFilter)
		command.Stdin = strings.NewReader(list)
		found, err := command.CombinedOutput()
		require.NoError(t, err, string(found))

		assert.Contains(t, string(found), "SecretStore tenant/pre-existing\n")
		assert.Contains(t, string(found), "ClusterGenerator -/pre-existing-ecr\n")
		assert.NotContains(t, string(found), "pre-existing-jwt", "a store with its own auth is not listed")

		for _, del := range [][]string{
			{"-n", "tenant", "delete", "secretstore", "pre-existing", "pre-existing-jwt"},
			{"delete", "clustergenerator", "pre-existing-ecr"},
		} {
			out, err := kubectl(t, kubeconfig, "", del...)
			require.NoError(t, err, out)
		}
	})

	runAWSCases(t, kubeconfig, []awsCase{
		{"a SecretStore on aws with no auth", "tenant", awsStore("SecretStore", "borrow", withRole("")),
			[]string{"SecretStore borrow in namespace tenant", "no auth of its own"}},
		{"a SecretStore on aws with an empty auth", "tenant", awsStore("SecretStore", "empty", withRole("      auth: {}\n")),
			[]string{"no auth of its own"}},
		{"a SecretStore on aws with its own ServiceAccount", "tenant", awsStore("SecretStore", "jwt", withRole(jwtAuth)), nil},
		{"a SecretStore on aws with its own keys", "tenant", awsStore("SecretStore", "keys", withRole(keyAuth)), nil},
		{"a SecretStore not on aws", "tenant", fakeStore("SecretStore", "fake"), nil},
		{"the release's ClusterSecretStore", "", awsStore("ClusterSecretStore", "example-app-config", withRole("")), nil},
		{"the release's store with another role", "",
			awsStore("ClusterSecretStore", "example-app-config", "      role: arn:aws:iam::444455556666:role/other\n"),
			[]string{"is release pod's, but differs from what it renders", "assumes exactly " + readerRole}},
		{"the release's store with no role", "", awsStore("ClusterSecretStore", "example-app-config", ""),
			[]string{"differs from what it renders"}},
		{"the release's store with auth", "", awsStore("ClusterSecretStore", "example-app-config", withRole(jwtAuth)),
			[]string{"differs from what it renders"}},
		{"the release's store with additionalRoles", "",
			awsStore("ClusterSecretStore", "example-app-config", withRole("      additionalRoles: [arn:aws:iam::444455556666:role/other]\n")),
			[]string{"differs from what it renders"}},
		{"the release's store with sessionTags", "",
			awsStore("ClusterSecretStore", "example-app-config", withRole("      sessionTags: [{key: team, value: a}]\n")),
			[]string{"differs from what it renders"}},
		{"the release's store with transitiveTagKeys", "",
			awsStore("ClusterSecretStore", "example-app-config", withRole("      transitiveTagKeys: [team]\n")),
			[]string{"differs from what it renders"}},
		{"the release's store with an externalID", "",
			awsStore("ClusterSecretStore", "example-app-config", withRole("      externalID: x\n")),
			[]string{"differs from what it renders"}},
		{"another ClusterSecretStore on aws", "", awsStore("ClusterSecretStore", "other", withRole("")),
			[]string{"ClusterSecretStore other", "not one of the stores release pod renders"}},
		{"another ClusterSecretStore on aws, even with auth", "", awsStore("ClusterSecretStore", "other-jwt", withRole(jwtAuth)),
			[]string{"not one of the stores release pod renders"}},
		{"a ClusterSecretStore not on aws", "", fakeStore("ClusterSecretStore", "fake"), nil},
		{"an ECR generator with no auth", "tenant", generator("ECRAuthorizationToken", "ecr", ""),
			[]string{"ECRAuthorizationToken ecr in namespace tenant", "names no auth of its own"}},
		{"an ECR generator with its own ServiceAccount", "tenant", generator("ECRAuthorizationToken", "ecr-jwt", jwtAuth), nil},
		{"an STS generator with no auth", "tenant", generator("STSSessionToken", "sts", ""),
			[]string{"STSSessionToken sts in namespace tenant", "names no auth of its own"}},
		{"a ClusterGenerator wrapping ECR with no auth", "", clusterGenerator("ECRAuthorizationToken", "cluster-ecr", ""),
			[]string{"ClusterGenerator cluster-ecr", "names no auth of its own"}},
		{"a ClusterGenerator wrapping ECR with an empty auth", "", clusterGenerator("ECRAuthorizationToken", "cluster-ecr-empty", "      auth: {}\n"),
			[]string{"names no auth of its own"}},
		{"a ClusterGenerator wrapping ECR with its own ServiceAccount", "",
			clusterGenerator("ECRAuthorizationToken", "cluster-ecr-jwt", clusterJWTAuth), nil},
		{"a ClusterGenerator wrapping STS with no auth", "", clusterGenerator("STSSessionToken", "cluster-sts", ""),
			[]string{"ClusterGenerator cluster-sts", "names no auth of its own"}},
		{"a ClusterGenerator of nothing AWS", "", clusterGenerator("UUID", "cluster-uuid", ""), nil},
	})

	// A release that changes a store's role or adds a store: the policy that
	// knows only the old shape refuses the new one, which is why the chart
	// puts the policy a sync wave before the stores; once the new policy is
	// applied and picked up, the new shape is admitted and the old one is not.
	t.Run("a changed release is admitted once its policy is", func(t *testing.T) {
		moved := awsStore("ClusterSecretStore", "example-app-config", "      role: "+nextRole+"\n")
		added := awsStore("ClusterSecretStore", "example-app-added", withRole(""))

		for _, manifest := range []string{moved, added} {
			out, ok := admit(t, kubeconfig, "", manifest)
			require.False(t, ok, "the old policy admitted a store it does not know:\n%s", manifest)
			assert.Contains(t, out, "release pod")
		}

		installAWSPolicy(t, kubeconfig, "pod", podValuesNext)

		waitFor(t, "the updated policy to be picked up", func() bool {
			_, ok := admit(t, kubeconfig, "", moved)

			return ok
		})

		out, ok := admit(t, kubeconfig, "", added)
		assert.True(t, ok, out)

		out, ok = admit(t, kubeconfig, "", awsStore("ClusterSecretStore", "example-app-config", withRole("")))
		assert.False(t, ok, "the old role is refused once the policy moved on")
		assert.Contains(t, out, "assumes exactly "+nextRole)
	})

	// A store held in deletion by its own finalizer is still read, so a
	// spec change while it waits is judged; only the finalizer's removal,
	// spec untouched, is let through.
	t.Run("a store held in deletion cannot shed its auth", func(t *testing.T) {
		held := strings.Replace(awsStore("SecretStore", "held", withRole(jwtAuth)),
			"metadata:\n  name: held\n", "metadata:\n  name: held\n  finalizers: [example.com/hold]\n", 1)

		out, err := kubectl(t, kubeconfig, held, "-n", "tenant", "create", "-f", "-")
		require.NoError(t, err, out)

		out, err = kubectl(t, kubeconfig, "", "-n", "tenant", "delete", "secretstore", "held", "--wait=false")
		require.NoError(t, err, out)

		out, err = kubectl(t, kubeconfig, "", "-n", "tenant", "patch", "secretstore", "held", "--type=json",
			"-p", `[{"op":"remove","path":"/spec/provider/aws/auth"}]`)
		require.Error(t, err, "a terminating store shed its auth:\n%s", out)
		assert.Contains(t, out, "no auth of its own")

		out, err = kubectl(t, kubeconfig, "", "-n", "tenant", "patch", "secretstore", "held", "--type=json",
			"-p", `[{"op":"remove","path":"/metadata/finalizers"}]`)
		require.NoError(t, err, "the finalizer's removal must pass: %s", out)

		waitFor(t, "the held store to go", func() bool {
			_, err := kubectl(t, kubeconfig, "", "-n", "tenant", "get", "secretstore", "held")

			return err != nil
		})
	})

	// webIdentity: the pod release's policy goes, and a web release's
	// policy (opt-in in this mode) takes its place.
	out, err = kubectl(t, kubeconfig, "", "delete", "validatingadmissionpolicybinding,validatingadmissionpolicy", "pod-aws-stores")
	require.NoError(t, err, out)

	waitFor(t, "the pod release's policy to stop enforcing", func() bool {
		_, ok := admit(t, kubeconfig, "", awsStore("ClusterSecretStore", "probe", withRole("")))

		return ok
	})

	installAWSPolicy(t, kubeconfig, "web", webValues)

	runAWSCases(t, kubeconfig, []awsCase{
		{"web: the release's store", "", awsStore("ClusterSecretStore", "example-web-config", webAuth), nil},
		{"web: the release's store on another ServiceAccount", "",
			awsStore("ClusterSecretStore", "example-web-config", "      auth:\n        jwt:\n          serviceAccountRef: {name: other, namespace: external-secrets}\n"),
			[]string{"is release web's, but differs from what it renders", "external-secrets/eso-web-config only"}},
		{"web: the release's store with no namespace on its ref", "",
			awsStore("ClusterSecretStore", "example-web-config", "      auth:\n        jwt:\n          serviceAccountRef: {name: eso-web-config}\n"),
			[]string{"differs from what it renders"}},
		{"web: the release's store with a role on top", "", awsStore("ClusterSecretStore", "example-web-config", withRole(webAuth)),
			[]string{"differs from what it renders"}},
		{"web: the release's store with keys", "", awsStore("ClusterSecretStore", "example-web-config", keyAuth),
			[]string{"differs from what it renders"}},
		{"web: the release's store with additionalRoles", "",
			awsStore("ClusterSecretStore", "example-web-config", webAuth+"      additionalRoles: ["+readerRole+"]\n"),
			[]string{"differs from what it renders"}},
		{"web: another ClusterSecretStore on aws", "", awsStore("ClusterSecretStore", "other", webAuth),
			[]string{"not one of the stores release web renders"}},
		{"web: a SecretStore with no auth", "tenant", awsStore("SecretStore", "borrow", withRole("")),
			[]string{"no auth of its own"}},
	})
}
