package conformance_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

const consumersChart = "../charts/openbao-consumers"

// TestIssuanceAlertRulesParse renders the alert cases of openbao-consumers
// in every format and runs `promtool check rules` over the rules each one
// carries. A render that produces an expression that does not parse must
// fail here, not in an ArgoCD app-of-apps that a ruler's webhook refuses
// for hours.
func TestIssuanceAlertRulesParse(t *testing.T) {
	helmBinary := tool(t, "helm")
	promtool := tool(t, "promtool")

	cases, err := filepath.Glob("../tests/cases/openbao-consumers/alerts-*/values.yaml")
	require.NoError(t, err)
	require.NotEmpty(t, cases, "no alerts case under tests/cases/openbao-consumers")

	for _, values := range cases {
		name := filepath.Base(filepath.Dir(values))

		for _, format := range []string{"vmrule", "prometheusrule", "configmap"} {
			t.Run(name+"/"+format, func(t *testing.T) {
				out, err := exec.Command(helmBinary, "template", "issuance", consumersChart,
					"--namespace", "default", "-f", values, "--set", "alerts.format="+format).CombinedOutput()
				require.NoError(t, err, string(out))

				rules := extractRules(t, string(out), format)
				file := filepath.Join(t.TempDir(), "rules.yaml")
				require.NoError(t, os.WriteFile(file, []byte(rules), 0o600))

				checked, err := exec.Command(promtool, "check", "rules", file).CombinedOutput()
				require.NoError(t, err, "promtool refused the rules:\n%s\n%s", checked, rules)
				assert.Contains(t, string(checked), "SUCCESS")
			})
		}
	}
}

// TestPromtoolRefusesABadExpression proves the check above is not vacuous:
// the same promtool call fails on an expression that does not parse.
func TestPromtoolRefusesABadExpression(t *testing.T) {
	promtool := tool(t, "promtool")
	file := filepath.Join(t.TempDir(), "rules.yaml")
	bad := "groups:\n- name: bad\n  rules:\n  - alert: Bad\n    expr: 'up == :=='\n"
	require.NoError(t, os.WriteFile(file, []byte(bad), 0o600))

	out, err := exec.Command(promtool, "check", "rules", file).CombinedOutput()
	require.Error(t, err, string(out))
}

// extractRules returns the Prometheus rules file the render carries: the
// spec of a VMRule or PrometheusRule, or the file inside the ConfigMap.
func extractRules(t *testing.T, rendered, format string) string {
	t.Helper()

	kind := map[string]string{"vmrule": "VMRule", "prometheusrule": "PrometheusRule", "configmap": "ConfigMap"}[format]

	for _, doc := range strings.Split(rendered, "\n---\n") {
		var object struct {
			Kind string         `yaml:"kind"`
			Spec map[string]any `yaml:"spec"`
			Data map[string]string
		}
		if yaml.Unmarshal([]byte(doc), &object) != nil || object.Kind != kind {
			continue
		}

		if format == "configmap" {
			file, ok := object.Data["issuance-alerts.rules.yaml"]
			require.True(t, ok, "the ConfigMap has no issuance-alerts.rules.yaml")

			return file
		}

		out, err := yaml.Marshal(object.Spec)
		require.NoError(t, err)

		return string(out)
	}

	t.Fatalf("no %s in the render", kind)

	return ""
}
