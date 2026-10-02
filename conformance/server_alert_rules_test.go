package conformance_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const serverMetricsCase = "../tests/cases/openbao-ops/server-metrics/values.yaml"

// renderServerRules renders openbao-ops's server alerts in one format and
// returns the Prometheus rules file the render carries.
func renderServerRules(t *testing.T, format string) string {
	t.Helper()

	out, err := exec.Command(tool(t, "helm"), "template", "ops", opsChart,
		"--namespace", "default", "-f", serverMetricsCase,
		"--set", "serverMetrics.alerts.format="+format).CombinedOutput()
	require.NoError(t, err, string(out))

	return extractRules(t, string(out), format)
}

// TestServerAlertRulesParse runs `promtool check rules` over the server
// alerts in every format the chart renders: an expression that does not
// parse must fail here, not in a ruler's webhook.
func TestServerAlertRulesParse(t *testing.T) {
	promtool := tool(t, "promtool")

	for _, format := range []string{"vmrule", "prometheusrule", "configmap"} {
		t.Run(format, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "rules.yaml")
			require.NoError(t, os.WriteFile(file, []byte(renderServerRules(t, format)), 0o600))

			checked, err := exec.Command(promtool, "check", "rules", file).CombinedOutput()
			require.NoError(t, err, "promtool refused the rules:\n%s", checked)
			assert.Contains(t, string(checked), "SUCCESS")
		})
	}
}

// TestServerAlertRulesBehave runs the promtool unit tests in
// tests/promtool against the rules the chart renders: each alert fires on
// the series that should fire it, with its labels and text, and a healthy
// cluster fires none.
func TestServerAlertRulesBehave(t *testing.T) {
	promtool := tool(t, "promtool")
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(renderServerRules(t, "prometheusrule")), 0o600))

	tests, err := os.ReadFile("../tests/promtool/openbao-server-alerts.test.yaml")
	require.NoError(t, err)

	file := filepath.Join(dir, "openbao-server-alerts.test.yaml")
	require.NoError(t, os.WriteFile(file, tests, 0o600))

	out, err := exec.Command(promtool, "test", "rules", file).CombinedOutput()
	require.NoError(t, err, "promtool test rules:\n%s", out)
	assert.Contains(t, string(out), "SUCCESS")
}
