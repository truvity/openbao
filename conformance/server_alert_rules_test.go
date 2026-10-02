package conformance_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
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

// ingressRules renders openbao-ops's server NetworkPolicy and returns each
// ingress rule as the ports it opens and whether it is the metrics agent's
// (the peer carrying the agent's pod label).
func ingressRules(t *testing.T, extra ...string) []struct {
	Ports   []int
	Scraper bool
} {
	t.Helper()

	args := append([]string{"template", "ops", opsChart, "--namespace", "default", "-f", serverMetricsCase}, extra...)
	out, err := exec.Command(tool(t, "helm"), args...).CombinedOutput()
	require.NoError(t, err, string(out))

	var rules []struct {
		Ports   []int
		Scraper bool
	}

	for _, doc := range strings.Split(string(out), "\n---\n") {
		var np struct {
			Kind     string
			Metadata struct{ Name string }
			Spec     struct {
				Ingress []struct {
					From  []map[string]any
					Ports []struct{ Port int }
				}
			}
		}

		if yaml.Unmarshal([]byte(doc), &np) != nil || np.Kind != "NetworkPolicy" || !strings.HasSuffix(np.Metadata.Name, "-ingress") {
			continue
		}

		for _, r := range np.Spec.Ingress {
			rule := struct {
				Ports   []int
				Scraper bool
			}{Scraper: strings.Contains(fmt.Sprint(r.From), "metrics-agent")}
			for _, p := range r.Ports {
				rule.Ports = append(rule.Ports, p.Port)
			}

			rules = append(rules, rule)
		}
	}

	return rules
}

// TestOpenBAOServerMetricsKeepEveryIngressRule: the scraper rule ADDS to the
// client, peer, snapshot and job rules (none is removed or narrowed), and it
// opens the metrics port and nothing else: not the API port, not the cluster
// port.
func TestOpenBAOServerMetricsKeepEveryIngressRule(t *testing.T) {
	without := ingressRules(t, "--set", "serverMetrics.scraper=null")
	with := ingressRules(t)

	require.NotEmpty(t, without)
	require.Len(t, with, len(without)+1, "exactly one rule is added")

	for _, rule := range without {
		assert.Contains(t, with, rule, "an earlier ingress rule is gone or changed")
	}

	for _, rule := range with {
		if rule.Scraper {
			assert.Equal(t, []int{8202}, rule.Ports, "the scraper reaches the metrics port only")
		} else {
			assert.NotContains(t, rule.Ports, 8202, "no other rule opens the metrics port")
		}
	}
}

// TestServerMetricsPortIsItsOwn: the metrics port may not be the API or
// cluster port, or the scraper could not be admitted to it alone.
func TestServerMetricsPortIsItsOwn(t *testing.T) {
	for _, port := range []string{"8200", "8201"} {
		out, err := exec.Command(tool(t, "helm"), "template", "ops", opsChart, "--namespace", "default",
			"-f", serverMetricsCase, "--set", "serverMetrics.port="+port).CombinedOutput()
		require.Error(t, err, "port %s rendered", port)
		assert.Contains(t, string(out), "must differ from server.apiPort")
	}
}
