package conformance_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

const (
	opsChart = "../charts/openbao-ops"
	// readyMessage is cert-manager's own text, with a quote in it: a
	// channel that builds a message by pasting it in has to escape it, and
	// an implementation that does not is silent exactly when it matters.
	readyMessage = `Failed to sign: the server said "no route to host"`
)

// renderedCronJob is the part of a rendered CronJob this test reads.
type renderedCronJob struct {
	Kind string `yaml:"kind"`
	Spec struct {
		JobTemplate struct {
			Spec struct {
				Template struct {
					Spec struct {
						Containers []struct {
							Name    string   `yaml:"name"`
							Image   string   `yaml:"image"`
							Command []string `yaml:"command"`
							// The other half of what the pod gives the
							// script: the values it must not read as
							// shell arrive here.
							Env []struct {
								Name  string `yaml:"name"`
								Value string `yaml:"value"`
							} `yaml:"env"`
						} `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		} `yaml:"jobTemplate"`
	} `yaml:"spec"`
}

// delivery is one alert as the channel it was sent to saw it.
type delivery struct {
	// path and headers are a webhook's; a command-line channel has none.
	path    string
	headers http.Header
	body    string
}

// TestCertificateExpiryAlertContract runs both shipped implementations of
// the alert contract (docs/doctrine.md): read /work/status, and when fewer
// than ALERT_BEFORE_SECONDS are left, alert and exit non-zero.
//
// The script the chart renders is what runs here, and each implementation
// is observed at its own channel -- SNS at the CLI it publishes with, the
// Alertmanager preset at a webhook that really receives the post. A preset
// whose script only a reviewer has read is a preset nobody has run.
func TestCertificateExpiryAlertContract(t *testing.T) {
	helmBinary := tool(t, "helm")

	for _, preset := range []struct {
		name string
		// open returns the values that select the implementation and a
		// view of what its channel has received so far.
		open   func(t *testing.T, binDir string) ([]string, func() []delivery)
		verify func(t *testing.T, sent delivery)
	}{
		{
			name: "sns",
			open: func(t *testing.T, binDir string) ([]string, func() []delivery) {
				t.Helper()

				received := commandShim(t, binDir, "aws")

				return []string{
					"certificateExpiry.alert.sns.enabled=true",
					"certificateExpiry.alert.sns.topicArn=example-topic",
					"certificateExpiry.alert.sns.region=eu-example-1",
				}, received
			},
			verify: func(t *testing.T, sent delivery) {
				t.Helper()

				lines := strings.Split(sent.body, "\n")
				assert.Equal(t, []string{"sns", "publish", "--topic-arn", "example-topic"}, lines[:4])

				// The message is handed over as a file rather than as an
				// argument: it carries the certificate's own words and a
				// runbook, and a shell that has to quote those is a shell
				// that one day does not.
				reference := lines[len(lines)-1]
				assert.Equal(t, "--message", lines[len(lines)-2])
				require.True(t, strings.HasPrefix(reference, "file://"), reference)

				message, err := os.ReadFile(strings.TrimPrefix(reference, "file://"))
				require.NoError(t, err)
				assert.Contains(t, string(message), "days left")
				assert.Contains(t, string(message), readyMessage, "the Ready message reaches the channel")
				assert.Contains(t, string(message), "example-cluster", "and whose certificate it is")
			},
		},
		{
			name: "alertmanager",
			open: func(t *testing.T, _ string) ([]string, func() []delivery) {
				t.Helper()

				// The container posts with curl; the dev shell pins one.
				tool(t, "curl")

				webhook, received := webhook(t)

				return []string{
					"certificateExpiry.alert.alertmanager.enabled=true",
					"certificateExpiry.alert.alertmanager.url=" + webhook,
					"certificateExpiry.alert.alertmanager.release=openbao",
				}, received
			},
			verify: func(t *testing.T, sent delivery) {
				t.Helper()

				assert.Equal(t, "/api/v2/alerts", sent.path, "the v2 API's path, appended by the chart")
				assert.Equal(t, "application/json", sent.headers.Get("Content-Type"))

				var alerts []struct {
					Labels      map[string]string `json:"labels"`
					Annotations map[string]string `json:"annotations"`
				}

				require.NoError(t, json.Unmarshal([]byte(sent.body), &alerts), sent.body)
				require.Len(t, alerts, 1, "one alert, not a batch")

				assert.Equal(t, map[string]string{
					"alertname": "OpenBAOCertificateExpiring",
					"severity":  "warning",
					"release":   "openbao",
				}, alerts[0].Labels, "the labels a route matches on")

				assert.Contains(t, alerts[0].Annotations["summary"], "days")
				assert.Contains(t, alerts[0].Annotations["description"], "example-cluster")
				assert.Contains(t, alerts[0].Annotations["description"], readyMessage,
					"the Ready message survives the JSON body it is escaped into")
			},
		},
	} {
		t.Run(preset.name, func(t *testing.T) {
			binDir := t.TempDir()
			values, received := preset.open(t, binDir)
			script, environment := alertScript(t, helmBinary, values...)

			t.Run("inside the window it alerts and fails the run", func(t *testing.T) {
				code := runAlert(t, script, binDir, environment, time.Now().Add(10*24*time.Hour))
				assert.NotEqual(t, 0, code, "a renewal that keeps failing must fail the job, not log")

				sent := received()
				require.Len(t, sent, 1, "one alert per run")
				preset.verify(t, sent[0])
			})

			t.Run("outside it says nothing and passes", func(t *testing.T) {
				before := len(received())

				code := runAlert(t, script, binDir, environment, time.Now().Add(60*24*time.Hour))
				assert.Equal(t, 0, code)
				assert.Len(t, received(), before, "no alert while there is time to renew")
			})
		})
	}
}

// tool is a binary the dev shell pins. As with `bao`, a missing one skips
// the test unless OPENBAO_CONFORMANCE=required -- which `just test`, and
// so CI, sets -- where it is a failure: a contract test that quietly
// skipped would prove nothing.
func tool(t *testing.T, name string) string {
	t.Helper()

	path, err := exec.LookPath(name)
	if err != nil {
		if os.Getenv(requireVariable) == "required" {
			t.Fatalf("%s=required and no `%s` on PATH: run the test in the dev shell (devbox), which pins it", requireVariable, name)
		}

		t.Skipf("no `%s` on PATH; the dev shell pins it, and %s=required makes this a failure", name, requireVariable)
	}

	return path
}

// alertScript renders openbao-ops with the expiry check on and returns the
// alert container's script. The renewal lead time is explicit because this
// render carries no certificate of its own.
func alertScript(t *testing.T, helmBinary string, values ...string) (string, []string) {
	t.Helper()

	args := []string{
		"template", "expiry", opsChart, "--namespace", "openbao",
		"--set", "certificateExpiry.enabled=true",
		"--set", "certificateExpiry.clusterName=example-cluster",
		"--set", "certificateExpiry.renewBeforeSeconds=2592000",
	}
	for _, value := range values {
		args = append(args, "--set", value)
	}

	rendered, err := exec.Command(helmBinary, args...).CombinedOutput()
	require.NoError(t, err, "helm template: %s", rendered)

	decoder := yaml.NewDecoder(bytes.NewReader(rendered))

	for {
		var object renderedCronJob

		err := decoder.Decode(&object)
		if errors.Is(err, io.EOF) {
			break
		}

		require.NoError(t, err)

		if object.Kind != "CronJob" {
			continue
		}

		for _, container := range object.Spec.JobTemplate.Spec.Template.Spec.Containers {
			if container.Name != "alert" {
				continue
			}

			require.Len(t, container.Command, 3, "a preset's alert container is `/bin/sh -ec <script>`")

			environment := make([]string, 0, len(container.Env))
			for _, e := range container.Env {
				environment = append(environment, e.Name+"="+e.Value)
			}

			return container.Command[2], environment
		}
	}

	t.Fatal("the render has no alert container")

	return "", nil
}

// runAlert runs the alert container's script over the status the read
// container leaves behind, and answers with its exit code.
//
// The pod's absolute paths are relocated into a temporary directory: a
// test cannot write /work, and those paths are the only thing about the
// script a shell on this machine cannot honour as the pod does.
func runAlert(t *testing.T, script, binDir string, environment []string, notAfter time.Time) int {
	t.Helper()

	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	require.NoError(t, os.Mkdir(work, 0o755))

	status := fmt.Sprintf("%s\nFalse\n%s\n", notAfter.UTC().Format(time.RFC3339), readyMessage)
	require.NoError(t, os.WriteFile(filepath.Join(work, "status"), []byte(status), 0o644))

	local := strings.NewReplacer(
		"/work/", work+string(os.PathSeparator),
		"/tmp/alert.json", filepath.Join(dir, "alert.json"),
		"/tmp/message", filepath.Join(dir, "message"),
	).Replace(script)

	command := exec.Command("/bin/sh", "-ec", local)
	command.Env = append(os.Environ(), environment...)
	command.Env = append(command.Env, "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	out, err := command.CombinedOutput()
	t.Logf("the alert container said:\n%s", out)

	var exit *exec.ExitError

	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	default:
		t.Fatalf("running the alert container: %v", err)

		return -1
	}
}

// commandShim puts a recording stand-in for a command-line channel's
// binary on the script's PATH, and answers with what it was called with.
func commandShim(t *testing.T, binDir, name string) func() []delivery {
	t.Helper()

	calls := filepath.Join(t.TempDir(), "calls")

	// One argument per line, with a form feed between calls: an alert's
	// own text carries newlines.
	shim := fmt.Sprintf("#!/bin/sh\nfor arg in \"$@\"; do printf '%%s\\n' \"$arg\"; done >> %q\nprintf '\\f' >> %q\n", calls, calls)
	require.NoError(t, os.WriteFile(filepath.Join(binDir, name), []byte(shim), 0o755))

	return func() []delivery {
		raw, err := os.ReadFile(calls)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		require.NoError(t, err)

		var sent []delivery

		for _, call := range strings.Split(strings.TrimSuffix(string(raw), "\f"), "\f") {
			sent = append(sent, delivery{body: strings.TrimSuffix(call, "\n")})
		}

		return sent
	}
}

// webhook is an Alertmanager-shaped receiver: its URL, and what it has
// been posted.
func webhook(t *testing.T) (string, func() []delivery) {
	t.Helper()

	var (
		mu   sync.Mutex
		sent []delivery
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		mu.Lock()
		sent = append(sent, delivery{path: r.URL.Path, headers: r.Header.Clone(), body: string(body)})
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	return server.URL, func() []delivery {
		mu.Lock()
		defer mu.Unlock()

		return slices.Clone(sent)
	}
}
