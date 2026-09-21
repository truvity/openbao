package conformance_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/openbao/internal/fakeissuer"
)

// The watches (charts/openbao-ops: snapshotAge, jobSuccess,
// rootGeneration) each answer a question about an install that nothing
// else answers, and each writes its whole report to /work/alert for one
// shared alert container to deliver. What is proved here is the part a
// review cannot: the scripts the chart renders are RUN — over fabricated
// listings, against a stand-in for the API each reads, and, for the root
// watch, against a real `bao server -dev` with a real JWT login.
//
// A watch whose script only a reviewer has read is a watch nobody has run.

const (
	// watchNamespace is the namespace every render here is made for; the
	// scripts quote it in what they tell an operator to look at.
	watchNamespace = "openbao"
	// rootWatchRole and rootWatchPolicy are the role and policy the root
	// watch logs in as. The policy is the whole of its access.
	rootWatchRole   = "openbao-root-generation"
	rootWatchPolicy = "openbao-root-generation"
	// rootWatchAudience is auth.audience, which the JWT role binds.
	rootWatchAudience = "openbao"
)

// watchCronJob is the part of a rendered CronJob these tests read.
type watchCronJob struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		JobTemplate struct {
			Spec struct {
				Template struct {
					Spec struct {
						InitContainers []watchContainer `yaml:"initContainers"`
						Containers     []watchContainer `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		} `yaml:"jobTemplate"`
	} `yaml:"spec"`
}

type watchContainer struct {
	Name    string   `yaml:"name"`
	Command []string `yaml:"command"`
	// Env is half of what the pod gives the script: since 2026-09-21 the
	// values a script must not read as shell arrive this way, so a test
	// that ran the command without the environment would be running
	// something the pod never runs.
	Env []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	} `yaml:"env"`
}

// TestSnapshotAgeAsksTheStore runs the check container's script over
// listings a store might really answer with. It is the watch's whole
// judgement: everything before it is one `list` per store, and everything
// after it is delivery.
func TestSnapshotAgeAsksTheStore(t *testing.T) {
	helmBinary := tool(t, "helm")
	script, environment := containerScript(t, helmBinary, "openbao-snapshot-age", "check", snapshotAgeValues()...)

	stamp := func(at time.Time) string { return "raft/" + at.UTC().Format("20060102T150405Z") + ".snap" }

	for _, c := range []struct {
		name string
		// newest and unreachable are what the list containers left behind.
		newest      map[string]string
		unreachable map[string]string
		quiet       bool
		expect      []string
	}{
		{
			name:   "both stores fresh",
			newest: map[string]string{"primary": stamp(time.Now().Add(-2 * time.Hour)), "replica": stamp(time.Now().Add(-3 * time.Hour))},
			quiet:  true,
		},
		{
			name:   "the primary has stopped being filled",
			newest: map[string]string{"primary": stamp(time.Now().Add(-30 * time.Hour)), "replica": stamp(time.Now().Add(-3 * time.Hour))},
			expect: []string{"1 of 2 store(s)", "primary (the backup account", "30h behind", "more than 12h old"},
		},
		{
			name: "the copy has stopped arriving while the primary is fresh",
			// What a stalled replication looks like from the data's side.
			newest: map[string]string{"primary": stamp(time.Now().Add(-1 * time.Hour)), "replica": stamp(time.Now().Add(-40 * time.Hour))},
			expect: []string{"replica (the copy replication keeps", "40h behind", "has stopped arriving"},
		},
		{
			name:   "a store with nothing in it at all",
			newest: map[string]string{"primary": "", "replica": stamp(time.Now().Add(-1 * time.Hour))},
			expect: []string{"holds no snapshot at all under raft/"},
		},
		{
			name:        "a store nothing could list",
			newest:      map[string]string{"replica": stamp(time.Now().Add(-1 * time.Hour))},
			unreachable: map[string]string{"primary": "An error occurred (AccessDenied) when calling ListObjectsV2"},
			expect:      []string{"could not be listed", "AccessDenied"},
		},
		{
			name: "an object whose name says nothing about when it was taken",
			// The upload contract's name is what carries the time; a
			// store holding something else cannot be judged, and
			// answering "fresh" would be a guess.
			newest: map[string]string{"primary": "raft/latest.snap", "replica": stamp(time.Now().Add(-1 * time.Hour))},
			expect: []string{"carries no <taken-at>"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			work := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(work, "newest"), 0o755))
			require.NoError(t, os.Mkdir(filepath.Join(work, "error"), 0o755))

			for store, key := range c.newest {
				require.NoError(t, os.WriteFile(filepath.Join(work, "newest", store), []byte(key), 0o644))
			}

			for store, why := range c.unreachable {
				require.NoError(t, os.WriteFile(filepath.Join(work, "error", store), []byte(why), 0o644))
			}

			out, code := runScript(t, script, work, "", environment)
			assert.Equal(t, 0, code, "the check never fails the pod: the alert container is the only thing that tells anyone")

			report, err := os.ReadFile(filepath.Join(work, "alert"))
			require.NoError(t, err, "the check always leaves a report file, empty when there is nothing wrong")

			if c.quiet {
				assert.Empty(t, string(report), "a store with a fresh snapshot in it is silence:\n%s", out)

				return
			}

			require.NotEmpty(t, string(report))

			summary, description, found := strings.Cut(string(report), "\n")
			require.True(t, found, "a report is a summary line and a description")
			assert.Contains(t, summary, "OpenBAO has no fresh backup")
			assert.Contains(t, summary, "example-cluster", "the summary says whose backups these are")

			for _, want := range c.expect {
				assert.Contains(t, string(report), want)
			}

			assert.Contains(t, description, "Look at: kubectl -n "+watchNamespace, "what to look at")
			assert.Contains(t, description, "The way back:", "and the way back")
		})
	}
}

// TestSnapshotAgeListRefusesToFailThePod runs the s3 preset's list
// container against a stand-in for the CLI. A probe that exits non-zero
// takes the alert container down with it, and a store nothing can reach
// is exactly the case worth hearing about -- so the failure has to become
// an answer, not a crash.
func TestSnapshotAgeListRefusesToFailThePod(t *testing.T) {
	helmBinary := tool(t, "helm")
	script, environment := containerScript(t, helmBinary, "openbao-snapshot-age", "list-primary", snapshotAgeValues()...)

	t.Run("the newest key becomes this store's answer", func(t *testing.T) {
		work, binDir := t.TempDir(), t.TempDir()
		writeShim(t, binDir, "aws", "printf 'raft/20260921T051700Z.snap\\n'", 0)

		_, code := runScript(t, script, work, binDir, environment)
		require.Equal(t, 0, code)

		answer, err := os.ReadFile(filepath.Join(work, "newest", "primary"))
		require.NoError(t, err)
		assert.Equal(t, "raft/20260921T051700Z.snap", string(answer))
		assert.NoFileExists(t, filepath.Join(work, "error", "primary"))
	})

	t.Run("an empty prefix is an empty answer, not a failure", func(t *testing.T) {
		work, binDir := t.TempDir(), t.TempDir()
		// What the AWS CLI prints for a query that matched nothing.
		writeShim(t, binDir, "aws", "printf 'None\\n'", 0)

		_, code := runScript(t, script, work, binDir, environment)
		require.Equal(t, 0, code)

		answer, err := os.ReadFile(filepath.Join(work, "newest", "primary"))
		require.NoError(t, err)
		assert.Empty(t, string(answer), "the check reports a store that holds nothing; the probe does not decide")
	})

	t.Run("a store it cannot reach leaves the reason and exits zero", func(t *testing.T) {
		work, binDir := t.TempDir(), t.TempDir()
		writeShim(t, binDir, "aws", "echo 'An error occurred (AccessDenied) when calling ListObjectsV2' >&2", 1)

		_, code := runScript(t, script, work, binDir, environment)
		require.Equal(t, 0, code, "a probe that fails the pod tells nobody")

		why, err := os.ReadFile(filepath.Join(work, "error", "primary"))
		require.NoError(t, err)
		assert.Contains(t, string(why), "AccessDenied")

		answer, err := os.ReadFile(filepath.Join(work, "newest", "primary"))
		require.NoError(t, err)
		assert.Empty(t, string(answer))
	})
}

// TestJobSuccessAsksWhenEachJobLastSucceeded runs the read container's
// script against a stand-in for kubectl. The case that matters is the
// quiet one: a CronJob that stops being scheduled never produces a failed
// Job, so "no failures" is not "working".
func TestJobSuccessAsksWhenEachJobLastSucceeded(t *testing.T) {
	helmBinary := tool(t, "helm")
	script, environment := containerScript(t, helmBinary, "openbao-job-success", "read", jobSuccessValues()...)

	answered := func(suspend, last string) string {
		return fmt.Sprintf("printf '%s\\n%s\\n'", suspend, last)
	}
	when := func(ago time.Duration) string { return time.Now().Add(-ago).UTC().Format(time.RFC3339) }

	for _, c := range []struct {
		name   string
		shim   string
		code   int
		quiet  bool
		expect []string
	}{
		{
			name:  "it succeeded within its schedule",
			shim:  answered("", when(24*time.Hour)),
			quiet: true,
		},
		{
			name:   "it has not succeeded for longer than it is allowed",
			shim:   answered("", when(10*24*time.Hour)),
			expect: []string{"last succeeded 240h ago", "more than the 216h it is allowed"},
		},
		{
			name: "it is suspended, which produces no failed Job at all",
			shim: answered("true", when(1*time.Hour)),
			// Suspended and recent: every other signal is green.
			expect: []string{"is SUSPENDED", "will not run again"},
		},
		{
			name:   "it has never succeeded",
			shim:   answered("", ""),
			expect: []string{"has never recorded a successful run"},
		},
		{
			name:   "the CronJob is not there any more",
			shim:   "echo 'Error from server (NotFound): cronjobs.batch \"openbao-restore-check\" not found' >&2",
			code:   1,
			expect: []string{"could not be read", "NotFound", "A job that is not there is not running"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			work, binDir := t.TempDir(), t.TempDir()
			writeShim(t, binDir, "kubectl", c.shim, c.code)

			out, code := runScript(t, script, work, binDir, environment)
			assert.Equal(t, 0, code, "the read never fails the pod")

			report, err := os.ReadFile(filepath.Join(work, "alert"))
			require.NoError(t, err)

			if c.quiet {
				assert.Empty(t, string(report), "a job that is succeeding is silence:\n%s", out)

				return
			}

			require.NotEmpty(t, string(report))
			assert.Contains(t, string(report), "have not succeeded lately")
			assert.Contains(t, string(report), "example-cluster")

			for _, want := range c.expect {
				assert.Contains(t, string(report), want)
			}

			assert.Contains(t, string(report), "Look at: kubectl -n "+watchNamespace)
			assert.Contains(t, string(report), "The way back:")
		})
	}
}

// TestRootGenerationWatchesARealServer runs the root watch's script
// against a real `bao server -dev`, logged in through a real JWT mount as
// a role whose policy is one read of sys/generate-root-token/attempt.
//
// The endpoint is the whole reason this watch can exist, and it is not
// the one an operator types: `bao operator generate-root -status` is
// served by an unauthenticated HTTP handler that OpenBAO 2.6 does not
// answer at all (405 on /v1/sys/generate-root/attempt). The path that
// works is the logical one, reachable by a token a policy bounds -- so
// the watch needs no root, no recovery share and no unauthenticated
// endpoint, and a test that did not log in would prove none of that.
func TestRootGenerationWatchesARealServer(t *testing.T) {
	helmBinary := tool(t, "helm")
	binary := tool(t, "bao")

	address := devServer(t, binary)

	issuer, err := fakeissuer.New(nil)
	require.NoError(t, err)

	t.Cleanup(issuer.Close)

	bao := func(t *testing.T, token string, args ...string) (string, error) {
		t.Helper()

		command := exec.Command(binary, args...)
		command.Env = append(os.Environ(), "BAO_ADDR="+address, "BAO_TOKEN="+token, "HOME="+t.TempDir())
		out, err := command.CombinedOutput()

		return string(out), err
	}

	mustBao := func(t *testing.T, args ...string) string {
		t.Helper()

		out, err := bao(t, rootToken, args...)
		require.NoError(t, err, "bao %s: %s", strings.Join(args, " "), out)

		return out
	}

	// The door the watch comes through, and the whole of what it may do.
	mustBao(t, "auth", "enable", "-path=jwt", "jwt")
	mustBao(t, "write", "auth/jwt/config", "oidc_discovery_url="+issuer.URL)

	policy := filepath.Join(t.TempDir(), "policy.hcl")
	require.NoError(t, os.WriteFile(policy, []byte(
		"path \"sys/generate-root-token/attempt\" {\n  capabilities = [\"read\"]\n}\n"), 0o644))
	mustBao(t, "policy", "write", rootWatchPolicy, policy)
	mustBao(t, "write", "auth/jwt/role/"+rootWatchRole,
		"role_type=jwt", "bound_audiences="+rootWatchAudience, "user_claim=sub",
		"token_policies="+rootWatchPolicy, "token_ttl=10m")

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(issuer.Token(fakeissuer.Claims{
		Subject: "system:serviceaccount:openbao:openbao-root-generation", Audience: rootWatchAudience,
	})), 0o644))

	script, environment := containerScript(t, helmBinary, "openbao-root-generation", "read", rootGenerationValues()...)
	// The pod's own address and login path are the two things a shell on
	// this machine cannot honour as the pod does, so the render's
	// BAO_ADDR and BAO_CACERT are overridden after it.
	script = strings.NewReplacer("/var/run/openbao/token", tokenFile).Replace(script)
	environment = append(environment,
		"BAO_ADDR="+address, "BAO_CACERT=",
		"PATH="+filepath.Dir(binary)+string(os.PathListSeparator)+os.Getenv("PATH"))

	t.Run("nothing is happening and it says nothing", func(t *testing.T) {
		work := t.TempDir()

		out, code := runScript(t, script, work, "", environment)
		require.Equal(t, 0, code, out)

		report, err := os.ReadFile(filepath.Join(work, "alert"))
		require.NoError(t, err)
		assert.Empty(t, string(report))
		assert.Contains(t, out, "no root-token generation in progress")
	})

	t.Run("an attempt in progress is reported with the way to stop it", func(t *testing.T) {
		otp, err := bao(t, rootToken, "operator", "generate-root", "-generate-otp")
		require.NoError(t, err, otp)
		mustBao(t, "operator", "generate-root", "-init", "-otp="+strings.TrimSpace(otp))

		t.Cleanup(func() { mustBao(t, "operator", "generate-root", "-cancel") })

		work := t.TempDir()

		out, code := runScript(t, script, work, "", environment)
		require.Equal(t, 0, code, out)

		report, err := os.ReadFile(filepath.Join(work, "alert"))
		require.NoError(t, err)

		summary, description, found := strings.Cut(string(report), "\n")
		require.True(t, found, string(report))
		assert.Equal(t, "example-cluster: a root token is being generated in OpenBAO", summary)
		assert.Contains(t, description, "started=true")
		assert.Contains(t, description, "key shares given", "how far along it is")
		assert.Contains(t, description, "Look at: bao operator generate-root -status")
		assert.Contains(t, description, "bao operator generate-root -cancel", "the way back")
	})

	t.Run("being unable to ask is itself the alert", func(t *testing.T) {
		// Taking the policy away is a step someone would take before
		// generating a root token, so a watch that went quiet for it
		// would be worse than no watch.
		mustBao(t, "policy", "delete", rootWatchPolicy)

		t.Cleanup(func() { mustBao(t, "policy", "write", rootWatchPolicy, policy) })

		work := t.TempDir()

		out, code := runScript(t, script, work, "", environment)
		require.Equal(t, 0, code, out)

		report, err := os.ReadFile(filepath.Join(work, "alert"))
		require.NoError(t, err)
		assert.Contains(t, string(report), "cannot see OpenBAO")
		assert.Contains(t, string(report), "sys/generate-root-token/attempt")
		assert.Contains(t, string(report), "The way back:")
	})
}

// TestWatchAlertContract holds both shipped presets to the watches' alert
// contract (docs/doctrine.md): read /work/alert, and when it is not empty
// deliver it and exit non-zero. Each is observed at its own channel -- SNS
// at the CLI it publishes with, Alertmanager at a webhook that really
// receives the post.
func TestWatchAlertContract(t *testing.T) {
	helmBinary := tool(t, "helm")

	const (
		summary = "example-cluster: OpenBAO has no fresh backup in 1 of 2 store(s)"
		// A report carries the words of whatever failed, and those come
		// from a cloud's error messages: a channel that pastes them into
		// a body has to escape them, and one that does not is silent
		// exactly when it matters.
		detail = `  primary could not be listed: the store said "no such bucket"`
	)

	for _, preset := range []struct {
		name   string
		open   func(t *testing.T, binDir string) ([]string, func() []delivery)
		verify func(t *testing.T, sent delivery)
	}{
		{
			name: "sns",
			open: func(t *testing.T, binDir string) ([]string, func() []delivery) {
				t.Helper()

				return []string{
					"snapshotAge.alert.sns.enabled=true",
					"snapshotAge.alert.sns.topicArn=example-topic",
					"snapshotAge.alert.sns.region=eu-example-1",
					"snapshotAge.alert.sns.runbook=The way back is docs/operations/openbao-restore.md.",
				}, commandShim(t, binDir, "aws")
			},
			verify: func(t *testing.T, sent delivery) {
				t.Helper()

				lines := strings.Split(sent.body, "\n")
				require.GreaterOrEqual(t, len(lines), 6)
				assert.Equal(t, []string{"sns", "publish", "--topic-arn", "example-topic", "--subject", summary}, lines[:6])

				// The report is handed over as a file rather than as an
				// argument, so nothing has to quote it.
				reference := lines[len(lines)-1]
				assert.Equal(t, "--message", lines[len(lines)-2])
				assert.True(t, strings.HasPrefix(reference, "file://"), reference)

				message, err := os.ReadFile(strings.TrimPrefix(reference, "file://"))
				require.NoError(t, err)
				assert.Contains(t, string(message), detail, "the report reaches the channel unaltered")
				assert.Contains(t, string(message), "The way back is docs/operations/openbao-restore.md.")
			},
		},
		{
			name: "alertmanager",
			open: func(t *testing.T, _ string) ([]string, func() []delivery) {
				t.Helper()

				tool(t, "curl")

				url, received := webhook(t)

				return []string{
					"snapshotAge.alert.alertmanager.enabled=true",
					"snapshotAge.alert.alertmanager.url=" + url,
					"snapshotAge.alert.alertmanager.release=openbao",
					"snapshotAge.alert.alertmanager.runbook=docs/operations/openbao-restore.md",
				}, received
			},
			verify: func(t *testing.T, sent delivery) {
				t.Helper()

				assert.Equal(t, "/api/v2/alerts", sent.path)
				assert.Equal(t, "application/json", sent.headers.Get("Content-Type"))

				var alerts []struct {
					Labels      map[string]string `json:"labels"`
					Annotations map[string]string `json:"annotations"`
				}

				require.NoError(t, json.Unmarshal([]byte(sent.body), &alerts), sent.body)
				require.Len(t, alerts, 1, "one alert, not a batch")
				assert.Equal(t, map[string]string{
					"alertname": "OpenBAOSnapshotStale",
					"severity":  "critical",
					"release":   "openbao",
				}, alerts[0].Labels, "the labels a route matches on")
				assert.Equal(t, summary, alerts[0].Annotations["summary"])
				assert.Contains(t, alerts[0].Annotations["description"], `the store said "no such bucket"`,
					"the words of what failed survive the JSON body they are escaped into")
				assert.Equal(t, "docs/operations/openbao-restore.md", alerts[0].Annotations["runbook"])
			},
		},
	} {
		t.Run(preset.name, func(t *testing.T) {
			binDir := t.TempDir()
			values, received := preset.open(t, binDir)
			script, environment := containerScript(t, helmBinary, "openbao-snapshot-age", "alert",
				append(snapshotAgeStores(), values...)...)

			t.Run("an empty report says nothing and passes", func(t *testing.T) {
				work := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(work, "alert"), nil, 0o644))

				_, code := runScript(t, script, work, binDir, environment)
				assert.Equal(t, 0, code)
				assert.Empty(t, received(), "silence is what a healthy run delivers")
			})

			t.Run("a report is delivered and fails the run", func(t *testing.T) {
				before := len(received())
				work := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(work, "alert"),
					[]byte(summary+"\n"+detail+"\n"), 0o644))

				_, code := runScript(t, script, work, binDir, environment)
				assert.NotEqual(t, 0, code, "a watch that found something must fail the job, not log")

				sent := received()
				require.Len(t, sent, before+1, "one alert per run")
				preset.verify(t, sent[before])
			})
		})
	}
}

// snapshotAgeValues is the watch with the channel every other test
// reaches it through.
func snapshotAgeValues() []string {
	return append(snapshotAgeStores(),
		"snapshotAge.alert.sns.enabled=true",
		"snapshotAge.alert.sns.topicArn=example-topic",
		"snapshotAge.alert.sns.region=eu-example-1",
	)
}

// snapshotAgeStores renders the watch over two stores: the one the
// snapshots are written to, and the copy another region keeps.
func snapshotAgeStores() []string {
	return []string{
		"snapshotAge.enabled=true",
		"snapshotAge.clusterName=example-cluster",
		"snapshotAge.stores[0].name=primary",
		"snapshotAge.stores[0].description=the backup account in the primary region",
		"snapshotAge.stores[0].prefix=raft/",
		"snapshotAge.stores[0].maxAgeSeconds=43200",
		"snapshotAge.stores[0].s3.enabled=true",
		"snapshotAge.stores[0].s3.bucket=example-openbao-backups",
		"snapshotAge.stores[0].s3.region=eu-example-1",
		"snapshotAge.stores[1].name=replica",
		"snapshotAge.stores[1].description=the copy replication keeps in the DR region",
		"snapshotAge.stores[1].prefix=raft/",
		"snapshotAge.stores[1].maxAgeSeconds=50400",
		"snapshotAge.stores[1].s3.enabled=true",
		"snapshotAge.stores[1].s3.bucket=example-openbao-backups-replica",
		"snapshotAge.stores[1].s3.region=eu-example-2",
	}
}

func jobSuccessValues() []string {
	return []string{
		"jobSuccess.enabled=true",
		"jobSuccess.clusterName=example-cluster",
		"jobSuccess.cronJobs[0].name=openbao-restore-check",
		"jobSuccess.cronJobs[0].description=the weekly restore that proves a snapshot still opens",
		"jobSuccess.cronJobs[0].maxAgeSeconds=777600",
		"jobSuccess.alert.sns.enabled=true",
		"jobSuccess.alert.sns.topicArn=example-topic",
		"jobSuccess.alert.sns.region=eu-example-1",
	}
}

func rootGenerationValues() []string {
	return []string{
		"rootGeneration.enabled=true",
		"rootGeneration.clusterName=example-cluster",
		"rootGeneration.baoRole=" + rootWatchRole,
		"auth.mountPath=jwt",
		"auth.audience=" + rootWatchAudience,
		"rootGeneration.alert.sns.enabled=true",
		"rootGeneration.alert.sns.topicArn=example-topic",
		"rootGeneration.alert.sns.region=eu-example-1",
	}
}

// containerScript renders openbao-ops and returns the script of one
// container of one CronJob -- an initContainer or the main one, since a
// watch is a probe and a delivery and both are the chart's.
func containerScript(t *testing.T, helmBinary, cronJob, container string, values ...string) (string, []string) {
	t.Helper()

	args := []string{"template", "watch", opsChart, "--namespace", watchNamespace}
	for _, value := range values {
		args = append(args, "--set", value)
	}

	rendered, err := exec.Command(helmBinary, args...).CombinedOutput()
	require.NoError(t, err, "helm template: %s", rendered)

	decoder := yaml.NewDecoder(bytes.NewReader(rendered))

	for {
		var object watchCronJob

		err := decoder.Decode(&object)
		if errors.Is(err, io.EOF) {
			break
		}

		require.NoError(t, err)

		if object.Kind != "CronJob" || object.Metadata.Name != cronJob {
			continue
		}

		spec := object.Spec.JobTemplate.Spec.Template.Spec

		for _, candidate := range append(append([]watchContainer{}, spec.InitContainers...), spec.Containers...) {
			if candidate.Name != container {
				continue
			}

			require.Len(t, candidate.Command, 3, "the chart's own containers are `/bin/sh -ec <script>`")

			environment := make([]string, 0, len(candidate.Env))
			for _, e := range candidate.Env {
				environment = append(environment, e.Name+"="+e.Value)
			}

			return candidate.Command[2], environment
		}
	}

	t.Fatalf("the render has no container %q in CronJob %q", container, cronJob)

	return "", nil
}

// runScript runs a rendered container's script and answers with what it
// printed and its exit code.
//
// The pod's absolute paths are relocated into a temporary directory: a
// test cannot write /work, and those paths are the only thing about these
// scripts a shell on this machine cannot honour as the pod does.
func runScript(t *testing.T, script, work, binDir string, environment []string) (string, int) {
	t.Helper()

	local := strings.NewReplacer(
		"/work/", work+string(os.PathSeparator),
		"/tmp/message", filepath.Join(work, "message"),
		"/tmp/alert.json", filepath.Join(work, "alert.json"),
	).Replace(script)

	command := exec.Command("/bin/sh", "-ec", local)
	command.Env = append(os.Environ(), environment...)

	if binDir != "" {
		command.Env = append(command.Env, "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	}

	out, err := command.CombinedOutput()
	t.Logf("the container said:\n%s", out)

	var exit *exec.ExitError

	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exit):
		return string(out), exit.ExitCode()
	default:
		t.Fatalf("running the container: %v", err)

		return "", -1
	}
}

// writeShim puts a scripted stand-in for one command on the script's PATH.
func writeShim(t *testing.T, binDir, name, body string, code int) {
	t.Helper()

	shim := fmt.Sprintf("#!/bin/sh\n%s\nexit %d\n", body, code)
	require.NoError(t, os.WriteFile(filepath.Join(binDir, name), []byte(shim), 0o755))
}

// TestValuesAreNeverRunAsShell renders every watch with values that would
// execute if anything read them as shell, runs the scripts, and looks for
// what those values would have left behind.
//
// The bug this holds shut was live: a runbook that named a command in
// backticks -- the ordinary way to write one -- was rendered into the
// alert container's script, so the shell RAN it, the command failed, and
// the one sentence that says how to stop what is being reported never
// reached the alert. Helm's `quote` is a double-quoted string, and a
// double-quoted string is still read by the shell.
//
// A value is data. The test is written the way an operator would find out:
// the values here are the shapes a real runbook or description has -- a
// command in backticks, a path in $( ) -- plus a marker that writes a file
// if it is ever evaluated.
func TestValuesAreNeverRunAsShell(t *testing.T) {
	helmBinary := tool(t, "helm")
	proof := filepath.Join(t.TempDir(), "executed")

	// Each of these is a value a person might really write, with one
	// addition that leaves evidence. `sh -c` would create the file.
	hostile := func(what string) string {
		return what + " `touch " + proof + "` and $(touch " + proof + ")"
	}

	cluster := hostile("kernel")
	runbook := hostile("cancel it with bao operator generate-root -cancel")
	description := hostile("the backup account")

	values := []string{
		"snapshotAge.enabled=true",
		"snapshotAge.clusterName=" + cluster,
		"snapshotAge.stores[0].name=primary",
		"snapshotAge.stores[0].description=" + description,
		"snapshotAge.stores[0].prefix=raft/",
		"snapshotAge.stores[0].maxAgeSeconds=43200",
		"snapshotAge.stores[0].s3.enabled=true",
		"snapshotAge.stores[0].s3.bucket=example-openbao-backups",
		"snapshotAge.stores[0].s3.region=eu-example-1",
		"snapshotAge.alert.sns.enabled=true",
		"snapshotAge.alert.sns.topicArn=example-topic",
		"snapshotAge.alert.sns.region=eu-example-1",
		"snapshotAge.alert.sns.runbook=" + runbook,
	}

	t.Run("a store's description reaches the report as text", func(t *testing.T) {
		script, environment := containerScript(t, helmBinary, "openbao-snapshot-age", "check", values...)

		work := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(work, "newest"), 0o755))
		require.NoError(t, os.Mkdir(filepath.Join(work, "error"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(work, "newest", "primary"),
			[]byte("raft/20200101T000000Z.snap"), 0o644))

		out, code := runScript(t, script, work, "", environment)
		require.Equal(t, 0, code, out)

		report, err := os.ReadFile(filepath.Join(work, "alert"))
		require.NoError(t, err)
		assert.Contains(t, string(report), description, "the description a person wrote is what the report says")
		assert.Contains(t, string(report), cluster, "and so is the cluster's name")
		assert.NoFileExists(t, proof, "a value was evaluated by the shell that was meant to print it")
	})

	t.Run("a runbook reaches the channel as text", func(t *testing.T) {
		script, environment := containerScript(t, helmBinary, "openbao-snapshot-age", "alert", values...)

		binDir := t.TempDir()
		received := commandShim(t, binDir, "aws")

		work := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(work, "alert"), []byte("a summary\nand why\n"), 0o644))

		_, code := runScript(t, script, work, binDir, environment)
		assert.NotEqual(t, 0, code, "a report delivered fails the run")

		sent := received()
		require.Len(t, sent, 1)

		reference := strings.TrimPrefix(strings.Split(sent[0].body, "\n")[7], "file://")
		message, err := os.ReadFile(reference)
		require.NoError(t, err)
		assert.Contains(t, string(message), runbook, "the runbook is delivered, backticks and all")
		assert.NoFileExists(t, proof, "the runbook was evaluated by the shell that was meant to send it")
	})

	t.Run("the root watch names its role and mount as text", func(t *testing.T) {
		script, environment := containerScript(t, helmBinary, "openbao-root-generation", "read",
			"rootGeneration.enabled=true",
			"rootGeneration.clusterName="+cluster,
			"rootGeneration.alert.sns.enabled=true",
			"rootGeneration.alert.sns.topicArn=example-topic",
			"rootGeneration.alert.sns.region=eu-example-1",
		)

		binDir := t.TempDir()
		// A login that fails is the blind path, which is the one that
		// quotes the role, the mount and the cluster back at the reader.
		writeShim(t, binDir, "bao", "echo 'connection refused' >&2", 1)

		work := t.TempDir()

		out, code := runScript(t, script, work, binDir, environment)
		require.Equal(t, 0, code, out)

		report, err := os.ReadFile(filepath.Join(work, "alert"))
		require.NoError(t, err)
		assert.Contains(t, string(report), cluster)
		assert.NoFileExists(t, proof, "a value was evaluated by the shell that was meant to print it")
	})
}
