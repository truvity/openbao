package apply_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/openbao/pkg/apply"
)

const skipEnv = "EXAMPLE_SKIP_SNAPSHOT"

// fakeKubectl answers by the verb and kind it is asked about, and records
// every call.
type fakeKubectl struct {
	lastSuccessful string
	cronJobErr     error
	conditions     []string // one answer per poll; the last repeats
	calls          []string
}

func (f *fakeKubectl) run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))

	switch {
	case args[0] == "get" && args[1] == "cronjob":
		return []byte(f.lastSuccessful), f.cronJobErr
	case args[0] == "create":
		return nil, nil
	case args[0] == "get" && args[1] == "job":
		answer := f.conditions[0]
		if len(f.conditions) > 1 {
			f.conditions = f.conditions[1:]
		}

		return []byte(answer), nil
	}

	return nil, errors.New("unexpected kubectl " + strings.Join(args, " "))
}

func takeSnapshot(kubectl *fakeKubectl) error {
	return apply.SnapshotJob{
		Kubectl:   kubectl.run,
		Namespace: "openbao",
		CronJob:   "openbao-snapshot",
		SkipEnv:   skipEnv,
		Poll:      time.Millisecond,
		Logger:    slog.New(slog.DiscardHandler),
		Now:       func() time.Time { return time.Date(2026, 9, 13, 15, 4, 5, 0, time.UTC) },
	}.Run(context.Background())
}

func TestSnapshotWaitsForTheJobToComplete(t *testing.T) {
	kubectl := &fakeKubectl{
		lastSuccessful: "2026-09-13T12:17:40Z",
		conditions:     []string{"", "SuccessCriteriaMet\n", "SuccessCriteriaMet\nComplete\n"},
	}

	require.NoError(t, takeSnapshot(kubectl))

	want := "create job openbao-snapshot-pre-apply-20260913150405 --from=cronjob/openbao-snapshot -n openbao"
	require.Len(t, kubectl.calls, 5, "the CronJob read, the Job created, and three polls")
	assert.Equal(t, want, kubectl.calls[1])
}

func TestSnapshotStopsTheApplyWhenTheJobFails(t *testing.T) {
	kubectl := &fakeKubectl{lastSuccessful: "2026-09-13T12:17:40Z", conditions: []string{"FailureTarget\n", "FailureTarget\nFailed\n"}}

	err := takeSnapshot(kubectl)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logs job/openbao-snapshot-pre-apply-20260913150405", "the failure names the job's logs")
	assert.Contains(t, err.Error(), skipEnv, "and the way around")
}

func TestSnapshotStepsAsideOnAFreshInstall(t *testing.T) {
	kubectl := &fakeKubectl{}

	require.NoError(t, takeSnapshot(kubectl))
	assert.Len(t, kubectl.calls, 1, "only the CronJob read: nothing to run before the job's role exists")
}

func TestSnapshotNeedsTheCronJob(t *testing.T) {
	kubectl := &fakeKubectl{cronJobErr: errors.New(`cronjobs.batch "openbao-snapshot" not found`)}

	require.Error(t, takeSnapshot(kubectl), "a missing CronJob must stop the apply")
}

func TestSnapshotSkipsOnlyWithAReason(t *testing.T) {
	t.Setenv(skipEnv, "the snapshot role is what this apply repairs")

	kubectl := &fakeKubectl{lastSuccessful: "2026-09-13T12:17:40Z"}
	require.NoError(t, takeSnapshot(kubectl))
	assert.Empty(t, kubectl.calls)
}

func TestSnapshotRefusesAnIncompleteJob(t *testing.T) {
	require.Error(t, apply.SnapshotJob{Namespace: "openbao", CronJob: "openbao-snapshot"}.Run(context.Background()))
}
