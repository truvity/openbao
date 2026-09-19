package apply

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	// DefaultSnapshotWait outlasts a snapshot job's usual deadline (900 s
	// in openbao-ops), so the job reports Failed before the wait gives up.
	DefaultSnapshotWait = 16 * time.Minute
	// DefaultSnapshotPoll is how often the job is checked.
	DefaultSnapshotPoll = 5 * time.Second
)

type (
	// Kubectl runs kubectl and returns its standard output.
	Kubectl func(ctx context.Context, args ...string) ([]byte, error)

	// SnapshotJob takes a Raft snapshot before an apply changes anything:
	// a Job created from the snapshot CronJob (openbao-ops renders one),
	// waited on until it has stored the snapshot. Pass its Run as
	// Options.BeforeApply.
	//
	// It steps aside, loudly, in two cases only: SkipEnv names a reason,
	// or the CronJob has never succeeded. The second is a fresh install,
	// where the very apply being guarded creates the job's OpenBAO role.
	// Once one snapshot has landed, a failing snapshot stops the apply.
	SnapshotJob struct {
		Kubectl Kubectl
		// Namespace and CronJob name the snapshot CronJob.
		Namespace string
		CronJob   string
		// SkipEnv is the environment variable that, set to a reason,
		// applies without a snapshot: for when the snapshot path itself is
		// what the apply repairs. Empty for no way to skip.
		SkipEnv string
		// Wait and Poll default to DefaultSnapshotWait and
		// DefaultSnapshotPoll.
		Wait time.Duration
		Poll time.Duration
		// Logger defaults to slog.Default(); Now to time.Now.
		Logger *slog.Logger
		Now    func() time.Time
	}
)

// KubectlWith runs the kubectl on PATH against a kubeconfig; stderr is
// folded into the error.
func KubectlWith(kubeconfig string) Kubectl {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "kubectl", args...)
		cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)

		var stderr strings.Builder

		cmd.Stderr = &stderr

		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("kubectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}

		return out, nil
	}
}

// Run takes the snapshot, or says loudly why it does not.
func (j SnapshotJob) Run(ctx context.Context) error {
	logger := j.Logger
	if logger == nil {
		logger = slog.Default()
	}

	now := time.Now
	if j.Now != nil {
		now = j.Now
	}

	if j.Kubectl == nil || j.Namespace == "" || j.CronJob == "" {
		return fmt.Errorf("pre-apply snapshot: kubectl, the namespace and the CronJob are required")
	}

	if j.SkipEnv != "" {
		if reason := strings.TrimSpace(os.Getenv(j.SkipEnv)); reason != "" {
			logger.WarnContext(ctx, "applying WITHOUT a pre-apply snapshot", slog.String("skip_reason", reason))

			return nil
		}
	}

	last, err := j.Kubectl(ctx, "get", "cronjob", j.CronJob, "-n", j.Namespace, "-o", "jsonpath={.status.lastSuccessfulTime}")
	if err != nil {
		return fmt.Errorf("pre-apply snapshot: %w", err)
	}

	if strings.TrimSpace(string(last)) == "" {
		logger.WarnContext(ctx, "no snapshot has ever succeeded; applying without one (a fresh install gets the job's role from this apply)",
			slog.String("cronjob", j.Namespace+"/"+j.CronJob))

		return nil
	}

	job := j.CronJob + "-pre-apply-" + now().UTC().Format("20060102150405")
	if _, err := j.Kubectl(ctx, "create", "job", job, "--from=cronjob/"+j.CronJob, "-n", j.Namespace); err != nil {
		return fmt.Errorf("pre-apply snapshot: %w", err)
	}

	logger.InfoContext(ctx, "taking a pre-apply snapshot", slog.String("job", j.Namespace+"/"+job))

	return j.waitFor(ctx, job)
}

// waitFor polls a Job until it is Complete or Failed. Complete and Failed
// are the terminal conditions; SuccessCriteriaMet and FailureTarget come
// first and are not.
func (j SnapshotJob) waitFor(ctx context.Context, job string) error {
	wait, poll := j.Wait, j.Poll
	if wait <= 0 {
		wait = DefaultSnapshotWait
	}

	if poll <= 0 {
		poll = DefaultSnapshotPoll
	}

	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	logs := fmt.Sprintf("kubectl -n %s logs job/%s --all-containers", j.Namespace, job)

	skip := ""
	if j.SkipEnv != "" {
		skip = fmt.Sprintf(", or set %s=<reason> to apply without it", j.SkipEnv)
	}

	for {
		out, err := j.Kubectl(ctx, "get", "job", job, "-n", j.Namespace,
			"-o", `jsonpath={range .status.conditions[?(@.status=="True")]}{.type}{"\n"}{end}`)
		if err != nil {
			return fmt.Errorf("pre-apply snapshot %s: %w", job, err)
		}

		for condition := range strings.FieldsSeq(string(out)) {
			switch condition {
			case "Complete":
				return nil
			case "Failed":
				return fmt.Errorf("pre-apply snapshot %s failed; see `%s`%s", job, logs, skip)
			}
		}

		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("pre-apply snapshot %s did not finish in %s; see `%s`", job, wait, logs)
			}

			return ctx.Err()
		case <-time.After(poll):
		}
	}
}
