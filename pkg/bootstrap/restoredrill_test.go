package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const restoreCheckCronJob = `{
  "metadata": {"name": "openbao-restore-check", "namespace": "openbao"},
  "spec": {"jobTemplate": {"spec": {"template": {"spec": {
    "serviceAccountName": "restore",
    "restartPolicy": "Never",
    "initContainers": [
      {"name": "plugin", "command": ["/bin/sh", "-c", "true"]},
      {"name": "fetch", "command": ["/bin/sh", "-ec", "aws s3 cp --bucket snaps s3://x/y /work/openbao.snap"]}
    ],
    "containers": [
      {"name": "check", "image": "openbao:2", "command": ["/bin/sh", "-c", "check"]},
      {"name": "sidecar", "image": "other"}
    ]
  }}}}}
}`

func TestBuildPodTurnsTheRestoreCheckIntoADrillPod(t *testing.T) {
	drill := RestoreDrill{Namespace: "openbao"}

	raw, err := drill.BuildPod([]byte(restoreCheckCronJob))
	require.NoError(t, err)

	var pod struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name        string            `json:"name"`
			Namespace   string            `json:"namespace"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			ActiveDeadlineSeconds int    `json:"activeDeadlineSeconds"`
			ServiceAccountName    string `json:"serviceAccountName"`
			InitContainers        []struct {
				Name    string   `json:"name"`
				Command []string `json:"command"`
			} `json:"initContainers"`
			Containers []struct {
				Name    string   `json:"name"`
				Image   string   `json:"image"`
				Command []string `json:"command"`
			} `json:"containers"`
		} `json:"spec"`
	}

	require.NoError(t, json.Unmarshal(raw, &pod))

	assert.Equal(t, "Pod", pod.Kind)
	assert.Equal(t, "openbao-drill", pod.Metadata.Name)
	assert.Equal(t, "openbao", pod.Metadata.Namespace)
	assert.Equal(t, "true", pod.Metadata.Annotations["karpenter.sh/do-not-disrupt"])
	assert.Equal(t, "openbao-drill", pod.Metadata.Labels["app.kubernetes.io/name"])
	assert.Equal(t, 10800, pod.Spec.ActiveDeadlineSeconds)
	assert.Equal(t, "restore", pod.Spec.ServiceAccountName, "the check's own pod spec carries over")

	require.Len(t, pod.Spec.Containers, 1, "only the checking container remains")
	assert.Equal(t, "hold", pod.Spec.Containers[0].Name)
	assert.Equal(t, "openbao:2", pod.Spec.Containers[0].Image)
	assert.Equal(t, []string{"/bin/sh", "-ec"}, pod.Spec.Containers[0].Command[:2])
	assert.Contains(t, pod.Spec.Containers[0].Command[2], "bao operator raft snapshot restore -force /work/openbao.snap")
	assert.Contains(t, pod.Spec.Containers[0].Command[2], "exec sleep 10800")
	assert.NotContains(t, pod.Spec.Containers[0].Command[2], "%")

	fetch := pod.Spec.InitContainers[1].Command
	assert.Equal(t, "plugin", pod.Spec.InitContainers[0].Name)
	assert.True(t, strings.HasPrefix(fetch[2], "until aws s3api list-objects-v2 --bucket snaps --prefix raft/ --max-items 1 "), fetch[2])
	assert.True(t, strings.HasSuffix(fetch[2], "aws s3 cp --bucket snaps s3://x/y /work/openbao.snap"), "the original command follows the wait")
	assert.Equal(t, "/bin/sh", pod.Spec.InitContainers[0].Command[0])
}

func TestBuildPodRefusesWhatItCannotRebuild(t *testing.T) {
	for name, tc := range map[string]struct {
		cronJob string
		want    string
	}{
		"not json":              {cronJob: `{`, want: "parse the openbao-restore-check CronJob"},
		"no pod template":       {cronJob: `{"spec": {}}`, want: "no pod template"},
		"no checking container": {cronJob: podTemplate(`{"containers":[{"name":"x"}]}`), want: `no "check" container`},
		"a fetch with no bucket": {
			cronJob: podTemplate(`{"initContainers":[{"name":"fetch","command":["sh","-c","true"]}],"containers":[{"name":"check"}]}`),
			want:    "names no --bucket",
		},
		"a fetch with no command": {cronJob: podTemplate(`{"initContainers":[{"name":"fetch"}],"containers":[{"name":"check"}]}`), want: "no command"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := RestoreDrill{}.BuildPod([]byte(tc.cronJob))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// kubectlDouble answers the drill's kubectl calls and records them.
type kubectlDouble struct {
	calls   []string
	applied []byte
	exists  bool
	logs    []string
	phase   string
	// deleteFails makes the pod delete fail; cancel is called on the first
	// logs call, to cancel the caller's context mid-wait.
	deleteFails bool
	cancel      func()
}

func (k *kubectlDouble) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	k.calls = append(k.calls, strings.Join(args, " "))

	if slices.Contains(args, "delete") && (ctx.Err() != nil || k.deleteFails) {
		return nil, errors.New("delete refused")
	}

	if slices.Contains(args, "logs") && k.cancel != nil {
		k.cancel()
	}

	switch {
	case strings.Contains(strings.Join(args, " "), "get pod openbao-drill -o"):
		return []byte(k.phase), nil
	case strings.Contains(strings.Join(args, " "), "get pod openbao-drill"):
		if k.exists {
			return nil, nil
		}

		return nil, errors.New("not found")
	case strings.Contains(strings.Join(args, " "), "get cronjob"):
		return []byte(restoreCheckCronJob), nil
	case slices.Contains(args, "apply"):
		k.applied = stdin
		k.exists = true

		return nil, nil
	case strings.Contains(strings.Join(args, " "), "logs"):
		if len(k.logs) == 0 {
			return nil, nil
		}

		out := k.logs[0]
		if len(k.logs) > 1 {
			k.logs = k.logs[1:]
		}

		return []byte(out), nil
	}

	return nil, nil
}

func TestRestoreDrillStartWaitsForTheCopyAndStopDeletesIt(t *testing.T) {
	var out, errOut bytes.Buffer

	kubectl := &kubectlDouble{logs: []string{"", "restoring\n", "restored\ndrill copy ready: alias/unseal\n"}, phase: "Running"}
	drill := RestoreDrill{
		Context: "ctx", Namespace: "openbao", Poll: time.Millisecond,
		Stdout: &out, Stderr: &errOut, Run: kubectl.run,
	}

	require.NoError(t, drill.Start(context.Background()))
	assert.Equal(t, "drill copy ready: alias/unseal\n", out.String())
	assert.NotEmpty(t, kubectl.applied)
	assert.Equal(t, "--context ctx -n openbao get pod openbao-drill", kubectl.calls[0])

	// A second start finds the pod and refuses; nothing is applied twice.
	applied := len(kubectl.applied)
	err := drill.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Len(t, kubectl.applied, applied)

	require.NoError(t, drill.Stop(context.Background()))
	assert.Equal(t, "--context ctx -n openbao delete pod openbao-drill --ignore-not-found --wait=true", kubectl.calls[len(kubectl.calls)-1])
}

func TestRestoreDrillStartReportsAFailedPodWithoutTokens(t *testing.T) {
	var errOut bytes.Buffer

	kubectl := &kubectlDouble{logs: []string{"boom with s.leaked-token-abcdefghijklmnop\n"}, phase: "Failed"}
	drill := RestoreDrill{Namespace: "openbao", Poll: time.Millisecond, Stderr: &errOut, Stdout: &bytes.Buffer{}, Run: kubectl.run}

	err := drill.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, errOut.String(), "boom")
	assert.NotContains(t, errOut.String(), "leaked-token")
	assert.Contains(t, fmt.Sprint(kubectl.calls), "logs openbao-drill --all-containers")
}

// podTemplate wraps a pod spec in the CronJob around it.
func podTemplate(spec string) string {
	return `{"spec":{"jobTemplate":{"spec":{"template":{"spec":` + spec + `}}}}}`
}

func deletedAfterApply(calls []string) bool {
	applied := false

	for _, call := range calls {
		if strings.Contains(call, "apply") {
			applied = true
		}

		if applied && strings.Contains(call, "delete pod openbao-drill") {
			return true
		}
	}

	return false
}

// A failed or cancelled Start must not leave a copy of every secret running.
func TestRestoreDrillStartDeletesThePodItCreatedWhenItFails(t *testing.T) {
	t.Run("the pod fails", func(t *testing.T) {
		kubectl := &kubectlDouble{phase: "Failed"}
		drill := RestoreDrill{Namespace: "openbao", Poll: time.Millisecond, Stderr: &bytes.Buffer{}, Run: kubectl.run}

		require.Error(t, drill.Start(context.Background()))
		assert.True(t, deletedAfterApply(kubectl.calls), "%v", kubectl.calls)
	})

	t.Run("the caller cancels", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		kubectl := &kubectlDouble{phase: "Running", cancel: cancel}
		drill := RestoreDrill{Namespace: "openbao", Poll: time.Millisecond, Stderr: &bytes.Buffer{}, Run: kubectl.run}

		err := drill.Start(ctx)
		require.ErrorIs(t, err, context.Canceled)
		assert.True(t, deletedAfterApply(kubectl.calls), "the delete must run on a context that survives the cancellation: %v", kubectl.calls)
		assert.NotContains(t, err.Error(), "could NOT be deleted")
	})

	t.Run("the delete fails too", func(t *testing.T) {
		kubectl := &kubectlDouble{phase: "Failed", deleteFails: true}
		drill := RestoreDrill{Namespace: "openbao", Poll: time.Millisecond, Stderr: &bytes.Buffer{}, Run: kubectl.run}

		err := drill.Start(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could NOT be deleted")
		assert.Contains(t, err.Error(), "kubectl -n openbao delete pod openbao-drill")
	})
}

func TestRestoreDrillHoldIsCapped(t *testing.T) {
	for _, hold := range []time.Duration{MaxDrillHold + time.Second, -time.Hour} {
		_, err := RestoreDrill{Hold: hold}.BuildPod([]byte(restoreCheckCronJob))
		require.Error(t, err, hold)
	}

	_, err := RestoreDrill{Hold: MaxDrillHold}.BuildPod([]byte(restoreCheckCronJob))
	require.NoError(t, err)
}
