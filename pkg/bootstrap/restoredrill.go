package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// holdScript is what the drill pod's last container runs: it initializes
// the scratch server with a throwaway recovery key, restores the snapshot
// over it, and waits. The scratch root token never leaves the pod and dies
// with the restore; from then on only what the snapshot grants works.
const holdScript = `wait_for() {
  i=0
  while [ "$i" -lt 90 ]; do
    rc=0
    bao status >/dev/null 2>&1 || rc=$?
    case "$1:$rc" in any:0|any:2|unsealed:0) return 0 ;; esac
    i=$((i + 1))
    sleep 2
  done
  echo "the scratch server never became $1 (bao status exit $rc)"
  return 1
}
wait_for any
BAO_TOKEN=$(bao operator init -recovery-shares=1 -recovery-threshold=1 -format=json |
  sed -n 's/^ *"root_token": *"\([^"]*\)".*/\1/p')
[ -n "$BAO_TOKEN" ] || { echo "initializing the scratch server returned no root token"; exit 1; }
export BAO_TOKEN
wait_for unsealed
bao operator raft snapshot restore -force /work/openbao.snap
unset BAO_TOKEN
wait_for unsealed
echo "drill copy ready: $(cat /work/key)"
exec sleep %d
`

const (
	readyPrefix = "drill copy ready"
	// DefaultDrillHold is how long the scratch pod lives at the latest.
	DefaultDrillHold = 3 * time.Hour
)

var bucketFlag = regexp.MustCompile(`--bucket ([^ ]+)`)

// RestoreDrill is the rebuild drill: a scratch pod that restores the newest
// snapshot into a throwaway server, so an operator can look at a copy of the
// data without touching the live cluster.
//
// The pod is the weekly restore check's own pod spec, read from the live
// CronJob, so image, seal and snapshot fetch are what that check proves every
// week. Only the last container differs: it restores and then waits for the
// operator instead of checking and exiting. The copy holds every secret in the
// snapshot; it listens on loopback, should admit no ingress (a network policy
// the caller owns), and dies with the pod, at the latest after Hold.
//
// Nothing here reads a secret: the pod is built from the CronJob's spec and
// the only thing printed is the copy's readiness line.
type RestoreDrill struct {
	// Context is the kube context, Namespace the namespace of the install.
	Context   string
	Namespace string
	// Pod is the scratch pod's name; default openbao-drill.
	Pod string
	// CronJob is the restore check to copy; default openbao-restore-check.
	CronJob string
	// Container is the restore check's checking container; default check.
	Container string
	// LocalPort and RemotePort are the forward's ends; default 18200 and
	// [DefaultAPIPort].
	LocalPort  int
	RemotePort int
	// Hold is the pod's longest life; default [DefaultDrillHold].
	Hold time.Duration
	// Poll is the wait between readiness checks; default 5 seconds. The
	// readiness window is 90 polls.
	Poll time.Duration
	// Kubectl is the binary; default kubectl.
	Kubectl string
	// Stdout and Stderr receive the readiness line and diagnostics; default
	// os.Stdout and os.Stderr.
	Stdout io.Writer
	Stderr io.Writer
	// Run runs kubectl with args and stdin and returns stdout; a seam for
	// tests. Default: the Kubectl binary.
	Run func(ctx context.Context, stdin []byte, args ...string) ([]byte, error)
}

func (d RestoreDrill) pod() string       { return orString(d.Pod, "openbao-drill") }
func (d RestoreDrill) cronJob() string   { return orString(d.CronJob, "openbao-restore-check") }
func (d RestoreDrill) container() string { return orString(d.Container, "check") }

func (d RestoreDrill) hold() time.Duration {
	if d.Hold == 0 {
		return DefaultDrillHold
	}

	return d.Hold
}

func (d RestoreDrill) poll() time.Duration {
	if d.Poll == 0 {
		return 5 * time.Second
	}

	return d.Poll
}

func orString(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}

func (d RestoreDrill) stdout() io.Writer {
	if d.Stdout == nil {
		return os.Stdout
	}

	return d.Stdout
}

func (d RestoreDrill) stderr() io.Writer {
	if d.Stderr == nil {
		return os.Stderr
	}

	return d.Stderr
}

func (d RestoreDrill) kubectlArgs(args ...string) []string {
	base := []string{}
	if d.Context != "" {
		base = append(base, "--context", d.Context)
	}

	return append(append(base, "-n", d.Namespace), args...)
}

func (d RestoreDrill) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	if d.Run != nil {
		return d.Run(ctx, stdin, d.kubectlArgs(args...)...)
	}

	cmd := exec.CommandContext(ctx, orString(d.Kubectl, "kubectl"), d.kubectlArgs(args...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}

	return out, nil
}

// BuildPod turns the restore check CronJob (as JSON) into the drill pod.
func (d RestoreDrill) BuildPod(cronJobJSON []byte) ([]byte, error) {
	var cronJob struct {
		Metadata struct {
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			JobTemplate struct {
				Spec struct {
					Template struct {
						Spec map[string]any `json:"spec"`
					} `json:"template"`
				} `json:"spec"`
			} `json:"jobTemplate"`
		} `json:"spec"`
	}

	if err := json.Unmarshal(cronJobJSON, &cronJob); err != nil {
		return nil, fmt.Errorf("parse the %s CronJob: %w", d.cronJob(), err)
	}

	spec := cronJob.Spec.JobTemplate.Spec.Template.Spec
	if spec == nil {
		return nil, fmt.Errorf("the %s CronJob has no pod template", d.cronJob())
	}

	spec["activeDeadlineSeconds"] = int64(d.hold().Seconds())

	if err := d.waitForNetworkPolicy(spec); err != nil {
		return nil, err
	}

	if err := d.holdContainer(spec); err != nil {
		return nil, err
	}

	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      d.pod(),
			"namespace": cronJob.Metadata.Namespace,
			"labels":    map[string]any{"app.kubernetes.io/name": d.pod(), "app.kubernetes.io/part-of": "openbao"},
			// The node pool may be volatile; an operator is mid-drill on this pod.
			"annotations": map[string]any{"karpenter.sh/do-not-disrupt": "true"},
		},
		"spec": spec,
	}

	return json.Marshal(pod)
}

// waitForNetworkPolicy prefixes the fetch init container with a wait for the
// bucket on short timeouts: network policy reaches a new pod a few seconds
// after it starts, and a first AWS call dropped in that window hangs for
// minutes on the CLI default timeouts.
func (d RestoreDrill) waitForNetworkPolicy(spec map[string]any) error {
	inits, _ := spec["initContainers"].([]any)

	for _, item := range inits {
		container, _ := item.(map[string]any)
		if container["name"] != "fetch" {
			continue
		}

		command, _ := container["command"].([]any)
		if len(command) == 0 {
			return errors.New("the fetch init container has no command")
		}

		last, _ := command[len(command)-1].(string)

		match := bucketFlag.FindStringSubmatch(last)
		if match == nil {
			return errors.New("the fetch init container's command names no --bucket")
		}

		wait := "until aws s3api list-objects-v2 --bucket " + match[1] +
			" --prefix raft/ --max-items 1 --cli-connect-timeout 3 --cli-read-timeout 5 >/dev/null 2>&1; " +
			"do echo \"waiting for the network policy\"; sleep 2; done\n"
		command[len(command)-1] = wait + last
	}

	return nil
}

// holdContainer replaces the containers by the restore check's checking one,
// renamed hold and running the hold script.
func (d RestoreDrill) holdContainer(spec map[string]any) error {
	containers, _ := spec["containers"].([]any)

	for _, item := range containers {
		container, _ := item.(map[string]any)
		if container["name"] != d.container() {
			continue
		}

		container["name"] = "hold"
		container["command"] = []any{"/bin/sh", "-ec", fmt.Sprintf(holdScript, int64(d.hold().Seconds()))}
		spec["containers"] = []any{container}

		return nil
	}

	return fmt.Errorf("the %s CronJob has no %q container to hold the drill copy in", d.cronJob(), d.container())
}

// Start creates the pod and waits until the copy is restored and ready.
func (d RestoreDrill) Start(ctx context.Context) error {
	if _, err := d.run(ctx, nil, "get", "pod", d.pod()); err == nil {
		return fmt.Errorf("%s already exists; stop it first", d.pod())
	}

	cronJob, err := d.run(ctx, nil, "get", "cronjob", d.cronJob(), "-o", "json")
	if err != nil {
		return err
	}

	pod, err := d.BuildPod(cronJob)
	if err != nil {
		return err
	}

	if _, err := d.run(ctx, pod, "apply", "-f", "-"); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(d.stderr(), "waiting for the restore (fetch, unseal, restore)...")

	for range 90 {
		logs, _ := d.run(ctx, nil, "logs", d.pod(), "-c", "hold")
		if line := readyLine(logs); line != "" {
			_, _ = fmt.Fprintln(d.stdout(), line)

			return nil
		}

		phase, err := d.run(ctx, nil, "get", "pod", d.pod(), "-o", "jsonpath={.status.phase}")
		if err == nil && strings.TrimSpace(string(phase)) == "Failed" {
			d.dumpLogs(ctx)

			return errors.New("the drill pod failed")
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for the drill copy: %w", ctx.Err())
		case <-time.After(d.poll()):
		}
	}

	d.dumpLogs(ctx)

	return fmt.Errorf("the drill copy was not ready after %s", 90*d.poll())
}

func readyLine(logs []byte) string {
	for _, line := range strings.Split(string(logs), "\n") {
		if strings.HasPrefix(line, readyPrefix) {
			return line
		}
	}

	return ""
}

// dumpLogs prints the pod's logs, scrubbed of anything token-shaped.
func (d RestoreDrill) dumpLogs(ctx context.Context) {
	logs, _ := d.run(ctx, nil, "logs", d.pod(), "--all-containers")

	_, _ = fmt.Fprintln(d.stderr(), (*redactor)(nil).scrub(string(logs)))
}

// Forward port-forwards the drill pod's loopback API to 127.0.0.1 and blocks
// until the context ends or kubectl exits.
func (d RestoreDrill) Forward(ctx context.Context) error {
	local := d.LocalPort
	if local == 0 {
		local = 18200
	}

	remote := d.RemotePort
	if remote == 0 {
		remote = DefaultAPIPort
	}

	cmd := exec.CommandContext(ctx, orString(d.Kubectl, "kubectl"),
		d.kubectlArgs("port-forward", "pod/"+d.pod(), strconv.Itoa(local)+":"+strconv.Itoa(remote))...)
	cmd.Stdout, cmd.Stderr = d.stdout(), d.stderr()

	return cmd.Run()
}

// Stop deletes the pod, and the copy with it.
func (d RestoreDrill) Stop(ctx context.Context) error {
	_, err := d.run(ctx, nil, "delete", "pod", d.pod(), "--ignore-not-found", "--wait=true")

	return err
}
