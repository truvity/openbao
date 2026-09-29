package serverpreset

import (
	"fmt"
	"strings"
)

// RetrySidecarOptions tunes RetrySidecarContainer. Every field has a
// working default (the zero value); set one only to depart from it.
type RetrySidecarOptions struct {
	// Image is the container's image — the server's own image, by
	// convention (as tlsReload, openbao-ops's certificate-reload sidecar,
	// also runs the server's image): it already carries sh, wget, tr and
	// kill, and keeping it equal to the server's own tag is what proves a
	// restore and a snapshot ran the same `bao` (docs/server.md,
	// "Image").
	Image string
	// APIPort is the port `bao server`'s own listener answers on, dialled
	// over loopback. Default 8200.
	APIPort int
	// HealthTimeoutSeconds is how long the sidecar waits for the
	// server's OWN listener before ever sending it a signal — SIGHUP's
	// default disposition terminates a process that has not installed a
	// handler for it yet, so signalling a server that has not started
	// listening restarts the container instead of retrying anything.
	// Default 300 (5 minutes).
	HealthTimeoutSeconds int
	// Attempts and IntervalSeconds bound the retry loop once the server
	// is healthy: SIGHUP, wait IntervalSeconds, check every plugin's
	// Command() file again, until every one exists or Attempts run out.
	// Defaults: 20 attempts, 30 seconds apart — 10 minutes, long enough
	// for a network policy agent to admit a fresh pod's egress the way
	// it was observed to (docs/server.md's plugin rollout runbook).
	Attempts        int
	IntervalSeconds int
	// VolumeName is the plugin directory's volume — the same one
	// PluginVolume/PluginVolumeMount name — mounted here read-only: the
	// sidecar only ever checks for a file, never writes one.
	VolumeName string
	// PluginDirectory is where the sidecar looks for each plugin's
	// Command() file. Empty: Config.PluginDirectory (or
	// DefaultPluginDirectory).
	PluginDirectory string
}

const (
	defaultAPIPort              = 8200
	defaultHealthTimeoutSeconds = 300
	defaultRetryAttempts        = 20
	defaultRetryIntervalSeconds = 30
)

func (o RetrySidecarOptions) apiPort() int {
	if o.APIPort == 0 {
		return defaultAPIPort
	}

	return o.APIPort
}

func (o RetrySidecarOptions) healthTimeoutSeconds() int {
	if o.HealthTimeoutSeconds == 0 {
		return defaultHealthTimeoutSeconds
	}

	return o.HealthTimeoutSeconds
}

func (o RetrySidecarOptions) attempts() int {
	if o.Attempts == 0 {
		return defaultRetryAttempts
	}

	return o.Attempts
}

func (o RetrySidecarOptions) intervalSeconds() int {
	if o.IntervalSeconds == 0 {
		return defaultRetryIntervalSeconds
	}

	return o.IntervalSeconds
}

// RetrySidecarContainer is the fragment that makes a fresh pod's
// declarative plugin download actually finish, for every architecture
// this package supports (it shells out to sh, tr, kill and wget — no
// architecture-specific tooling): observed live, a fresh pod's FIRST
// download times out because whatever admits its egress has not caught up
// with the new pod yet, plugin_download_behavior "continue" starts the
// server anyway with that plugin simply missing, and nothing retries it
// on its own. A SIGHUP re-runs the SAME declarative download and
// registration from the server's current config — but the server copies
// its config to a scratch file at startup and never re-reads the mounted
// one, so this is a RETRY of the same attempt, never a way to pick up a
// changed config.
//
// It requires shareProcessNamespace: true on the pod (it signals the
// `bao server` process by walking /proc), exactly as tlsReload
// (charts/openbao-ops) does — a pod that runs both sets it once. Renders
// an error when Plugins is empty: a server with nothing to download has
// nothing for this sidecar to retry, so a caller should not add it to
// extraContainers unconditionally regardless of whether any plugin is
// configured — which is also why Config.Values does not add it for that
// caller automatically the way it adds the plugin volume.
func (c *Config) RetrySidecarContainer(opts RetrySidecarOptions) (map[string]any, error) {
	if len(c.Plugins) == 0 {
		return nil, fmt.Errorf("RetrySidecarContainer: Plugins is empty — nothing for a retry sidecar to retry")
	}

	if strings.TrimSpace(opts.Image) == "" {
		return nil, fmt.Errorf("RetrySidecarContainer: Image is required")
	}

	if strings.TrimSpace(opts.VolumeName) == "" {
		return nil, fmt.Errorf("RetrySidecarContainer: VolumeName is required")
	}

	dir := opts.PluginDirectory
	if dir == "" {
		dir = c.pluginDirectory()
	}

	script := c.retrySidecarScript(dir, opts)

	return map[string]any{
		"name":    "plugin-retry",
		"image":   opts.Image,
		"command": []any{"/bin/sh", "-c"},
		"args":    []any{script},
		"volumeMounts": []any{
			map[string]any{"name": opts.VolumeName, "mountPath": dir, "readOnly": true},
		},
	}, nil
}

// retrySidecarScript is a POSIX /bin/sh script, deliberately: the same
// shell tlsReload's fragment already assumes the server's image carries.
func (c *Config) retrySidecarScript(dir string, opts RetrySidecarOptions) string {
	var b strings.Builder

	fmt.Fprintf(&b, "port=%d\n", opts.apiPort())
	fmt.Fprintf(&b, "health_timeout=%d\n", opts.healthTimeoutSeconds())
	fmt.Fprintf(&b, "attempts=%d\n", opts.attempts())
	fmt.Fprintf(&b, "interval=%d\n", opts.intervalSeconds())
	b.WriteString("\n")
	b.WriteString(`# Never signal bao before it is serving: SIGHUP's default action
# terminates a process that has not installed its handler yet, which
# would restart the server container instead of retrying anything.
waited=0
while [ "$waited" -lt "$health_timeout" ]; do
  wget -q -T 2 -O /dev/null --no-check-certificate \
    "https://127.0.0.1:$port/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200" 2>/dev/null && break
  waited=$((waited + 5))
  sleep 5
done

signal_bao() {
  for p in /proc/[0-9]*; do
    cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
    case "$cmd" in
      "bao server "*) kill -HUP "${p#/proc/}" && echo "plugin-retry: reloaded bao (pid ${p#/proc/})" ;;
    esac
  done
}

`)

	fmt.Fprintf(&b, "plugins=\"%s\"\n", strings.Join(pluginCommandPaths(c.Plugins, dir), " "))
	b.WriteString(`
attempt=1
while [ "$attempt" -le "$attempts" ]; do
  missing=0
  for plugin in $plugins; do
    [ -e "$plugin" ] || missing=1
  done
  [ "$missing" -eq 0 ] && break
  echo "plugin-retry: attempt $attempt/$attempts, reloading bao to retry the plugin download"
  signal_bao
  sleep "$interval"
  attempt=$((attempt + 1))
done

for plugin in $plugins; do
  if [ -e "$plugin" ]; then
    echo "plugin-retry: $plugin present"
  else
    echo "plugin-retry: giving up after $attempts attempts, $plugin still missing -- a later restart tries again"
  fi
done

# Idle rather than exit either way: exiting (0 or not) only earns this
# container a restart under the pod's own restartPolicy, which would
# repeat the same wait-then-give-up cycle forever instead of holding the
# result it already logged.
while true; do
  sleep 3600
done
`)

	return b.String()
}

func pluginCommandPaths(plugins []Plugin, dir string) []string {
	out := make([]string, len(plugins))
	for i, p := range plugins {
		out[i] = strings.TrimSuffix(dir, "/") + "/" + p.Command()
	}

	return out
}
