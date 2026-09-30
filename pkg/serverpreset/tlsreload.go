package serverpreset

import (
	"fmt"
	"path"
	"strings"
)

// TLSReloadOptions tunes TLSReloadSidecarContainer. Image,
// CertificateFile, CertificateVolume and PluginVolume are required; every
// other field has a working default (the zero value).
type TLSReloadOptions struct {
	// Name is the container's name. Default "tls-reload".
	Name string
	// Image is the container's image — the server's own image, by
	// convention (it already carries sh, wget, cksum, tr and kill), kept
	// equal to the server's tag like [RetrySidecarOptions.Image].
	Image string
	// CertificateFile is the serving certificate the sidecar watches, as
	// the pod mounts it. A checksum change signals the server to reload it.
	CertificateFile string
	// CertificateVolume is the volume that carries CertificateFile; it is
	// mounted read-only at the file's directory.
	CertificateVolume string
	// PluginVolume is the plugin directory's volume (the one
	// PluginVolume/PluginVolumeMount name), mounted read-only.
	PluginVolume string
	// PluginDirectory is where the sidecar looks for the plugin's
	// Command() file. Empty: Config.PluginDirectory (or
	// DefaultPluginDirectory).
	PluginDirectory string
	// APIPort is the port `bao server`'s own listener answers on, dialled
	// over loopback. Default 8200.
	APIPort int
	// HealthTimeoutSeconds is how long the sidecar waits for the server's
	// own listener before it ever signals it (checked every 5 seconds).
	// Default 300.
	HealthTimeoutSeconds int
	// Attempts and IntervalSeconds bound the plugin retry loop: SIGHUP,
	// wait IntervalSeconds, look for the plugin file again, until it
	// exists or Attempts run out. Defaults: 20 attempts, 30 seconds apart.
	Attempts        int
	IntervalSeconds int
	// WatchIntervalSeconds is how often the certificate is checksummed
	// once the retry loop is done. Default 60.
	WatchIntervalSeconds int
	// PluginComment is rendered as shell comments above the plugin path
	// (one `# ` line per line of text). Empty: a one-line default. It is
	// part of the container's args, so a consumer that already runs an
	// equivalent hand-written sidecar passes its own text to keep the
	// pod template unchanged.
	PluginComment string
	// Resources and SecurityContext are copied into the container when
	// non-nil; nil leaves them out of the render (the chart's own defaults
	// then apply).
	Resources       map[string]any
	SecurityContext map[string]any
}

// TLSReloadSidecarContainer is the one sidecar that does both jobs a
// server pod's signalling sidecar has: it retries the declarative plugin
// download (the same health-gated SIGHUP loop as [Config.RetrySidecarContainer],
// which it does not replace) and then watches the serving certificate,
// SIGHUPping `bao server` whenever its checksum changes. The chart runs
// `bao server` under a `/bin/sh -ec` wrapper at PID 1 that swallows
// SIGHUP, so without a sidecar a renewed certificate is never loaded.
//
// It requires shareProcessNamespace: true on the pod (it finds the `bao
// server` process by walking /proc). The script follows one plugin, so the
// Config must declare exactly one of Plugins; use RetrySidecarContainer
// beside a certificate-watch-only sidecar for several. Opt-in: nothing in
// [Config.Values] calls it.
func (c *Config) TLSReloadSidecarContainer(opts TLSReloadOptions) (map[string]any, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	if len(c.Plugins) != 1 {
		return nil, fmt.Errorf("TLSReloadSidecarContainer: Plugins must hold exactly one plugin (got %d); the retry loop follows one plugin file", len(c.Plugins))
	}

	for name, v := range map[string]string{
		"Image": opts.Image, "CertificateFile": opts.CertificateFile,
		"CertificateVolume": opts.CertificateVolume, "PluginVolume": opts.PluginVolume,
	} {
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("TLSReloadSidecarContainer: %s is required", name)
		}
	}

	if !strings.HasPrefix(opts.CertificateFile, "/") {
		return nil, fmt.Errorf("TLSReloadSidecarContainer: CertificateFile %q must be an absolute path", opts.CertificateFile)
	}

	dir := opts.PluginDirectory
	if dir == "" {
		dir = c.pluginDirectory()
	}

	ro := RetrySidecarOptions{APIPort: opts.APIPort, HealthTimeoutSeconds: opts.HealthTimeoutSeconds, Attempts: opts.Attempts, IntervalSeconds: opts.IntervalSeconds}

	watch := opts.WatchIntervalSeconds
	if watch == 0 {
		watch = defaultWatchIntervalSeconds
	}

	comment := opts.PluginComment
	if strings.TrimSpace(comment) == "" {
		comment = "plugin: the <type>-<name>-<version> link the declarative download creates in plugin_directory."
	}

	var cb strings.Builder

	for _, line := range strings.Split(strings.TrimRight(comment, "\n"), "\n") {
		if line == "" {
			cb.WriteString("#\n")

			continue
		}

		cb.WriteString("# " + line + "\n")
	}

	script := strings.NewReplacer(
		"@COMMENT@", cb.String(),
		"@PLUGIN@", strings.TrimSuffix(dir, "/")+"/"+c.Plugins[0].Command(),
		"@HEALTH_CHECKS@", itoa((ro.healthTimeoutSeconds()+4)/5),
		"@HEALTHWAIT@", humanSeconds(ro.healthTimeoutSeconds()),
		"@PORT@", itoa(ro.apiPort()),
		"@ATTEMPTS@", itoa(ro.attempts()),
		"@INTERVAL@", itoa(ro.intervalSeconds()),
		"@PREFIX@", opts.PluginVolume,
		"@CRT@", opts.CertificateFile,
		"@WATCH@", itoa(watch),
		"@CRTNAME@", path.Base(path.Dir(opts.CertificateFile)),
	).Replace(tlsReloadScript)

	name := opts.Name
	if name == "" {
		name = "tls-reload"
	}

	container := map[string]any{
		"name":    name,
		"image":   opts.Image,
		"command": []any{"/bin/sh", "-c"},
		"args":    []any{script},
		"volumeMounts": []any{
			map[string]any{"name": opts.CertificateVolume, "mountPath": path.Dir(opts.CertificateFile), "readOnly": true},
			map[string]any{"name": opts.PluginVolume, "mountPath": dir, "readOnly": true},
		},
	}

	if opts.Resources != nil {
		container["resources"] = opts.Resources
	}

	if opts.SecurityContext != nil {
		container["securityContext"] = opts.SecurityContext
	}

	return container, nil
}

const defaultWatchIntervalSeconds = 60

// humanSeconds spells a whole number of minutes as minutes.
func humanSeconds(n int) string {
	if n%60 == 0 {
		return fmt.Sprintf("%d min", n/60)
	}

	return fmt.Sprintf("%d s", n)
}

// tlsReloadScript is a POSIX /bin/sh script: the server's image carries
// sh, wget, cksum, tr and kill and nothing else this needs.
const tlsReloadScript = `@COMMENT@plugin=@PLUGIN@

# Never signal bao before it is serving: SIGHUP's
# default action terminates a process that has not yet
# installed its handler, which would restart the server
# container. Wait for its own listener first (up to @HEALTHWAIT@).
ready=0
while [ "$ready" -lt @HEALTH_CHECKS@ ]; do
  wget -q -T 2 -O /dev/null --no-check-certificate 'https://127.0.0.1:@PORT@/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200' 2>/dev/null && break
  ready=$((ready + 1))
  sleep 5
done

attempt=1
while [ ! -e "$plugin" ] && [ "$attempt" -le @ATTEMPTS@ ]; do
  echo "@PREFIX@: $plugin not present yet (attempt $attempt/@ATTEMPTS@), reloading bao to retry the plugin download"
  for p in /proc/[0-9]*; do
    cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
    case "$cmd" in
      "bao server "*) kill -HUP "${p#/proc/}" && echo "@PREFIX@: reloaded bao (pid ${p#/proc/}), attempt $attempt/@ATTEMPTS@" ;;
    esac
  done
  sleep @INTERVAL@
  attempt=$((attempt + 1))
done
if [ -e "$plugin" ]; then
  echo "@PREFIX@: $plugin present"
else
  echo "@PREFIX@: giving up after @ATTEMPTS@ attempts, $plugin still not present -- the ordinary TLS-watch loop below will still reload bao on the next certificate change"
fi

crt=@CRT@
last=$(cksum "$crt")
while sleep @WATCH@; do
  cur=$(cksum "$crt") || continue
  [ "$cur" = "$last" ] && continue
  for p in /proc/[0-9]*; do
    cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
    case "$cmd" in
      "bao server "*) kill -HUP "${p#/proc/}" && echo "@CRTNAME@ changed: reloaded bao (pid ${p#/proc/})" ;;
    esac
  done
  last=$cur
done
`
