package serverpreset

import (
	"fmt"
	"strings"
)

// SealPluginSourceVolume is the pod volume that makes the seal plugin's
// image visible to the init container: a Kubernetes image volume
// (`volumes[].image`), which the KUBELET pulls — by digest, through
// whatever registry mirror the node is configured with — and mounts
// read-only. The pod itself never needs egress to a registry for it.
//
// Only the init container mounts it. Requires a cluster with image volumes
// (Kubernetes 1.35+, or 1.31+ with the ImageVolume feature gate) and a
// runtime that supports them (containerd 2.1+, CRI-O 1.31+); on anything
// older the pod is not admitted, which is the loud failure a seal wants.
//
// Only meaningful with DeliveryInitCopy; nil-safe: it returns nil without
// a Seal.Plugin.
func (c *Config) SealPluginSourceVolume() map[string]any {
	sp := c.Seal.Plugin
	if sp == nil {
		return nil
	}

	policy := sp.PullPolicy
	if policy == "" {
		policy = "IfNotPresent"
	}

	return map[string]any{
		"name": sp.sourceVolume(),
		"image": map[string]any{
			"reference":  sp.Image + "@" + sp.Digest,
			"pullPolicy": policy,
		},
	}
}

// SealPluginInitContainer is the init container that installs the seal
// plugin: it copies the binary from the image volume (SealPluginSourceVolume)
// into the plugin directory and exits, before `bao server` starts. Nothing
// here touches the network, so the fresh-pod egress race that troubled the
// auth plugin's download cannot happen, and nothing here waits for the
// server: the seal has no Ready to wait for.
//
// The copy is atomic (temp file, then rename) and made executable, because
// the image carries the binary as 0644. It runs on every pod start, over
// whatever an earlier start left. pluginVolume names the emptyDir
// (PluginVolume/PluginVolumeMount), mounted read-write at the plugin
// directory.
//
// Errors without a Seal.Plugin or with DeliveryPreinstalled: there is
// nothing to install.
func (c *Config) SealPluginInitContainer(pluginVolume string) (map[string]any, error) {
	sp := c.Seal.Plugin
	if sp == nil {
		return nil, fmt.Errorf("SealPluginInitContainer: Seal.Plugin is nil — nothing to install")
	}

	if err := c.validateSealPlugin(); err != nil {
		return nil, err
	}

	if sp.delivery() != DeliveryInitCopy {
		return nil, fmt.Errorf("SealPluginInitContainer: Delivery is %q — only %q installs anything", sp.delivery(), DeliveryInitCopy)
	}

	if strings.TrimSpace(pluginVolume) == "" {
		return nil, fmt.Errorf("SealPluginInitContainer: pluginVolume is required")
	}

	dir := strings.TrimSuffix(c.pluginDirectory(), "/")

	return map[string]any{
		"name":    "seal-plugin-install",
		"image":   sp.CopyImage,
		"command": []any{"/bin/sh", "-c"},
		"args":    []any{c.sealPluginScript(dir)},
		"securityContext": map[string]any{
			"allowPrivilegeEscalation": false,
			"readOnlyRootFilesystem":   true,
			"capabilities":             map[string]any{"drop": []any{"ALL"}},
		},
		"volumeMounts": []any{
			map[string]any{"name": pluginVolume, "mountPath": c.pluginDirectory()},
			map[string]any{"name": sp.sourceVolume(), "mountPath": sealPluginSourceMount, "readOnly": true},
		},
	}, nil
}

func (c *Config) sealPluginScript(dir string) string {
	sp := c.Seal.Plugin

	var b strings.Builder

	fmt.Fprintf(&b, "set -eu\n")
	fmt.Fprintf(&b, "src=%s/%s\n", sealPluginSourceMount, sp.binaryName())
	fmt.Fprintf(&b, "dst=%s/%s\n", dir, c.SealPluginCommand())
	b.WriteString(`
if [ ! -s "$src" ]; then
  echo "seal-plugin-install: $src is missing or empty -- the image does not carry the plugin binary at its root" >&2
  exit 1
fi
`)

	if sum := c.sealPluginChecksum(); sum != "" {
		// Verified before anything is installed: a wrong binary is a failed
		// init container, never a server that runs it.
		fmt.Fprintf(&b, "echo \"%s  $src\" | sha256sum -c - >/dev/null || "+
			"{ echo \"seal-plugin-install: $src does not match the pinned checksum\" >&2; exit 1; }\n", sum)
	}

	b.WriteString(`
# Copy beside the destination and rename, so a start interrupted here never
# leaves a half-written binary under the name the server will execute. The
# image carries the binary as 0644.
cp "$src" "$dst.tmp"
chmod 0555 "$dst.tmp"
mv -f "$dst.tmp" "$dst"
echo "seal-plugin-install: installed $dst"
`)

	return b.String()
}

// RestoreCheckPluginVolume is the name charts/openbao-ops gives the
// restore check's writable plugin directory (an emptyDir). The init container
// RestoreCheckValues renders mounts it by this name.
const RestoreCheckPluginVolume = "seal-plugin"

// RestoreCheckValues is the part of charts/openbao-ops' values that gives the
// restore check's scratch server the same seal the real server has, on
// OpenBAO 2.7, where the awskms seal is an external plugin. The scratch
// server is a second `bao server` on the same image, so without this it
// exits "unknown wrapper: awskms".
//
// It returns, ready to merge under `restoreCheck`:
//
//   - sealConfig: SealHCL, the `seal` stanza and the `plugin "kms"` block;
//   - sealPlugin.directory: plugin_directory (which the chart writes);
//   - with DeliveryInitCopy, sealPlugin.initContainer and
//     sealPlugin.sourceVolume: exactly the init container and image volume
//     the server pod gets (SealPluginInitContainer, SealPluginSourceVolume),
//     mounting the emptyDir the chart names RestoreCheckPluginVolume.
//
// Errors without a Seal.Plugin: a restore check with a built-in seal needs
// none of this and sets only sealConfig.
func (c *Config) RestoreCheckValues() (map[string]any, error) {
	if c.Seal.Plugin == nil {
		return nil, fmt.Errorf("RestoreCheckValues: Seal.Plugin is nil — a built-in seal needs no plugin values")
	}

	seal, err := c.SealHCL()
	if err != nil {
		return nil, err
	}

	plugin := map[string]any{"directory": c.pluginDirectory()}

	if c.Seal.Plugin.delivery() == DeliveryInitCopy {
		init, err := c.SealPluginInitContainer(RestoreCheckPluginVolume)
		if err != nil {
			return nil, err
		}

		plugin["initContainer"] = init
		plugin["sourceVolume"] = c.SealPluginSourceVolume()
	}

	return map[string]any{"sealConfig": seal, "sealPlugin": plugin}, nil
}
