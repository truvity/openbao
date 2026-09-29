// Package serverpreset builds the server-side HCL and Helm-values
// fragments an OpenBAO install running the upstream openbao/openbao-helm
// chart needs to run an EXTERNAL plugin safely — a listener, Raft storage,
// an awskms seal, and a declarative plugin block — plus the emptyDir
// plugin directory and the egress allowlist those pieces need.
//
// It exists because OpenBAO, unlike Vault, ships no cloud auth methods
// built in: every cloud auth or secrets method is an external plugin, and
// the declarative download-and-register path that installs one has three
// failure modes that only show up on a real server, none of which look
// like what breaks:
//
//   - plugin_directory must EXIST before `bao server` starts, whether or
//     not the OCI download that follows succeeds. A directory that is
//     never created (because the first download failed, or because
//     nothing bothered) makes the server EXIT — "expand plugin
//     directory: lstat" — not warn and continue.
//   - plugin_download_behavior accepts exactly "fail" or "continue".
//     Anything else, including the word "warn", is silently ignored.
//   - a fresh pod's first download races whatever admits its egress: the
//     download times out before the policy has caught up, and nothing
//     retries it on its own. A SIGHUP re-runs the same declarative
//     download and registration from the server's current config — but
//     only once the server is actually serving; SIGHUP's default
//     disposition terminates a process that has not installed a handler
//     for it yet.
//
// docs/server.md is the runbook this package's output is proven against
// (a real `bao server`, conformance/server_preset_test.go) and the
// migration note for an install that already authors this HCL by hand.
package serverpreset

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// DefaultPluginDirectory is where the emptyDir this package's Values
// mounts, and the plugin_directory HCL line, agree the plugins live.
const DefaultPluginDirectory = "/openbao/plugins"

// DefaultDownloadBehavior is "continue": a failed download logs and the
// server still starts, with that plugin simply unavailable until
// something retries it (RetryScript, or the next pod restart) — never a
// crash-looping voter. The other legal value, "fail", refuses to start at
// all on a failed download; anything else ("warn" included) is accepted
// by the server and silently ignored, which is why Validate refuses it
// here instead.
const DefaultDownloadBehavior = "continue"

// hclIdent is what OpenBAO's HCL parser accepts unquoted-adjacent as a
// block label, and what this package accepts anywhere it interpolates a
// string into HCL without its own quoting logic: no line breaks, no
// quotes. It is deliberately stricter than HCL's own grammar — this
// package has no HCL escaper, so anything it cannot prove is one line
// with no quote in it, it refuses to interpolate at all.
var hclIdent = regexp.MustCompile(`^[A-Za-z0-9_./:@-]+$`)

// sha256Hex is what OpenBAO's own checksum lines look like: lowercase hex,
// the length of a SHA-256 digest.
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{` + itoa(hex.EncodedLen(sha256.Size)) + `}$`)

func itoa(n int) string { return fmt.Sprintf("%d", n) }

type (
	// Plugin is one external plugin registered declaratively — a `plugin
	// "<Kind>" "<Name>" { ... }` block, downloaded from an OCI image and
	// verified against a checksum before the server ever runs it.
	Plugin struct {
		// Kind is the plugin's catalog type: "auth", "secret" or
		// "database" — the first label of the HCL block.
		Kind string
		// Name is the plugin's catalog name — the second label, and half
		// of the on-disk name (Command).
		Name string
		// Image is the OCI reference the server pulls, e.g.
		// "ghcr.io/openbao/openbao-plugin-auth-aws". No tag: Version is
		// the tag.
		Image string
		// Version is both the OCI tag and the catalog version — the
		// `version` HCL line, and the other half of the on-disk name. A
		// mount that uses this plugin must pin the SAME string as its
		// own plugin_version, or it resolves to the unversioned catalog
		// key and then to a builtin, never to this entry.
		Version string
		// BinaryName is the archive's own binary name, for the record —
		// OpenBAO's declarative download does NOT run it: it links the
		// verified binary as Command, and a catalog entry naming
		// BinaryName points at nothing. Kept so a reader can tell the
		// download's own archive layout from what the catalog actually
		// runs.
		BinaryName string
		// SHA256ByArch is the plugin's raw-binary checksum, one entry per
		// architecture the image is published for — never a bare string.
		// The image is multi-arch; the SERVER resolves it to whatever
		// architecture the node it lands on actually is, and a single
		// checksum can only ever verify one of them. Keyed by Go's own
		// GOARCH spelling ("amd64", "arm64").
		SHA256ByArch map[string]string
		// EgressHosts is every host the OCI pull needs — the registry
		// AND its blob host, when the registry serves layers from a
		// different one (ghcr.io does: pkg-containers.githubusercontent.com).
		// Data, not derived, because that split is a property of the
		// registry, not of this package's guesswork.
		EgressHosts []string
		// RequiresSTS is true for a plugin that authenticates a caller
		// by verifying a signed STS GetCallerIdentity call against AWS
		// itself (the aws auth method does) — Config.EgressDomains adds
		// STS, global and regional, for any such plugin.
		RequiresSTS bool
	}

	// Seal is the server's auto-unseal mechanism.
	Seal struct {
		// Type is "awskms" today — the only seal type this package
		// renders. OpenBAO 2.7 moves awskms auto-unseal out of the main
		// distribution into an external plugin (like Plugin above, but
		// downloaded and verified BEFORE the server can unseal, which
		// makes egress and the startup race matter even more than they
		// do for an auth plugin); Validate refuses any other Type today
		// with that as the reason, so a caller who reaches for
		// "awskms-plugin" gets an explanation, not a parse error.
		Type string
		// Region and KMSKeyID are the awskms seal's own HCL fields.
		Region   string
		KMSKeyID string
	}

	// Listener is the one TCP listener OpenBAO's chart configures, TLS
	// terminated inside the pod from a cert-manager-renewed Secret — see
	// docs/server.md, "Reloading a renewed certificate", for the sidecar
	// that makes a renewal reach this listener without a restart.
	Listener struct {
		Address        string // e.g. "[::]:8200"
		ClusterAddress string // e.g. "[::]:8201"
		TLSCertFile    string
		TLSKeyFile     string
	}

	// Raft is the storage backend: one voter per pod, retry-joining every
	// peer including itself (OpenBAO ignores a retry_join to its own
	// address once it holds a peer set).
	Raft struct {
		Path string // e.g. "/openbao/data"
		// Peers is one entry per voter — its own leader_api_addr, so the
		// caller decides the naming scheme (a StatefulSet's ordinal
		// pods, in the reference shape) rather than this package
		// guessing it from a count.
		Peers []RaftPeer
	}

	// RaftPeer is one retry_join block.
	RaftPeer struct {
		LeaderAPIAddr       string
		LeaderCACertFile    string
		LeaderTLSServername string
	}

	// Config is everything this package renders: the plugin catalog, the
	// seal, the listener, Raft, and the handful of top-level settings
	// docs/server.md's reference HCL sets beside them.
	Config struct {
		// Arch is the EXPLICIT architecture selector — never derived,
		// never guessed. A caller whose node selection could resolve to
		// more than one architecture must resolve that FIRST (see
		// ResolveArch) and pass the one answer here: a plugin's
		// SHA256ByArch can only ever verify a single architecture's
		// binary, so a config that does not commit to one before
		// rendering would pin a checksum for the wrong node silently —
		// exactly the incident this package exists to not repeat.
		Arch string
		// PluginDirectory is where plugins land, and what the caller's
		// emptyDir (PluginVolume/PluginVolumeMount) must mount at.
		// Empty: DefaultPluginDirectory.
		PluginDirectory string
		// DownloadBehavior is "fail" or "continue". Empty:
		// DefaultDownloadBehavior. Any other value is refused, not
		// silently accepted the way the server itself accepts and
		// ignores "warn".
		DownloadBehavior string
		// Plugins is the whole declarative catalog. Empty renders no
		// plugin_* settings at all — a server with nothing to download
		// does not need a plugin directory either.
		Plugins []Plugin
		// Seal is the auto-unseal mechanism. Zero value renders no seal
		// stanza (an install that unseals by hand).
		Seal     Seal
		Listener Listener
		Raft     Raft
		// UI serves the web UI on the same listener (`ui = true`).
		UI bool
		// DisableStandbyReads: standbys forward every request to the
		// active node rather than serving reads themselves. See
		// docs/server.md — a client behind a load balancer that targets
		// every pod can otherwise read its own write from a standby that
		// has not applied it yet.
		DisableStandbyReads bool
		// ServiceRegistration names a service_registration block, e.g.
		// "kubernetes". Empty renders none.
		ServiceRegistration string
		// AuditDevice, when non-empty, is the description of a
		// declarative `audit "file" "<AuditDevice>"` device writing to
		// stdout. OpenBAO refuses API-created audit devices (v2.3.2+),
		// so a server whose audit trail matters declares one here.
		AuditDevice string
	}
)

// Command is the on-disk name OpenBAO's declarative download links the
// verified binary as — "<Kind>-<Name>-<Version>", NOT BinaryName. A
// catalog entry (plugin_auto_register writes one; a mount's plugin_version
// reads it back) that names anything else points at nothing. Observed
// live: the download creates /openbao/plugins/auth-aws-v0.1.1, a symlink
// into its own OCI cache, regardless of what the plugin's own archive
// calls its binary.
func (p Plugin) Command() string {
	return p.Kind + "-" + p.Name + "-" + p.Version
}

// Validate refuses a plugin this package cannot render safely: an empty
// field HCL needs, a value that is not one HCL-safe line, an unversioned
// plugin (Version is also the catalog version a mount pins — see the
// Version field — so "" would leave every mount unable to pin one), and
// no checksum recorded for ANY architecture at all.
func (p Plugin) Validate() error {
	for name, v := range map[string]string{"Kind": p.Kind, "Name": p.Name, "Image": p.Image, "Version": p.Version, "BinaryName": p.BinaryName} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("plugin %s %s: %s is required", p.Kind, p.Name, name)
		}

		if !hclIdent.MatchString(v) {
			return fmt.Errorf("plugin %s %s: %s %q is not one HCL-safe token (no quotes, no line breaks)", p.Kind, p.Name, name, v)
		}
	}

	if len(p.SHA256ByArch) == 0 {
		return fmt.Errorf("plugin %s %s: SHA256ByArch is empty — a plugin verified against no checksum is not this package's to render", p.Kind, p.Name)
	}

	for arch, sum := range p.SHA256ByArch {
		if !sha256Hex.MatchString(sum) {
			return fmt.Errorf("plugin %s %s: SHA256ByArch[%q] %q is not a lowercase sha256 hex digest", p.Kind, p.Name, arch, sum)
		}
	}

	return nil
}

// checksumForArch returns the plugin's checksum for arch, refusing a
// plugin pinned for architectures that do not include it — the mixed-arch
// mistake this package exists to catch at render time rather than at
// "the download's checksum never matches, forever, on this node pool".
func (p Plugin) checksumForArch(arch string) (string, error) {
	sum, ok := p.SHA256ByArch[arch]
	if !ok {
		archs := make([]string, 0, len(p.SHA256ByArch))
		for a := range p.SHA256ByArch {
			archs = append(archs, a)
		}

		sort.Strings(archs)

		return "", fmt.Errorf(
			"plugin %s %s: no checksum recorded for arch %q (have %v) — "+
				"Config.Arch must be a resolved, single architecture (see ResolveArch), and every plugin must carry that architecture's checksum",
			p.Kind, p.Name, arch, archs)
	}

	return sum, nil
}

// ResolveArch is the general form of the mixed-architecture refusal: given
// every architecture a node selection could actually land a pod on, it
// returns the one to pin Config.Arch to, or refuses when there is more
// than one. A single sha256sum can only ever verify one architecture's
// binary — OpenBAO checks the extracted binary's digest, not its file
// format — so a node selection that mixes architectures cannot be served
// by one static checksum at all, and the answer is to narrow the
// selection, not to guess.
func ResolveArch(archs []string) (string, error) {
	distinct := map[string]bool{}
	for _, a := range archs {
		if strings.TrimSpace(a) == "" {
			return "", fmt.Errorf("resolve arch: empty architecture in %v", archs)
		}

		distinct[a] = true
	}

	if len(distinct) == 0 {
		return "", fmt.Errorf("resolve arch: no architectures given")
	}

	if len(distinct) > 1 {
		sorted := make([]string, 0, len(distinct))
		for a := range distinct {
			sorted = append(sorted, a)
		}

		sort.Strings(sorted)

		return "", fmt.Errorf(
			"node selection runs architectures %v — a single sha256sum cannot verify a mixed-architecture pool; "+
				"narrow the selection to one architecture before pinning a plugin checksum", sorted)
	}

	for a := range distinct {
		return a, nil
	}

	panic("unreachable")
}

// Validate refuses a Config this package cannot render safely.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Arch) == "" {
		return fmt.Errorf("config: Arch is required — an explicit architecture selector, never derived (see ResolveArch)")
	}

	behavior := c.downloadBehavior()
	if behavior != "fail" && behavior != "continue" {
		return fmt.Errorf(
			`DownloadBehavior must be "fail" or "continue", not %q — `+
				`the server itself accepts and silently ignores any other value, including "warn"`, behavior)
	}

	names := map[string]bool{}

	for i := range c.Plugins {
		p := &c.Plugins[i]
		if err := p.Validate(); err != nil {
			return err
		}

		if _, err := p.checksumForArch(c.Arch); err != nil {
			return err
		}

		key := p.Kind + "/" + p.Name
		if names[key] {
			return fmt.Errorf("plugin %s declared twice", key)
		}

		names[key] = true
	}

	if err := c.Seal.validate(); err != nil {
		return err
	}

	if len(c.Plugins) > 0 && strings.TrimSpace(c.pluginDirectory()) == "" {
		return fmt.Errorf("PluginDirectory is required when Plugins is non-empty")
	}

	return nil
}

func (s Seal) validate() error {
	if s.Type == "" {
		return nil
	}

	if s.Type != "awskms" {
		return fmt.Errorf(
			"seal type %q is not supported — this package renders \"awskms\" only; OpenBAO 2.7 moves awskms auto-unseal to an "+
				"external plugin, and support for that (download-before-unseal, its own egress and startup race) is not built yet",
			s.Type)
	}

	if strings.TrimSpace(s.Region) == "" || strings.TrimSpace(s.KMSKeyID) == "" {
		return fmt.Errorf("seal awskms: Region and KMSKeyID are both required")
	}

	return nil
}

func (c *Config) downloadBehavior() string {
	if c.DownloadBehavior == "" {
		return DefaultDownloadBehavior
	}

	return c.DownloadBehavior
}

func (c *Config) pluginDirectory() string {
	if c.PluginDirectory == "" {
		return DefaultPluginDirectory
	}

	return c.PluginDirectory
}

// PluginHCL renders plugin_directory, plugin_auto_download,
// plugin_auto_register, plugin_download_behavior and one `plugin "<Kind>"
// "<Name>" { ... }` block per entry of Plugins — the whole of what a
// server needs to download, verify and register an external plugin on its
// own, with no API call. Empty when Plugins is empty: a server with
// nothing to download does not declare a plugin directory either.
//
// plugin_auto_register is always true here, deliberately: OpenBAO refuses
// a catalog entry that points into its own OCI cache through the
// sys/plugins/catalog API ("cannot execute files outside of configured
// plugin directory") — only the declarative path may register what it
// downloaded, so a plugin listed here with no way to register it is not a
// choice this package offers.
func (c *Config) PluginHCL() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}

	if len(c.Plugins) == 0 {
		return "", nil
	}

	var b strings.Builder

	fmt.Fprintf(&b, "plugin_directory         = %q\n", c.pluginDirectory())
	fmt.Fprintf(&b, "plugin_auto_download     = true\n")
	fmt.Fprintf(&b, "plugin_auto_register     = true\n")
	fmt.Fprintf(&b, "plugin_download_behavior = %q\n", c.downloadBehavior())

	for i := range c.Plugins {
		p := &c.Plugins[i]

		sum, err := p.checksumForArch(c.Arch)
		if err != nil {
			return "", err
		}

		fmt.Fprintf(&b, "plugin %q %q {\n", p.Kind, p.Name)
		fmt.Fprintf(&b, "  image       = %q\n", p.Image)
		fmt.Fprintf(&b, "  version     = %q\n", p.Version)
		fmt.Fprintf(&b, "  binary_name = %q\n", p.BinaryName)
		fmt.Fprintf(&b, "  sha256sum   = %q\n", sum)
		fmt.Fprintf(&b, "}\n")
	}

	return b.String(), nil
}

// SealHCL renders the `seal "awskms" { ... }` stanza, or "" when Seal is
// the zero value.
func (c *Config) SealHCL() (string, error) {
	if err := c.Seal.validate(); err != nil {
		return "", err
	}

	if c.Seal.Type == "" {
		return "", nil
	}

	var b strings.Builder

	fmt.Fprintf(&b, "seal %q {\n", c.Seal.Type)
	fmt.Fprintf(&b, "  region     = %q\n", c.Seal.Region)
	fmt.Fprintf(&b, "  kms_key_id = %q\n", c.Seal.KMSKeyID)
	fmt.Fprintf(&b, "}\n")

	return b.String(), nil
}

// ListenerHCL renders the `listener "tcp" { ... }` stanza.
func (c *Config) ListenerHCL() string {
	l := c.Listener

	var b strings.Builder

	fmt.Fprintf(&b, "listener \"tcp\" {\n")
	fmt.Fprintf(&b, "  address         = %q\n", l.Address)
	fmt.Fprintf(&b, "  cluster_address = %q\n", l.ClusterAddress)
	fmt.Fprintf(&b, "  tls_cert_file   = %q\n", l.TLSCertFile)
	fmt.Fprintf(&b, "  tls_key_file    = %q\n", l.TLSKeyFile)
	fmt.Fprintf(&b, "}\n")

	return b.String()
}

// RaftHCL renders the `storage "raft" { ... }` stanza with one retry_join
// per peer, or "" when Raft has no peers (a single-node install with a
// different storage backend of its own).
func (c *Config) RaftHCL() string {
	if len(c.Raft.Peers) == 0 {
		return ""
	}

	var b strings.Builder

	fmt.Fprintf(&b, "storage \"raft\" {\n")
	fmt.Fprintf(&b, "  path = %q\n", c.Raft.Path)

	for _, peer := range c.Raft.Peers {
		fmt.Fprintf(&b, "  retry_join {\n")
		fmt.Fprintf(&b, "    leader_api_addr       = %q\n", peer.LeaderAPIAddr)
		fmt.Fprintf(&b, "    leader_ca_cert_file   = %q\n", peer.LeaderCACertFile)
		fmt.Fprintf(&b, "    leader_tls_servername = %q\n", peer.LeaderTLSServername)
		fmt.Fprintf(&b, "  }\n")
	}

	fmt.Fprintf(&b, "}\n")

	return b.String()
}

// HCL renders the whole server configuration: ui, disable_standby_reads,
// the listener, Raft, the seal, service_registration, the plugin catalog,
// and the audit device — in the order docs/server.md's reference
// configuration uses, so a diff against an existing hand-authored config
// is easy to read line for line.
func (c *Config) HCL() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}

	var b strings.Builder

	if c.UI {
		fmt.Fprintf(&b, "ui = true\n")
	}

	if c.DisableStandbyReads {
		fmt.Fprintf(&b, "disable_standby_reads = true\n")
	}

	b.WriteString(c.ListenerHCL())

	if raft := c.RaftHCL(); raft != "" {
		b.WriteString(raft)
	}

	seal, err := c.SealHCL()
	if err != nil {
		return "", err
	}

	b.WriteString(seal)

	if c.ServiceRegistration != "" {
		fmt.Fprintf(&b, "service_registration %q {}\n", c.ServiceRegistration)
	}

	plugins, err := c.PluginHCL()
	if err != nil {
		return "", err
	}

	b.WriteString(plugins)

	if c.AuditDevice != "" {
		fmt.Fprintf(&b, "audit \"file\" %q {\n", c.AuditDevice)
		fmt.Fprintf(&b, "  options {\n")
		fmt.Fprintf(&b, "    file_path = \"stdout\"\n")
		fmt.Fprintf(&b, "  }\n")
		fmt.Fprintf(&b, "}\n")
	}

	return b.String(), nil
}

// PluginVolume and PluginVolumeMount are the emptyDir this package's HCL
// assumes exists before the server starts — plugin_directory must exist
// at startup whether or not the download that follows succeeds, and an
// emptyDir mounted fresh guarantees it, in every pod, on every restart.
// Nothing needs to persist here: the download re-verifies the plugin
// against its checksum every time anyway, so a plugin that survived a
// restart would prove nothing an emptyDir doesn't.
//
// Both are plain maps so a caller can toYaml them straight into the
// upstream chart's server.volumes / server.volumeMounts without this
// package importing a Kubernetes types dependency it otherwise has no use
// for.
func (c *Config) PluginVolume(name string) map[string]any {
	return map[string]any{
		"name":     name,
		"emptyDir": map[string]any{},
	}
}

// PluginVolumeMount is the corresponding server.volumeMounts entry.
func (c *Config) PluginVolumeMount(name string) map[string]any {
	return map[string]any{
		"name":      name,
		"mountPath": c.pluginDirectory(),
	}
}

// EgressDomains is every hostname a server running this Config needs
// egress to, sorted and deduplicated: each plugin's OCI registry and blob
// hosts, AWS STS (global and regional) for any plugin that verifies a
// caller against it, and the seal's KMS host. It is not a NetworkPolicy —
// the shape of an egress allowlist (a plain NetworkPolicy's CIDRs versus
// an ApplicationNetworkPolicy's or Cilium's domain names) is the
// platform's, not this package's — but it is exactly the list either one
// needs, so the caller's own policy (openbao-ops' networkPolicy.egress.rules,
// or a consumer's own) can be built from it without re-deriving what
// "plugins on" actually requires reaching.
func (c *Config) EgressDomains() []string {
	set := map[string]bool{}

	needsSTS := false

	for _, p := range c.Plugins {
		for _, h := range p.EgressHosts {
			set[h] = true
		}

		if p.RequiresSTS {
			needsSTS = true
		}
	}

	if needsSTS {
		set["sts.amazonaws.com"] = true

		if c.Seal.Region != "" {
			set[fmt.Sprintf("sts.%s.amazonaws.com", c.Seal.Region)] = true
		}
	}

	if c.Seal.Type == "awskms" && c.Seal.Region != "" {
		set[fmt.Sprintf("kms.%s.amazonaws.com", c.Seal.Region)] = true
	}

	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}

	sort.Strings(out)

	return out
}

// Values assembles the upstream openbao-helm chart's server.ha.raft.config,
// and — only when Plugins is non-empty — server.volumes and
// server.volumeMounts for the plugin directory, as a plain map ready to
// merge into that chart's valuesObject. volumeName names the emptyDir
// (PluginVolume/PluginVolumeMount); the reference example uses
// "openbao-plugins".
//
// This is deliberately narrow: it renders what THIS package is
// responsible for (the plugin catalog, the seal, the listener, Raft) and
// nothing an estate decides for itself (the image, resources, node
// placement, replica count) — docs/server.md's reference values still
// carry those by hand, merged with what this returns.
func (c *Config) Values(volumeName string) (map[string]any, error) {
	hcl, err := c.HCL()
	if err != nil {
		return nil, err
	}

	server := map[string]any{
		"ha": map[string]any{
			"raft": map[string]any{
				"config": hcl,
			},
		},
	}

	if len(c.Plugins) > 0 {
		if strings.TrimSpace(volumeName) == "" {
			return nil, fmt.Errorf("Values: volumeName is required when Plugins is non-empty")
		}

		server["volumes"] = []any{c.PluginVolume(volumeName)}
		server["volumeMounts"] = []any{c.PluginVolumeMount(volumeName)}
	}

	return map[string]any{"server": server}, nil
}
