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
// OpenBAO 2.7 makes the awskms seal an external KMS plugin too, and a seal
// cannot wait for the server to be Ready: the plugin binary must be on disk
// BEFORE `bao server` starts, because the server cannot unseal — cannot
// become Ready — without it. [SealPlugin] is that: an init container
// installs the binary from a digest-pinned image, the `plugin "kms"` block
// registers the local file, and nothing about the seal depends on the
// network, the retry sidecar or a download. See docs/server.md, "The seal
// as a plugin (OpenBAO 2.7)".
//
// docs/server.md is the runbook this package's output is proven against
// (a real `bao server`, conformance/server_preset_test.go) and the
// migration note for an install that already authors this HCL by hand.
package serverpreset

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
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

// ociDigest is an OCI content digest as a registry and a kubelet spell it:
// "sha256:" and 64 lowercase hex digits.
var ociDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// fileName is a name that is one path element: what the plugin directory
// may hold and what `command` may name (OpenBAO resolves it relative to
// plugin_directory and refuses anything else).
var fileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// serverVersion reads "2.7.0", "v2.7.0" or "2.7.0-rc1" as (major, minor).
var serverVersion = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)(?:\.[0-9]+)?(?:[-+].*)?$`)

const (
	// SealPluginKind is the plugin type of an external KMS seal: the first
	// label of its `plugin` block. KMS plugins cannot be registered through
	// the API (they must exist while the server is sealed), so this is the
	// only way one is ever declared.
	SealPluginKind = "kms"

	// DeliveryInitCopy installs the seal plugin with an init container that
	// copies the binary out of a digest-pinned OCI image into the plugin
	// directory before `bao server` starts. The default.
	DeliveryInitCopy = "init-copy"
	// DeliveryPreinstalled renders only the HCL: the binary is already in
	// the plugin directory when the server starts, put there by whatever
	// the adopter owns (an image that bakes it in, a node-local volume).
	// Nothing verifies that; the server refuses to start if it is missing.
	DeliveryPreinstalled = "preinstalled"

	// DefaultSealPluginBinaryName is the file the plugin's image carries at
	// its root (openbao-plugins publishes `FROM scratch` images with the
	// binary as the ENTRYPOINT).
	DefaultSealPluginBinaryName = "openbao-plugin-kms-aws"
	// DefaultSealPluginDelivery is DeliveryInitCopy.
	DefaultSealPluginDelivery = DeliveryInitCopy
	// DefaultSealPluginSourceVolume names the image volume the init
	// container reads the binary from.
	DefaultSealPluginSourceVolume = "seal-plugin-src"

	sealPluginSourceMount = "/seal-plugin-src"
)

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
		// renders. Built in up to OpenBAO 2.6, an external KMS plugin from
		// 2.7 (see Plugin below); Validate refuses any other Type, so a
		// caller who reaches for another provider gets an explanation,
		// not a parse error.
		Type string
		// Region and KMSKeyID are the awskms seal's own HCL fields.
		Region   string
		KMSKeyID string
		// Endpoint is the seal's `endpoint` line — a VPC endpoint, or a
		// KMS-compatible service. Empty: the region's public KMS host.
		// EgressDomains names this host instead of the public one.
		Endpoint string
		// Plugin, when non-nil, runs the seal as an external KMS plugin —
		// mandatory from OpenBAO 2.7 (the seal is no longer built in),
		// available from 2.6. Nil renders the built-in seal exactly as
		// before, which only a server older than 2.7 has.
		Plugin *SealPlugin
	}

	// SealPlugin is the awskms seal delivered as an external KMS plugin:
	// a `plugin "kms" "<Seal.Type>"` block registering a binary that must
	// already be on disk when the server starts (see the package comment),
	// and — with the default DeliveryInitCopy — the init container and image
	// volume that put it there.
	SealPlugin struct {
		// Delivery is [DeliveryInitCopy] (the default, empty) or
		// [DeliveryPreinstalled].
		Delivery string
		// Image is the plugin's OCI repository without tag or digest, e.g.
		// "ghcr.io/openbao/openbao-plugin-kms-aws". It is the kubelet, not
		// the pod, that pulls it, so this is the one place an adopter
		// points at its own mirror or pull-through cache. Required for
		// DeliveryInitCopy.
		Image string
		// Digest pins the image: the manifest-list digest, "sha256:<hex>",
		// which the kubelet resolves to the node's architecture (no
		// per-architecture checksum, unlike [Plugin.SHA256ByArch]).
		// Required for DeliveryInitCopy; a tag alone is never enough.
		Digest string
		// Version is the plugin's release version ("v0.1.0"), the `version`
		// line and the tail of the on-disk name (Command).
		Version string
		// BinaryName is the binary's name at the image's root. Empty:
		// [DefaultSealPluginBinaryName].
		BinaryName string
		// SHA256ByArch is the plugin binary's checksum per architecture, as
		// the plugin release's checksums file lists it (the raw binary, not
		// the archive or the image). REQUIRED for a server below 2.7
		// (ServerVersion set), which refuses a manually installed plugin
		// with no checksum; optional from 2.7, where the image digest is
		// the pin. When present it is rendered as `sha256sum` and also
		// verified by the init container before it installs anything. It
		// must carry Config.Arch.
		SHA256ByArch map[string]string
		// CopyImage is the init container's own image: anything with `sh`,
		// `cp`, `chmod` and `mv` — the server's image, by convention, for
		// the same pairing reason as the retry sidecar. Required for
		// DeliveryInitCopy.
		CopyImage string
		// SourceVolume names the image volume. Empty:
		// [DefaultSealPluginSourceVolume].
		SourceVolume string
		// PullPolicy is the image volume's pullPolicy. Empty:
		// IfNotPresent (the digest makes that safe).
		PullPolicy string
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
		// ServerVersion is the OpenBAO version this configuration is for
		// ("2.7.0"). Optional, and only ever a guard: empty renders as
		// before. From 2.7 on, a Seal with no Plugin is refused — the seal
		// is not built in there, and the server would fail to start on it.
		// Below 2.6 a Seal.Plugin is refused (no KMS plugins). The mode
		// itself is always the explicit Seal.Plugin, never inferred from
		// this.
		ServerVersion string
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
		// PluginVolumeSizeLimit, when set (a Kubernetes quantity such as
		// "256Mi"), caps the plugin emptyDir PluginVolume renders. Empty
		// renders an unbounded emptyDir, as before.
		PluginVolumeSizeLimit string
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
		// ExternalStorage says the storage backend is configured outside
		// this package (another backend, or a stanza the caller appends).
		// [Config.HCL] and [Config.Values] refuse a Config with no Raft peers
		// and no ExternalStorage, because a server with no storage block does
		// not start; the flag is the explicit alternative. It renders
		// nothing.
		ExternalStorage bool
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

// validateServer is what a whole-server render ([Config.HCL],
// [Config.Values]) needs beyond [Config.Validate]: the listener and the
// storage are rendered there, so an empty one is refused rather than
// written as `address = ""` or left out. The plugin-only entry points
// (PluginHCL, SealHCL, EgressDomains, the retry sidecar) do not need
// either and do not call it.
func (c *Config) validateServer() error {
	if strings.TrimSpace(c.Listener.Address) == "" {
		return fmt.Errorf("config: Listener.Address is required — the listener renders `address = \"\"` otherwise, which no server accepts")
	}

	if len(c.Raft.Peers) == 0 {
		if !c.ExternalStorage {
			return fmt.Errorf("config: no storage block — set Raft.Peers, or ExternalStorage when the storage backend is configured elsewhere; " +
				"a server with no storage block does not start")
		}

		return nil
	}

	if strings.TrimSpace(c.Raft.Path) == "" {
		return fmt.Errorf("config: Raft.Path is required when Raft.Peers is set")
	}

	for i, peer := range c.Raft.Peers {
		if strings.TrimSpace(peer.LeaderAPIAddr) == "" {
			return fmt.Errorf("config: Raft.Peers[%d].LeaderAPIAddr is required", i)
		}
	}

	return nil
}

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

		if p.Kind == SealPluginKind {
			return fmt.Errorf("plugin %s %s: a KMS plugin is never downloaded by the server — set Seal.Plugin, which installs it BEFORE the server starts; "+
				"a server-side download is racing the network at exactly the moment the seal needs the binary", p.Kind, p.Name)
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

	if err := c.validateSealPlugin(); err != nil {
		return err
	}

	if len(c.Plugins) > 0 && strings.TrimSpace(c.pluginDirectory()) == "" {
		return fmt.Errorf("PluginDirectory is required when Plugins is non-empty")
	}

	return nil
}

// versionAtLeast reports whether ServerVersion is at least major.minor;
// known is false when ServerVersion is empty.
func (c *Config) versionAtLeast(major, minor int) (atLeast, known bool, err error) {
	if strings.TrimSpace(c.ServerVersion) == "" {
		return false, false, nil
	}

	m := serverVersion.FindStringSubmatch(strings.TrimSpace(c.ServerVersion))
	if m == nil {
		return false, false, fmt.Errorf("ServerVersion %q is not a version like 2.7.0", c.ServerVersion)
	}

	gotMajor, _ := strconv.Atoi(m[1])
	gotMinor, _ := strconv.Atoi(m[2])

	return gotMajor > major || (gotMajor == major && gotMinor >= minor), true, nil
}

// validateSealPlugin refuses a seal that cannot be satisfied at startup —
// the checks a sealed server cannot make up for later, because it cannot
// become Ready to be retried, patched or signalled.
func (c *Config) validateSealPlugin() error {
	s := &c.Seal

	from27, known, err := c.versionAtLeast(2, 7)
	if err != nil {
		return err
	}

	if s.Type != "" && s.Plugin == nil && known && from27 {
		return fmt.Errorf("seal %q has no Plugin, but ServerVersion %s has no built-in %s seal (external plugin since 2.7.0): "+
			"the server would fail to start — set Seal.Plugin", s.Type, c.ServerVersion, s.Type)
	}

	if s.Plugin == nil {
		return nil
	}

	if s.Type == "" {
		return fmt.Errorf("seal plugin: Seal.Type is empty — a plugin with no seal to serve")
	}

	if from26, known, _ := c.versionAtLeast(2, 6); known && !from26 {
		return fmt.Errorf("seal plugin: ServerVersion %s predates KMS plugins (2.6.0); use the built-in seal", c.ServerVersion)
	}

	if err := s.Plugin.validate(c.pluginDirectory(), s.Type); err != nil {
		return err
	}

	sum, have := s.Plugin.SHA256ByArch[c.Arch]
	if !have && (len(s.Plugin.SHA256ByArch) > 0 || (known && !from27)) {
		return fmt.Errorf("seal plugin: no SHA256ByArch entry for arch %q — a server below 2.7 refuses a plugin with no checksum "+
			"(\"error verifying checksum: no checksum provided\"), and a checksum map must carry the architecture Config.Arch names", c.Arch)
	}

	if have && !sha256Hex.MatchString(sum) {
		return fmt.Errorf("seal plugin: SHA256ByArch[%q] %q is not a lowercase sha256 hex digest", c.Arch, sum)
	}

	return nil
}

// sealPluginChecksum is the checksum for Config.Arch, or "".
func (c *Config) sealPluginChecksum() string {
	if c.Seal.Plugin == nil {
		return ""
	}

	return c.Seal.Plugin.SHA256ByArch[c.Arch]
}

func (sp *SealPlugin) validate(dir, sealName string) error {
	if !fileName.MatchString(sealName) {
		return fmt.Errorf("seal plugin: seal name %q is not a plain name", sealName)
	}

	if !strings.HasPrefix(dir, "/") || !hclIdent.MatchString(dir) {
		return fmt.Errorf("seal plugin: PluginDirectory %q must be an absolute path (plugin_directory must exist at startup, and a seal cannot wait for it)", dir)
	}

	if !fileName.MatchString(sp.Version) {
		return fmt.Errorf("seal plugin: Version %q is required and must be one plain token such as v0.1.0", sp.Version)
	}

	if !fileName.MatchString(sp.binaryName()) {
		return fmt.Errorf("seal plugin: BinaryName %q is not a plain file name", sp.binaryName())
	}

	switch sp.Delivery {
	case "", DeliveryInitCopy:
	case DeliveryPreinstalled:
		return nil
	default:
		return fmt.Errorf("seal plugin: Delivery %q is not %q or %q", sp.Delivery, DeliveryInitCopy, DeliveryPreinstalled)
	}

	if strings.TrimSpace(sp.Image) == "" || !hclIdent.MatchString(sp.Image) || strings.Contains(sp.Image, "@") ||
		strings.Contains(sp.Image[strings.LastIndex(sp.Image, "/")+1:], ":") {
		return fmt.Errorf("seal plugin: Image %q must be a repository with no tag and no digest, e.g. ghcr.io/openbao/openbao-plugin-kms-aws "+
			"(the digest is Digest)", sp.Image)
	}

	if !ociDigest.MatchString(sp.Digest) {
		return fmt.Errorf("seal plugin: Digest %q must be sha256:<64 lowercase hex> — a seal plugin is pinned by digest, never by tag alone", sp.Digest)
	}

	if strings.TrimSpace(sp.CopyImage) == "" || !hclIdent.MatchString(sp.CopyImage) {
		return fmt.Errorf("seal plugin: CopyImage is required — the init container's image, which needs sh, cp, chmod and mv (the server's own image does)")
	}

	if !fileName.MatchString(sp.sourceVolume()) {
		return fmt.Errorf("seal plugin: SourceVolume %q is not a plain name", sp.sourceVolume())
	}

	switch sp.PullPolicy {
	case "", "IfNotPresent", "Always", "Never":
	default:
		return fmt.Errorf("seal plugin: PullPolicy %q is not IfNotPresent, Always or Never", sp.PullPolicy)
	}

	return nil
}

func (sp *SealPlugin) binaryName() string {
	if sp.BinaryName == "" {
		return DefaultSealPluginBinaryName
	}

	return sp.BinaryName
}

func (sp *SealPlugin) sourceVolume() string {
	if sp.SourceVolume == "" {
		return DefaultSealPluginSourceVolume
	}

	return sp.SourceVolume
}

func (sp *SealPlugin) delivery() string {
	if sp.Delivery == "" {
		return DefaultSealPluginDelivery
	}

	return sp.Delivery
}

// SealPluginCommand is the seal plugin's on-disk name in the plugin directory,
// "kms-<seal>-<version>" — the same "<kind>-<name>-<version>" shape
// [Plugin.Command] uses, so one directory holds both without a collision.
func (c *Config) SealPluginCommand() string {
	if c.Seal.Plugin == nil {
		return ""
	}

	return SealPluginKind + "-" + c.Seal.Type + "-" + c.Seal.Plugin.Version
}

// hasSealPlugin says the rendered server needs a plugin directory for the
// seal, whatever else Plugins holds.
func (c *Config) hasSealPlugin() bool { return c.Seal.Plugin != nil }

func (s Seal) validate() error {
	if s.Type == "" {
		return nil
	}

	if s.Type != "awskms" {
		return fmt.Errorf(
			"seal type %q is not supported — this package renders \"awskms\" only (built in up to OpenBAO 2.6, an external plugin from OpenBAO 2.7); "+
				"other providers' plugins are not built yet", s.Type)
	}

	if strings.TrimSpace(s.Region) == "" || strings.TrimSpace(s.KMSKeyID) == "" {
		return fmt.Errorf("seal awskms: Region and KMSKeyID are both required")
	}

	if s.Endpoint != "" {
		u, err := url.Parse(s.Endpoint)
		if err != nil || !hclIdent.MatchString(s.Endpoint) || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
			return fmt.Errorf("seal awskms: Endpoint %q must be an http(s) URL with a host", s.Endpoint)
		}
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

	if len(c.Plugins) == 0 && !c.hasSealPlugin() {
		return "", nil
	}

	var b strings.Builder

	if len(c.Plugins) == 0 {
		// Only the seal plugin: a local binary, nothing to download, so
		// none of the download settings.
		fmt.Fprintf(&b, "plugin_directory = %q\n", c.pluginDirectory())

		return b.String(), nil
	}

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

// SealHCL renders the `seal "awskms" { ... }` stanza — followed, with a
// Seal.Plugin, by the `plugin "kms" "awskms"` block that registers the
// binary — or "" when Seal is the zero value. (plugin_directory itself is
// PluginHCL's line, once, for every plugin.)
func (c *Config) SealHCL() (string, error) {
	if err := c.Seal.validate(); err != nil {
		return "", err
	}

	if err := c.validateSealPlugin(); err != nil {
		return "", err
	}

	if c.Seal.Type == "" {
		return "", nil
	}

	var b strings.Builder

	fmt.Fprintf(&b, "seal %q {\n", c.Seal.Type)
	fmt.Fprintf(&b, "  region     = %q\n", c.Seal.Region)
	fmt.Fprintf(&b, "  kms_key_id = %q\n", c.Seal.KMSKeyID)

	if c.Seal.Endpoint != "" {
		fmt.Fprintf(&b, "  endpoint   = %q\n", c.Seal.Endpoint)
	}

	fmt.Fprintf(&b, "}\n")

	if p := c.Seal.Plugin; p != nil {
		// The registration of a binary that is already on disk: no image
		// and no download. The checksum line is only there when one is
		// given (2.6 requires it; 2.7 does not, and the init container's
		// digest pin is the integrity check).
		fmt.Fprintf(&b, "plugin %q %q {\n", SealPluginKind, c.Seal.Type)
		fmt.Fprintf(&b, "  command = %q\n", c.SealPluginCommand())
		fmt.Fprintf(&b, "  version = %q\n", p.Version)

		if sum := c.sealPluginChecksum(); sum != "" {
			fmt.Fprintf(&b, "  sha256sum = %q\n", sum)
		}

		fmt.Fprintf(&b, "}\n")
	}

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

	if err := c.validateServer(); err != nil {
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
	emptyDir := map[string]any{}
	if c.PluginVolumeSizeLimit != "" {
		emptyDir["sizeLimit"] = c.PluginVolumeSizeLimit
	}

	return map[string]any{
		"name":     name,
		"emptyDir": emptyDir,
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

	// The seal plugin adds nothing here: with DeliveryInitCopy the KUBELET
	// pulls its image (node egress, not the pod's), and the plugin's KMS
	// calls go to the same host the built-in seal used.
	switch {
	case c.Seal.Type == "awskms" && c.Seal.Endpoint != "":
		if u, err := url.Parse(c.Seal.Endpoint); err == nil && u.Hostname() != "" {
			set[u.Hostname()] = true
		}
	case c.Seal.Type == "awskms" && c.Seal.Region != "":
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

	if len(c.Plugins) > 0 || c.hasSealPlugin() {
		if strings.TrimSpace(volumeName) == "" {
			return nil, fmt.Errorf("Values: volumeName is required when Plugins or Seal.Plugin is set")
		}

		volumes := []any{c.PluginVolume(volumeName)}

		if c.hasSealPlugin() && c.Seal.Plugin.delivery() == DeliveryInitCopy {
			volumes = append(volumes, c.SealPluginSourceVolume())

			init, err := c.SealPluginInitContainer(volumeName)
			if err != nil {
				return nil, err
			}

			server["extraInitContainers"] = []any{init}
		}

		server["volumes"] = volumes
		server["volumeMounts"] = []any{c.PluginVolumeMount(volumeName)}
	}

	return map[string]any{"server": server}, nil
}
