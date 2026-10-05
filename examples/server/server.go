// Package server is a neutral, complete example of the server preset
// (pkg/serverpreset): a three-voter Raft cluster, awskms auto-unseal, and
// the `aws` IAM auth method as a declarative external plugin — the shape
// docs/server.md documents, and the one the migration note there proves
// against.
//
// values.yaml beside it is its golden: the exact fragment this example
// derives, ready to merge into the upstream openbao/openbao-helm chart's
// valuesObject next to the image, resources and node placement an estate
// decides for itself.
package server

import (
	"strconv"

	"github.com/truvity/secrets/pkg/serverpreset"
)

// Endpoint is the one name the serving certificate carries, and what every
// in-cluster client verifies instead of whatever address it dials — see
// docs/server.md, "Verifying one name".
const Endpoint = "openbao.example.internal"

// Region is the AWS region the seal and the aws auth plugin's STS calls
// use.
const Region = "eu-example-1"

// Voters is the reference Raft membership — the smallest quorum that
// survives losing a node, and (docs/server.md, "The seal's health check is
// a KMS budget") the largest that stays inside AWS's KMS free tier.
const Voters = 3

// AWSAuthPluginSHA256ByArch is the aws auth method's published checksum,
// per architecture, exactly as openbao/openbao-plugins' releases publish
// them (checksums-auth-aws.txt) for this version. A placeholder here: an
// adopter pins the real digest from that release's own checksums file,
// never copies these bytes.
var AWSAuthPluginSHA256ByArch = map[string]string{
	"amd64": "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
	"arm64": "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
}

// Config returns the example's serverpreset.Config, resolved to one
// architecture (arch) the way a caller resolves its own node selection
// first — see serverpreset.ResolveArch.
func Config(arch string) *serverpreset.Config {
	peers := make([]serverpreset.RaftPeer, Voters)
	for i := range peers {
		peers[i] = serverpreset.RaftPeer{
			LeaderAPIAddr:       "https://openbao-" + strconv.Itoa(i) + ".openbao-internal:8200",
			LeaderCACertFile:    "/openbao/userconfig/openbao-tls/ca.crt",
			LeaderTLSServername: Endpoint,
		}
	}

	return &serverpreset.Config{
		Arch: arch,
		UI:   true,
		// Standbys forward every request to the active node — see
		// docs/server.md: a client behind a load balancer that targets
		// every pod can otherwise read its own write from a standby that
		// has not applied it yet.
		DisableStandbyReads: true,
		Listener: serverpreset.Listener{
			Address:        "[::]:8200",
			ClusterAddress: "[::]:8201",
			TLSCertFile:    "/openbao/userconfig/openbao-tls/tls.crt",
			TLSKeyFile:     "/openbao/userconfig/openbao-tls/tls.key",
		},
		Raft: serverpreset.Raft{Path: "/openbao/data", Peers: peers},
		Seal: serverpreset.Seal{
			Type: "awskms", Region: Region, KMSKeyID: "alias/openbao-unseal",
		},
		ServiceRegistration: "kubernetes",
		AuditDevice:         "to-stdout",
		// Metrics for the openbao-ops chart's serverMetrics to scrape: the
		// telemetry stanza, and a token-free /v1/sys/metrics on a
		// second listener of its own, gated by the network policy.
		Telemetry: &serverpreset.Telemetry{MetricsAddress: "[::]:9101"},
		Plugins: []serverpreset.Plugin{{
			Kind:       "auth",
			Name:       "aws",
			Image:      "ghcr.io/openbao/openbao-plugin-auth-aws",
			Version:    "v0.1.1",
			BinaryName: "openbao-plugin-auth-aws",
			// ghcr.io serves manifests; the blob layers themselves come
			// from a separate host — an OCI pull needs egress to both, or
			// the download times out on the second half of the fetch,
			// which reads as "no egress" from the log even though the
			// manifest request succeeded.
			EgressHosts:  []string{"ghcr.io", "pkg-containers.githubusercontent.com"},
			RequiresSTS:  true,
			SHA256ByArch: AWSAuthPluginSHA256ByArch,
		}},
	}
}

// ServerImage is the tag every one of the example's containers that runs
// the server's own image agrees on — the plugin-retry sidecar included,
// for the same reason tlsReload (charts/openbao-ops) keeps its own image
// equal to the server's: a restore that runs a different `bao` than the
// snapshot came from is proving the wrong pairing (docs/server.md,
// "Image").
const ServerImage = "openbao/openbao:2.6.2"

// PluginVolumeName is the emptyDir both PluginVolume/PluginVolumeMount and
// the plugin-retry sidecar's mount agree on.
const PluginVolumeName = "openbao-plugins"

// Values is Config's rendered values fragment PLUS the plugin-retry
// sidecar, wired the way an install actually needs both: the sidecar
// requires shareProcessNamespace (it signals `bao server` across
// containers), and the chart's OWN certificate-reload sidecar
// (charts/openbao-ops' tlsReload fragment) already needs the same
// setting, so a real values.yaml sets it once and lists both containers
// under server.extraContainers — this example carries the plugin-retry
// side of that only, and notes the other in a comment rather than
// reaching into another chart's template to render it.
func Values(arch string) (map[string]any, error) {
	cfg := Config(arch)

	values, err := cfg.Values(PluginVolumeName)
	if err != nil {
		return nil, err
	}

	sidecar, err := cfg.RetrySidecarContainer(serverpreset.RetrySidecarOptions{
		Image: ServerImage, VolumeName: PluginVolumeName,
	})
	if err != nil {
		return nil, err
	}

	server, _ := values["server"].(map[string]any)
	server["shareProcessNamespace"] = true
	// tlsReload (charts/openbao-ops) goes here too, spliced in by hand as
	// docs/server.md shows — left out of this fragment because it is
	// already a released, tested part of a DIFFERENT chart, not this
	// package's to re-render.
	server["extraContainers"] = []any{sidecar}

	return values, nil
}

// ServerImage27 is ServerImage for OpenBAO 2.7: the release where the awskms
// seal stops being built in.
const ServerImage27 = "openbao/openbao:2.7.0"

// SealPluginImage and SealPluginDigest pin the awskms seal plugin, as
// openbao/openbao-plugins publishes it: the repository (an adopter points
// this at its own mirror or pull-through cache) and the manifest-list digest
// of the release, which the kubelet resolves to the node's architecture. An
// adopter reads the digest of the version it adopts from the registry, never
// from this file.
const (
	SealPluginImage   = "ghcr.io/openbao/openbao-plugin-kms-aws"
	SealPluginDigest  = "sha256:fe9fb94872048c9474156c044ea8852bb5c2e968fc9304a3725e4d434b488541"
	SealPluginVersion = "v0.1.0"
)

// SealPluginSHA256ByArch is the seal plugin binary's checksum per
// architecture, from the release's checksums-kms-aws.txt. Optional on 2.7
// (the digest already pins the image; a checksum adds a check the init
// container makes before installing) and required below it.
var SealPluginSHA256ByArch = map[string]string{
	"amd64": "fa332cf1863a948d4b166ed9acb7da1608fb1dffbde4425626d787424fda5a05",
	"arm64": "9925bd77bb644fbf8a3a479deb39768e5a230e9b2b4eafad18971b54b3b580e2",
}

// Config27 is Config for OpenBAO 2.7: the same server, with the seal run
// as an external KMS plugin installed by an init container before the server
// starts (docs/server.md, "The seal as a plugin (OpenBAO 2.7)").
func Config27(arch string) *serverpreset.Config {
	cfg := Config(arch)
	cfg.ServerVersion = "2.7.0"
	cfg.Seal.Plugin = &serverpreset.SealPlugin{
		Image:     SealPluginImage,
		Digest:    SealPluginDigest,
		Version:   SealPluginVersion,
		CopyImage: ServerImage27,
		// The image digest is the pin; the checksum is a second one the
		// init container checks before it installs.
		SHA256ByArch: SealPluginSHA256ByArch,
	}

	return cfg
}

// Values27 is Values for OpenBAO 2.7: the fragment of [Config27] with the
// retry sidecar on the same image as the server.
func Values27(arch string) (map[string]any, error) {
	cfg := Config27(arch)

	values, err := cfg.Values(PluginVolumeName)
	if err != nil {
		return nil, err
	}

	sidecar, err := cfg.RetrySidecarContainer(serverpreset.RetrySidecarOptions{
		Image: ServerImage27, VolumeName: PluginVolumeName,
	})
	if err != nil {
		return nil, err
	}

	server, _ := values["server"].(map[string]any)
	server["shareProcessNamespace"] = true
	server["extraContainers"] = []any{sidecar}

	return values, nil
}
