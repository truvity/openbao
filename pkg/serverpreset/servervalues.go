package serverpreset

import (
	"fmt"
	"strconv"
	"strings"
)

type (
	// ServerImage is the server's image, as the upstream chart's
	// server.image takes it.
	ServerImage struct {
		// Registry is optional (the chart's own default applies without it).
		Registry   string
		Repository string
		// Tag is required: without it the chart runs its own appVersion,
		// and a bump of the pin you keep elsewhere never reaches the server.
		Tag string
	}

	// DataStorage is the Raft data volume's claim.
	DataStorage struct {
		Size string
		// StorageClass is optional: empty leaves the cluster default.
		StorageClass string
	}

	// ServerValuesOptions is what [Config.ServerValues] needs beyond the
	// Config: the decisions an install makes for itself (image, resources,
	// placement, storage) and the names the pod's wiring depends on.
	ServerValuesOptions struct {
		// PluginVolumeName names the plugin emptyDir (and the seal plugin's
		// source volume sits beside it). Required.
		PluginVolumeName string
		// Image is the server's image. Repository and Tag are required.
		Image ServerImage
		// ServiceAccountName is the pod's ServiceAccount, which the chart
		// creates. Empty: "openbao".
		ServiceAccountName string
		// TLSSecretName is the Secret that holds the serving certificate
		// (tls.crt, tls.key) and the CA (ca.crt). The chart mounts it at
		// /openbao/userconfig/<name>, so Listener.TLSCertFile and
		// Listener.TLSKeyFile must be under that directory. Required.
		TLSSecretName string
		// Endpoint is the one name the serving certificate carries and the
		// in-pod CLI verifies (BAO_TLS_SERVER_NAME), instead of the loopback
		// address it dials. Required.
		Endpoint string
		// Environment is added to server.extraEnvironmentVars, after
		// BAO_CACERT and BAO_TLS_SERVER_NAME (which it cannot override), for
		// example AWS_REGION.
		Environment map[string]string
		// TLSReload, when non-nil, adds the signalling sidecar of
		// [Config.TLSReloadSidecarContainer] and shareProcessNamespace. Empty
		// fields are filled from the server: Image from Image, CertificateFile
		// from Listener.TLSCertFile, CertificateVolume from the chart's
		// "userconfig-<TLSSecretName>" volume, PluginVolume from
		// PluginVolumeName.
		TLSReload *TLSReloadOptions
		// Replicas is the number of voters. Zero: one per Raft peer.
		Replicas int
		// DataStorage is the Raft data volume. Size is required.
		DataStorage DataStorage
		// Resources, NodeSelector, Tolerations and TopologySpreadConstraints
		// are copied into server.* as given, when non-nil.
		Resources                 map[string]any
		NodeSelector              map[string]any
		Tolerations               []any
		TopologySpreadConstraints []any
		// UIServicePort is the port of the chart's "ui" Service, which
		// targets the API listener's port. Zero: 443. Used only when
		// Config.UI is set.
		UIServicePort int
	}
)

// portOf is the port of a "[::]:8200" style listener address.
func portOf(address string) (int, error) {
	i := strings.LastIndex(address, ":")
	if i < 0 {
		return 0, fmt.Errorf("address %q has no port", address)
	}

	n, err := strconv.Atoi(address[i+1:])
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("address %q has no valid port", address)
	}

	return n, nil
}

func (i ServerImage) String() string {
	ref := i.Repository + ":" + i.Tag
	if i.Registry != "" {
		ref = i.Registry + "/" + ref
	}

	return ref
}

// ServerValues assembles the complete valuesObject for the upstream
// openbao-helm chart's server, minus what an install decides for itself:
// the image, resources, placement and storage come in through opts.
//
// What it renders beyond [Config.Values] is the wiring the HCL assumes: the
// serving Secret mounted and the in-pod CLI pointed at it, the metrics
// container port when Telemetry.MetricsAddress is set, the "ui" Service when
// Config.UI is set (every ready pod an endpoint, because a standby forwards a
// request to the active node itself), a Raft StatefulSet whose pods start
// together (podManagementPolicy Parallel: OrderedReady would stall pods
// behind one that is not initialised), the pod-security container context,
// the optional signalling sidecar, and no injector, CSI provider, auth
// delegator or audit volume. The HCL is [Config.HCL], untouched, so a diff
// against a hand-authored configuration is the adoption check
// (docs/server.md).
//
// The StatefulSet of the chart updates on delete: a change here reaches a pod
// only when it is deleted, one at a time, the leader last.
func (c *Config) ServerValues(opts ServerValuesOptions) (map[string]any, error) {
	for name, v := range map[string]string{
		"PluginVolumeName": opts.PluginVolumeName, "Image.Repository": opts.Image.Repository,
		"Image.Tag": opts.Image.Tag, "TLSSecretName": opts.TLSSecretName,
		"Endpoint": opts.Endpoint, "DataStorage.Size": opts.DataStorage.Size,
	} {
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("ServerValues: %s is required", name)
		}
	}

	mount := "/openbao/userconfig/" + opts.TLSSecretName + "/"

	for _, f := range []string{c.Listener.TLSCertFile, c.Listener.TLSKeyFile} {
		if !strings.HasPrefix(f, mount) {
			return nil, fmt.Errorf("ServerValues: %q is not under %q, where the chart mounts Secret %q", f, mount, opts.TLSSecretName)
		}
	}

	apiPort, err := portOf(c.Listener.Address)
	if err != nil {
		return nil, fmt.Errorf("ServerValues: Listener.Address: %w", err)
	}

	values, err := c.Values(opts.PluginVolumeName)
	if err != nil {
		return nil, err
	}

	server, _ := values["server"].(map[string]any)
	ha, _ := server["ha"].(map[string]any)
	raft, _ := ha["raft"].(map[string]any)

	replicas := opts.Replicas
	if replicas == 0 {
		replicas = len(c.Raft.Peers)
	}

	if replicas < 1 {
		return nil, fmt.Errorf("ServerValues: Replicas is required when the Config has no Raft peers")
	}

	raft["enabled"] = true
	raft["setNodeId"] = true
	ha["enabled"] = true
	ha["replicas"] = replicas
	ha["disruptionBudget"] = map[string]any{"enabled": true, "maxUnavailable": 1}

	sa := opts.ServiceAccountName
	if sa == "" {
		sa = "openbao"
	}

	env := map[string]any{
		"BAO_CACERT":          mount + "ca.crt",
		"BAO_TLS_SERVER_NAME": opts.Endpoint,
	}

	for k, v := range opts.Environment {
		if _, taken := env[k]; !taken {
			env[k] = v
		}
	}

	image := map[string]any{"repository": opts.Image.Repository, "tag": opts.Image.Tag}
	if opts.Image.Registry != "" {
		image["registry"] = opts.Image.Registry
	}

	server["image"] = image
	server["authDelegator"] = map[string]any{"enabled": false}
	server["serviceAccount"] = map[string]any{"create": true, "name": sa}
	server["podManagementPolicy"] = "Parallel"
	server["extraEnvironmentVars"] = env
	server["extraVolumes"] = []any{map[string]any{"type": "secret", "name": opts.TLSSecretName}}
	server["statefulSet"] = map[string]any{"securityContext": map[string]any{"container": map[string]any{
		"allowPrivilegeEscalation": false,
		"capabilities":             map[string]any{"drop": []any{"ALL"}},
	}}}

	if c.Telemetry != nil && c.Telemetry.MetricsAddress != "" {
		port, err := portOf(c.Telemetry.MetricsAddress)
		if err != nil {
			return nil, fmt.Errorf("ServerValues: Telemetry.MetricsAddress: %w", err)
		}

		server["extraPorts"] = []any{map[string]any{"containerPort": port, "name": "metrics", "protocol": "TCP"}}
	}

	if opts.TLSReload != nil {
		tr := *opts.TLSReload

		if tr.Image == "" {
			tr.Image = opts.Image.String()
		}

		if tr.CertificateFile == "" {
			tr.CertificateFile = c.Listener.TLSCertFile
		}

		if tr.CertificateVolume == "" {
			tr.CertificateVolume = "userconfig-" + opts.TLSSecretName
		}

		if tr.PluginVolume == "" {
			tr.PluginVolume = opts.PluginVolumeName
		}

		sidecar, err := c.TLSReloadSidecarContainer(tr)
		if err != nil {
			return nil, err
		}

		server["shareProcessNamespace"] = true
		server["extraContainers"] = []any{sidecar}
	}

	if opts.NodeSelector != nil {
		server["nodeSelector"] = opts.NodeSelector
	}

	if opts.Tolerations != nil {
		server["tolerations"] = opts.Tolerations
	}

	if opts.TopologySpreadConstraints != nil {
		server["topologySpreadConstraints"] = opts.TopologySpreadConstraints
	}

	if opts.Resources != nil {
		server["resources"] = opts.Resources
	}

	data := map[string]any{"enabled": true, "size": opts.DataStorage.Size}
	if opts.DataStorage.StorageClass != "" {
		data["storageClass"] = opts.DataStorage.StorageClass
	}

	server["dataStorage"] = data
	server["auditStorage"] = map[string]any{"enabled": false}

	ui := map[string]any{"enabled": c.UI}

	if c.UI {
		port := opts.UIServicePort
		if port == 0 {
			port = 443
		}

		ui["activeOpenbaoPodOnly"] = false
		ui["publishNotReadyAddresses"] = false
		ui["serviceType"] = "ClusterIP"
		ui["externalPort"] = port
		ui["targetPort"] = apiPort
	}

	return map[string]any{
		"global":   map[string]any{"tlsDisable": false},
		"injector": map[string]any{"enabled": false},
		"csi":      map[string]any{"enabled": false},
		"ui":       ui,
		"server":   server,
	}, nil
}
