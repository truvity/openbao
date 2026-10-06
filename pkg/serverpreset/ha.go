package serverpreset

import (
	"fmt"
	"strings"
)

const (
	// DefaultAPIPort is the API listener's port inside the pod, and
	// DefaultClusterPort the Raft/cluster listener's.
	DefaultAPIPort     = 8200
	DefaultClusterPort = 8201
	// DefaultMetricsPort is the port of the metrics-only listener, the one
	// port a metrics agent may reach (charts/openbao-ops serverMetrics.port).
	// Not 8202: the openbao chart declares that one for replication.
	DefaultMetricsPort = 9101
	// DefaultAuditDevice is the declarative audit device's name: a file
	// device writing to stdout, because OpenBAO refuses API-created audit
	// devices (v2.3.2+).
	DefaultAuditDevice = "to-stdout"
	// DataPath is the Raft data directory the chart's volume mounts.
	DataPath = "/openbao/data"
	// StatefulSetName is the name the upstream chart gives the server
	// StatefulSet and its pods, and the prefix of the headless Service.
	StatefulSetName = "openbao"

	// AuthAWSImage and AuthAWSBinary are the openbao-plugins `auth-aws`
	// release's OCI repository and its binary's own name inside that image.
	AuthAWSImage  = "ghcr.io/openbao/openbao-plugin-auth-aws"
	AuthAWSBinary = "openbao-plugin-auth-aws"

	chartUserConfig = "/openbao/userconfig/"
)

// HAOptions is what [Config.ApplyHA] needs to render the reference HA shape:
// a TLS-terminating API listener on every pod, a metrics-only listener,
// Raft retry-joining every pod by name, the Kubernetes service registration
// and a declarative audit device.
type HAOptions struct {
	// Replicas is the number of Raft voters. Required.
	Replicas int
	// Endpoint is the one name the serving certificate carries, which every
	// Raft peer verifies. Required.
	Endpoint string
	// TLSSecretName is the Secret that holds tls.crt, tls.key and ca.crt,
	// which the chart mounts under /openbao/userconfig. Required.
	TLSSecretName string
	// UI serves the web UI on the API listener.
	UI bool
	// AuditDescription is the audit device's description. Empty: none.
	AuditDescription string
}

// PodName is the name of the server pod with ordinal i, which is also the
// first label of its address in the headless Service: the first voter,
// where initialisation runs, is PodName(0).
func PodName(i int) string { return fmt.Sprintf("%s-%d", StatefulSetName, i) }

// InternalService is the headless Service the chart creates for the Raft
// peers' pod-name addresses.
const InternalService = StatefulSetName + "-internal"

// ApplyHA fills the listener, telemetry, Raft, registration and audit
// settings of the reference HA shape (docs/server.md) into the Config,
// leaving the plugin catalog and the seal to the caller.
//
//   - DisableStandbyReads: a client behind a load balancer that targets every
//     pod can otherwise read its own write from a standby that has not
//     applied it yet;
//   - ServiceRegistration "kubernetes";
//   - the API listener on [::]:8200 and the cluster listener on [::]:8201,
//     serving the certificate of Secret TLSSecretName;
//   - the metrics listener on [::]:9101;
//   - one Raft retry_join per pod, dialled by pod name through the headless
//     Service and verified by the endpoint's name, the one name the serving
//     certificate is certain to carry (a short pod name can sit under a
//     private chain's name constraint no more than an IP SAN can).
func (c *Config) ApplyHA(opts HAOptions) error {
	for name, v := range map[string]string{"Endpoint": opts.Endpoint, "TLSSecretName": opts.TLSSecretName} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("ApplyHA: %s is required", name)
		}
	}

	if opts.Replicas < 1 {
		return fmt.Errorf("ApplyHA: Replicas is required")
	}

	mount := chartUserConfig + opts.TLSSecretName + "/"

	c.UI = opts.UI
	c.DisableStandbyReads = true
	c.ServiceRegistration = "kubernetes"
	c.AuditDevice = DefaultAuditDevice
	c.AuditDescription = opts.AuditDescription
	c.Listener = Listener{
		Address:        fmt.Sprintf("[::]:%d", DefaultAPIPort),
		ClusterAddress: fmt.Sprintf("[::]:%d", DefaultClusterPort),
		TLSCertFile:    mount + "tls.crt",
		TLSKeyFile:     mount + "tls.key",
	}
	c.Telemetry = &Telemetry{MetricsAddress: fmt.Sprintf("[::]:%d", DefaultMetricsPort)}
	c.Raft.Path = DataPath
	c.Raft.Peers = nil

	for i := range opts.Replicas {
		c.Raft.Peers = append(c.Raft.Peers, RaftPeer{
			LeaderAPIAddr:       fmt.Sprintf("https://%s.%s:%d", PodName(i), InternalService, DefaultAPIPort),
			LeaderCACertFile:    mount + "ca.crt",
			LeaderTLSServername: opts.Endpoint,
		})
	}

	return nil
}

// AuthAWSPlugin is the openbao-plugins `auth-aws` release as a catalog
// entry: the aws IAM auth method ships as an external plugin, not in the
// server binary. Its download needs the registry and its blob host, and the
// method verifies a caller against AWS STS.
func AuthAWSPlugin(version string, sha256ByArch map[string]string) Plugin {
	return Plugin{
		Kind:         "auth",
		Name:         "aws",
		Image:        AuthAWSImage,
		Version:      version,
		BinaryName:   AuthAWSBinary,
		SHA256ByArch: sha256ByArch,
		EgressHosts:  []string{"ghcr.io", "pkg-containers.githubusercontent.com"},
		RequiresSTS:  true,
	}
}

// ZoneSpread is the topology spread constraint that keeps the server's pods
// in different zones: at most one pod of skew, refusing to schedule rather
// than doubling up, selecting the chart's pod labels of the release.
func ZoneSpread(release string) []any {
	return []any{map[string]any{
		"maxSkew":           1,
		"topologyKey":       "topology.kubernetes.io/zone",
		"whenUnsatisfiable": "DoNotSchedule",
		"labelSelector": map[string]any{"matchLabels": map[string]any{
			"app.kubernetes.io/name":     StatefulSetName,
			"app.kubernetes.io/instance": release,
			"component":                  "server",
		}},
	}}
}

// restrictedContainerSecurityContext is what Pod Security "restricted" asks
// of a container that needs neither privilege nor capability.
func restrictedContainerSecurityContext() map[string]any {
	return map[string]any{
		"allowPrivilegeEscalation": false,
		"capabilities":             map[string]any{"drop": []any{"ALL"}},
	}
}
