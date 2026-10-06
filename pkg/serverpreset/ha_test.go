package serverpreset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyHA(t *testing.T) {
	c := &Config{}
	require.NoError(t, c.ApplyHA(HAOptions{Replicas: 3, Endpoint: "bao.example.private", TLSSecretName: "bao-tls", UI: true, AuditDescription: "audit"}))

	assert.True(t, c.UI)
	assert.True(t, c.DisableStandbyReads)
	assert.Equal(t, "kubernetes", c.ServiceRegistration)
	assert.Equal(t, DefaultAuditDevice, c.AuditDevice)
	assert.Equal(t, "[::]:8200", c.Listener.Address)
	assert.Equal(t, "[::]:8201", c.Listener.ClusterAddress)
	assert.Equal(t, "/openbao/userconfig/bao-tls/tls.crt", c.Listener.TLSCertFile)
	assert.Equal(t, "/openbao/userconfig/bao-tls/tls.key", c.Listener.TLSKeyFile)
	assert.Equal(t, "[::]:9101", c.Telemetry.MetricsAddress)
	assert.Equal(t, DataPath, c.Raft.Path)
	require.Len(t, c.Raft.Peers, 3)
	assert.Equal(t, "https://openbao-2.openbao-internal:8200", c.Raft.Peers[2].LeaderAPIAddr)
	assert.Equal(t, "/openbao/userconfig/bao-tls/ca.crt", c.Raft.Peers[0].LeaderCACertFile)
	assert.Equal(t, "bao.example.private", c.Raft.Peers[1].LeaderTLSServername)
	assert.Equal(t, "openbao-0", PodName(0))

	// Applying again does not accumulate peers.
	require.NoError(t, c.ApplyHA(HAOptions{Replicas: 1, Endpoint: "bao.example.private", TLSSecretName: "bao-tls"}))
	assert.Len(t, c.Raft.Peers, 1)

	for name, opts := range map[string]HAOptions{
		"no replicas": {Endpoint: "e", TLSSecretName: "s"},
		"no endpoint": {Replicas: 1, TLSSecretName: "s"},
		"no secret":   {Replicas: 1, Endpoint: "e"},
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, (&Config{}).ApplyHA(opts)) })
	}
}

func TestAuthAWSPluginAndZoneSpread(t *testing.T) {
	p := AuthAWSPlugin("v0.1.1", map[string]string{"arm64": "abc"})
	assert.Equal(t, "auth-aws-v0.1.1", p.Command())
	assert.True(t, p.RequiresSTS)
	assert.Contains(t, p.EgressHosts, "ghcr.io")

	spread := ZoneSpread("rel")
	require.Len(t, spread, 1)
	selector := spread[0].(map[string]any)["labelSelector"].(map[string]any)["matchLabels"].(map[string]any)
	assert.Equal(t, "rel", selector["app.kubernetes.io/instance"])
}
