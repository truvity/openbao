package estate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/estate"
)

func TestConfigOutputs(t *testing.T) {
	var absent *estate.ConfigOutputs

	assert.False(t, absent.Ready())
	assert.False(t, (&estate.ConfigOutputs{}).Ready())
	assert.True(t, (&estate.ConfigOutputs{Namespaces: []string{"ops"}}).Ready())
	assert.Empty(t, absent.SSHUserCAPublicKey("ops"))

	// A placeholder file with no outputs is valid.
	require.NoError(t, (&estate.ConfigOutputs{}).Validate())

	require.Error(t, (&estate.ConfigOutputs{InternalCAPEM: "not a certificate"}).Validate())
	require.Error(t, (&estate.ConfigOutputs{TrustRootCAPEM: "not a certificate"}).Validate())

	const ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

	good := &estate.ConfigOutputs{SSHUserCAPublicKeys: map[string]string{"ops": ed25519 + "\n"}}
	require.NoError(t, good.Validate())
	require.NoError(t, good.ValidateSSHKeyTypes("ssh-ed25519", "ssh-ed25519"))
	require.ErrorContains(t, good.ValidateSSHKeyTypes("ssh-rsa", "ssh-ed25519"), "want ssh-rsa")
	assert.Equal(t, ed25519, good.SSHUserCAPublicKey("ops"))

	require.Error(t, (&estate.ConfigOutputs{SSHHostCAPublicKeys: map[string]string{"ops": "not a key"}}).Validate())
	require.Error(t, (&estate.ConfigOutputs{SSHHostCAPublicKeys: map[string]string{"ops": `command="x" ` + ed25519}}).Validate())
}
