package estate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/estate"
	"github.com/truvity/secrets/pkg/estate/internal/example"
)

func TestIssuerViews(t *testing.T) {
	in := example.Inputs(t, "testdata/contract.yaml")
	pki := &in.PKI

	private, err := pki.Issuer("private", "private")
	require.NoError(t, err)
	assert.Equal(t, "private-ca", private.Name)
	assert.Equal(t, "private-ca", private.LoginRole)
	assert.Empty(t, private.Audience)
	assert.Equal(t, pki.Contract.DNSTrustDomain("private").IssuingMountPath()+"/sign/private", private.SignPath)
	assert.Equal(t, pki.Contract.Global.KeyAlgorithm, private.Policy.KeyAlgorithm)
	assert.Equal(t, 384, private.Policy.KeySize)
	assert.NotEmpty(t, private.Policy.Duration)

	// A second issuer on the private chain logs in as the chain's own login.
	workload, err := pki.SharedLoginIssuer("workload-ca", "private", "workload")
	require.NoError(t, err)
	assert.Equal(t, "workload-ca", workload.Name)
	assert.Equal(t, "private-ca", workload.LoginRole)
	assert.Equal(t, "openbao-private-ca", workload.Audience)
	assert.Equal(t, private.SignPath[:len(private.SignPath)-len("private")]+"workload", workload.SignPath)

	_, err = pki.Issuer("private", "nope")
	require.ErrorContains(t, err, `no "nope" role`)
	_, err = pki.Issuer("nowhere", "private")
	require.ErrorContains(t, err, "no cluster issuer")
}

func TestIdentityViewsWaitForTheSignedCA(t *testing.T) {
	in := example.Inputs(t, "testdata/contract.yaml")

	// The example commits no signed environment CA: nothing renders.
	for _, environment := range []string{"alpha", "not-an-identity-environment"} {
		signed, err := in.PKI.IdentityEnvironmentSigned(environment)
		require.NoError(t, err)
		assert.False(t, signed, environment)

		issuer, err := in.PKI.IdentityIssuer(environment, "identity")
		require.NoError(t, err)
		assert.Nil(t, issuer)

		ca, err := in.PKI.IdentityEnvironmentCA(environment, "alpha.example.private")
		require.NoError(t, err)
		assert.Nil(t, ca)
	}
}
