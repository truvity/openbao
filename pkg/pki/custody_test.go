package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/custody"
)

const (
	testKey     = "arn:aws:kms:eu-central-1:111122223333:key/mrk-example"
	testReplica = "arn:aws:kms:eu-north-1:111122223333:key/mrk-example"
	testRole    = "arn:aws:iam::111122223333:role/root-ceremony"
	testAdmin   = "arn:aws:iam::111122223333:role/root-admin"
)

func validOutputs() *CustodyOutputs {
	return &CustodyOutputs{
		AdminRoleARN:    testAdmin,
		CeremonyRoleARN: testRole,
		Generations: map[string]CustodyGeneration{"example-root-2026-01": {
			Alias:           custody.DefaultAliasPrefix + "example-root-2026-01",
			PrimaryKeyARN:   testKey,
			PrimaryRegion:   "eu-central-1",
			ReplicaKeyARN:   testReplica,
			ReplicaRegion:   "eu-north-1",
			CeremonyRoleARN: testRole,
		}},
	}
}

func matching() CustodyRequest {
	return CustodyRequest{KeyARN: testKey, ArtifactKeyARN: testKey, RoleARN: testRole, Profile: validContract().Generations[0].Custody.Profile}
}

func TestVerifyCustodyMatch(t *testing.T) {
	verdict, err := validContract().VerifyCustody(validOutputs(), "example-root-2026-01", matching())
	require.NoError(t, err)
	assert.Equal(t, testKey, verdict.KeyARN)
	assert.Equal(t, testRole, verdict.RoleARN)
	assert.Contains(t, strings.Join(verdict.Proven, "\n"), "replica region eu-north-1")

	// Nothing but the key needs to be given: role and profile default to the published ones.
	verdict, err = validContract().VerifyCustody(validOutputs(), "example-root-2026-01", CustodyRequest{KeyARN: testKey})
	require.NoError(t, err)
	assert.Equal(t, testRole, verdict.RoleARN)
	assert.Equal(t, validContract().Generations[0].Custody.Profile, verdict.Profile)
}

// The default alias prefix of pkg/custody is what Validate expects, so a
// stack deployed with the defaults publishes outputs this accepts.
func TestDefaultAliasPrefixIsAccepted(t *testing.T) {
	require.NoError(t, validOutputs().Validate())
}

func TestVerifyCustodyRefusals(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*CustodyOutputs, *CustodyRequest, *Contract)
		want    string
		generic bool
	}{
		{"wrong key", func(_ *CustodyOutputs, r *CustodyRequest, _ *Contract) {
			r.KeyARN = strings.Replace(testKey, "example", "wrong", 1)
		}, "the key to sign with is", false},
		{"root artifact names another key", func(_ *CustodyOutputs, r *CustodyRequest, _ *Contract) {
			r.ArtifactKeyARN = strings.Replace(testKey, "example", "wrong", 1)
		}, "committed root artifact of generation", false},
		{"no key", func(_ *CustodyOutputs, r *CustodyRequest, _ *Contract) { r.KeyARN = "" }, "the key to sign with is required", false},
		{"wrong role", func(_ *CustodyOutputs, r *CustodyRequest, _ *Contract) { r.RoleARN = testAdmin }, "--role-arn is", false},
		{"wrong profile", func(_ *CustodyOutputs, r *CustodyRequest, _ *Contract) { r.Profile = "other" }, "--aws-profile is", false},
		{"unknown generation", func(*CustodyOutputs, *CustodyRequest, *Contract) {}, "unknown root generation", true},
		{"contract region moved", func(_ *CustodyOutputs, _ *CustodyRequest, c *Contract) {
			c.Generations[0].Custody.Region = "eu-west-3"
		}, "custody region is eu-west-3", false},
		{"contract replica moved", func(_ *CustodyOutputs, _ *CustodyRequest, c *Contract) {
			c.Generations[0].Custody.DisasterRecovery.Region = "eu-west-3"
		}, "disaster-recovery region is eu-west-3", false},
		{"contract account moved", func(_ *CustodyOutputs, _ *CustodyRequest, c *Contract) {
			c.Generations[0].Custody.AccountID = "444455556666"
		}, "custody account is 444455556666", false},
		{"outputs generation count differs", func(o *CustodyOutputs, _ *CustodyRequest, _ *Contract) {
			surplus := o.Generations["example-root-2026-01"]
			surplus.Alias = custody.DefaultAliasPrefix + "surplus"
			o.Generations["surplus"] = surplus
		}, "which the contract does not author", false},
		{"alias of another generation", func(o *CustodyOutputs, _ *CustodyRequest, _ *Contract) {
			g := o.Generations["example-root-2026-01"]
			g.Alias = custody.DefaultAliasPrefix + "some-other"
			o.Generations["example-root-2026-01"] = g
		}, "alias", false},
		{"replica region equals primary", func(o *CustodyOutputs, _ *CustodyRequest, _ *Contract) {
			g := o.Generations["example-root-2026-01"]
			g.ReplicaRegion = g.PrimaryRegion
			o.Generations["example-root-2026-01"] = g
		}, "must both be set and differ", false},
		{"key is not multi-region", func(o *CustodyOutputs, r *CustodyRequest, _ *Contract) {
			g := o.Generations["example-root-2026-01"]
			g.PrimaryKeyARN = "arn:aws:kms:eu-central-1:111122223333:key/single"
			o.Generations["example-root-2026-01"] = g
			r.KeyARN, r.ArtifactKeyARN = g.PrimaryKeyARN, g.PrimaryKeyARN
		}, "not a multi-region KMS key ARN", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			outputs, request, contract, generation := validOutputs(), matching(), validContract(), "example-root-2026-01"
			c.mutate(outputs, &request, contract)

			if c.generic {
				generation = "nope"
			}

			_, err := contract.VerifyCustody(outputs, generation, request)
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.want)
		})
	}
}

// A contract with no disaster-recovery region states none to check; the
// outputs still have to publish a replica in a different region.
func TestVerifyCustodyWithoutAuthoredReplicaRegion(t *testing.T) {
	contract := validContract()
	contract.Generations[0].Custody.DisasterRecovery = DisasterRecovery{}

	_, err := contract.VerifyCustody(validOutputs(), "example-root-2026-01", matching())
	require.NoError(t, err)
}

func TestLoadCustodyOutputs(t *testing.T) {
	_, err := LoadCustodyOutputs(filepath.Join(t.TempDir(), "absent.yaml"))
	require.ErrorContains(t, err, "absent.yaml")

	path := filepath.Join(t.TempDir(), "outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte("adminRoleArn: x\nunknown: 1\n"), 0o644))

	_, err = LoadCustodyOutputs(path)
	require.ErrorContains(t, err, "unknown")
}
