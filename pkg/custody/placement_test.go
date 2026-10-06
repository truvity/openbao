package custody

import (
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func examplePlacement(id string) Placement {
	return Placement{
		Generation:                 Generation{ID: id, Region: testPrimary, ReplicaRegion: testReplica},
		AccountID:                  testAccount,
		Profile:                    "example-custody",
		TrustedPrincipalARNPattern: testPattern,
	}
}

func TestWithPlacementsTakesTheSharedCustodyAndTheGenerations(t *testing.T) {
	args, err := Args{AdminRoleName: "a", CeremonyRoleName: "b"}.
		WithPlacements([]Placement{examplePlacement("g1"), examplePlacement("g2")})
	require.NoError(t, err)
	assert.Equal(t, testAccount, args.AccountID)
	assert.Equal(t, "example-custody", args.Profile)
	assert.Equal(t, testPattern, args.TrustedPrincipalARNPattern)
	assert.Equal(t, "a", args.AdminRoleName)
	assert.Equal(t, []Generation{
		{ID: "g1", Region: testPrimary, ReplicaRegion: testReplica},
		{ID: "g2", Region: testPrimary, ReplicaRegion: testReplica},
	}, args.Generations)
}

func TestWithPlacementsRefusesGenerationsThatDisagree(t *testing.T) {
	for name, change := range map[string]func(*Placement){
		"account":   func(p *Placement) { p.AccountID = "444455556666" },
		"profile":   func(p *Placement) { p.Profile = "other" },
		"principal": func(p *Placement) { p.TrustedPrincipalARNPattern = "arn:aws:iam::111122223333:role/other" },
	} {
		second := examplePlacement("g2")
		change(&second)
		_, err := Args{}.WithPlacements([]Placement{examplePlacement("g1"), second})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "same custody account/profile/trusted principal as g1", name)
	}
	_, err := Args{}.WithPlacements(nil)
	require.Error(t, err)
}

func TestExportPublishesRolesAndEveryGeneration(t *testing.T) {
	mocks := &custodyMocks{}
	require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error {
		deployed, err := Deploy(ctx, testArgs())
		if err != nil {
			return err
		}
		deployed.Export(ctx)
		return nil
	}, pulumi.WithMocks("example", "custody", mocks)))
}
