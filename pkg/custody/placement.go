package custody

import (
	"fmt"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type (
	// Placement is one root generation as an estate's contract authors it:
	// the key placement plus the custody account it names. The roles are one
	// pair for every generation, so every placement must name the same
	// account, profile and trusted principal.
	Placement struct {
		Generation
		AccountID                  string
		Profile                    string
		TrustedPrincipalARNPattern string
	}
)

// WithPlacements returns the Args with the account, profile, trusted
// principal and generations taken from the placements (oldest first). It
// refuses placements that disagree on the shared custody account, profile
// or trusted principal, and an empty list.
func (a Args) WithPlacements(placements []Placement) (Args, error) {
	if len(placements) == 0 {
		return Args{}, fmt.Errorf("custody requires at least one root generation")
	}
	first := placements[0]
	generations := make([]Generation, 0, len(placements))
	for _, placement := range placements {
		if placement.AccountID != first.AccountID ||
			placement.Profile != first.Profile ||
			placement.TrustedPrincipalARNPattern != first.TrustedPrincipalARNPattern {
			return Args{}, fmt.Errorf("all root generations must use the same custody account/profile/trusted principal as %s", first.ID)
		}
		generations = append(generations, placement.Generation)
	}
	a.AccountID = first.AccountID
	a.Profile = first.Profile
	a.TrustedPrincipalARNPattern = first.TrustedPrincipalARNPattern
	a.Generations = generations
	return a, nil
}

// Export publishes what a custody stack's consumers read: the two role ARNs
// as "adminRoleArn" and "ceremonyRoleArn", and per generation, under
// "generations", its alias, primary and replica key ARNs and regions, and
// the ceremony role ARN.
func (c *Custody) Export(ctx *pulumi.Context) {
	outputs := pulumi.Map{}
	for _, generation := range c.Generations {
		outputs[generation.ID] = pulumi.Map{
			"alias":           pulumi.String(generation.Alias),
			"primaryKeyArn":   generation.Key.Arn,
			"primaryRegion":   pulumi.String(generation.Region),
			"replicaKeyArn":   generation.Replica.Arn,
			"replicaRegion":   pulumi.String(generation.ReplicaRegion),
			"ceremonyRoleArn": c.CeremonyRole.Arn,
		}
	}
	ctx.Export("adminRoleArn", c.AdminRole.Arn)
	ctx.Export("ceremonyRoleArn", c.CeremonyRole.Arn)
	ctx.Export("generations", outputs)
}
