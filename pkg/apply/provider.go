package apply

import (
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// NewProvider logs in to root with a JWT and uses the login token as is:
// no child token, because a short-lived login token cannot mint a child
// that outlives it. The token is fetched now and marked secret; nothing is
// stored. Other programs that write into OpenBAO as the same operator use
// it too, so every program logs in the same way.
func NewProvider(c *pulumi.Context, name, address string, login Login, opts ...pulumi.ResourceOption) (*vault.Provider, error) {
	if login.Token == nil {
		return nil, fmt.Errorf("apply: the login has no token source")
	}

	token, err := login.Token(c.Context())
	if err != nil {
		return nil, err
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("apply: the login token is empty")
	}

	args := &vault.ProviderArgs{
		Address:        pulumi.String(address),
		SkipChildToken: pulumi.Bool(true),
		AuthLoginJwt: &vault.ProviderAuthLoginJwtArgs{
			Mount:            pulumi.String(login.Mount),
			Role:             pulumi.String(login.Role),
			Jwt:              pulumi.ToSecret(pulumi.String(token)).(pulumi.StringOutput),
			UseRootNamespace: pulumi.Bool(true),
		},
	}

	if login.CACertFile != "" {
		args.CaCertFile = pulumi.String(login.CACertFile)
	}

	provider, err := vault.NewProvider(c, name, args, opts...)
	if err != nil {
		return nil, fmt.Errorf("apply: openbao provider: %w", err)
	}

	return provider, nil
}
