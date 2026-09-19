package model_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/openbao/pkg/model"
)

func roster() model.Roster {
	return model.Roster{
		Issuer: "https://id.example.com",
		TTL:    "1h",
		UI:     &model.RosterUI{RedirectURIs: []string{model.UICallback("https://openbao.example.com/", model.RosterUIMount)}},
	}
}

// The defaults are the names access-roster's clients use unless told
// otherwise: a door built from nothing but an issuer and a lifetime is the
// one accessctl logs in on.
func TestRosterDoorDefaults(t *testing.T) {
	door := roster().Door()

	assert.Equal(t, model.JWTMount{
		Path:         "jwt-roster",
		DiscoveryURL: "https://id.example.com",
		Roles: []model.Role{{
			Name:           "roster",
			BoundAudiences: []string{"openbao"},
			UserClaim:      "sub",
			GroupsClaim:    "groups",
			TTL:            "1h",
		}},
	}, door)
	require.NoError(t, door.Validate())
}

// The UI's role mirrors the roster role -- user claim, groups claim,
// mappings, TTL -- and differs only in the audience, which is the UI's
// client, and in being a browser sign-in.
func TestRosterUIDoorMirrorsTheRosterRole(t *testing.T) {
	r := roster()
	r.ClaimMappings = map[string]string{"email": "email"}

	ui, ok := r.UIDoor()
	require.True(t, ok)
	require.NoError(t, ui.Validate())

	assert.Equal(t, "oidc", ui.Path)
	assert.Equal(t, model.MethodOIDC, ui.Type)
	assert.Equal(t, "openbao-ui", ui.ClientID)
	assert.Equal(t, "roster", ui.DefaultRole)
	assert.Equal(t, "https://id.example.com", ui.DiscoveryURL)

	cli := r.Door().Roles[0]
	browser := ui.Roles[0]
	assert.Equal(t, []string{"openbao-ui"}, browser.BoundAudiences)
	assert.Equal(t, model.MethodOIDC, browser.Type)
	assert.Equal(t, []string{"https://openbao.example.com/ui/vault/auth/oidc/oidc/callback"}, browser.AllowedRedirectURIs)
	assert.Equal(t, []string{"profile", "email"}, browser.OIDCScopes)

	browser.Type, browser.BoundAudiences, browser.AllowedRedirectURIs, browser.OIDCScopes = "", cli.BoundAudiences, nil, nil
	assert.Equal(t, cli, browser, "apart from the audience and the browser fields, the two roles are one")

	cli.ClaimMappings["email"] = "changed"
	assert.Equal(t, "email", ui.Roles[0].ClaimMappings["email"], "the roles must not share a mapping")
}

func TestRosterOverrides(t *testing.T) {
	r := model.Roster{
		Issuer: "https://issuer.example.org", Audience: "vault", GroupsClaim: "roles", UserClaim: "email",
		TTL: "15m", Mount: "jwt-people", Role: "people", Description: "people",
		UI: &model.RosterUI{Mount: "sso", ClientID: "vault-ui", RedirectURIs: []string{"https://v.example.org/cb"}, Scopes: []string{"email"}},
	}

	doors := r.Doors()
	require.Len(t, doors, 2)
	assert.Equal(t, []string{"jwt-people", "sso"}, r.DoorPaths())
	assert.Equal(t, "people", doors[0].Roles[0].Name)
	assert.Equal(t, []string{"vault"}, doors[0].Roles[0].BoundAudiences)
	assert.Equal(t, "roles", doors[0].Roles[0].GroupsClaim)
	assert.Equal(t, "email", doors[0].Roles[0].UserClaim)
	assert.Equal(t, "people", doors[0].Description)
	assert.Equal(t, []string{"vault-ui"}, doors[1].Roles[0].BoundAudiences)
	assert.Equal(t, "people", doors[1].DefaultRole)
	assert.Equal(t, []string{"email"}, doors[1].Roles[0].OIDCScopes)
	assert.Equal(t, model.Identity{PrimaryDoor: "jwt-people"}, r.Identity(nil))

	for i := range doors {
		require.NoError(t, doors[i].Validate())
	}
}

func TestRosterWithoutUI(t *testing.T) {
	r := roster()
	r.UI = nil

	_, ok := r.UIDoor()
	assert.False(t, ok)
	assert.Len(t, r.Doors(), 1)
	assert.Equal(t, []string{"jwt-roster"}, r.DoorPaths())
	assert.Equal(t, model.Namespace{}, r.RootUI("ops"))

	_, group := r.Grant("dev:reader", model.Rule{Path: "kv/data/*", Capabilities: []string{model.CapRead}})
	assert.Equal(t, []string{"jwt-roster"}, group.Doors)
}

// What the preset cannot default is refused by the model's own checks, so
// a roster door is never applied half-said.
func TestRosterRefusals(t *testing.T) {
	noIssuer := roster()
	noIssuer.Issuer = ""
	require.ErrorContains(t, ptr(noIssuer.Door()).Validate(), "no issuer")

	noTTL := roster()
	noTTL.TTL = ""
	require.ErrorContains(t, ptr(noTTL.Door()).Validate(), "ttl")

	noRedirect := roster()
	noRedirect.UI = &model.RosterUI{}
	ui, _ := noRedirect.UIDoor()
	require.ErrorContains(t, ui.Validate(), "redirect")
}

// A grant is the one pattern by which an internal group name becomes a
// policy: a policy of the group's own name, and the group admitted through
// every door -- or, for a job's group, the roster door alone.
func TestRosterGrants(t *testing.T) {
	r := roster()
	sign := model.Rule{Path: "ssh/sign/user", Capabilities: []string{model.CapUpdate}}

	policy, group := r.Grant("dev:ssh:user", sign)
	assert.Equal(t, model.Policy{Name: "dev:ssh:user", Rules: []model.Rule{sign}}, policy)
	assert.Equal(t, model.Group{Name: "dev:ssh:user", Policies: []string{"dev:ssh:user"}, Doors: []string{"jwt-roster", "oidc"}}, group)

	_, job := r.JobGrant("ci-release", model.Rule{Path: "kv/data/ci/release", Capabilities: []string{model.CapRead}})
	assert.Equal(t, []string{"jwt-roster"}, job.Doors)
}

// The operators' door: declared as the bootstrap, admitted through the
// roster door alone, carrying every capability; the UI's door into root
// is applied and carries the bootstrap's policy by name.
func TestRosterOperators(t *testing.T) {
	r := roster()
	r.TTL = "15m"

	bootstrap := r.Bootstrap("all:openbao:operator")
	require.NoError(t, bootstrap.Validate())
	assert.Equal(t, []model.JWTMount{r.Door()}, bootstrap.Auth)
	assert.Equal(t, []model.Policy{model.OperatorPolicy("all:openbao:operator")}, bootstrap.Policies)
	assert.Equal(t, []model.Group{{Name: "all:openbao:operator", Policies: []string{"all:openbao:operator"}, Doors: []string{"jwt-roster"}}}, bootstrap.Groups)

	root := r.RootUI("all:openbao:operator")
	require.NoError(t, root.Validate())
	require.Len(t, root.Auth, 1)
	assert.Equal(t, "oidc", root.Auth[0].Path)
	assert.Empty(t, root.Policies, "the policy is the bootstrap's")
	assert.Equal(t, []string{"oidc"}, root.Groups[0].Doors)

	desired := model.Desired{Bootstrap: bootstrap, Root: root, Identity: r.Identity(nil)}
	require.NoError(t, desired.Validate())
}

// The yaml a review reads for a roster door, from the preset alone. The
// same shape is in examples/roster/desired.yaml, applied end to end by the
// conformance test.
func ExampleRoster() {
	r := model.Roster{
		Issuer: "https://id.example.com",
		TTL:    "1h",
		UI:     &model.RosterUI{RedirectURIs: []string{model.UICallback("https://openbao.example.com", model.RosterUIMount)}},
	}

	policy, group := r.Grant("dev:ssh:user", model.Rule{Path: "ssh/sign/user", Capabilities: []string{model.CapUpdate}})

	out, err := yaml.Marshal(model.Namespace{Name: "dev", Auth: r.Doors(), Policies: []model.Policy{policy}, Groups: []model.Group{group}})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)

		return
	}

	fmt.Print(string(out))
	// Output:
	// name: dev
	// auth:
	//     - path: jwt-roster
	//       discoveryUrl: https://id.example.com
	//       roles:
	//         - name: roster
	//           boundAudiences:
	//             - openbao
	//           userClaim: sub
	//           groupsClaim: groups
	//           ttl: 1h
	//     - path: oidc
	//       type: oidc
	//       clientId: openbao-ui
	//       defaultRole: roster
	//       discoveryUrl: https://id.example.com
	//       roles:
	//         - name: roster
	//           type: oidc
	//           boundAudiences:
	//             - openbao-ui
	//           userClaim: sub
	//           groupsClaim: groups
	//           allowedRedirectUris:
	//             - https://openbao.example.com/ui/vault/auth/oidc/oidc/callback
	//           oidcScopes:
	//             - profile
	//             - email
	//           ttl: 1h
	// policies:
	//     - name: dev:ssh:user
	//       rules:
	//         - path: ssh/sign/user
	//           capabilities:
	//             - update
	// groups:
	//     - name: dev:ssh:user
	//       policies:
	//         - dev:ssh:user
	//       doors:
	//         - jwt-roster
	//         - oidc
}

func ptr[T any](v T) *T { return &v }
