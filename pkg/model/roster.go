package model

import (
	"maps"
	"slices"
	"strings"
)

// The names an access-roster installation and its clients agree on unless
// told otherwise: accessctl logs in on RosterMount as RosterRole with a
// token exchanged for RosterAudience, and the web UI signs in on
// RosterUIMount as RosterUIClient. docs/integrations/access-roster.md is
// the whole contract.
const (
	// RosterMount is the JWT auth mount people and jobs log in through.
	RosterMount = "jwt-roster"
	// RosterRole is the one role on that mount: the groups claim decides
	// the rest.
	RosterRole = "roster"
	// RosterAudience is the issuer's exchange client whose tokens OpenBAO
	// accepts: the audience of every token presented at RosterMount.
	RosterAudience = "openbao"
	// RosterGroupsClaim is the claim carrying the caller's internal group
	// names, flat, one string per group.
	RosterGroupsClaim = "groups"
	// RosterUserClaim names an entity alias after the token's subject.
	RosterUserClaim = "sub"
	// RosterUIMount is the web UI's door: the path the UI's OIDC tab
	// assumes, so nobody types a mount path.
	RosterUIMount = "oidc"
	// RosterUIClient is the issuer's confidential client the UI signs in
	// as, and so the audience of the ID token OpenBAO receives.
	RosterUIClient = "openbao-ui"
)

type (
	// Roster is an OIDC issuer whose tokens carry a flat groups claim --
	// access-roster's access-issuer, or any issuer shaped like it -- as an
	// OpenBAO server trusts it: one people-and-jobs door per namespace, an
	// optional web UI door beside it, and identity groups named after the
	// groups in the claim.
	//
	// The zero values of the optional fields are the defaults above. Issuer
	// and TTL have none: which issuer, and how long a login lives, are
	// always said out loud.
	Roster struct {
		// Issuer is the issuer's URL: its OIDC discovery base and the bound
		// issuer. Required.
		Issuer string
		// Audience defaults to RosterAudience.
		Audience string
		// GroupsClaim defaults to RosterGroupsClaim.
		GroupsClaim string
		// UserClaim defaults to RosterUserClaim.
		UserClaim string
		// ClaimMappings copy claims into the alias metadata (claim ->
		// metadata key), so an audit entry says who a login was. None by
		// default.
		ClaimMappings map[string]string
		// TTL is a login token's whole life, on both doors: a Go duration.
		// Required.
		TTL string
		// Mount and Role default to RosterMount and RosterRole.
		Mount string
		Role  string
		// Description is what `sys/auth` shows for the door; empty for none.
		Description string
		// UI, when set, adds the web UI's door beside this one.
		UI *RosterUI
	}

	// RosterUI is the web UI's door: the JWT/OIDC plugin in OIDC mode,
	// signing people in through the browser as a confidential client of
	// the same issuer. Its role mirrors the roster role -- the same user
	// claim, groups claim, claim mappings and TTL -- so a person gets the
	// same token either way; only the audience differs, because an ID
	// token is issued to the UI's client.
	RosterUI struct {
		// Mount defaults to RosterUIMount; ClientID to RosterUIClient. The
		// client's secret is an input of the apply
		// (apply.Options.OIDCClientSecrets), never desired state.
		Mount    string
		ClientID string
		// RedirectURIs are the UI's callbacks ([UICallback]). Required: one
		// serves every namespace, because the mount keeps the namespace in
		// the OIDC state.
		RedirectURIs []string
		// Scopes default to profile and email. OpenBAO adds openid itself,
		// and access-roster puts groups in every token it mints, so no
		// groups scope is asked for.
		Scopes []string
		// Description is what `sys/auth` shows for the door; empty for none.
		Description string
	}
)

// UICallback is the web UI's OIDC callback on a server reached at address,
// for a UI door on mount: the one redirect URI the issuer's UI client
// registers, whatever the namespace.
func UICallback(address, mount string) string {
	return strings.TrimSuffix(address, "/") + "/ui/vault/auth/" + mount + "/oidc/callback"
}

// OperatorPolicy grants every capability on every path: in root it reaches
// every namespace below it too. It is what the operators' group carries in
// place of a root token.
func OperatorPolicy(name string) Policy {
	return Policy{Name: name, Rules: []Rule{{
		Path:         "*",
		Capabilities: []string{CapCreate, CapRead, CapUpdate, CapPatch, CapDelete, CapList, CapSudo},
	}}}
}

// Door is the people-and-jobs mount: one role, bound to the audience,
// mapping the groups claim, attaching no policy itself -- the identity
// groups aliased on this mount carry the policies.
func (r Roster) Door() JWTMount {
	r = r.resolved()

	return JWTMount{
		Path:         r.Mount,
		Description:  r.Description,
		DiscoveryURL: r.Issuer,
		Roles: []Role{{
			Name:           r.Role,
			BoundAudiences: []string{r.Audience},
			UserClaim:      r.UserClaim,
			GroupsClaim:    r.GroupsClaim,
			ClaimMappings:  cloneMap(r.ClaimMappings),
			TTL:            r.TTL,
		}},
	}
}

// UIDoor is the web UI's mount, and false when the roster has no UI.
func (r Roster) UIDoor() (JWTMount, bool) {
	if r.UI == nil {
		return JWTMount{}, false
	}

	r = r.resolved()
	ui := r.UI

	return JWTMount{
		Path:         ui.Mount,
		Type:         MethodOIDC,
		Description:  ui.Description,
		ClientID:     ui.ClientID,
		DefaultRole:  r.Role,
		DiscoveryURL: r.Issuer,
		Roles: []Role{{
			Name:                r.Role,
			Type:                MethodOIDC,
			BoundAudiences:      []string{ui.ClientID},
			UserClaim:           r.UserClaim,
			GroupsClaim:         r.GroupsClaim,
			ClaimMappings:       cloneMap(r.ClaimMappings),
			AllowedRedirectURIs: slices.Clone(ui.RedirectURIs),
			OIDCScopes:          slices.Clone(ui.Scopes),
			TTL:                 r.TTL,
		}},
	}, true
}

// Doors are the roster's mounts for one namespace: the people-and-jobs
// door, then the UI's when there is one.
func (r Roster) Doors() []JWTMount {
	doors := []JWTMount{r.Door()}
	if ui, ok := r.UIDoor(); ok {
		doors = append(doors, ui)
	}

	return doors
}

// DoorPaths are the paths of [Roster.Doors], in the same order: what a
// person's group is admitted through.
func (r Roster) DoorPaths() []string {
	r = r.resolved()

	paths := []string{r.Mount}
	if r.UI != nil {
		paths = append(paths, r.UI.Mount)
	}

	return paths
}

// Identity makes the people-and-jobs door primary: its identity groups keep
// the bare group names, the UI's are `<name>@<ui mount>`.
func (r Roster) Identity(metadata map[string]string) Identity {
	return Identity{PrimaryDoor: r.resolved().Mount, Metadata: cloneMap(metadata)}
}

// Grant is a policy named after a group, with the rules given, and the
// group admitted through every door of the roster: the shape by which an
// internal group name in the token becomes a policy.
func (r Roster) Grant(name string, rules ...Rule) (Policy, Group) {
	return grant(name, rules, r.DoorPaths())
}

// JobGrant is [Roster.Grant] through the people-and-jobs door alone: for a
// group only jobs hold, which have no browser, so a grant on the UI door
// would be one nothing can use.
func (r Roster) JobGrant(name string, rules ...Rule) (Policy, Group) {
	return grant(name, rules, []string{r.resolved().Mount})
}

// Bootstrap is the operators' door in root, for [Desired.Bootstrap]: the
// people-and-jobs door, the operators' policy ([OperatorPolicy]) and the
// operators' group admitted through it. The apply logs in through it and
// never applies it; the server's initialisation creates it.
func (r Roster) Bootstrap(operators string) Namespace {
	policy, group := r.JobGrant(operators, OperatorPolicy(operators).Rules...)

	return Namespace{
		Auth:     []JWTMount{r.Door()},
		Policies: []Policy{policy},
		Groups:   []Group{group},
	}
}

// RootUI is what root needs, beside the bootstrap, for operators to sign
// in to the web UI there: the UI door and the operators' group admitted
// through it, carrying the policy the bootstrap declares. Empty when the
// roster has no UI.
func (r Roster) RootUI(operators string) Namespace {
	ui, ok := r.UIDoor()
	if !ok {
		return Namespace{}
	}

	return Namespace{
		Auth:   []JWTMount{ui},
		Groups: []Group{{Name: operators, Policies: []string{operators}, Doors: []string{ui.Path}}},
	}
}

// resolved fills in every default.
func (r Roster) resolved() Roster {
	r.Audience = orDefault(r.Audience, RosterAudience)
	r.GroupsClaim = orDefault(r.GroupsClaim, RosterGroupsClaim)
	r.UserClaim = orDefault(r.UserClaim, RosterUserClaim)
	r.Mount = orDefault(r.Mount, RosterMount)
	r.Role = orDefault(r.Role, RosterRole)

	if r.UI != nil {
		ui := *r.UI
		ui.Mount = orDefault(ui.Mount, RosterUIMount)
		ui.ClientID = orDefault(ui.ClientID, RosterUIClient)

		if len(ui.Scopes) == 0 {
			ui.Scopes = []string{"profile", "email"}
		}

		r.UI = &ui
	}

	return r
}

func grant(name string, rules []Rule, doors []string) (Policy, Group) {
	return Policy{Name: name, Rules: slices.Clone(rules)},
		Group{Name: name, Policies: []string{name}, Doors: doors}
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}

	return value
}

// cloneMap copies a map so no two roles share one; nil stays nil, so an
// empty mapping is left out of the yaml.
func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}

	return maps.Clone(in)
}
