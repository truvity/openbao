package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/truvity/secrets/pkg/model"
)

// DefaultTokenTTL is how long an operator login lives unless
// [OperatorLogin.TTL] says otherwise.
const DefaultTokenTTL = "15m"

type (
	// OperatorLogin is the one login path the bootstrap opens: a token of the
	// roster issuer for the OpenBAO audience, whose groups claim names the
	// operator group.
	OperatorLogin struct {
		// Issuer is the roster issuer URL; OpenBAO discovers its keys.
		Issuer string
		// Group is the internal group whose members operate OpenBAO; the
		// identity group and its policy carry the same name.
		Group string
		// TTL is a login token's whole life (a Go duration); default
		// [DefaultTokenTTL].
		TTL string
		// ClaimMappings copy claims into the alias metadata, so an audit
		// entry says who a login was. Nil means email and name; a non-nil
		// map, even an empty one, is used as given.
		ClaimMappings map[string]string
		// Description is what `sys/auth` shows for the door.
		Description string
	}

	mount struct {
		Type     string `json:"type"`
		Accessor string `json:"accessor"`
	}

	mountRequest struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	}

	roleRequest struct {
		RoleType       string            `json:"role_type"`
		BoundAudiences []string          `json:"bound_audiences"`
		UserClaim      string            `json:"user_claim"`
		GroupsClaim    string            `json:"groups_claim"`
		ClaimMappings  map[string]string `json:"claim_mappings"`
		TokenTTL       string            `json:"token_ttl"`
		TokenMaxTTL    string            `json:"token_max_ttl"`
	}

	groupRequest struct {
		Name     string   `json:"name,omitempty"`
		Type     string   `json:"type"`
		Policies []string `json:"policies"`
	}

	aliasRequest struct {
		Name          string `json:"name"`
		MountAccessor string `json:"mount_accessor"`
		CanonicalID   string `json:"canonical_id"`
	}

	group struct {
		ID              string   `json:"id"`
		Type            string   `json:"type"`
		Policies        []string `json:"policies"`
		MemberEntityIDs []string `json:"member_entity_ids"`
		Alias           struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			MountAccessor string `json:"mount_accessor"`
		} `json:"alias"`
	}
)

// roster is the model's roster the login describes.
func (l OperatorLogin) roster() model.Roster {
	mappings := l.ClaimMappings
	if mappings == nil {
		mappings = map[string]string{"email": "email", "name": "name"}
	}

	ttl := l.TTL
	if ttl == "" {
		ttl = DefaultTokenTTL
	}

	return model.Roster{Issuer: l.Issuer, TTL: ttl, ClaimMappings: mappings, Description: l.Description}
}

// Configure opens operator login with the bootstrap root token. Every write
// converges, so running it again repairs drift and changes nothing else.
//
// It refuses to run on a server that is not ready, one that is unaudited, and
// (unless [Settings.AllowNonEmpty]) one that already has mounts beyond the
// operators' door.
func (b *Bootstrap) Configure(ctx context.Context, login OperatorLogin) error {
	defer b.begin()()

	titles, err := b.Keeper.Titles(ctx)
	if err != nil {
		return fmt.Errorf("list the break-glass items: %w", err)
	}

	if !titles[RootTokenItem] {
		b.Logger.InfoContext(ctx, "no bootstrap root token on file: it was revoked, and operators own configuration from here")

		return nil
	}

	token, err := b.Keeper.Reveal(ctx, RootTokenItem)
	if err != nil {
		return fmt.Errorf("read the bootstrap root token: %w", b.API.redactor.scrubErr(err))
	}
	defer zero(token)

	api := b.API.WithToken(token)
	defer api.Wipe()

	if err := b.waitReady(ctx, api); err != nil {
		return err
	}

	if err := b.requireAudit(ctx, api); err != nil {
		return err
	}

	// The operators' door is the public model's bootstrap (Roster.Bootstrap):
	// the one piece of root the apply logs in through and never applies, so
	// it is created here, once, with the root token.
	bootstrap := login.roster().Bootstrap(login.Group)
	if len(bootstrap.Auth) != 1 || len(bootstrap.Auth[0].Roles) != 1 || len(bootstrap.Policies) != 1 || len(bootstrap.Groups) != 1 {
		return fmt.Errorf("the operators' bootstrap is not one door, one role, one policy and one group: %+v", bootstrap)
	}

	door := bootstrap.Auth[0]

	if err := b.requireEmpty(ctx, api, door.Path); err != nil {
		return err
	}

	accessor, err := b.ensureRosterMount(ctx, api, &door)
	if err != nil {
		return err
	}

	if err := b.ensureOperatorGroup(ctx, api, &bootstrap.Policies[0], &bootstrap.Groups[0], accessor); err != nil {
		return err
	}

	b.Logger.InfoContext(ctx, "operator login is open; log in once through the roster, then run revoke-root",
		slog.String("mount", door.Path),
		slog.String("role", door.Roles[0].Name),
		slog.String("group", login.Group),
	)

	return nil
}

// builtinMounts are what every OpenBAO server mounts itself.
var builtinMounts = map[string]bool{"sys/": true, "cubbyhole/": true, "identity/": true, "token/": true}

// requireEmpty refuses to configure a server that already carries mounts
// beyond the operators' door and the built-in ones, unless told it may.
func (b *Bootstrap) requireEmpty(ctx context.Context, api *Client, doorPath string) error {
	if b.Settings.AllowNonEmpty {
		return nil
	}

	auth, err := authMounts(ctx, api)
	if err != nil {
		return err
	}

	var secrets struct {
		Data map[string]mount `json:"data"`
	}

	if err := api.do(ctx, http.MethodGet, "sys/mounts", nil, &secrets); err != nil {
		return err
	}

	var extra []string

	for path := range auth {
		if !builtinMounts[path] && path != doorPath+"/" {
			extra = append(extra, "auth/"+path)
		}
	}

	for path := range secrets.Data {
		if !builtinMounts[path] {
			extra = append(extra, path)
		}
	}

	if len(extra) > 0 {
		slices.Sort(extra)

		return fmt.Errorf("the server is not empty (mounts: %s): configure only opens a fresh install; "+
			"if this is deliberate, say so with the allow-non-empty setting", strings.Join(extra, ", "))
	}

	return nil
}

// waitReady waits until the node is unsealed, a leader is elected and every
// voter has joined: configuring a cluster still forming would succeed on
// one node and be missing from the snapshot of another.
func (b *Bootstrap) waitReady(ctx context.Context, api *Client) error {
	timeout := b.Settings.readyTimeout()
	deadline := time.Now().Add(timeout)

	for {
		voters, why, err := b.readiness(ctx, api)
		if err != nil {
			return err
		}

		if why == "" {
			b.Logger.InfoContext(ctx, "openbao unsealed with a full raft quorum",
				slog.Int("voters", voters),
			)

			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("openbao not ready after %s: %s", timeout, why)
		}

		b.Logger.InfoContext(ctx, "waiting for openbao",
			slog.String("reason", why),
		)

		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for openbao: %w", ctx.Err())
		case <-time.After(b.Poll):
		}
	}
}

// Ready reports whether the server is unsealed with a leader and a full set
// of Raft voters, and when it is not, why. It needs a token that can read the
// Raft configuration.
func (b *Bootstrap) Ready(ctx context.Context, api *Client) (voters int, why string, err error) {
	return b.readiness(ctx, api)
}

// readiness returns the voter count and, when not ready, why not.
func (b *Bootstrap) readiness(ctx context.Context, api *Client) (voters int, why string, err error) {
	var seal struct {
		Sealed bool `json:"sealed"`
	}

	if err := api.do(ctx, http.MethodGet, "sys/seal-status", nil, &seal); err != nil {
		return 0, "", err
	}

	if seal.Sealed {
		return 0, "sealed", nil
	}

	var raft struct {
		Data struct {
			Config struct {
				Servers []struct {
					Voter bool `json:"voter"`
				} `json:"servers"`
			} `json:"config"`
		} `json:"data"`
	}

	// Until a leader exists a node answers 5xx, which means wait; anything
	// else (a refused token, a dropped port-forward) is a real failure.
	if err := api.do(ctx, http.MethodGet, "sys/storage/raft/configuration", nil, &raft); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status >= http.StatusInternalServerError {
			return 0, "no raft leader yet: " + err.Error(), nil
		}

		return 0, "", err
	}

	for _, server := range raft.Data.Config.Servers {
		if server.Voter {
			voters++
		}
	}

	if want := b.Settings.voters(); voters < want {
		return voters, fmt.Sprintf("%d of %d raft voters joined", voters, want), nil
	}

	return voters, "", nil
}

// requireAudit refuses to configure anything unaudited. The device comes
// from the server config, never the API (OpenBAO v2.3.2+ refuses that).
func (b *Bootstrap) requireAudit(ctx context.Context, api *Client) error {
	var devices struct {
		Data map[string]any `json:"data"`
	}

	if err := api.do(ctx, http.MethodGet, "sys/audit", nil, &devices); err != nil {
		return err
	}

	device := b.Settings.audit()
	if _, ok := devices.Data[device+"/"]; !ok {
		return fmt.Errorf("audit device %s/ is not enabled: the pods run a server config without the audit stanza; "+
			"roll them onto a config that declares it", device)
	}

	return nil
}

// ensureRosterMount mounts the JWT method, points it at the roster issuer and
// writes the role; it returns the mount accessor group aliases bind to.
func (b *Bootstrap) ensureRosterMount(ctx context.Context, api *Client, door *model.JWTMount) (string, error) {
	path := door.Path + "/"

	auth, err := authMounts(ctx, api)
	if err != nil {
		return "", err
	}

	existing, mounted := auth[path]
	switch {
	case mounted && existing.Type != model.MethodJWT:
		return "", fmt.Errorf("auth mount %s is %q, not jwt: remove it deliberately", path, existing.Type)
	case !mounted:
		body := mountRequest{
			Type:        model.MethodJWT,
			Description: door.Description,
		}

		if err := api.do(ctx, http.MethodPost, "sys/auth/"+door.Path, body, nil); err != nil {
			return "", err
		}

		b.Logger.InfoContext(ctx, "auth mount created",
			slog.String("mount", path),
		)

		if auth, err = authMounts(ctx, api); err != nil {
			return "", err
		}
	}

	config := map[string]string{
		"oidc_discovery_url": door.DiscoveryURL,
		"bound_issuer":       door.DiscoveryURL,
	}

	if err := api.do(ctx, http.MethodPost, "auth/"+door.Path+"/config", config, nil); err != nil {
		return "", err
	}

	declared := &door.Roles[0]
	role := roleRequest{
		RoleType:       model.MethodJWT,
		BoundAudiences: declared.BoundAudiences,
		UserClaim:      declared.UserClaim,
		GroupsClaim:    declared.GroupsClaim,
		ClaimMappings:  declared.ClaimMappings,
		TokenTTL:       declared.TTL,
		TokenMaxTTL:    declared.TTL,
	}

	if err := api.do(ctx, http.MethodPost, "auth/"+door.Path+"/role/"+declared.Name, role, nil); err != nil {
		return "", err
	}

	accessor := auth[path].Accessor
	if accessor == "" {
		return "", fmt.Errorf("auth mount %s has no accessor", path)
	}

	return accessor, nil
}

func authMounts(ctx context.Context, api *Client) (map[string]mount, error) {
	var answer struct {
		Data map[string]mount `json:"data"`
	}

	if err := api.do(ctx, http.MethodGet, "sys/auth", nil, &answer); err != nil {
		return nil, err
	}

	return answer.Data, nil
}

// ensureOperatorGroup writes the operator policy (model.OperatorPolicy:
// every capability everywhere, in root and, through root, in every child
// namespace -- operators replace the root token), the external identity group
// of the same name, and the alias that ties the group to the name in a
// roster token's groups claim. The directory group is never named here.
func (b *Bootstrap) ensureOperatorGroup(ctx context.Context, api *Client, policy *model.Policy, operators *model.Group, accessor string) error {
	name := operators.Name
	escaped := url.PathEscape(name)

	if err := api.do(ctx, http.MethodPut, "sys/policies/acl/"+url.PathEscape(policy.Name), map[string]string{"policy": policy.HCL()}, nil); err != nil {
		return err
	}

	current, found, err := readGroup(ctx, api, name)
	if err != nil {
		return err
	}

	body := groupRequest{Type: "external", Policies: operators.Policies}

	switch {
	case found && current.Type != "external":
		return fmt.Errorf("identity group %s is %q: an internal group cannot take a roster alias; remove it deliberately", name, current.Type)
	case found && slices.Equal(current.Policies, operators.Policies):
	case found:
		if err := api.do(ctx, http.MethodPost, "identity/group/name/"+escaped, body, nil); err != nil {
			return err
		}
	default:
		body.Name = name

		if err := api.do(ctx, http.MethodPost, "identity/group", body, nil); err != nil {
			return err
		}

		b.Logger.InfoContext(ctx, "identity group created",
			slog.String("group", name),
		)
	}

	if current, _, err = readGroup(ctx, api, name); err != nil {
		return err
	}

	alias := aliasRequest{Name: name, MountAccessor: accessor, CanonicalID: current.ID}

	switch {
	case current.Alias.ID == "":
		return api.do(ctx, http.MethodPost, "identity/group-alias", alias, nil)
	case current.Alias.Name != name || current.Alias.MountAccessor != accessor:
		return api.do(ctx, http.MethodPost, "identity/group-alias/id/"+current.Alias.ID, alias, nil)
	default:
		return nil
	}
}

func readGroup(ctx context.Context, api *Client, name string) (group, bool, error) {
	var answer struct {
		Data *group `json:"data"`
	}

	err := api.do(ctx, http.MethodGet, "identity/group/name/"+url.PathEscape(name), nil, &answer)

	switch {
	case hasStatus(err, http.StatusNotFound):
		return group{}, false, nil
	case err != nil:
		return group{}, false, err
	case answer.Data == nil:
		return group{}, false, nil
	default:
		return *answer.Data, true, nil
	}
}
