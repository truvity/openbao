package model

import (
	"fmt"
	"strings"
)

const (
	// MethodOIDC is the JWT/OIDC plugin's type for a browser sign-in, on a
	// mount and on its roles. A jwt mount or role leaves Type empty.
	MethodOIDC = "oidc"
	// MethodJWT is what an empty Type means.
	MethodJWT = "jwt"
)

// DefaultSupportedAlgorithms is what a mount accepts when it names no
// SupportedAlgorithms of its own. The plugin's own default is RS256 alone
// for an oidc-type role ("all" for a jwt-type role), which refuses an
// issuer that signs ES256 or ES384; this library states these three
// explicitly instead, on every mount it applies. See JWTMount.Algorithms.
var DefaultSupportedAlgorithms = []string{"RS256", "ES256", "ES384"}

// jwtSigningAlgorithms is every signing algorithm SupportedAlgorithms may
// name. HS256/HS384/HS512 (a shared secret) and "none" are never among
// them: a mount that accepted either would let anyone who can read the
// issuer's public JWKS -- which is everyone -- mint its own tokens.
var jwtSigningAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"EdDSA": true,
}

type (
	// JWTMount is one auth method of the JWT/OIDC plugin: whose tokens it
	// accepts, and the roles a login names.
	//
	// Two kinds of role live on such a mount. A WORKLOAD role binds one
	// token subject -- a Kubernetes ServiceAccount's projected token
	// ([ServiceAccountSubject]) -- and attaches its policies to the token
	// directly. A PEOPLE role maps the issuer's groups claim onto identity
	// groups and attaches nothing itself: the groups' aliases on this mount
	// carry the policies.
	JWTMount struct {
		Path string `yaml:"path"`
		// Type is MethodOIDC for a browser sign-in mount (the web UI's
		// door), empty for jwt. An oidc mount keeps the namespace in the
		// OIDC state, so one redirect URI serves every namespace, and is
		// listed on the UI's sign-in page.
		Type string `yaml:"type,omitempty"`
		// Description is what `sys/auth` shows an operator.
		Description string `yaml:"description,omitempty"`
		// ClientID is the issuer client an oidc mount signs in as. Its
		// secret is an input of the apply and is never desired state.
		ClientID string `yaml:"clientId,omitempty"`
		// DefaultRole is the role a login that names none gets.
		DefaultRole string `yaml:"defaultRole,omitempty"`
		// DiscoveryURL is the issuer's OIDC discovery base, which is also
		// the bound issuer.
		DiscoveryURL string `yaml:"discoveryUrl"`
		// SupportedAlgorithms is the signing algorithms this mount accepts
		// from a token, whether the login is a jwt role's or an oidc role's
		// browser callback. Empty means DefaultSupportedAlgorithms; call
		// Algorithms rather than reading this field, so the default lives
		// in one place.
		SupportedAlgorithms []string `yaml:"supportedAlgorithms,omitempty"`
		Roles               []Role   `yaml:"roles"`
	}

	// Role is one role on a JWT/OIDC mount.
	Role struct {
		Name string `yaml:"name"`
		// Type is MethodOIDC for a browser sign-in role, empty for jwt.
		Type           string   `yaml:"type,omitempty"`
		BoundAudiences []string `yaml:"boundAudiences"`
		// BoundSubject pins the role to one `sub`: a workload.
		BoundSubject string `yaml:"boundSubject,omitempty"`
		// UserClaim names the entity alias after a claim of the token.
		UserClaim string `yaml:"userClaim"`
		// GroupsClaim maps the token's groups onto identity groups: people.
		GroupsClaim string `yaml:"groupsClaim,omitempty"`
		// ClaimMappings copy claims into the alias metadata, so an audit
		// entry says who a login was (claim -> metadata key).
		ClaimMappings map[string]string `yaml:"claimMappings,omitempty"`
		// AllowedRedirectURIs and OIDCScopes belong to an oidc role only.
		AllowedRedirectURIs []string `yaml:"allowedRedirectUris,omitempty"`
		OIDCScopes          []string `yaml:"oidcScopes,omitempty"`
		// Policies are attached to the token directly; people get theirs
		// from identity groups instead.
		Policies []string `yaml:"policies,omitempty"`
		// TTL is both the token's lifetime and its maximum: a Go duration.
		TTL string `yaml:"ttl"`
	}
)

// Algorithms is what this mount actually accepts: SupportedAlgorithms if it
// names any, DefaultSupportedAlgorithms otherwise. pkg/apply calls this,
// never SupportedAlgorithms directly, so the default resolution lives in
// this one place.
func (m *JWTMount) Algorithms() []string {
	if len(m.SupportedAlgorithms) > 0 {
		return m.SupportedAlgorithms
	}

	return DefaultSupportedAlgorithms
}

// ServiceAccountSubject is the `sub` of a Kubernetes ServiceAccount's
// projected token, which a workload role binds.
func ServiceAccountSubject(namespace, serviceAccount string) string {
	return "system:serviceaccount:" + namespace + ":" + serviceAccount
}

// Validate refuses a mount that could not be applied: every mount is a path
// on an issuer, an oidc mount signs in as a client, and a default role is
// one of the mount's own.
func (m *JWTMount) Validate() error {
	if strings.TrimSpace(m.Path) == "" {
		return fmt.Errorf("an auth mount has no path")
	}

	if m.Type != "" && m.Type != MethodOIDC {
		return fmt.Errorf("auth mount %q has type %q, want empty (jwt) or %s", m.Path, m.Type, MethodOIDC)
	}

	if strings.TrimSpace(m.DiscoveryURL) == "" {
		return fmt.Errorf("auth mount %q has no issuer", m.Path)
	}

	if m.Type == MethodOIDC && strings.TrimSpace(m.ClientID) == "" {
		return fmt.Errorf("oidc mount %q signs in as no client", m.Path)
	}

	if err := validateAlgorithms(m.SupportedAlgorithms); err != nil {
		return fmt.Errorf("auth mount %q: %w", m.Path, err)
	}

	seen := make(map[string]bool, len(m.Roles))

	for i := range m.Roles {
		role := &m.Roles[i]
		if err := role.Validate(); err != nil {
			return fmt.Errorf("auth mount %q: %w", m.Path, err)
		}

		if role.Type == MethodOIDC && m.Type != MethodOIDC {
			return fmt.Errorf("auth mount %q: oidc role %q on a jwt mount", m.Path, role.Name)
		}

		if seen[role.Name] {
			return fmt.Errorf("auth mount %q declares role %q twice", m.Path, role.Name)
		}

		seen[role.Name] = true
	}

	if m.DefaultRole != "" && !seen[m.DefaultRole] {
		return fmt.Errorf("auth mount %q defaults to role %q, which it does not declare", m.Path, m.DefaultRole)
	}

	return nil
}

// validateAlgorithms refuses a name jwtSigningAlgorithms does not list --
// which is every HS* algorithm and "none" along with any typo -- and a
// name repeated.
func validateAlgorithms(algorithms []string) error {
	seen := make(map[string]bool, len(algorithms))

	for _, algorithm := range algorithms {
		if !jwtSigningAlgorithms[algorithm] {
			return fmt.Errorf("supported algorithm %q is not one the JWT plugin signs with", algorithm)
		}

		if seen[algorithm] {
			return fmt.Errorf("supported algorithm %q named twice", algorithm)
		}

		seen[algorithm] = true
	}

	return nil
}

// Validate refuses a role that would admit more than it names: a role binds
// an audience, binds a subject or maps a groups claim (a role with neither
// admits every token of the audience), names the claim that becomes the
// entity, and expires.
func (r *Role) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("a role has no name")
	}

	if r.Type != "" && r.Type != MethodOIDC {
		return fmt.Errorf("role %q has type %q, want empty (jwt) or %s", r.Name, r.Type, MethodOIDC)
	}

	if len(r.BoundAudiences) == 0 {
		return fmt.Errorf("role %q binds no audience", r.Name)
	}

	if strings.TrimSpace(r.BoundSubject) == "" && strings.TrimSpace(r.GroupsClaim) == "" {
		return fmt.Errorf("role %q binds no subject and maps no groups claim, so it admits every token for its audience", r.Name)
	}

	if strings.TrimSpace(r.UserClaim) == "" {
		return fmt.Errorf("role %q names no user claim", r.Name)
	}

	if _, err := durationSeconds(r.TTL); err != nil {
		return fmt.Errorf("role %q: %w", r.Name, err)
	}

	if r.Type != MethodOIDC && (len(r.AllowedRedirectURIs) > 0 || len(r.OIDCScopes) > 0) {
		return fmt.Errorf("role %q is a jwt role with oidc redirect URIs or scopes", r.Name)
	}

	if r.Type == MethodOIDC && len(r.AllowedRedirectURIs) == 0 {
		return fmt.Errorf("oidc role %q allows no redirect URI", r.Name)
	}

	return nil
}
