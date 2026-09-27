package model

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// rootPrincipal is the account no SSH role may name.
const rootPrincipal = "root"

// hostCertMaxTTL is the longest a host certificate may live: 30 days.
// Unlike CredentialMaxTTL (an estate's own, optional ceiling over every
// credential), this one is not configurable -- a host certificate is
// trusted by every client that carries its CA's `@cert-authority` line
// with no renewal signal of its own, so the repository, not the estate,
// draws the line. A role that needs longer is a role that should re-sign
// more often, not a wider cap.
const hostCertMaxTTL = 30 * 24 * time.Hour

// forceCommandExtensions are the certificate extensions that defeat a
// forced command: a PTY or any forwarding lets the caller reach a shell or
// another host instead of the one command the certificate is for.
var forceCommandExtensions = []string{"permit-pty", "permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding"}

type (
	// SSHMount is one SSH secrets engine: a user CA whose signing key
	// OpenBAO generates and never exports, and the roles below it. The
	// mount caps every lease at the longest role maximum.
	//
	// A user CA never shares a mount, and therefore never shares a key,
	// with a host CA ([SSHHostMount]): a key clients trust for hosts must
	// never also be a key sshd trusts for users. That is a property of
	// the mount, not a flag on a role, which is why hosts have a sibling
	// type instead of a `kind` on this one -- the two roles have almost no
	// field in common (principals and a default user versus domains and
	// bare/subdomain flags), and keeping them apart means a host role can
	// never be written, by mistake or otherwise, onto a user mount: the
	// compiler refuses it, not a runtime check.
	SSHMount struct {
		Path        string `yaml:"path"`
		Description string `yaml:"description,omitempty"`
		// KeyType is the CA's own key (ed25519, ecdsa-sha2-nistp256, ...).
		KeyType string    `yaml:"keyType"`
		Roles   []SSHRole `yaml:"roles"`
	}

	// SSHRole is one user-certificate role. Host certificates, user-chosen
	// key ids, templates and empty principals are refused by the apply
	// whatever is written here; the fields are what differs between roles.
	SSHRole struct {
		Name string `yaml:"name"`
		// AllowedUsers are the principals a certificate may name, spelled
		// out: no `*`, no template, never root.
		AllowedUsers []string `yaml:"allowedUsers"`
		// DefaultUser is the principal a request that names none gets.
		DefaultUser string `yaml:"defaultUser"`
		// KeyTypes are the user key types the role will sign.
		KeyTypes []string `yaml:"keyTypes"`
		// KeyIDFormat writes the certificate's key id; the caller cannot.
		// `{{token_display_name}}` names the login that asked.
		KeyIDFormat string `yaml:"keyIdFormat"`
		// Extensions are both allowed and default: a request can ask for
		// no more than it is given anyway.
		Extensions []string `yaml:"extensions"`
		// ForceCommand, when set, is the one command every certificate
		// this role signs carries as its `force-command` critical option.
		// The apply renders it as the role's only default critical
		// option, but the role's own configuration cannot make it
		// unconditional by itself: OpenBAO applies a default critical
		// option only when the request's own critical_options is
		// entirely absent, and otherwise takes the request's map as
		// given -- allowed_critical_options limits which keys a present
		// map may name, but not whether the caller may present one at
		// all. The grant that reaches this role's sign path must
		// therefore deny the critical_options parameter outright
		// (Rule.DeniedParameters); Namespace.Validate refuses a grant
		// that does not (docs/safety.md). A role with ForceCommand may
		// also not grant permit-pty or any forwarding extension -- a
		// forced command that can still open a terminal or forward a
		// port is not forced. Existing roles that leave ForceCommand
		// empty render exactly as they did before this field existed.
		ForceCommand string `yaml:"forceCommand,omitempty"`
		TTL          string `yaml:"ttl"`
		MaxTTL       string `yaml:"maxTtl"`
	}

	// SSHHostMount is one SSH host-CA secrets engine: a CA whose signing
	// key OpenBAO generates and never exports, on its own mount so its key
	// is never the one a user CA signs with ([SSHMount]). A client that
	// trusts this CA's public key in one `@cert-authority <domains> <key>`
	// line trusts every host certificate the roles below it sign, instead
	// of pinning each host's own key.
	SSHHostMount struct {
		Path        string `yaml:"path"`
		Description string `yaml:"description,omitempty"`
		// KeyType is the CA's own key (ed25519, ecdsa-sha2-nistp256, ...).
		KeyType string        `yaml:"keyType"`
		Roles   []SSHHostRole `yaml:"roles"`
	}

	// SSHHostRole is one host-certificate role: it signs a host's own key
	// as proof of the names in AllowedDomains, never a user's. Every
	// refusal a user role carries applies here too, plus the ones a host
	// certificate needs of its own: no wildcard or templated domain, and
	// no lifetime beyond hostCertMaxTTL, because a host certificate is
	// trusted by whatever has the CA's public key, with no per-signing
	// review.
	SSHHostRole struct {
		Name string `yaml:"name"`
		// AllowedDomains are the host names a certificate may claim,
		// spelled out literally: no `*`, no template.
		AllowedDomains []string `yaml:"allowedDomains"`
		// AllowBareDomains and AllowSubdomains say which of AllowedDomains'
		// exact names, and which of their subdomains, a certificate may
		// claim. At least one must be true, or the role signs nothing.
		AllowBareDomains bool `yaml:"allowBareDomains"`
		AllowSubdomains  bool `yaml:"allowSubdomains"`
		// KeyTypes are the host key types the role will sign.
		KeyTypes []string `yaml:"keyTypes"`
		// KeyIDFormat writes the certificate's key id; the caller cannot.
		KeyIDFormat string `yaml:"keyIdFormat"`
		TTL         string `yaml:"ttl"`
		MaxTTL      string `yaml:"maxTtl"`
	}
)

// Validate refuses a mount that would sign with no role, with no CA key
// type, or twice under one name.
func (m *SSHMount) Validate() error {
	if strings.TrimSpace(m.Path) == "" {
		return fmt.Errorf("an SSH mount has no path")
	}

	if strings.TrimSpace(m.KeyType) == "" {
		return fmt.Errorf("SSH mount %q names no CA key type", m.Path)
	}

	if len(m.Roles) == 0 {
		return fmt.Errorf("SSH mount %q has no role", m.Path)
	}

	seen := make(map[string]bool, len(m.Roles))

	for i := range m.Roles {
		if err := m.Roles[i].Validate(); err != nil {
			return fmt.Errorf("SSH mount %q: %w", m.Path, err)
		}

		if seen[m.Roles[i].Name] {
			return fmt.Errorf("SSH mount %q declares role %q twice", m.Path, m.Roles[i].Name)
		}

		seen[m.Roles[i].Name] = true
	}

	return nil
}

// Validate refuses a role that could sign for root, for anyone, for an
// account it does not list, with a key id the caller picks, for longer
// than it allows, or -- with ForceCommand set -- that also grants a way
// out of the command it forces.
func (r *SSHRole) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("an SSH role has no name")
	}

	if len(r.AllowedUsers) == 0 {
		return fmt.Errorf("SSH role %q allows no principal", r.Name)
	}

	for _, user := range r.AllowedUsers {
		switch {
		case strings.TrimSpace(user) == "":
			return fmt.Errorf("SSH role %q allows an empty principal", r.Name)
		case user == rootPrincipal:
			return fmt.Errorf("SSH role %q allows %s", r.Name, rootPrincipal)
		case strings.ContainsAny(user, "*,{}"):
			return fmt.Errorf("SSH role %q allows %q, which is a pattern or a list, not an account", r.Name, user)
		}
	}

	if !slices.Contains(r.AllowedUsers, r.DefaultUser) {
		return fmt.Errorf("SSH role %q defaults to %q, which it does not allow", r.Name, r.DefaultUser)
	}

	if len(r.KeyTypes) == 0 {
		return fmt.Errorf("SSH role %q signs no key type", r.Name)
	}

	if strings.TrimSpace(r.KeyIDFormat) == "" {
		return fmt.Errorf("SSH role %q writes no key id, so its certificates name nobody", r.Name)
	}

	for _, extension := range r.Extensions {
		if strings.TrimSpace(extension) == "" || strings.Contains(extension, ",") {
			return fmt.Errorf("SSH role %q names extension %q, which is not one extension", r.Name, extension)
		}
	}

	if strings.TrimSpace(r.ForceCommand) != "" {
		for _, extension := range r.Extensions {
			if slices.Contains(forceCommandExtensions, extension) {
				return fmt.Errorf("SSH role %q forces a command and also grants %q, which defeats it", r.Name, extension)
			}
		}
	}

	return lifetime("SSH role "+r.Name, r.TTL, r.MaxTTL)
}

// Validate refuses a mount that would sign with no role, with no CA key
// type, or twice under one name -- the same shape as [SSHMount.Validate].
func (m *SSHHostMount) Validate() error {
	if strings.TrimSpace(m.Path) == "" {
		return fmt.Errorf("an SSH host mount has no path")
	}

	if strings.TrimSpace(m.KeyType) == "" {
		return fmt.Errorf("SSH host mount %q names no CA key type", m.Path)
	}

	if len(m.Roles) == 0 {
		return fmt.Errorf("SSH host mount %q has no role", m.Path)
	}

	seen := make(map[string]bool, len(m.Roles))

	for i := range m.Roles {
		if err := m.Roles[i].Validate(); err != nil {
			return fmt.Errorf("SSH host mount %q: %w", m.Path, err)
		}

		if seen[m.Roles[i].Name] {
			return fmt.Errorf("SSH host mount %q declares role %q twice", m.Path, m.Roles[i].Name)
		}

		seen[m.Roles[i].Name] = true
	}

	return nil
}

// Validate refuses a role with no domain, a wildcard or templated domain,
// no key id, no key type, neither bare nor subdomains, or a lifetime
// beyond hostCertMaxTTL.
func (r *SSHHostRole) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("an SSH host role has no name")
	}

	if len(r.AllowedDomains) == 0 {
		return fmt.Errorf("SSH host role %q allows no domain, so it could sign nothing", r.Name)
	}

	for _, domain := range r.AllowedDomains {
		switch {
		case strings.TrimSpace(domain) == "":
			return fmt.Errorf("SSH host role %q allows an empty domain", r.Name)
		case strings.Contains(domain, "{{"):
			return fmt.Errorf("SSH host role %q allows %q, which is a template, not a domain", r.Name, domain)
		case strings.Contains(domain, "*"):
			return fmt.Errorf("SSH host role %q allows %q, which is a wildcard: host domains are literal names only", r.Name, domain)
		}
	}

	if !r.AllowBareDomains && !r.AllowSubdomains {
		return fmt.Errorf("SSH host role %q allows neither bare domains nor subdomains, so it could sign nothing", r.Name)
	}

	if len(r.KeyTypes) == 0 {
		return fmt.Errorf("SSH host role %q signs no key type", r.Name)
	}

	if strings.TrimSpace(r.KeyIDFormat) == "" {
		return fmt.Errorf("SSH host role %q writes no key id, so its certificates name nobody", r.Name)
	}

	if err := lifetime("SSH host role "+r.Name, r.TTL, r.MaxTTL); err != nil {
		return err
	}

	most, err := time.ParseDuration(r.MaxTTL)
	if err != nil {
		return fmt.Errorf("SSH host role %q max ttl %q: %w", r.Name, r.MaxTTL, err)
	}

	if most > hostCertMaxTTL {
		return fmt.Errorf("SSH host role %q lives up to %s, beyond the host certificate cap of %s", r.Name, most, hostCertMaxTTL)
	}

	return nil
}
