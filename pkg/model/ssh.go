package model

import (
	"fmt"
	"slices"
	"strings"
)

// rootPrincipal is the account no SSH role may name.
const rootPrincipal = "root"

type (
	// SSHMount is one SSH secrets engine: a user CA whose signing key
	// OpenBAO generates and never exports, and the roles below it. The
	// mount caps every lease at the longest role maximum.
	SSHMount struct {
		Path        string `yaml:"path"`
		Description string `yaml:"description,omitempty"`
		// KeyType is the CA's own key (ed25519, ecdsa-sha2-nistp256, ...).
		KeyType string    `yaml:"keyType"`
		Roles   []SSHRole `yaml:"roles"`
	}

	// SSHRole is one user-certificate role. Host certificates, user-chosen
	// key ids, critical options, templates and empty principals are
	// refused by the apply whatever is written here; the fields are what
	// differs between roles.
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
		TTL        string   `yaml:"ttl"`
		MaxTTL     string   `yaml:"maxTtl"`
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
// account it does not list, with a key id the caller picks, or for longer
// than it allows.
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

	return lifetime("SSH role "+r.Name, r.TTL, r.MaxTTL)
}
