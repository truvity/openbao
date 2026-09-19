// Package model is the desired state of an OpenBAO server, per namespace
// and per engine: KV mounts, JWT and OIDC auth mounts with their roles,
// identity groups and their aliases, ACL policies, PKI mounts with their
// issuers and roles, and SSH mounts with their CA and roles.
//
// It is a neutral shape, not an estate's configuration format. Nothing here
// loads a file or knows where a value comes from: a consuming estate derives
// a [Desired] from its own sources, reviews it (the types carry yaml tags,
// so the whole state can be written out as a golden file), and hands it to
// pkg/apply. [Desired.Validate] refuses a state that could not be applied
// as it reads, before anything is.
//
// The namespace tree is one level: root, and one namespace per environment
// directly below it. Projects, teams or tenants are policy paths and
// identity groups inside an environment's namespace, never namespaces of
// their own.
package model

import (
	"fmt"
	"strings"
	"time"
)

type (
	// Desired is an OpenBAO server's whole configuration.
	Desired struct {
		// Bootstrap is the door the apply itself logs in through: the
		// operators' auth mount in root, its role, and the group and policy
		// it grants. It is declared so a review sees the whole picture, and
		// it is NEVER applied: an apply that owned the door it logs in
		// through could lock itself out halfway. The server's
		// initialisation creates it.
		Bootstrap Namespace `yaml:"bootstrap"`
		// Root is what the apply owns in the root namespace. Its Name is
		// empty.
		Root Namespace `yaml:"root"`
		// Namespaces are the environments, each one level below root.
		Namespaces []Namespace `yaml:"namespaces"`
		// Identity is how groups become OpenBAO identity groups.
		Identity Identity `yaml:"identity"`
		// CredentialMaxTTL, when set, is the longest a credential may live:
		// every SSH role and every credential role is refused above it.
		CredentialMaxTTL string `yaml:"credentialMaxTtl,omitempty"`
	}

	// Namespace is one OpenBAO namespace and everything inside it.
	Namespace struct {
		// Name is empty for root, and a plain name (no `/`) otherwise.
		Name     string     `yaml:"name,omitempty"`
		KV       []KVMount  `yaml:"kv,omitempty"`
		PKI      []PKIMount `yaml:"pki,omitempty"`
		SSH      []SSHMount `yaml:"ssh,omitempty"`
		Auth     []JWTMount `yaml:"auth"`
		Policies []Policy   `yaml:"policies"`
		Groups   []Group    `yaml:"groups"`
	}
)

// Validate refuses a state that could not be applied as it reads: every
// namespace validates what it holds, no environment is declared twice, an
// issuer is signed only by one declared before it, and no credential
// outlives the ceiling.
func (d *Desired) Validate() error {
	if d.Bootstrap.Name != "" || d.Root.Name != "" {
		return fmt.Errorf("model: bootstrap and root are the root namespace and have no name")
	}

	if err := d.Bootstrap.Validate(); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	if err := d.Root.Validate(); err != nil {
		return err
	}

	seen := make(map[string]bool, len(d.Namespaces))

	for i := range d.Namespaces {
		namespace := &d.Namespaces[i]

		switch {
		case strings.TrimSpace(namespace.Name) == "":
			return fmt.Errorf("model: an environment namespace has no name")
		case strings.ContainsAny(namespace.Name, "/ "):
			return fmt.Errorf("model: namespace %q is not a plain name: the tree is one level below root", namespace.Name)
		case seen[namespace.Name]:
			return fmt.Errorf("model: namespace %q is declared twice", namespace.Name)
		}

		seen[namespace.Name] = true

		if err := namespace.Validate(); err != nil {
			return err
		}
	}

	if err := d.validateSigners(); err != nil {
		return err
	}

	if err := d.validateCredentialCeiling(); err != nil {
		return err
	}

	return d.Identity.Validate()
}

// Applied is every namespace the apply owns, root first: the order in
// which it registers them, and the order in which an issuer's signer must
// already be declared.
func (d *Desired) Applied() []*Namespace {
	out := make([]*Namespace, 0, len(d.Namespaces)+1)
	out = append(out, &d.Root)

	for i := range d.Namespaces {
		out = append(out, &d.Namespaces[i])
	}

	return out
}

// Validate refuses a namespace that declares one name twice -- a mount
// path, a policy, a group, a role on one mount -- because the second write
// would silently replace the first and the rules of whichever lost would
// vanish without a diff anyone reads. It also refuses a group admitted
// through a door that is no auth mount here, and a credential role that
// reads its subject from a mount that does not exist.
func (n *Namespace) Validate() error {
	label := n.label()
	mounts := map[string]bool{}
	claim := func(path string) error {
		if mounts[path] {
			return fmt.Errorf("model: namespace %s declares mount %q twice", label, path)
		}

		mounts[path] = true

		return nil
	}

	doors := map[string]bool{}

	for i := range n.Auth {
		mount := &n.Auth[i]
		if err := mount.Validate(); err != nil {
			return fmt.Errorf("model: namespace %s: %w", label, err)
		}

		if doors[mount.Path] {
			return fmt.Errorf("model: namespace %s declares auth mount %q twice", label, mount.Path)
		}

		doors[mount.Path] = true
	}

	for i := range n.KV {
		if err := n.KV[i].Validate(); err != nil {
			return fmt.Errorf("model: namespace %s: %w", label, err)
		}

		if err := claim(n.KV[i].Path); err != nil {
			return err
		}
	}

	for i := range n.SSH {
		if err := n.SSH[i].Validate(); err != nil {
			return fmt.Errorf("model: namespace %s: %w", label, err)
		}

		if err := claim(n.SSH[i].Path); err != nil {
			return err
		}
	}

	for i := range n.PKI {
		mount := &n.PKI[i]
		if err := mount.Validate(); err != nil {
			return fmt.Errorf("model: namespace %s: %w", label, err)
		}

		if err := claim(mount.Path); err != nil {
			return err
		}

		for j := range mount.CredentialRoles {
			role := &mount.CredentialRoles[j]
			if !doors[role.SubjectMount] {
				return fmt.Errorf("model: namespace %s: credential role %s/%s reads the subject from %q, which is no auth mount here",
					label, mount.Path, role.Name, role.SubjectMount)
			}
		}
	}

	policies := map[string]bool{}

	for i := range n.Policies {
		policy := &n.Policies[i]
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("model: namespace %s: %w", label, err)
		}

		if policies[policy.Name] {
			return fmt.Errorf("model: namespace %s declares policy %q twice", label, policy.Name)
		}

		policies[policy.Name] = true
	}

	groups := map[string]bool{}

	for i := range n.Groups {
		group := &n.Groups[i]
		if err := group.Validate(); err != nil {
			return fmt.Errorf("model: namespace %s: %w", label, err)
		}

		if groups[group.Name] {
			return fmt.Errorf("model: namespace %s declares group %q twice", label, group.Name)
		}

		groups[group.Name] = true

		for _, door := range group.Doors {
			if !doors[door] {
				return fmt.Errorf("model: namespace %s: group %q is admitted through %q, which is no auth mount here", label, group.Name, door)
			}
		}
	}

	return nil
}

// Label names the namespace in messages and resource names: "root" for
// root, which is no namespace at all rather than an empty one.
func (n *Namespace) label() string {
	if n.Name == "" {
		return "root"
	}

	return n.Name
}

// Label is the namespace's name, or "root".
func (n *Namespace) Label() string { return n.label() }

// validateSigners resolves every SignedBy reference to an issuer of a
// mount declared EARLIER -- root first, then the namespaces in order -- so
// an apply can create every signer, and configure its mount's URLs, before
// anything below it is signed.
func (d *Desired) validateSigners() error {
	declared := map[IssuerRef]bool{}

	for _, namespace := range d.Applied() {
		for i := range namespace.PKI {
			mount := &namespace.PKI[i]

			for j := range mount.Issuers {
				issuer := &mount.Issuers[j]
				if issuer.SignedBy == nil {
					continue
				}

				if !declared[*issuer.SignedBy] {
					return fmt.Errorf("model: issuer %s/%s/%s is signed by %s, which is not an issuer of a mount declared before it",
						namespace.label(), mount.Path, issuer.Name, issuer.SignedBy)
				}
			}

			for j := range mount.Issuers {
				declared[IssuerRef{Namespace: namespace.Name, Mount: mount.Path, Issuer: mount.Issuers[j].Name}] = true
			}
		}
	}

	return nil
}

// validateCredentialCeiling refuses an SSH or credential role whose maximum
// is above CredentialMaxTTL.
func (d *Desired) validateCredentialCeiling() error {
	if strings.TrimSpace(d.CredentialMaxTTL) == "" {
		return nil
	}

	ceiling, err := time.ParseDuration(d.CredentialMaxTTL)
	if err != nil || ceiling <= 0 {
		return fmt.Errorf("model: credential ceiling %q is not a positive duration", d.CredentialMaxTTL)
	}

	check := func(what, maxTTL string) error {
		most, err := time.ParseDuration(maxTTL)
		if err != nil {
			return fmt.Errorf("model: %s max ttl %q: %w", what, maxTTL, err)
		}

		if most > ceiling {
			return fmt.Errorf("model: %s lives up to %s, beyond the credential ceiling %s", what, most, ceiling)
		}

		return nil
	}

	for _, namespace := range append([]*Namespace{&d.Bootstrap}, d.Applied()...) {
		for i := range namespace.SSH {
			for j := range namespace.SSH[i].Roles {
				role := &namespace.SSH[i].Roles[j]
				if err := check("SSH role "+namespace.label()+"/"+namespace.SSH[i].Path+"/"+role.Name, role.MaxTTL); err != nil {
					return err
				}
			}
		}

		for i := range namespace.PKI {
			for j := range namespace.PKI[i].CredentialRoles {
				role := &namespace.PKI[i].CredentialRoles[j]
				if err := check("credential role "+namespace.label()+"/"+namespace.PKI[i].Path+"/"+role.Name, role.MaxTTL); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// lifetime refuses a default above the maximum and a lifetime that never
// ends. Both are Go durations.
func lifetime(what, ttl, maxTTL string) error {
	def, err := time.ParseDuration(ttl)
	if err != nil {
		return fmt.Errorf("%s ttl %q: %w", what, ttl, err)
	}

	most, err := time.ParseDuration(maxTTL)
	if err != nil {
		return fmt.Errorf("%s max ttl %q: %w", what, maxTTL, err)
	}

	switch {
	case def <= 0 || most <= 0:
		return fmt.Errorf("%s issues credentials that never expire", what)
	case def > most:
		return fmt.Errorf("%s defaults to %s, beyond its own maximum %s", what, def, most)
	}

	return nil
}
