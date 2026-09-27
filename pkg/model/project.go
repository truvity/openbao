package model

import "fmt"

// ProjectNamespace is a project's namespace, nested one level below an
// environment: `<environment>/<project>` ([ADR 0001](../../docs/decisions/0001-namespaces-are-environment-project.md)).
// It holds mounts and nothing that admits anybody -- KV and PKI today,
// Transit later -- never a login, a policy, an identity group or an SSH
// mount, and never a project of its own.
//
// It is a type of its own rather than a reuse of [Namespace] with runtime
// refusals, for the same reason [SSHHostMount] is a sibling type of
// [SSHMount] instead of a `kind` flag on it: a shared type would carry
// fields that mean nothing here (Auth, Policies, Groups, SSH, SSHHost, and
// a nested Projects), so most of ADR 0001's refusals are enforced by this
// type's shape -- there is no field to write one in -- and never need a
// runtime check at all.
type ProjectNamespace struct {
	// Name is a single, plain path segment: no `/`, no `..`, never empty.
	Name string     `yaml:"name"`
	KV   []KVMount  `yaml:"kv,omitempty"`
	PKI  []PKIMount `yaml:"pki,omitempty"`
}

// ProjectPath is a policy rule path that reaches into a child project's
// mount: `<project>/<mount>/<subpath>`. A token that logs in at the
// environment and holds a policy naming this path reads it at
// `<environment>/<project>/<mount>/<subpath>`, with no second login (ADR
// 0001). It is a plain string builder, like [ServiceAccountSubject]: what
// refuses one that names a project or a mount the environment does not
// actually declare is [Namespace.Validate], run over the policy that uses
// it, not this function.
func ProjectPath(project, mount, subpath string) string {
	return project + "/" + mount + "/" + subpath
}

// Validate refuses a project with no name or an unsafe one, a KV or PKI
// mount declared twice, a credential role -- which reads its subject from
// an auth mount, and a project namespace holds none -- and a PKI issuer
// that is not signed by another issuer at all. It does not by itself
// confirm that other issuer is the parent environment's own: that needs
// the parent, and is [Namespace.validateProjects]'s to check, once this
// method has confirmed everything it can on its own.
func (p *ProjectNamespace) Validate() error {
	if err := validateNamespaceSegment(p.Name); err != nil {
		return fmt.Errorf("project %w", err)
	}

	mounts := map[string]bool{}
	claim := func(path string) error {
		if mounts[path] {
			return fmt.Errorf("project %q declares mount %q twice", p.Name, path)
		}

		mounts[path] = true

		return nil
	}

	for i := range p.KV {
		if err := p.KV[i].Validate(); err != nil {
			return fmt.Errorf("project %q: %w", p.Name, err)
		}

		if err := claim(p.KV[i].Path); err != nil {
			return err
		}
	}

	for i := range p.PKI {
		mount := &p.PKI[i]
		if err := mount.Validate(); err != nil {
			return fmt.Errorf("project %q: %w", p.Name, err)
		}

		if err := claim(mount.Path); err != nil {
			return err
		}

		if len(mount.CredentialRoles) > 0 {
			return fmt.Errorf(
				"project %q: PKI mount %q declares a credential role, but a project namespace has no auth mount to read a subject from",
				p.Name, mount.Path)
		}

		for j := range mount.Issuers {
			if mount.Issuers[j].SignedBy == nil {
				return fmt.Errorf(
					"project %q: PKI issuer %q is not signed by another issuer; "+
						"a project's issuing CA is never self-signed or external, only signed by its environment's own issuer",
					p.Name, mount.Issuers[j].Name)
			}
		}
	}

	return nil
}

// hasMount reports whether the project declares a KV or PKI mount at path.
func (p *ProjectNamespace) hasMount(path string) bool {
	for i := range p.KV {
		if p.KV[i].Path == path {
			return true
		}
	}

	for i := range p.PKI {
		if p.PKI[i].Path == path {
			return true
		}
	}

	return false
}
