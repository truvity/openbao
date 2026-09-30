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
// The namespace tree is `<environment>/<project>`: root, one namespace per
// environment directly below it, and, below each environment, one
// [ProjectNamespace] per project
// ([ADR 0001](../../docs/decisions/0001-namespaces-are-environment-project.md)).
// A project holds mounts alone; logins, policies and identity groups live
// only at the environment (and root), which may grant a project's mount by
// path ([ProjectPath]).
package model

import (
	"fmt"
	"slices"
	"sort"
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
		// Plugins are the server's plugin catalog: entries every namespace
		// sits below, applied once and before any of them (Plugin's own
		// doc comment). Empty on a server with no external plugin -- every
		// built-in auth and secrets engine needs no entry here.
		Plugins []Plugin `yaml:"plugins,omitempty"`
		// Identity is how groups become OpenBAO identity groups.
		Identity Identity `yaml:"identity"`
		// CredentialMaxTTL, when set, is the longest a short-lived
		// credential may live: every SSH user-certificate role and every
		// PKI credential role is refused above it. It does not reach SSH
		// host roles, which are refused above a fixed 30-day cap instead
		// (SSHHostRole.Validate): a host certificate is trusted by
		// whatever holds the CA's public key, with no per-signing review,
		// so it is deliberately allowed to live far longer than a
		// short-lived credential -- and the cap on it is this
		// repository's, not an estate's to raise.
		CredentialMaxTTL string `yaml:"credentialMaxTtl,omitempty"`
	}

	// Namespace is one OpenBAO namespace and everything inside it.
	Namespace struct {
		// Name is empty for root, and a plain name (no `/`) otherwise.
		Name    string         `yaml:"name,omitempty"`
		KV      []KVMount      `yaml:"kv,omitempty"`
		PKI     []PKIMount     `yaml:"pki,omitempty"`
		SSH     []SSHMount     `yaml:"ssh,omitempty"`
		SSHHost []SSHHostMount `yaml:"sshHost,omitempty"`
		Auth    []JWTMount     `yaml:"auth"`
		// AWSAuth is this namespace's AWS IAM auth backends -- a machine
		// login shape, disjoint from Auth's JWT/OIDC ones (AWSAuthMount).
		AWSAuth []AWSAuthMount `yaml:"awsAuth,omitempty"`
		// Projects are this namespace's child project namespaces -- only an
		// environment (never root or bootstrap) declares any (ADR 0001).
		Projects []ProjectNamespace `yaml:"projects,omitempty"`
		Policies []Policy           `yaml:"policies"`
		Groups   []Group            `yaml:"groups"`
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

	if len(d.Bootstrap.Projects) > 0 || len(d.Root.Projects) > 0 {
		return fmt.Errorf("model: bootstrap and root hold no project; a project nests one level below an environment (ADR 0001)")
	}

	if err := d.Bootstrap.Validate(); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	if err := d.Root.Validate(); err != nil {
		return err
	}

	seenPlugins := make(map[string]bool, len(d.Plugins))

	for i := range d.Plugins {
		plugin := &d.Plugins[i]

		if err := plugin.Validate(); err != nil {
			return fmt.Errorf("model: %w", err)
		}

		key := plugin.Type + "/" + plugin.Name

		if seenPlugins[key] {
			return fmt.Errorf("model: plugin %s is declared twice", key)
		}

		seenPlugins[key] = true
	}

	seen := make(map[string]bool, len(d.Namespaces))

	for i := range d.Namespaces {
		namespace := &d.Namespaces[i]

		if err := validateNamespaceSegment(namespace.Name); err != nil {
			return fmt.Errorf("model: environment namespace %w", err)
		}

		if seen[namespace.Name] {
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

	if err := d.validateSignerDepth(); err != nil {
		return err
	}

	if err := d.validateCredentialCeiling(); err != nil {
		return err
	}

	if err := d.validateProjectPolicyPaths(); err != nil {
		return err
	}

	// The primary door names identity groups; a desired state with no group
	// has nothing to name, so identity stands alone without one.
	if d.hasGroups() {
		return d.Identity.Validate()
	}

	return d.Identity.validateGroupless()
}

func (d *Desired) hasGroups() bool {
	for _, namespace := range d.Applied() {
		if len(namespace.Groups) > 0 {
			return true
		}
	}

	return false
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

	for i := range n.AWSAuth {
		mount := &n.AWSAuth[i]
		if err := mount.Validate(); err != nil {
			return fmt.Errorf("model: namespace %s: %w", label, err)
		}

		// AWS auth mounts share sys/auth/<path> with the JWT/OIDC ones
		// above: one path can be only one auth backend. AWS auth mounts
		// are never a group's door or a credential role's subject mount
		// (they admit no person and no group), so they join doors here
		// for the path collision check alone.
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

	for i := range n.SSHHost {
		if err := n.SSHHost[i].Validate(); err != nil {
			return fmt.Errorf("model: namespace %s: %w", label, err)
		}

		if err := claim(n.SSHHost[i].Path); err != nil {
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

	if err := n.validateForceCommandGrants(label); err != nil {
		return err
	}

	if err := n.validateProjects(label, mounts); err != nil {
		return err
	}

	if err := n.validateProjectRuleBreadth(label); err != nil {
		return err
	}

	return nil
}

// validateProjectRuleBreadth refuses a policy rule, in an environment that
// declares any project, whose first path segment carries a glob (`*` or
// `+`) rather than one literal name. A rule's path is relative to the
// namespace it is granted in, and OpenBAO resolves a child project's mount
// through the SAME path -- `<project>/<mount>/...` -- rather than a
// separate namespace hop ([ProjectPath], ADR 0001), so a glob in that
// first segment reaches every project this environment declares (a
// partner's among them) exactly as readily as it reaches the
// environment's own mounts, whether or not the glob was written with any
// project in mind: `*` grants everything below it, and a prefix glob
// (`wal*`) is refused even when no project happens to collide with it
// today, because one might tomorrow. A rule that means a specific
// project names it outright, in full, with [ProjectPath] or its
// equivalent; a rule that means only the environment's own mount already
// spells that mount's literal name first (`kv/data/*`, `pki/sign/service`,
// `ssh/sign/runner`) and is untouched by this refusal, since the glob
// there sits after the first segment, never in it.
func (n *Namespace) validateProjectRuleBreadth(label string) error {
	if len(n.Projects) == 0 {
		return nil
	}

	for i := range n.Policies {
		policy := &n.Policies[i]

		for j := range policy.Rules {
			path := policy.Rules[j].Path
			first, _, _ := strings.Cut(path, "/")

			if strings.ContainsAny(first, "*+") {
				return fmt.Errorf(
					"model: namespace %s: policy %q rule %q reaches with a glob in its first path segment, "+
						"which would also reach every project this environment declares; "+
						"name a project explicitly (ProjectPath) or keep the glob out of the first segment",
					label, policy.Name, path)
			}
		}
	}

	return nil
}

// validateProjects refuses a project with no name or an unsafe one
// (ProjectNamespace.Validate), one declared twice, one whose name collides
// with a mount this namespace holds directly -- the ambiguity a
// project-scoped policy path ([ProjectPath]) resolves by name alone -- and
// a PKI issuer that is not signed by an issuer this SAME namespace holds:
// a project's issuing CA is signed by its own environment's issuer, never
// a grandparent's, a sibling project's, or its own (ADR 0001).
func (n *Namespace) validateProjects(label string, mounts map[string]bool) error {
	if len(n.Projects) == 0 {
		return nil
	}

	issuers := map[IssuerRef]bool{}

	for i := range n.PKI {
		for j := range n.PKI[i].Issuers {
			issuers[IssuerRef{Namespace: n.Name, Mount: n.PKI[i].Path, Issuer: n.PKI[i].Issuers[j].Name}] = true
		}
	}

	names := map[string]bool{}

	for i := range n.Projects {
		project := &n.Projects[i]
		if err := project.Validate(); err != nil {
			return fmt.Errorf("model: namespace %s: %w", label, err)
		}

		switch {
		case names[project.Name]:
			return fmt.Errorf("model: namespace %s declares project %q twice", label, project.Name)
		case mounts[project.Name]:
			return fmt.Errorf("model: namespace %s: project %q shares its name with a mount declared directly in the namespace", label, project.Name)
		}

		names[project.Name] = true

		for j := range project.PKI {
			for k := range project.PKI[j].Issuers {
				// ProjectNamespace.Validate already refused a nil SignedBy.
				issuer := &project.PKI[j].Issuers[k]
				if issuer.SignedBy.Namespace != n.Name || !issuers[*issuer.SignedBy] {
					return fmt.Errorf(
						"model: namespace %s: project %q PKI issuer %q is signed by %s, which is not an issuer this environment declares directly",
						label, project.Name, issuer.Name, issuer.SignedBy)
				}
			}
		}
	}

	return nil
}

// validateNamespaceSegment refuses an empty name and one that is not a
// single, plain path segment: a `/` or a space would nest it, and `..`
// would climb out of it -- the same "refuse what we name" convention
// Rule.Validate applies to a policy path.
func validateNamespaceSegment(name string) error {
	switch {
	case strings.TrimSpace(name) == "":
		return fmt.Errorf("has no name")
	case strings.ContainsAny(name, "/ *+"), strings.Contains(name, ".."):
		return fmt.Errorf("%q is not a plain name: the tree is one level below its parent", name)
	default:
		return nil
	}
}

// validateForceCommandGrants refuses a policy that grants a force-command
// SSH role's sign path without denying the critical_options parameter.
// OpenBAO applies a role's default_critical_options only when the
// request's own critical_options is entirely absent; when the request
// carries one, however it is shaped, OpenBAO uses it in place of the
// default rather than adding to it, and allowed_critical_options only
// limits which keys such a request may name -- it does not stop the
// caller from naming one. Denying the parameter at the ACL layer is the
// only way this repository has found to make a forced command actually
// unconditional, and a grant that omits it is a promise the role cannot
// keep (docs/safety.md).
func (n *Namespace) validateForceCommandGrants(label string) error {
	forced := map[string]bool{}

	for i := range n.SSH {
		for j := range n.SSH[i].Roles {
			role := &n.SSH[i].Roles[j]
			if strings.TrimSpace(role.ForceCommand) != "" {
				forced[n.SSH[i].Path+"/sign/"+role.Name] = true
			}
		}
	}

	if len(forced) == 0 {
		return nil
	}

	for i := range n.Policies {
		for j := range n.Policies[i].Rules {
			rule := &n.Policies[i].Rules[j]
			if forced[rule.Path] && !slices.Contains(rule.DeniedParameters, "critical_options") {
				return fmt.Errorf(
					"model: namespace %s: policy %q grants %q, a forced command's sign path, without denying the critical_options parameter",
					label, n.Policies[i].Name, rule.Path)
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

// validateSignerDepth refuses an issuer whose MaxPathLength is too short
// for the CA levels this model actually puts beneath it -- not just the
// one issuer it is about to sign, but everything a further issuer signs
// off that one, transitively: root -> a domain intermediate -> an
// environment's issuing CA -> a project's issuing CA is four levels, and
// each one's own MaxPathLength must cover every level still below it, the
// same accounting an X.509 path-length constraint gets at verification
// time (RFC 5280 4.2.1.9) -- the count is cumulative down the whole
// remaining chain, not reset at each hop. OpenBAO 2.6.2 itself only
// refuses the immediate case, at sign time, against a real server (a
// signer whose own max_path_length is already 0): this catches the
// deeper one before anything is applied at all.
//
// There is no "unlimited" to special-case here. OpenBAO's own convention
// treats a negative max_path_length as no constraint at all, but
// PKIIssuer.Validate already refuses a negative MaxPathLength outright
// ("an unbounded CA is never declared"), so every issuer this reaches
// already carries a plain, non-negative budget -- 0 is not "unset", it is
// this model's explicit "signs no further CA at all".
func (d *Desired) validateSignerDepth() error {
	maxPathLength := map[IssuerRef]int{}
	children := map[IssuerRef][]IssuerRef{}

	register := func(namespace string, mounts []PKIMount) {
		for i := range mounts {
			for j := range mounts[i].Issuers {
				issuer := &mounts[i].Issuers[j]
				ref := IssuerRef{Namespace: namespace, Mount: mounts[i].Path, Issuer: issuer.Name}
				maxPathLength[ref] = issuer.MaxPathLength

				if issuer.SignedBy != nil {
					children[*issuer.SignedBy] = append(children[*issuer.SignedBy], ref)
				}
			}
		}
	}

	register("", d.Root.PKI)

	for i := range d.Namespaces {
		namespace := &d.Namespaces[i]
		register(namespace.Name, namespace.PKI)

		for j := range namespace.Projects {
			register(namespace.Name+"/"+namespace.Projects[j].Name, namespace.Projects[j].PKI)
		}
	}

	// depth(ref) is the number of CA levels this model puts strictly
	// beneath ref: 0 for an issuer nothing else is signed by, otherwise
	// one more than its deepest child. via is the child that makes it
	// so, named in the refusal alongside ref itself.
	depths, vias := map[IssuerRef]int{}, map[IssuerRef]IssuerRef{}

	var depth func(IssuerRef) int
	depth = func(ref IssuerRef) int {
		if cached, ok := depths[ref]; ok {
			return cached
		}

		best, bestVia := 0, IssuerRef{}

		for _, child := range children[ref] {
			if candidate := depth(child) + 1; candidate > best {
				best, bestVia = candidate, child
			}
		}

		depths[ref], vias[ref] = best, bestVia

		return best
	}

	refs := make([]IssuerRef, 0, len(maxPathLength))
	for ref := range maxPathLength {
		refs = append(refs, ref)
	}

	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })

	for _, ref := range refs {
		need := depth(ref)
		if maxPathLength[ref] < need {
			return fmt.Errorf(
				"model: issuer %s has max path length %d, too few for the %d CA level(s) this model puts beneath it, down to %s -- "+
					"0 already means an issuer signs no further CA at all",
				ref, maxPathLength[ref], need, vias[ref])
		}
	}

	return nil
}

// validateProjectPolicyPaths refuses a policy rule that names a project
// ([ProjectPath]) unless the SAME environment declares that project, and
// the mount named after it. A project's name and its mounts live at
// exactly one environment (ADR 0001); a rule is checked against its own
// namespace's declared projects only, never against another environment's,
// so a rule that would otherwise resolve through a same-named project one
// namespace over -- or through a project that used to exist and does not
// any more -- is refused instead of granted a path that either resolves to
// nothing or, worse, to a mount nobody meant.
//
// A path whose first segment is also a mount this namespace holds
// directly is left alone, never read as a project reference: that mount
// takes precedence, the same way validateProjects refuses a project whose
// name collides with one.
func (d *Desired) validateProjectPolicyPaths() error {
	projects := map[string]bool{}

	for i := range d.Namespaces {
		for j := range d.Namespaces[i].Projects {
			projects[d.Namespaces[i].Projects[j].Name] = true
		}
	}

	if len(projects) == 0 {
		return nil
	}

	for _, namespace := range d.Applied() {
		local := map[string]*ProjectNamespace{}
		for i := range namespace.Projects {
			local[namespace.Projects[i].Name] = &namespace.Projects[i]
		}

		mounts := map[string]bool{}
		for i := range namespace.KV {
			mounts[namespace.KV[i].Path] = true
		}

		for i := range namespace.PKI {
			mounts[namespace.PKI[i].Path] = true
		}

		for i := range namespace.SSH {
			mounts[namespace.SSH[i].Path] = true
		}

		for i := range namespace.SSHHost {
			mounts[namespace.SSHHost[i].Path] = true
		}

		for i := range namespace.Policies {
			policy := &namespace.Policies[i]

			for j := range policy.Rules {
				path := policy.Rules[j].Path

				first, rest, cut := strings.Cut(path, "/")
				if !cut || !projects[first] || mounts[first] {
					continue
				}

				project, declared := local[first]
				if !declared {
					return fmt.Errorf("model: namespace %s: policy %q rule %q names project %q, which this environment does not declare",
						namespace.label(), policy.Name, path, first)
				}

				mount, _, _ := strings.Cut(rest, "/")
				if !project.hasMount(mount) {
					return fmt.Errorf("model: namespace %s: policy %q rule %q names mount %q of project %q, which the project does not hold",
						namespace.label(), policy.Name, path, mount, first)
				}
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
