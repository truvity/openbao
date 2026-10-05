package builder

import (
	"fmt"
	"slices"
	"strings"

	"github.com/truvity/secrets/pkg/model"
)

// Op is what one [Clause] grants.
type Op string

const (
	// OpRead reads everything under one KV prefix: the secrets
	// (`data/<prefix>/*`) and their metadata, which it may also list.
	OpRead Op = "read"
	// OpWrite reads and changes everything under one KV prefix, and deletes
	// it. An empty prefix is the whole mount.
	OpWrite Op = "write"
	// OpPush is what a push job (an ExternalSecrets PushSecret, say) needs
	// on one KV prefix and no more: read a secret and its metadata before
	// writing, mark the metadata, write the data. It never lists, patches
	// or deletes.
	OpPush Op = "push"
	// OpKey reads one secret, addressed by its path inside the mount (a
	// trailing `*` is a prefix match, as OpenBAO's ACL has it): `read` on
	// the data endpoint, no metadata, no list.
	OpKey Op = "key"
	// OpSecrets is one project's own secrets, read or written (Write): the
	// project's own namespace mount if the environment declares the project
	// one ([Environment.Projects]), the project's prefix in the
	// environment's shared mount if it does not. A grant written this way
	// follows the project when it moves.
	OpSecrets Op = "secrets"
	// OpAll writes the whole shared mount and, beside it, every project
	// namespace the environment declares: an environment's administrators
	// reach every project, whichever side of a move it is on.
	OpAll Op = "all"
	// OpSign signs on one role of a signing engine (an SSH user CA, an SSH
	// host CA, a PKI issuer): `update` on `<mount>/sign/<role>`, and nothing
	// else -- never `issue`, `read` or `list`.
	OpSign Op = "sign"
	// OpSignForced is OpSign on a role that forces a command. The grant also
	// denies `critical_options` outright, which is the only way OpenBAO
	// honours the role's forced command unconditionally (docs/safety.md).
	OpSignForced Op = "sign-forced"
	// OpCA reads one CA's certificate and its issuer record, at Mount in
	// Namespace ("" for where the policy lives): what a restore check reads
	// to prove a recovered mount still holds the authority it should.
	OpCA Op = "ca"
	// OpCanary reads one KV canary secret in Namespace (docs/model.md, "KV
	// and the canary").
	OpCanary Op = "canary"
	// OpRules is a stanza written out as it is, for what none of the above
	// says (a system path).
	OpRules Op = "rules"
)

// Clause is one grant. Which fields it reads depends on its Op, and
// [Access.Validate] refuses one that names a field its Op does not use.
type Clause struct {
	Op Op `yaml:"op"`
	// Prefix is a KV prefix (OpRead, OpWrite, OpPush); empty is the whole
	// mount.
	Prefix string `yaml:"prefix,omitempty"`
	// Path is a secret's path inside the mount (OpKey, OpCanary).
	Path string `yaml:"path,omitempty"`
	// Project is the project OpSecrets grants, Write whether it writes.
	Project string `yaml:"project,omitempty"`
	Write   bool   `yaml:"write,omitempty"`
	// Mount and Role are the signing mount and role (OpSign, OpSignForced),
	// or the mount holding the CA (OpCA) or the canary (OpCanary).
	Mount string `yaml:"mount,omitempty"`
	Role  string `yaml:"role,omitempty"`
	// Issuer is the issuer name whose record OpCA reads.
	Issuer string `yaml:"issuer,omitempty"`
	// Namespace is where OpCA and OpCanary read, for a policy in root
	// (`<namespace>/<path>`).
	Namespace string `yaml:"namespace,omitempty"`
	// Rules are OpRules' stanzas.
	Rules []model.Rule `yaml:"rules,omitempty"`
}

// Access is what a policy grants, clause by clause, in order: the order is
// the order of the policy's stanzas, and so part of its text.
//
// A stanza a later clause repeats exactly (same path, same capabilities) is
// dropped, so two clauses may name the same authority twice, as a shared
// mount holding two issuers does. A later stanza that repeats a path with
// different capabilities is an error: OpenBAO would keep whichever came
// last.
type Access []Clause

// Read is [OpRead] on prefix.
func Read(prefix string) Clause { return Clause{Op: OpRead, Prefix: prefix} }

// Write is [OpWrite] on prefix.
func Write(prefix string) Clause { return Clause{Op: OpWrite, Prefix: prefix} }

// Push is [OpPush] on prefix.
func Push(prefix string) Clause { return Clause{Op: OpPush, Prefix: prefix} }

// Key is [OpKey] on one secret path.
func Key(path string) Clause { return Clause{Op: OpKey, Path: path} }

// Secrets is [OpSecrets] for project.
func Secrets(project string, write bool) Clause {
	return Clause{Op: OpSecrets, Project: project, Write: write}
}

// All is [OpAll].
func All() Clause { return Clause{Op: OpAll} }

// Sign is [OpSign] on one role.
func Sign(mount, role string) Clause { return Clause{Op: OpSign, Mount: mount, Role: role} }

// SignForced is [OpSignForced] on one role.
func SignForced(mount, role string) Clause { return Clause{Op: OpSignForced, Mount: mount, Role: role} }

// CA is [OpCA]: the certificate and the issuer record of issuer at mount, in
// namespace ("" for the policy's own).
func CA(namespace, mount, issuer string) Clause {
	return Clause{Op: OpCA, Namespace: namespace, Mount: mount, Issuer: issuer}
}

// Canary is [OpCanary]: the canary at path in the KV mount of namespace.
func Canary(namespace, mount, path string) Clause {
	return Clause{Op: OpCanary, Namespace: namespace, Mount: mount, Path: path}
}

// Rules is [OpRules].
func Rules(rules ...model.Rule) Clause { return Clause{Op: OpRules, Rules: rules} }

// The system paths a job may need, spelled once. Each is a whole stanza, for
// [Rules].

// SnapshotRule reads a Raft snapshot (root namespace, no sudo).
func SnapshotRule() model.Rule {
	return model.Rule{Path: "sys/storage/raft/snapshot", Capabilities: []string{model.CapRead}}
}

// NamespacesRule lists the namespaces under root.
func NamespacesRule() model.Rule {
	return model.Rule{Path: "sys/namespaces", Capabilities: []string{model.CapList}}
}

// RootGenerationRule reads whether a root-token generation attempt is open:
// the whole of what a root-generation watch may do. It is a root-namespace
// path.
func RootGenerationRule() model.Rule {
	return model.Rule{Path: "sys/generate-root-token/attempt", Capabilities: []string{model.CapRead}}
}

// PluginCatalogRule reads one plugin catalog entry. OpenBAO refuses either
// capability alone, so the stanza carries `read` and `sudo` together and
// names the one entry, never the catalog (docs/reference.md, "pluginCatalog").
func PluginCatalogRule(pluginType, name string) model.Rule {
	return model.Rule{
		Path:         "sys/plugins/catalog/" + pluginType + "/" + name,
		Capabilities: []string{model.CapRead, model.CapSudo},
	}
}

// kvScope is what a clause needs to know about the namespace it is granted
// in.
type kvScope struct {
	// mount is the namespace's shared KV mount.
	mount string
	// projects are the projects with a namespace of their own, by name.
	projects []Project
}

func (s kvScope) project(name string) (Project, bool) {
	for i := range s.projects {
		if s.projects[i].Name == name {
			return s.projects[i], true
		}
	}

	return Project{}, false
}

var (
	capsRead  = []string{model.CapRead}
	capsList  = []string{model.CapList, model.CapRead}
	capsWrite = []string{model.CapCreate, model.CapDelete, model.CapPatch, model.CapRead, model.CapUpdate}
	capsMeta  = []string{model.CapDelete, model.CapList, model.CapRead}
	capsPush  = []string{model.CapCreate, model.CapRead, model.CapUpdate}
)

// kvPath is a path inside the namespace's shared KV mount; the namespace
// itself is never part of it, which is what keeps a policy inside its wall.
func kvPath(mount, section, prefix string) string {
	if prefix == "" {
		return mount + "/" + section + "/*"
	}

	return mount + "/" + section + "/" + prefix + "/*"
}

func readRules(mount, prefix string) []model.Rule {
	return []model.Rule{
		{Path: kvPath(mount, "data", prefix), Capabilities: slices.Clone(capsRead)},
		{Path: kvPath(mount, "metadata", prefix), Capabilities: slices.Clone(capsList)},
	}
}

func writeRules(mount, prefix string) []model.Rule {
	return []model.Rule{
		{Path: kvPath(mount, "data", prefix), Capabilities: slices.Clone(capsWrite)},
		{Path: kvPath(mount, "metadata", prefix), Capabilities: slices.Clone(capsMeta)},
	}
}

func pushRules(mount, prefix string) []model.Rule {
	return []model.Rule{
		{Path: kvPath(mount, "data", prefix), Capabilities: slices.Clone(capsPush)},
		{Path: kvPath(mount, "metadata", prefix), Capabilities: slices.Clone(capsPush)},
	}
}

// projectRules is readRules or writeRules, addressed through a project's own
// namespace mount ([model.ProjectPath]) instead of the shared one: the same
// capabilities on the path a token that logged in at the environment reaches
// with no second login (docs/decisions/0001).
func projectRules(project Project, write bool) []model.Rule {
	data := model.ProjectPath(project.Name, project.KV.Path, "data/*")
	meta := model.ProjectPath(project.Name, project.KV.Path, "metadata/*")

	if write {
		return []model.Rule{
			{Path: data, Capabilities: slices.Clone(capsWrite)},
			{Path: meta, Capabilities: slices.Clone(capsMeta)},
		}
	}

	return []model.Rule{
		{Path: data, Capabilities: slices.Clone(capsRead)},
		{Path: meta, Capabilities: slices.Clone(capsList)},
	}
}

func signRule(mount, role string, forced bool) model.Rule {
	rule := model.Rule{Path: mount + "/sign/" + role, Capabilities: []string{model.CapUpdate}}
	if forced {
		rule.DeniedParameters = []string{"critical_options"}
	}

	return rule
}

func inNamespace(namespace, path string) string {
	if namespace == "" {
		return path
	}

	return namespace + "/" + path
}

// Rules writes the access out as the ACL stanzas of a policy, for a KV mount
// and the projects that have a namespace of their own in it.
func (a Access) Rules(kvMount string, projects ...Project) ([]model.Rule, error) {
	return a.rules(kvScope{mount: kvMount, projects: projects})
}

// rules writes the access out as ACL stanzas.
func (a Access) rules(scope kvScope) ([]model.Rule, error) {
	var out []model.Rule

	for i := range a {
		clause := &a[i]

		if err := clause.validate(); err != nil {
			return nil, err
		}

		if clause.usesKV() && scope.mount == "" {
			return nil, fmt.Errorf("builder: a %q clause needs a KV mount, and this policy is granted where there is none", clause.Op)
		}

		switch clause.Op {
		case OpRead:
			out = append(out, readRules(scope.mount, clause.Prefix)...)
		case OpWrite:
			out = append(out, writeRules(scope.mount, clause.Prefix)...)
		case OpPush:
			out = append(out, pushRules(scope.mount, clause.Prefix)...)
		case OpKey:
			out = append(out, model.Rule{Path: scope.mount + "/data/" + clause.Path, Capabilities: slices.Clone(capsRead)})
		case OpSecrets:
			if project, ok := scope.project(clause.Project); ok {
				out = append(out, projectRules(project, clause.Write)...)

				break
			}

			if clause.Write {
				out = append(out, writeRules(scope.mount, clause.Project)...)
			} else {
				out = append(out, readRules(scope.mount, clause.Project)...)
			}
		case OpAll:
			out = append(out, writeRules(scope.mount, "")...)

			for _, project := range scope.projects {
				out = append(out, projectRules(project, true)...)
			}
		case OpSign, OpSignForced:
			out = append(out, signRule(clause.Mount, clause.Role, clause.Op == OpSignForced))
		case OpCA:
			out = append(out,
				model.Rule{Path: inNamespace(clause.Namespace, clause.Mount+"/cert/ca"), Capabilities: slices.Clone(capsRead)},
				model.Rule{Path: inNamespace(clause.Namespace, clause.Mount+"/issuer/"+clause.Issuer+"/json"), Capabilities: slices.Clone(capsRead)},
			)
		case OpCanary:
			out = append(out, model.Rule{
				Path:         inNamespace(clause.Namespace, clause.Mount+"/data/"+clause.Path),
				Capabilities: slices.Clone(capsRead),
			})
		case OpRules:
			for _, rule := range clause.Rules {
				rule.Capabilities = slices.Clone(rule.Capabilities)
				rule.DeniedParameters = slices.Clone(rule.DeniedParameters)
				out = append(out, rule)
			}
		}
	}

	return dedupe(out)
}

// usesKV reports whether the clause addresses the namespace's KV mount.
func (c *Clause) usesKV() bool {
	switch c.Op {
	case OpRead, OpWrite, OpPush, OpKey, OpSecrets, OpAll:
		return true
	default:
		return false
	}
}

// clauseFields is, per Op, the fields it reads and, of those, the ones it
// cannot do without.
var clauseFields = map[Op]struct{ read, required []string }{
	OpRead:       {read: []string{"prefix"}},
	OpWrite:      {read: []string{"prefix"}},
	OpPush:       {read: []string{"prefix"}},
	OpKey:        {read: []string{"path"}, required: []string{"path"}},
	OpSecrets:    {read: []string{"project", "write"}, required: []string{"project"}},
	OpAll:        {},
	OpSign:       {read: []string{"mount", "role"}, required: []string{"mount", "role"}},
	OpSignForced: {read: []string{"mount", "role"}, required: []string{"mount", "role"}},
	OpCA:         {read: []string{"namespace", "mount", "issuer"}, required: []string{"mount", "issuer"}},
	OpCanary:     {read: []string{"namespace", "mount", "path"}, required: []string{"mount", "path"}},
	OpRules:      {read: []string{"rules"}, required: []string{"rules"}},
}

// validate refuses a clause with no Op or an unknown one, one that sets a
// field its Op does not read (a grant its author expected to be there), and
// one missing a field its Op needs.
func (c *Clause) validate() error {
	if c.Op == "" {
		return fmt.Errorf("builder: a clause names no op")
	}

	fields, ok := clauseFields[c.Op]
	if !ok {
		return fmt.Errorf("builder: clause op %q is unknown", c.Op)
	}

	set := map[string]bool{
		"prefix":    c.Prefix != "",
		"path":      c.Path != "",
		"project":   c.Project != "",
		"write":     c.Write,
		"mount":     c.Mount != "",
		"role":      c.Role != "",
		"issuer":    c.Issuer != "",
		"namespace": c.Namespace != "",
		"rules":     len(c.Rules) > 0,
	}

	for _, field := range fields.required {
		if !set[field] {
			return fmt.Errorf("builder: a %q clause names no %s", c.Op, field)
		}
	}

	for field, isSet := range set {
		if isSet && !slices.Contains(fields.read, field) {
			return fmt.Errorf("builder: a %q clause sets %s, which it does not read", c.Op, field)
		}
	}

	switch {
	case c.Op == OpSecrets && strings.ContainsAny(c.Project, "/*+"):
		return fmt.Errorf("builder: project %q is not one name", c.Project)
	case c.Op == OpCanary && strings.Contains(c.Path, "*"):
		return fmt.Errorf("builder: canary %q is not one secret path", c.Path)
	}

	return nil
}

// dedupe drops a stanza that repeats an earlier one exactly, and refuses one
// that repeats a path with other capabilities.
func dedupe(rules []model.Rule) ([]model.Rule, error) {
	first := make(map[string]model.Rule, len(rules))
	out := make([]model.Rule, 0, len(rules))

	for _, rule := range rules {
		earlier, seen := first[rule.Path]
		if !seen {
			first[rule.Path] = rule
			out = append(out, rule)

			continue
		}

		if !slices.Equal(earlier.Capabilities, rule.Capabilities) || !slices.Equal(earlier.DeniedParameters, rule.DeniedParameters) {
			return nil, fmt.Errorf("builder: path %q is granted twice with different capabilities", rule.Path)
		}
	}

	return out, nil
}
