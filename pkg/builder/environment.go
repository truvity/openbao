package builder

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/truvity/openbao/pkg/model"
)

type (
	// Environment is one environment's namespace: what logs in to it, what
	// it holds, and who may reach it.
	Environment struct {
		// Name is the namespace's name, one plain path segment.
		Name string `yaml:"name"`
		// KV is the environment's shared KV v2 mount, with its restore
		// canary.
		KV model.KVMount `yaml:"kv"`
		// Projects are the projects that have a namespace of their own
		// below this one, each with a KV mount and nothing else (a project
		// namespace holds mounts alone: no login, policy or group,
		// docs/decisions/0001). A project not listed keeps its secrets in
		// the shared mount, and [Secrets] follows either.
		Projects []Project `yaml:"projects,omitempty"`
		// Trusts are the clusters whose tokens this namespace accepts, in
		// the order their mounts are declared. The roster's doors follow
		// them.
		Trusts []Trust `yaml:"trusts,omitempty"`
		// SSH is the SSH engines, nil for none.
		SSH *SSH `yaml:"ssh,omitempty"`
		// HostAuth and HostLogins let fleets of hosts sign their own host
		// certificates with their IAM instance role. HostLogins need
		// HostAuth and an SSH host CA.
		HostAuth   *HostAuth   `yaml:"hostAuth,omitempty"`
		HostLogins []HostLogin `yaml:"hostLogins,omitempty"`
		// Grants are the groups people and jobs hold, each a policy and a
		// group admitted through the roster's doors.
		Grants []Grant `yaml:"grants,omitempty"`
		// Secrets are the single-secret reads jobs hold.
		Secrets []SecretGrant `yaml:"secrets,omitempty"`
		// Reserved are the KV prefixes Secrets may not reach.
		Reserved []Reservation `yaml:"reserved,omitempty"`
	}

	// Project is a project's own namespace below an environment.
	Project struct {
		Name string        `yaml:"name"`
		KV   model.KVMount `yaml:"kv"`
	}
)

// Derive writes the environment as a namespace of the model.
//
// The namespace's policies and groups are sorted by name; the host logins'
// policies follow, in the order the logins are declared. Everything else
// keeps the order it was written in: a mount's roles are the order of its
// workloads, and the auth mounts are the trusts' and then the roster's
// doors.
func (e *Environment) Derive(spec *Spec) (model.Namespace, error) {
	namespace, err := e.derive(spec)
	if err != nil {
		return model.Namespace{}, fmt.Errorf("builder: environment %q: %w", e.Name, err)
	}

	return namespace, nil
}

func (e *Environment) derive(spec *Spec) (model.Namespace, error) {
	if strings.TrimSpace(e.Name) == "" {
		return model.Namespace{}, fmt.Errorf("an environment has no name")
	}

	if strings.TrimSpace(e.KV.Path) == "" {
		return model.Namespace{}, fmt.Errorf("it has no KV mount")
	}

	scope := kvScope{mount: e.KV.Path, projects: e.Projects}

	namespace := model.Namespace{Name: e.Name, KV: []model.KVMount{e.KV}}

	var policies []model.Policy

	for i := range e.Projects {
		project := &e.Projects[i]
		if project.KV.Path == "" {
			return model.Namespace{}, fmt.Errorf("project %q has no KV mount", project.Name)
		}

		namespace.Projects = append(namespace.Projects, model.ProjectNamespace{Name: project.Name, KV: []model.KVMount{project.KV}})
	}

	for i := range e.Trusts {
		trust := &e.Trusts[i]
		if trust.Optional && len(trust.Workloads) == 0 {
			continue
		}

		mount, declared, err := trust.derive(spec.audience(), scope)
		if err != nil {
			return model.Namespace{}, err
		}

		namespace.Auth = append(namespace.Auth, mount)
		policies = append(policies, declared...)
	}

	namespace.Auth = append(namespace.Auth, spec.Roster.Doors()...)

	user, host, sshPolicies := e.SSH.derive()
	namespace.SSH = user
	namespace.SSHHost = host

	policies = append(policies, sshPolicies...)

	granted, groups, err := grants(spec.Roster, e.Grants, scope)
	if err != nil {
		return model.Namespace{}, err
	}

	policies = append(policies, granted...)
	namespace.Groups = append(namespace.Groups, groups...)

	secrets, secretGroups, err := secretGrants(spec.Roster, e.Secrets, e.KV.Path, e.Reserved)
	if err != nil {
		return model.Namespace{}, err
	}

	policies = append(policies, secrets...)
	namespace.Groups = append(namespace.Groups, secretGroups...)

	sort.Slice(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })
	sort.Slice(namespace.Groups, func(i, j int) bool { return namespace.Groups[i].Name < namespace.Groups[j].Name })

	awsAuth, hostPolicies, err := hostLogins(e.Name, e.HostAuth, e.HostLogins, e.SSH, &namespace.SSHHost)
	if err != nil {
		return model.Namespace{}, err
	}

	namespace.AWSAuth = awsAuth
	namespace.Policies = append(slices.Clone(policies), hostPolicies...)

	if err := e.checkPolicies(&namespace); err != nil {
		return model.Namespace{}, err
	}

	return namespace, nil
}

// checkPolicies refuses a workload or an alias that names a policy nobody
// declares: OpenBAO accepts the name and the token then carries nothing.
func (e *Environment) checkPolicies(namespace *model.Namespace) error {
	declared := make(map[string]bool, len(namespace.Policies))
	for i := range namespace.Policies {
		declared[namespace.Policies[i].Name] = true
	}

	for i := range namespace.Auth {
		for j := range namespace.Auth[i].Roles {
			role := &namespace.Auth[i].Roles[j]

			for _, policy := range role.Policies {
				if !declared[policy] {
					return fmt.Errorf("role %q on %q carries policy %q, which nothing declares", role.Name, namespace.Auth[i].Path, policy)
				}
			}
		}
	}

	return nil
}
