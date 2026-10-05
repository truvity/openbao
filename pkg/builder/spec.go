package builder

import (
	"fmt"
	"slices"
	"strings"

	"github.com/truvity/secrets/pkg/model"
)

// Spec is everything the desired state of a server depends on, but its PKI
// (pkg/pki derives that from its own contract, and [pki.Derivation.Apply]
// joins it to the result).
type Spec struct {
	// Roster is the issuer people and jobs sign in through: the doors every
	// environment namespace gets, with the lifetime of a token there.
	Roster model.Roster `yaml:"roster"`
	// Operators is the group that may change the server itself, and
	// OperatorsTTL the life of its tokens in root, where only operators log
	// in.
	Operators    string `yaml:"operators"`
	OperatorsTTL string `yaml:"operatorsTtl"`
	// Metadata is carried by every identity group.
	Metadata map[string]string `yaml:"metadata,omitempty"`
	// CredentialMaxTTL is the ceiling on every short-lived credential
	// ([model.Desired.CredentialMaxTTL]).
	CredentialMaxTTL string `yaml:"credentialMaxTtl,omitempty"`
	// Audience is the audience of every workload token; empty is
	// [model.RosterAudience].
	Audience string `yaml:"audience,omitempty"`
	// Plugins are the plugin catalog the server is given by the apply, for
	// a plugin the server does not register itself.
	Plugins []model.Plugin `yaml:"plugins,omitempty"`
	// Root is what the apply owns in root.
	Root Root `yaml:"root"`
	// Environments are the namespaces one level below root.
	Environments []Environment `yaml:"environments"`
}

// Built is a spec written out: the desired state, and the parts a review
// wants separately.
type Built struct {
	// Model is the whole desired state, validated. It holds no PKI: that
	// joins it.
	Model *model.Desired
	// Bootstrap is the operators' door in root; RootUI is the web UI's door
	// beside it, and RootJobs the jobs' mount and policies. Model.Root is
	// the last two together.
	Bootstrap model.Namespace
	RootUI    model.Namespace
	RootJobs  model.Namespace
	// Environments are the environments' namespaces, in Model.Namespaces'
	// order. They share nothing with Model.
	Environments []model.Namespace
}

func (s *Spec) audience() string {
	if strings.TrimSpace(s.Audience) == "" {
		return model.RosterAudience
	}

	return s.Audience
}

// Build writes the spec as a desired state. It is pure: the same spec gives
// the same state, environments sorted by name, every time.
func (s *Spec) Build() (*Built, error) {
	if strings.TrimSpace(s.Roster.Issuer) == "" {
		return nil, fmt.Errorf("builder: no roster issuer")
	}

	if strings.TrimSpace(s.Operators) == "" {
		return nil, fmt.Errorf("builder: no operators group")
	}

	operators := s.Roster
	operators.TTL = s.OperatorsTTL

	built := &Built{
		Bootstrap: operators.Bootstrap(s.Operators),
		RootUI:    operators.RootUI(s.Operators),
	}

	jobs, err := s.Root.derive(s)
	if err != nil {
		return nil, err
	}

	built.RootJobs = jobs

	root := model.Namespace{
		Auth:     append(append([]model.JWTMount{}, jobs.Auth...), built.RootUI.Auth...),
		Policies: append(append([]model.Policy{}, jobs.Policies...), built.RootUI.Policies...),
		Groups:   append(append([]model.Group{}, jobs.Groups...), built.RootUI.Groups...),
		KV:       slices.Clone(s.Root.KV),
	}

	out := &model.Desired{
		Bootstrap:        built.Bootstrap,
		Root:             root,
		Plugins:          slices.Clone(s.Plugins),
		Identity:         s.Roster.Identity(s.Metadata),
		CredentialMaxTTL: s.CredentialMaxTTL,
	}

	environments := sortEnvironments(s.Environments)
	for i := range environments {
		namespace, err := environments[i].Derive(s)
		if err != nil {
			return nil, err
		}

		built.Environments = append(built.Environments, namespace)
		out.Namespaces = append(out.Namespaces, cloneNamespace(namespace))
	}

	if err := out.Validate(); err != nil {
		return nil, err
	}

	built.Model = out

	return built, nil
}

// cloneNamespace copies a namespace's lists, so two views of it can be
// edited apart.
func cloneNamespace(n model.Namespace) model.Namespace {
	n.KV = slices.Clone(n.KV)
	n.PKI = slices.Clone(n.PKI)
	n.SSH = slices.Clone(n.SSH)
	n.SSHHost = slices.Clone(n.SSHHost)
	n.Auth = slices.Clone(n.Auth)
	n.AWSAuth = slices.Clone(n.AWSAuth)
	n.Projects = slices.Clone(n.Projects)
	n.Policies = slices.Clone(n.Policies)
	n.Groups = slices.Clone(n.Groups)

	return n
}
