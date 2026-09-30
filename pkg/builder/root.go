package builder

import (
	"fmt"
	"sort"

	"github.com/truvity/openbao/pkg/model"
)

// Root is what the apply owns in the root namespace beside the operators'
// door, which the server's initialisation creates: the jobs that must act
// there, and the mounts that must stay out of every environment's reach.
type Root struct {
	// Jobs is the cluster whose ServiceAccounts run OpenBAO's own jobs (a
	// Raft snapshot is a root-namespace endpoint, and a restore check reads
	// every namespace, so neither can log in anywhere narrower), and the job
	// each role is. A job's Access has no KV mount of its own to address:
	// it names the paths it needs ([Rules], [CA], [Canary]).
	Jobs Trust `yaml:"jobs"`
	// KV are mounts in root: credentials that must be out of every
	// environment's reach, because a policy declared inside an environment
	// cannot name a path in its parent.
	KV []model.KVMount `yaml:"kv,omitempty"`
}

// derive is the jobs as a namespace, its policies sorted by declaration.
func (r *Root) derive(spec *Spec) (model.Namespace, error) {
	mount, policies, err := r.Jobs.derive(spec.audience(), kvScope{})
	if err != nil {
		return model.Namespace{}, fmt.Errorf("builder: root: %w", err)
	}

	return model.Namespace{Auth: []model.JWTMount{mount}, Policies: policies}, nil
}

func sortEnvironments(namespaces []Environment) []Environment {
	out := append([]Environment(nil), namespaces...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}
