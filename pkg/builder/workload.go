package builder

import (
	"fmt"
	"strings"

	"github.com/truvity/openbao/pkg/model"
)

type (
	// Trust is one cluster whose ServiceAccount tokens a namespace accepts:
	// a JWT auth mount on the cluster's issuer, and the workloads that log
	// in on it.
	Trust struct {
		// Mount is the auth mount's path.
		Mount string `yaml:"mount"`
		// Description is what `sys/auth` shows an operator.
		Description string `yaml:"description,omitempty"`
		// Issuer is the cluster's OIDC issuer, whose published key set the
		// mount verifies tokens against.
		Issuer string `yaml:"issuer"`
		// Optional declares the mount only if some workload logs in on it: a
		// mount that admits nobody is one more door to keep an eye on. A
		// trust that is not optional is declared either way.
		Optional bool `yaml:"optional,omitempty"`
		// Workloads are the roles, in the order they are declared.
		Workloads []Workload `yaml:"workloads,omitempty"`
	}

	// Workload is one machine identity: a role on a [Trust]'s mount pinned
	// to one token subject, and the policy the token carries. A workload has
	// no group and no door of its own -- it holds its policy directly.
	Workload struct {
		// Role is the role's name on the mount.
		Role string `yaml:"role"`
		// Subject is the one `sub` the role admits: a ServiceAccount's
		// ([model.ServiceAccountSubject]).
		Subject string `yaml:"subject"`
		// Audience is the token audience the role is bound to; empty is the
		// spec's Audience.
		Audience string `yaml:"audience,omitempty"`
		// TTL is the token's whole life: a Go duration.
		TTL string `yaml:"ttl"`
		// Policy is the one policy the token carries; empty is Role. With
		// Access, the workload declares it. Without, it names a policy
		// declared elsewhere in the namespace (an SSH role's grant, say),
		// and refusing one nobody declares is [Environment.Derive]'s job.
		Policy string `yaml:"policy,omitempty"`
		// Access is what the policy grants. Empty declares no policy.
		Access Access `yaml:"access,omitempty"`
	}
)

// policyName is the policy a workload's token carries.
func (w *Workload) policyName() string {
	if w.Policy != "" {
		return w.Policy
	}

	return w.Role
}

// derive is the trust as the JWT mount it is, and the policies its workloads
// declare.
func (t *Trust) derive(audience string, scope kvScope) (model.JWTMount, []model.Policy, error) {
	mount := model.JWTMount{Path: t.Mount, Description: t.Description, DiscoveryURL: t.Issuer}

	var policies []model.Policy

	if strings.TrimSpace(t.Issuer) == "" {
		return model.JWTMount{}, nil, fmt.Errorf("builder: auth mount %q has no issuer", t.Mount)
	}

	for i := range t.Workloads {
		workload := &t.Workloads[i]

		if strings.TrimSpace(workload.Role) == "" || strings.TrimSpace(workload.Subject) == "" {
			return model.JWTMount{}, nil, fmt.Errorf("builder: auth mount %q has a workload with no role or no subject", t.Mount)
		}

		bound := workload.Audience
		if bound == "" {
			bound = audience
		}

		mount.Roles = append(mount.Roles, model.Role{
			Name:           workload.Role,
			BoundAudiences: []string{bound},
			BoundSubject:   workload.Subject,
			UserClaim:      model.RosterUserClaim,
			Policies:       []string{workload.policyName()},
			TTL:            workload.TTL,
		})

		if len(workload.Access) == 0 {
			continue
		}

		rules, err := workload.Access.rules(scope)
		if err != nil {
			return model.JWTMount{}, nil, fmt.Errorf("workload %q: %w", workload.Role, err)
		}

		policies = append(policies, model.Policy{Name: workload.policyName(), Rules: rules})
	}

	return mount, policies, nil
}
