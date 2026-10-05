package builder

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/truvity/secrets/pkg/model"
)

type (
	// Grant is a group's standing: a policy named after the group, and the
	// group admitted through the roster's doors. It is how an internal group
	// name in a token becomes something OpenBAO enforces ([model.Roster.Grant]).
	Grant struct {
		// Name is the group's name in the issuer's groups claim, and the
		// policy's.
		Name string `yaml:"name"`
		// Access is what the group may do.
		Access Access `yaml:"access"`
		// JobsOnly admits the group through the people-and-jobs door alone,
		// for a group only jobs hold: a job has no browser, so an alias on
		// the web UI's door would be a grant nothing can use.
		JobsOnly bool `yaml:"jobsOnly,omitempty"`
	}

	// SecretGrant lets groups read ONE secret, and nothing else: a policy
	// with `read` on the data endpoint of Path -- no metadata, no list, no
	// wildcard -- held by each of Groups through the jobs' door alone. A job
	// that must enumerate or write is asking for something wider, which is
	// reviewed elsewhere.
	SecretGrant struct {
		// Policy is the policy's name.
		Policy string `yaml:"policy"`
		// Path is `<prefix>/<key>` inside the shared KV mount.
		Path string `yaml:"path"`
		// Groups hold the policy. A group may hold several SecretGrants.
		Groups []string `yaml:"groups"`
	}

	// Reservation says a KV prefix is somebody's: a canary the restore check
	// reads, or what a push job writes. A [SecretGrant] refuses a path inside
	// one, so no reader is handed what a writer owns.
	Reservation struct {
		Prefix string `yaml:"prefix"`
		// Owner is who holds it, in the estate's own words, for the refusal.
		Owner string `yaml:"owner"`
	}
)

// grants writes each grant as a policy and a group.
func grants(roster model.Roster, list []Grant, scope kvScope) ([]model.Policy, []model.Group, error) {
	var (
		policies []model.Policy
		groups   []model.Group
	)

	for i := range list {
		grant := &list[i]

		if strings.TrimSpace(grant.Name) == "" {
			return nil, nil, fmt.Errorf("builder: a grant has no name")
		}

		rules, err := grant.Access.rules(scope)
		if err != nil {
			return nil, nil, fmt.Errorf("grant %q: %w", grant.Name, err)
		}

		grantFor := roster.Grant
		if grant.JobsOnly {
			grantFor = roster.JobGrant
		}

		policy, group := grantFor(grant.Name, rules...)
		policies = append(policies, policy)
		groups = append(groups, group)
	}

	return policies, groups, nil
}

// secretGrants writes each single-secret grant as a policy, and one group
// per holder carrying every policy it holds, sorted.
func secretGrants(roster model.Roster, list []SecretGrant, mount string, reserved []Reservation) ([]model.Policy, []model.Group, error) {
	var policies []model.Policy

	held := map[string][]string{}

	for i := range list {
		grant := &list[i]

		prefix, _, ok := strings.Cut(grant.Path, "/")
		if !ok || prefix == "" {
			return nil, nil, fmt.Errorf("builder: secret path %q is not <prefix>/<key>", grant.Path)
		}

		for _, reservation := range reserved {
			if prefix == reservation.Prefix {
				return nil, nil, fmt.Errorf("builder: secret path %q is inside %s's prefix %q", grant.Path, reservation.Owner, reservation.Prefix)
			}
		}

		rules, err := Access{Key(grant.Path)}.rules(kvScope{mount: mount})
		if err != nil {
			return nil, nil, err
		}

		policies = append(policies, model.Policy{Name: grant.Policy, Rules: rules})

		for _, group := range grant.Groups {
			if !slices.Contains(held[group], grant.Policy) {
				held[group] = append(held[group], grant.Policy)
			}
		}
	}

	jobs := roster.DoorPaths()[:1]

	var groups []model.Group

	for _, name := range slices.Sorted(maps.Keys(held)) {
		sort.Strings(held[name])
		groups = append(groups, model.Group{Name: name, Policies: held[name], Doors: slices.Clone(jobs)})
	}

	return policies, groups, nil
}
