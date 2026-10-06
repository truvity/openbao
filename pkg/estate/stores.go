package estate

import "slices"

type (
	// StoreFacts is what one cluster runs, as far as its secret stores go:
	// the facts a [StoreRule] gates on.
	StoreFacts struct {
		Cluster string `yaml:"cluster"`
		// Management reports whether this is the management cluster.
		Management bool `yaml:"management,omitempty"`
		// On are the cluster's switches that are on: components, overrides,
		// features.
		On map[string]bool `yaml:"on,omitempty"`
		// Tailnets are the tailnets the cluster's routers join, primary
		// first.
		Tailnets []string `yaml:"tailnets,omitempty"`
		// Clients are where the identity provider's clients run, as this
		// cluster's values carry them.
		Clients []ClientPlacement `yaml:"clients,omitempty"`
	}

	// ClientPlacement is one identity-provider client's placement: proxied
	// on ProxyCluster (empty: the provider's own cluster), or, with no
	// proxy, running its own flow on Cluster (empty: nowhere else).
	ClientPlacement struct {
		Proxied      bool   `yaml:"proxied,omitempty"`
		ProxyCluster string `yaml:"proxyCluster,omitempty"`
		Cluster      string `yaml:"cluster,omitempty"`
	}

	// StoreRule says when one store kind runs on a cluster. Every condition
	// set must hold.
	StoreRule struct {
		Kind string `yaml:"kind"`
		// When names the switch that must be on (StoreFacts.On).
		When string `yaml:"when,omitempty"`
		// PerTailnet makes one kind per tailnet, Kind + "-" + tailnet: a
		// shared one would let one tailnet's router read another's key.
		PerTailnet bool `yaml:"perTailnet,omitempty"`
		// Management limits the kind to the management cluster.
		Management bool `yaml:"management,omitempty"`
		// Clusters limits the kind to the clusters named; Except excludes
		// the clusters named.
		Clusters []string `yaml:"clusters,omitempty"`
		Except   []string `yaml:"except,omitempty"`
		// ClientsElsewhere holds where a client's secret has to travel: on a
		// cluster that proxies a client the provider's cluster does not, and
		// on the management cluster for every client proxied or running
		// somewhere else.
		ClientsElsewhere bool `yaml:"clientsElsewhere,omitempty"`
	}
)

// StoreKinds is the store kinds a cluster runs: each rule whose conditions
// hold, in the order of the rules. Each kind is a role on the cluster's
// mount ([Cluster.Stores]), so a role exists exactly where its store does.
func StoreKinds(facts *StoreFacts, rules []StoreRule) []string {
	var out []string

	for i := range rules {
		rule := &rules[i]
		if !rule.holds(facts) {
			continue
		}

		if !rule.PerTailnet {
			out = append(out, rule.Kind)

			continue
		}

		for _, tailnet := range facts.Tailnets {
			out = append(out, rule.Kind+"-"+tailnet)
		}
	}

	return out
}

func (r *StoreRule) holds(facts *StoreFacts) bool {
	switch {
	case r.When != "" && !facts.On[r.When],
		r.Management && !facts.Management,
		len(r.Clusters) > 0 && !slices.Contains(r.Clusters, facts.Cluster),
		slices.Contains(r.Except, facts.Cluster),
		r.ClientsElsewhere && !clientsElsewhere(facts):
		return false
	default:
		return true
	}
}

// clientsElsewhere reports whether one of the cluster's clients has its
// secret held on another cluster than the one that serves it. The
// management cluster carries every client and reads the ones placed
// elsewhere; any other cluster carries only the ones it serves.
func clientsElsewhere(facts *StoreFacts) bool {
	for _, client := range facts.Clients {
		if !client.Proxied {
			if facts.Management && client.Cluster != "" && client.Cluster != facts.Cluster {
				return true
			}

			continue
		}

		if facts.Management && (client.ProxyCluster == "" || client.ProxyCluster == facts.Cluster) {
			continue
		}

		return true
	}

	return false
}
