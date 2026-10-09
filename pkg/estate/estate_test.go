package estate_test

import (
	"bytes"
	"os"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/secrets/pkg/builder"
	"github.com/truvity/secrets/pkg/estate"
	"github.com/truvity/secrets/pkg/estate/internal/example"
)

// The whole state of the example estate, as the view and as the model. Both
// files are reviewed like a migration: UPDATE_GOLDEN=1 rewrites them.
func TestGoldenExampleEstate(t *testing.T) {
	desired, err := estate.Build(example.Inputs(t, "testdata/contract.yaml"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	state, err := desired.Model()
	if err != nil {
		t.Fatalf("model: %v", err)
	}

	assertGolden(t, "testdata/desired.yaml", desired)
	assertGolden(t, "testdata/model.yaml", state)
	assertGolden(t, "testdata/renames.yaml", desired.LegacyResourceNames())
}

func assertGolden(t *testing.T, path string, value any) {
	t.Helper()

	var got bytes.Buffer

	encoder := yaml.NewEncoder(&got)
	encoder.SetIndent(2)

	if err := encoder.Encode(value); err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}

	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}

		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s (UPDATE_GOLDEN=1 writes it): %v", path, err)
	}

	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("%s differs; review and rerun with UPDATE_GOLDEN=1", path)
	}
}

// Every refusal the derivation makes on a bad input.
func TestBuildRefuses(t *testing.T) {
	for name, mutate := range map[string]func(*estate.Inputs){
		"no roster issuer":         func(in *estate.Inputs) { in.Roster.Issuer = "" },
		"no management cluster":    func(in *estate.Inputs) { in.Management = "" },
		"a cluster with no issuer": func(in *estate.Inputs) { in.Clusters[0].Issuer = "" },
		"a store with no layout":   func(in *estate.Inputs) { in.Clusters[0].Stores = []string{"unknown"} },
		"runners and no workers":   func(in *estate.Inputs) { in.Clusters[1].Workers = false },
		"a runner with no subject": func(in *estate.Inputs) {
			in.Clusters[1].Runners = []estate.Runner{{Role: "runner-a"}}
		},
		"a writer into no cluster": func(in *estate.Inputs) { in.Writers[0].Prefixes["staging"] = []string{"apps"} },
		"a writer on the canary":   func(in *estate.Inputs) { in.Writers[0].Prefixes["dev"] = []string{"canary"} },
		"a writer declared twice":  func(in *estate.Inputs) { in.Writers = append(in.Writers, in.Writers[0]) },
		"an exporter with a path":  func(in *estate.Inputs) { in.Exporters[0].Prefixes["ops"] = []string{"a/b"} },
		"a fleet with no role ARN": func(in *estate.Inputs) { in.HostFleets[0].InstanceRoleARN = "" },
		"a fleet allowing nothing": func(in *estate.Inputs) {
			off := false
			in.HostFleets[0].Subdomains = &off
		},
		"a fleet with a wildcard": func(in *estate.Inputs) { in.HostFleets[0].Domain = "*.edge.example.net" },
		"no PKI contract":         func(in *estate.Inputs) { in.PKI.Contract = nil },
		"a domain with no issuer": func(in *estate.Inputs) { delete(in.PKI.ClusterIssuers, "origin") },
		"no database client role": func(in *estate.Inputs) { in.PKI.DBClientRole = "nobody" },
		"a CI read of a writer's": func(in *estate.Inputs) { in.CISecrets[0].Path = "backup/key" },
	} {
		t.Run(name, func(t *testing.T) {
			in := example.Inputs(t, "testdata/contract.yaml")
			mutate(&in)

			if _, err := estate.Build(in); err == nil {
				t.Error("built; want a refusal")
			}
		})
	}
}

// A store kind runs exactly where its rule holds, in the order of the rules.
func TestStoreKinds(t *testing.T) {
	rules := []estate.StoreRule{
		{Kind: "tunnel", When: "tunnel"},
		{Kind: "router", When: "router", PerTailnet: true},
		{Kind: "escrow", When: "escrow", Except: []string{"dev"}},
		{Kind: "clients", ClientsElsewhere: true},
		{Kind: "drill", Clusters: []string{"dev"}},
		{Kind: "platform", Management: true},
	}

	for _, tc := range []struct {
		facts estate.StoreFacts
		want  []string
	}{
		{
			facts: estate.StoreFacts{Cluster: "dev", On: map[string]bool{"tunnel": true, "router": true, "escrow": true}, Tailnets: []string{"a", "b"}},
			want:  []string{"tunnel", "router-a", "router-b", "drill"},
		},
		{
			facts: estate.StoreFacts{Cluster: "prod", On: map[string]bool{"escrow": true}, Clients: []estate.ClientPlacement{{Proxied: true, ProxyCluster: "prod"}}},
			want:  []string{"escrow", "clients"},
		},
		{
			// The management cluster carries every client: only one placed
			// elsewhere makes its secret travel.
			facts: estate.StoreFacts{Cluster: "ops", Management: true, Clients: []estate.ClientPlacement{{Proxied: true}, {Cluster: "ops"}}},
			want:  []string{"platform"},
		},
		{
			facts: estate.StoreFacts{Cluster: "ops", Management: true, Clients: []estate.ClientPlacement{{Cluster: "prod"}}},
			want:  []string{"clients", "platform"},
		},
	} {
		if got := estate.StoreKinds(&tc.facts, rules); !slices.Equal(got, tc.want) {
			t.Errorf("%s: kinds = %v, want %v", tc.facts.Cluster, got, tc.want)
		}
	}
}

// A store kind's role reads its whole prefix unless Stores.Access narrows it.
func TestStoreAccess(t *testing.T) {
	in := example.Inputs(t, "testdata/contract.yaml")

	if got := in.StoreAccess("app"); len(got) != 1 || got[0].Op != builder.OpRead {
		t.Errorf("app access = %+v, want a read of its prefix", got)
	}

	if got := in.StoreAccess("platform"); len(got) != 1 || got[0].Op != builder.OpKey {
		t.Errorf("platform access = %+v, want one key", got)
	}
}
