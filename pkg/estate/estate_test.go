package estate

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/secrets/pkg/builder"
	"github.com/truvity/secrets/pkg/model"
	"github.com/truvity/secrets/pkg/pki"
)

// exampleInputs is a small estate with made-up names: three clusters, ops
// the management one, every kind of input once.
func exampleInputs(t *testing.T) Inputs {
	t.Helper()

	contract, err := pki.Load("testdata/contract.yaml")
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}

	sa := model.ServiceAccountSubject

	return Inputs{
		Management: "ops",
		Names: Names{
			KVMount: "kv", Canary: "canary", OperatorKV: "operators", Operators: "all:openbao:operator",
			ClusterMountPrefix: "jwt-", WriterMount: "jwt-ops", RootMount: "jwt-ops",
			StoreSubject: sa("external-secrets", "external-secrets"),
			TokenTTL:     "15m", NamespaceTokenTTL: "1h", CredentialMaxTTL: "1h",
			Metadata: map[string]string{"source": "example"},
			Jobs: Jobs{
				RestoreCheck:   Job{Role: "restore-check", Subject: sa("openbao", "restore-check"), Policy: "restore-check"},
				Snapshot:       Job{Role: "snapshot", Subject: sa("openbao", "snapshot"), Policy: "snapshot"},
				RootGeneration: Job{Role: "root-generation", Subject: sa("openbao", "root-generation"), Policy: "root-generation"},
				PluginCatalog:  Job{Role: "plugin-catalog", Subject: sa("openbao", "plugin-catalog"), Policy: "plugin-catalog"},
				PluginType:     "auth", PluginName: "aws",
			},
			SSH: SSHNames{
				Shape: builder.SSHShape{
					UserKeyType: "ed25519", HostKeyType: "ed25519", KeyIDFormat: "{{token_display_name}}", Extension: "permit-pty",
					UserTTL: "1h", UserMaxTTL: "1h", HostTTL: "24h", HostMaxTTL: "24h",
				},
				Mount: "ssh", CAKeyType: "ed25519", HostMount: "ssh-host", HostKeyType: "ed25519",
				UserRole: "user", UserPrincipal: "ops", CIRole: "ci", CIPrincipal: "builder", CIForceCommand: "builder-serve",
			},
			Workers: Workers{
				LoginRole: "worker-host", Subject: sa("builders", "worker"), TTL: "15m", Policy: "worker-sign",
				HostRole: "worker", Domains: []string{"builders.example.internal"},
			},
			HostAuth: HostAuthNames{Mount: "aws", PluginVersion: "v0.1.0", TTL: "15m"},
		},
		Text: Text{
			OperatorKV: "operators only", EnvironmentKV: "the {env} secrets", ProjectKV: "the {project} secrets",
			SSHUser: "the {env} SSH user CA", SSHHostWorkers: "the {env} workers' host CA", SSHHostFleets: "the {env} fleets' host CA",
			HostAuth: "the {env} fleets' instance roles", LegacyRoot: "legacy root", LegacyParent: "legacy intermediate",
			LegacyEnvironment: "{env} legacy certificates", IdentityBootstrap: "{env} identity CA",
		},
		Groups: Groups{
			Name: func(env, thing, role string) string { return env + ":" + thing + ":" + role },
			Holds: func(group string) bool {
				return !strings.HasSuffix(group, ":viewer") || strings.HasPrefix(group, "dev:")
			},
			OpenBAO: "openbao", Writer: "writer", SSH: "ssh", SSHUser: "user", Database: "db", DatabaseClient: "client",
			Deployer: "deployer", Approver: "approver", Viewer: "viewer", DBA: "dba",
		},
		Roster: model.Roster{
			Issuer: "https://id.example.org", TTL: "1h", ClaimMappings: map[string]string{"email": "email"},
			UI: &model.RosterUI{RedirectURIs: []string{"https://bao.example.org/ui/vault/auth/oidc/oidc/callback"}},
		},
		Clusters: []Cluster{
			{
				Name: "prod", Issuer: "https://oidc.example.org/prod", Stores: []string{"app"},
				PrivateZone: "prod.example.private", OriginZone: "prod.example.net", OriginNames: []string{"shop.example.net"},
			},
			{
				Name: "dev", Issuer: "https://oidc.example.org/dev", Stores: []string{"app", "app"}, Workers: true,
				Runners:     []Runner{{Role: "runner-b", Subject: sa("runners", "b")}, {Role: "runner-a", Subject: sa("runners", "a")}},
				PrivateZone: "dev.example.private", OriginZone: "dev.example.net", OriginNames: []string{"*.dev.example.net"},
			},
			{
				Name: "ops", Issuer: "https://oidc.example.org/ops", Stores: []string{"app", "platform"},
				PrivateZone: "ops.example.private", OriginZone: "ops.example.net", OriginNames: []string{"console.example.net"},
			},
		},
		Projects:          map[string][]string{"shop": {"dev", "prod"}},
		ProjectSecrets:    map[string][]string{"shop": {"dev"}, "team": {"dev"}},
		ProjectViewers:    map[string][]string{"team": {"dev"}},
		ProjectNamespaces: []string{"dev"},
		Writers:           []Writer{{Name: "writer", Subject: sa("platform", "writer"), Prefixes: map[string][]string{"ops": {"backup"}, "dev": {"apps"}}}},
		Exporters:         []Writer{{Name: "exporter", Subject: sa("platform", "exporter"), Prefixes: map[string][]string{"ops": {"apps", "exports"}}}},
		Service: Service{
			Role: "svc", Subject: sa("svc", "svc"), Root: "svc", Writes: map[string][]string{"ops": {"svc/private", "svc/export"}},
			ConfigRole: "svc-config", ConfigPrefix: "svc/config", ConfigIn: []string{"ops"},
			ClientsRole: "svc-clients", ClientsKind: "clients", Clients: []string{"console"},
			Exports: []Export{{Role: "svc-export-app", Prefix: "svc/export/app", Environments: []string{"ops"}}},
		},
		CrossReads: []CrossRead{{Role: "metrics-reader", Key: "metrics/write-token", Environments: []string{"prod"}}},
		CISecrets:  []builder.SecretGrant{{Policy: "ci-npm", Path: "ci/npm", Groups: []string{"acme:widget:publish"}}},
		Stores: Stores{
			HasLayout:    func(kind string) bool { return kind != "unknown" },
			Access:       map[string]builder.Access{"platform": {builder.Key("platform/one-*")}},
			PolicyPrefix: "eso-",
		},
		PKI: PKI{
			Contract: contract, Private: "private", Origin: "origin", Identity: "identity", OriginRole: "origin",
			Signed:         map[string]bool{"dev": true},
			ClusterIssuers: map[string]string{"private": "private-ca", "origin": "origin-ca", "identity": "identity-ca"},
			PolicyPrefix:   "pki-", AudiencePrefix: "openbao-", Subject: sa("cert-manager", "cert-manager"),
			DBClientRole: "db-client", RestoreRole: "restore-check", BootstrapSuffix: "-root-signed",
			LegacyRoleIssuers: map[string]string{"dev": "example-identity-old-dev"},
			Legacy: Legacy{
				Organization: "Example Org",
				Root: PKIAuthority{Mount: "pki-example-root", IssuerName: "example-root", CommonName: "Example Legacy Root",
					TTL: "87600h", MaxPathLength: 2, PermittedDomain: "example.private"},
				Parent: PKIAuthority{Mount: "pki-example-private", IssuerName: "example-private", CommonName: "example.private Legacy CA",
					TTL: "43800h", MaxPathLength: 1, PermittedDomain: "example.private"},
				Domain: "example.private", Mount: "pki", TTL: "26280h",
				LeafRole: "cert-manager", LeafPolicy: "pki-cert-manager", LeafAudience: "openbao-cert-manager", LeafTTL: "720h", LeafMaxTTL: "2160h",
			},
		},
		HostFleets: []HostFleet{{
			Environment: "prod", Name: "edge", Domain: "edge.example.net", InstanceRoleARN: "arn:aws:iam::111122223333:role/prod-edge",
			AuthRole: "edge-host", SigningRole: "edge", Policy: "edge-sign", ServerID: "bao.prod.example.org",
		}},
	}
}

// The whole state of the example estate, as the view and as the model. Both
// files are reviewed like a migration: UPDATE_GOLDEN=1 rewrites them.
func TestGoldenExampleEstate(t *testing.T) {
	desired, err := Build(exampleInputs(t))
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
	for name, mutate := range map[string]func(*Inputs){
		"no roster issuer":         func(in *Inputs) { in.Roster.Issuer = "" },
		"no management cluster":    func(in *Inputs) { in.Management = "" },
		"a cluster with no issuer": func(in *Inputs) { in.Clusters[0].Issuer = "" },
		"a store with no layout":   func(in *Inputs) { in.Clusters[0].Stores = []string{"unknown"} },
		"runners and no workers":   func(in *Inputs) { in.Clusters[1].Workers = false },
		"a runner with no subject": func(in *Inputs) {
			in.Clusters[1].Runners = []Runner{{Role: "runner-a"}}
		},
		"a writer into no cluster": func(in *Inputs) { in.Writers[0].Prefixes["staging"] = []string{"apps"} },
		"a writer on the canary":   func(in *Inputs) { in.Writers[0].Prefixes["dev"] = []string{"canary"} },
		"a writer declared twice":  func(in *Inputs) { in.Writers = append(in.Writers, in.Writers[0]) },
		"an exporter with a path":  func(in *Inputs) { in.Exporters[0].Prefixes["ops"] = []string{"a/b"} },
		"a fleet with no role ARN": func(in *Inputs) { in.HostFleets[0].InstanceRoleARN = "" },
		"no PKI contract":          func(in *Inputs) { in.PKI.Contract = nil },
		"a domain with no issuer":  func(in *Inputs) { delete(in.PKI.ClusterIssuers, "origin") },
		"no database client role":  func(in *Inputs) { in.PKI.DBClientRole = "nobody" },
		"a CI read of a writer's":  func(in *Inputs) { in.CISecrets[0].Path = "backup/key" },
	} {
		t.Run(name, func(t *testing.T) {
			in := exampleInputs(t)
			mutate(&in)

			if _, err := Build(in); err == nil {
				t.Error("built; want a refusal")
			}
		})
	}
}

// A store kind runs exactly where its rule holds, in the order of the rules.
func TestStoreKinds(t *testing.T) {
	rules := []StoreRule{
		{Kind: "tunnel", When: "tunnel"},
		{Kind: "router", When: "router", PerTailnet: true},
		{Kind: "escrow", When: "escrow", Except: []string{"dev"}},
		{Kind: "clients", ClientsElsewhere: true},
		{Kind: "drill", Clusters: []string{"dev"}},
		{Kind: "platform", Management: true},
	}

	for _, tc := range []struct {
		facts StoreFacts
		want  []string
	}{
		{
			facts: StoreFacts{Cluster: "dev", On: map[string]bool{"tunnel": true, "router": true, "escrow": true}, Tailnets: []string{"a", "b"}},
			want:  []string{"tunnel", "router-a", "router-b", "drill"},
		},
		{
			facts: StoreFacts{Cluster: "prod", On: map[string]bool{"escrow": true}, Clients: []ClientPlacement{{Proxied: true, ProxyCluster: "prod"}}},
			want:  []string{"escrow", "clients"},
		},
		{
			// The management cluster carries every client: only one placed
			// elsewhere makes its secret travel.
			facts: StoreFacts{Cluster: "ops", Management: true, Clients: []ClientPlacement{{Proxied: true}, {Cluster: "ops"}}},
			want:  []string{"platform"},
		},
		{
			facts: StoreFacts{Cluster: "ops", Management: true, Clients: []ClientPlacement{{Cluster: "prod"}}},
			want:  []string{"clients", "platform"},
		},
	} {
		if got := StoreKinds(&tc.facts, rules); !slices.Equal(got, tc.want) {
			t.Errorf("%s: kinds = %v, want %v", tc.facts.Cluster, got, tc.want)
		}
	}
}

// A store kind's role reads its whole prefix unless Stores.Access narrows it.
func TestStoreAccess(t *testing.T) {
	in := exampleInputs(t)

	if got := in.StoreAccess("app"); len(got) != 1 || got[0].Op != builder.OpRead {
		t.Errorf("app access = %+v, want a read of its prefix", got)
	}

	if got := in.StoreAccess("platform"); len(got) != 1 || got[0].Op != builder.OpKey {
		t.Errorf("platform access = %+v, want one key", got)
	}
}
