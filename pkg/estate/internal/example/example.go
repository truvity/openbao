// Package example is a small estate with made-up names, for the tests of
// pkg/estate and its stack.
package example

import (
	"strings"
	"testing"

	"github.com/truvity/secrets/pkg/builder"
	"github.com/truvity/secrets/pkg/estate"
	"github.com/truvity/secrets/pkg/model"
	"github.com/truvity/secrets/pkg/pki"
)

// Inputs is a small estate with made-up names: three clusters, ops
// the management one, every kind of input once.
func Inputs(t testing.TB, contractPath string) estate.Inputs {
	t.Helper()

	contract, err := pki.Load(contractPath)
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}

	sa := model.ServiceAccountSubject

	return estate.Inputs{
		Management: "ops",
		Names: estate.Names{
			KVMount: "kv", Canary: "canary", OperatorKV: "operators", Operators: "all:openbao:operator",
			ClusterMountPrefix: "jwt-", WriterMount: "jwt-ops", RootMount: "jwt-ops",
			StoreSubject: sa("external-secrets", "external-secrets"),
			TokenTTL:     "15m", NamespaceTokenTTL: "1h", CredentialMaxTTL: "1h",
			Metadata: map[string]string{"source": "example"},
			Jobs: estate.Jobs{
				RestoreCheck:   estate.Job{Role: "restore-check", Subject: sa("openbao", "restore-check"), Policy: "restore-check"},
				Snapshot:       estate.Job{Role: "snapshot", Subject: sa("openbao", "snapshot"), Policy: "snapshot"},
				RootGeneration: estate.Job{Role: "root-generation", Subject: sa("openbao", "root-generation"), Policy: "root-generation"},
				PluginCatalog:  estate.Job{Role: "plugin-catalog", Subject: sa("openbao", "plugin-catalog"), Policy: "plugin-catalog"},
				PluginType:     "auth", PluginName: "aws",
			},
			SSH: estate.SSHNames{
				Shape: builder.SSHShape{
					UserKeyType: "ed25519", HostKeyType: "ed25519", KeyIDFormat: "{{token_display_name}}", Extension: "permit-pty",
					UserTTL: "1h", UserMaxTTL: "1h", HostTTL: "24h", HostMaxTTL: "24h",
				},
				Mount: "ssh", CAKeyType: "ed25519", HostMount: "ssh-host", HostKeyType: "ed25519",
				UserRole: "user", UserPrincipal: "ops", CIRole: "ci", CIPrincipal: "builder", CIForceCommand: "builder-serve",
			},
			Workers: estate.Workers{
				LoginRole: "worker-host", Subject: sa("builders", "worker"), TTL: "15m", Policy: "worker-sign",
				HostRole: "worker", Domains: []string{"builders.example.internal"},
			},
			HostAuth: estate.HostAuthNames{Mount: "aws", PluginVersion: "v0.1.0", TTL: "15m"},
		},
		Text: estate.Text{
			OperatorKV: "operators only", EnvironmentKV: "the {env} secrets", ProjectKV: "the {project} secrets",
			SSHUser: "the {env} SSH user CA", SSHHostWorkers: "the {env} workers' host CA", SSHHostFleets: "the {env} fleets' host CA",
			HostAuth: "the {env} fleets' instance roles", LegacyRoot: "legacy root", LegacyParent: "legacy intermediate",
			LegacyEnvironment: "{env} legacy certificates", IdentityBootstrap: "{env} identity CA",
		},
		Groups: estate.Groups{
			Name: func(env, thing, role string) string { return env + ":" + thing + ":" + role },
			Holds: func(group string) bool {
				return !strings.HasSuffix(group, ":viewer") || strings.HasPrefix(group, "alpha:")
			},
			OpenBAO: "openbao", Writer: "writer", SSH: "ssh", SSHUser: "user", Database: "db", DatabaseClient: "client",
			Deployer: "deployer", Approver: "approver", Viewer: "viewer", DBA: "dba",
		},
		Roster: model.Roster{
			Issuer: "https://id.example.org", TTL: "1h", ClaimMappings: map[string]string{"email": "email"},
			UI: &model.RosterUI{RedirectURIs: []string{"https://bao.example.org/ui/vault/auth/oidc/oidc/callback"}},
		},
		Clusters: []estate.Cluster{
			{
				Name: "beta", Issuer: "https://oidc.example.org/beta", Stores: []string{"app"},
				PrivateZone: "beta.example.private", OriginZone: "beta.example.net", OriginNames: []string{"shop.example.net"},
			},
			{
				Name: "alpha", Issuer: "https://oidc.example.org/alpha", Stores: []string{"app", "app"}, Workers: true,
				Runners:     []estate.Runner{{Role: "runner-b", Subject: sa("runners", "b")}, {Role: "runner-a", Subject: sa("runners", "a")}},
				PrivateZone: "alpha.example.private", OriginZone: "alpha.example.net", OriginNames: []string{"*.alpha.example.net"},
			},
			{
				Name: "ops", Issuer: "https://oidc.example.org/ops", Stores: []string{"app", "platform"},
				PrivateZone: "ops.example.private", OriginZone: "ops.example.net", OriginNames: []string{"console.example.net"},
			},
		},
		Projects:          map[string][]string{"shop": {"alpha", "beta"}},
		ProjectSecrets:    map[string][]string{"shop": {"alpha"}, "team": {"alpha"}},
		ProjectViewers:    map[string][]string{"team": {"alpha"}},
		ProjectNamespaces: []string{"alpha"},
		Writers:           []estate.Writer{{Name: "writer", Subject: sa("platform", "writer"), Prefixes: map[string][]string{"ops": {"backup"}, "alpha": {"apps"}}}},
		Exporters:         []estate.Writer{{Name: "exporter", Subject: sa("platform", "exporter"), Prefixes: map[string][]string{"ops": {"apps", "exports"}}}},
		Service: estate.Service{
			Role: "svc", Subject: sa("svc", "svc"), Root: "svc", Writes: map[string][]string{"ops": {"svc/private", "svc/export"}},
			ConfigRole: "svc-config", ConfigPrefix: "svc/config", ConfigIn: []string{"ops"},
			ClientsRole: "svc-clients", ClientsKind: "clients", Clients: []string{"console"},
			Exports: []estate.Export{{Role: "svc-export-app", Prefix: "svc/export/app", Environments: []string{"ops"}}},
		},
		CrossReads: []estate.CrossRead{{Role: "metrics-reader", Key: "metrics/write-token", Environments: []string{"beta"}}},
		CISecrets:  []builder.SecretGrant{{Policy: "ci-npm", Path: "ci/npm", Groups: []string{"acme:widget:publish"}}},
		Stores: estate.Stores{
			HasLayout:    func(kind string) bool { return kind != "unknown" },
			Access:       map[string]builder.Access{"platform": {builder.Key("platform/one-*")}},
			PolicyPrefix: "eso-",
		},
		PKI: estate.PKI{
			Contract: contract, Private: "private", Origin: "origin", Identity: "identity", OriginRole: "origin",
			Signed:         map[string]bool{"alpha": true},
			ClusterIssuers: map[string]string{"private": "private-ca", "origin": "origin-ca", "identity": "identity-ca"},
			PolicyPrefix:   "pki-", AudiencePrefix: "openbao-", Subject: sa("cert-manager", "cert-manager"),
			DBClientRole: "db-client", RestoreRole: "restore-check", BootstrapSuffix: "-root-signed",
			LegacyRoleIssuers: map[string]string{"alpha": "example-identity-old-alpha"},
			Legacy: estate.Legacy{
				Organization: "Example Org",
				Root: estate.PKIAuthority{Mount: "pki-example-root", IssuerName: "example-root", CommonName: "Example Legacy Root",
					TTL: "87600h", MaxPathLength: 2, PermittedDomain: "example.private"},
				Parent: estate.PKIAuthority{Mount: "pki-example-private", IssuerName: "example-private", CommonName: "example.private Legacy CA",
					TTL: "43800h", MaxPathLength: 1, PermittedDomain: "example.private"},
				Domain: "example.private", Mount: "pki", TTL: "26280h",
				LeafRole: "cert-manager", LeafPolicy: "pki-cert-manager", LeafAudience: "openbao-cert-manager", LeafTTL: "720h", LeafMaxTTL: "2160h",
			},
		},
		HostFleets: []estate.HostFleet{{
			Environment: "beta", Name: "edge", Domain: "edge.example.net", InstanceRoleARN: "arn:aws:iam::111122223333:role/beta-edge",
			AuthRole: "edge-host", SigningRole: "edge", Policy: "edge-sign", ServerID: "bao.beta.example.org",
		}},
	}
}
