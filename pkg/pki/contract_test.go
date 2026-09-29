package pki

import (
	"strings"
	"testing"
)

// validContract returns a deep, well-formed Contract equivalent to
// testdata/contract.yaml, as a Go value: negative tests mutate a field and
// assert the one refusal they are exercising, without round-tripping YAML.
func validContract() *Contract {
	return &Contract{
		SchemaVersion: SchemaVersion,
		dir:           ".",
		Global: Global{
			Immutable:               true,
			KeyAlgorithm:            "ECDSA",
			KeyCurve:                "P-384",
			SignatureAlgorithm:      "ECDSA_SHA_384",
			MinimumTLSVersion:       "TLS1.3",
			AdditionalLeafKeyCurves: []string{"P-256"},
		},
		Generations: []RootGeneration{
			{
				ID:       "example-root-2026-01",
				Lifetime: "175200h",
				Certificate: RootCertificate{
					NotBefore:  "2026-01-01T00:00:00Z",
					Subject:    Subject{CommonName: "Example Private Root 2026-01", Organization: "Example Org"},
					MaxPathLen: 3,
				},
				Custody: RootCustody{
					Provider:                   "aws-kms",
					AccountID:                  "111122223333",
					Profile:                    "example-root@admin",
					Region:                     "eu-central-1",
					TrustedPrincipalARNPattern: "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_role-admin_*",
					DisasterRecovery:           DisasterRecovery{Mode: "multi-region-replica", Region: "eu-north-1"},
				},
				State: GenerationActive,
			},
		},
		TrustDomains: TrustDomains{
			DNS: []DNSTrustDomain{
				{
					Name:           "internal",
					Suffix:         "internal.example.org",
					RootGeneration: "example-root-2026-01",
					DomainIntermediate: DomainIntermediate{
						Name:                "example-internal-2026-01",
						Subject:             Subject{CommonName: "internal.example.org Intermediate CA", Organization: "Example Org"},
						KeyCurve:            "P-384",
						MaxPathLen:          2,
						PermittedDNSDomains: []string{"internal.example.org", "cluster.local"},
					},
					Lifetimes: standardLifetimes(),
					Roles: []LeafRole{
						{
							Name:      "server",
							Names:     NameShape{Source: NameSourceEnvironmentZone, Patterns: []string{ZonePlaceholder}, Bare: true, Subdomains: true},
							Usage:     Usage{Server: true, Client: true},
							KeyCurve:  "P-384",
							Lifetimes: leafLifetimes(),
						},
						{
							Name:      "workload",
							Names:     NameShape{Source: NameSourceStatic, Patterns: []string{"svc.cluster.local"}, Bare: false, Subdomains: true},
							Usage:     Usage{Server: true, Client: true},
							KeyCurve:  "P-384",
							Lifetimes: leafLifetimes(),
						},
					},
				},
				{
					Name:           "edge",
					Suffix:         "edge.example.org",
					RootGeneration: "example-root-2026-01",
					RequireTrusted: true,
					DomainIntermediate: DomainIntermediate{
						Name:       "example-edge-2026-01",
						Subject:    Subject{CommonName: "edge.example.org Intermediate CA", Organization: "Example Org"},
						KeyCurve:   "P-384",
						MaxPathLen: 2,
					},
					Lifetimes: standardLifetimes(),
					Roles: []LeafRole{
						{
							Name:          "edge",
							Names:         NameShape{Source: NameSourceCatalog, Bare: true, Subdomains: false},
							Usage:         Usage{Server: true, Client: false},
							KeyCurve:      "P-384",
							AllowWildcard: true,
							Lifetimes:     leafLifetimes(),
						},
					},
				},
			},
			URI: []URITrustDomain{
				{
					Name:           "workload",
					RootGeneration: "example-root-2026-01",
					DomainIntermediate: URIDomainIntermediate{
						Name:                "example-workload-2026-01",
						Subject:             Subject{CommonName: "Workload Identity Intermediate CA", Organization: "Example Org"},
						KeyCurve:            "P-384",
						MaxPathLen:          2,
						PermittedURIDomains: []string{".internal.example.org"},
					},
					Lifetimes: Lifetimes{
						DomainIntermediate:  "87600h",
						ClusterIntermediate: "26280h",
						LeafDefault:         "1h",
						LeafMaximum:         "24h",
						RenewBefore:         "10m",
					},
					Environments: []string{"dev", "prod"},
					Role: URIRole{
						Name:          "identity",
						URISANPattern: "spiffe://" + ZonePlaceholder + "/*",
						Usage:         Usage{Server: true, Client: true},
						KeyCurve:      "P-256",
						Lifetimes:     LeafLifetimes{Default: "1h", Maximum: "24h", RenewBefore: "10m"},
					},
					EnvironmentCA:          &EnvironmentCA{KeyCurve: "P-384", MaxPathLen: 0, CommonNameSuffix: "Workload Identity CA"},
					RootSignedEnvironments: []string{"dev"},
				},
			},
		},
		Alerts: Alerts{
			Enabled: false,
			Thresholds: AlertThresholds{
				RootGeneration:      "43800h",
				DomainIntermediate:  "17520h",
				ClusterIntermediate: "4320h",
				Leaf:                "240h",
			},
		},
		SignAlerts: SignAlerts{Notify: []string{"security@example.org"}},
		Migration:  Migration{TrustedGenerations: []string{"example-root-2026-01"}},
	}
}

func standardLifetimes() Lifetimes {
	return Lifetimes{
		DomainIntermediate:  "87600h",
		ClusterIntermediate: "26280h",
		LeafDefault:         "720h",
		LeafMaximum:         "2160h",
		RenewBefore:         "240h",
	}
}

func leafLifetimes() LeafLifetimes {
	return LeafLifetimes{Default: "720h", Maximum: "2160h", RenewBefore: "240h"}
}

func TestValidContractPasses(t *testing.T) {
	if err := validContract().Validate(); err != nil {
		t.Fatalf("validContract() should validate cleanly: %v", err)
	}
}

func TestLoadContractFixture(t *testing.T) {
	contract, err := Load("testdata/contract.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := contract.TrustDomainNames(); len(got) != 3 {
		t.Fatalf("TrustDomainNames() = %v, want 3 names", got)
	}

	if contract.ArtifactDirectory() != DefaultArtifactDir {
		t.Fatalf("ArtifactDirectory() = %q, want %q", contract.ArtifactDirectory(), DefaultArtifactDir)
	}
}

func TestLoadRefusesUnknownField(t *testing.T) {
	if _, err := Load("testdata/contract-unknown-field.yaml"); err == nil {
		t.Fatal("Load should refuse an unknown field")
	}
}

func TestLoadRefusesMissingFile(t *testing.T) {
	if _, err := Load("testdata/does-not-exist.yaml"); err == nil {
		t.Fatal("Load should refuse a missing file")
	}
}

// mutate applies f to a deep-enough copy of validContract() and returns the
// result, for a test that must change exactly one field without disturbing
// the fixture other tests share.
func mutate(f func(*Contract)) *Contract {
	contract := validContract()
	f(contract)

	return contract
}

func wantErr(t *testing.T, err error, substring string) {
	t.Helper()

	if err == nil {
		t.Fatalf("Validate() should have refused; want error containing %q", substring)
	}

	if !strings.Contains(err.Error(), substring) {
		t.Fatalf("Validate() error = %q, want it to contain %q", err.Error(), substring)
	}
}

func TestValidateRefusals(t *testing.T) {
	tests := []struct {
		name      string
		contract  *Contract
		wantError string
	}{
		{"wrong schema version", mutate(func(c *Contract) { c.SchemaVersion = 2 }), "schemaVersion must be"},
		{"mutable global", mutate(func(c *Contract) { c.Global.Immutable = false }), "global.immutable must be true"},
		{"empty key curve", mutate(func(c *Contract) { c.Global.KeyCurve = "" }), "are all required"},
		{
			"additional curve repeats global curve",
			mutate(func(c *Contract) { c.Global.AdditionalLeafKeyCurves = []string{"P-384"} }),
			"must not repeat global.keyCurve",
		},
		{"no generations", mutate(func(c *Contract) { c.Generations = nil }), "at least one rootGeneration is required"},
		{"two active generations", mutate(func(c *Contract) {
			second := c.Generations[0]
			second.ID = "example-root-2027-01"
			c.Generations = append(c.Generations, second)
		}), "exactly one rootGeneration must be active"},
		{"no active generation", mutate(func(c *Contract) { c.Generations[0].State = GenerationRetired }), "exactly one rootGeneration must be active"},
		{"duplicated generation id", mutate(func(c *Contract) {
			second := c.Generations[0]
			c.Generations = append(c.Generations, second)
		}), "is duplicated"},
		{"non canonical notBefore", mutate(func(c *Contract) { c.Generations[0].Certificate.NotBefore = "2026-01-01T00:00:00+01:00" }), "canonical UTC RFC3339"},
		{"root maxPathLen zero", mutate(func(c *Contract) { c.Generations[0].Certificate.MaxPathLen = 0 }), "at least 1"},
		{"root carries a dns constraint", mutate(func(c *Contract) {
			c.Generations[0].Certificate.PermittedDNSDomains = []string{"example.org"}
		}), "permittedDnsDomains must be empty"},
		{"bad custody provider", mutate(func(c *Contract) { c.Generations[0].Custody.Provider = "gcp-kms" }), "custody.provider must be"},
		{"bad account id", mutate(func(c *Contract) { c.Generations[0].Custody.AccountID = "abc" }), "12-digit AWS account ID"},
		{"dr region equals primary", mutate(func(c *Contract) {
			c.Generations[0].Custody.DisasterRecovery.Region = c.Generations[0].Custody.Region
		}), "must be set and differ"},
		{"bad generation state", mutate(func(c *Contract) { c.Generations[0].State = "unknown" }), "is not allowed"},
		{"dns domain no suffix", mutate(func(c *Contract) { c.TrustDomains.DNS[0].Suffix = "" }), "suffix is required"},
		{"dns domain unknown generation", mutate(func(c *Contract) { c.TrustDomains.DNS[0].RootGeneration = "nope" }), "references unknown generation"},
		{"lifetime ordering violated", mutate(func(c *Contract) {
			c.TrustDomains.DNS[0].Lifetimes.ClusterIntermediate = c.TrustDomains.DNS[0].Lifetimes.DomainIntermediate
		}), "lifetimes must satisfy"},
		{"domain intermediate wrong curve", mutate(func(c *Contract) { c.TrustDomains.DNS[0].DomainIntermediate.KeyCurve = "P-256" }), "keyCurve must be"},
		{"domain intermediate wrong pathlen", mutate(func(c *Contract) { c.TrustDomains.DNS[0].DomainIntermediate.MaxPathLen = 1 }), "maxPathLen must be"},
		{"constrained domain missing own suffix", mutate(func(c *Contract) {
			c.TrustDomains.DNS[0].DomainIntermediate.PermittedDNSDomains = []string{"cluster.local"}
		}), "must include the trust domain's own suffix"},
		{"duplicate dns constraint", mutate(func(c *Contract) {
			c.TrustDomains.DNS[0].DomainIntermediate.PermittedDNSDomains = []string{"internal.example.org", "internal.example.org"}
		}), "duplicated"},
		{"no roles", mutate(func(c *Contract) { c.TrustDomains.DNS[0].Roles = nil }), "must declare at least one role"},
		{"duplicate role name", mutate(func(c *Contract) {
			c.TrustDomains.DNS[0].Roles = append(c.TrustDomains.DNS[0].Roles, c.TrustDomains.DNS[0].Roles[0])
		}), "duplicates role name"},
		{"role key curve not allowed", mutate(func(c *Contract) { c.TrustDomains.DNS[0].Roles[0].KeyCurve = "P-521" }), "is neither global.keyCurve"},
		{"wildcard without catalog source", mutate(func(c *Contract) { c.TrustDomains.DNS[0].Roles[0].AllowWildcard = true }), "may be true only where"},
		{"role with neither usage", mutate(func(c *Contract) {
			c.TrustDomains.DNS[0].Roles[0].Usage = Usage{}
		}), "usage must allow server or client"},
		{"role name shape neither bare nor subdomains", mutate(func(c *Contract) {
			c.TrustDomains.DNS[0].Roles[0].Names.Bare = false
			c.TrustDomains.DNS[0].Roles[0].Names.Subdomains = false
		}), "must admit the bare name"},
		{"environment-zone pattern outside constraint", mutate(func(c *Contract) {
			c.TrustDomains.DNS[0].Roles[0].Names.Patterns = []string{"sub." + ZonePlaceholder}
			c.TrustDomains.DNS[0].Roles[0].Names.Source = NameSourceStatic
			c.TrustDomains.DNS[0].Roles[0].Names.Patterns = []string{"sub.evil.example.org"}
		}), "outside the domain intermediate's name constraint"},
		{"catalog source with patterns", mutate(func(c *Contract) {
			c.TrustDomains.DNS[1].Roles[0].Names.Patterns = []string{"x"}
		}), "patterns must be empty for source"},
		{"uri domain no environments", mutate(func(c *Contract) { c.TrustDomains.URI[0].Environments = nil }), "must name at least one environment"},
		{"uri domain duplicate environment", mutate(func(c *Contract) {
			c.TrustDomains.URI[0].Environments = []string{"dev", "dev"}
		}), "duplicates"},
		{"root signed environment not declared", mutate(func(c *Contract) {
			c.TrustDomains.URI[0].RootSignedEnvironments = []string{"stage"}
		}), "is not in"},
		{"environmentCA without rootSignedEnvironments", mutate(func(c *Contract) {
			c.TrustDomains.URI[0].RootSignedEnvironments = nil
		}), "environmentCA is declared but rootSignedEnvironments is empty"},
		{"rootSignedEnvironments without environmentCA", mutate(func(c *Contract) {
			c.TrustDomains.URI[0].EnvironmentCA = nil
		}), "rootSignedEnvironments is declared but environmentCA is not"},
		{"environmentCA pathlen not shorter", mutate(func(c *Contract) {
			c.TrustDomains.URI[0].EnvironmentCA.MaxPathLen = 2
		}), "strictly less than the domain's own intermediate maxPathLen"},
		{"environmentCA no common name suffix", mutate(func(c *Contract) {
			c.TrustDomains.URI[0].EnvironmentCA.CommonNameSuffix = ""
		}), "commonNameSuffix is required"},
		{"environmentCA artifact pattern without environment placeholder", mutate(func(c *Contract) {
			c.TrustDomains.URI[0].EnvironmentCA.ArtifactPattern = "{generation}-legacy.yaml"
		}), `must contain "{environment}"`},
		{"uri role wrong curve", mutate(func(c *Contract) { c.TrustDomains.URI[0].Role.KeyCurve = "P-521" }), "is neither global.keyCurve"},
		{"alerts enabled", mutate(func(c *Contract) { c.Alerts.Enabled = true }), "alerts.enabled must remain false"},
		{"sign alerts empty", mutate(func(c *Contract) { c.SignAlerts.Notify = nil }), "must name at least one recipient"},
		{"sign alerts bad address", mutate(func(c *Contract) { c.SignAlerts.Notify = []string{"not-an-address"} }), "is not an email address"},
		{"migration empty", mutate(func(c *Contract) { c.Migration.TrustedGenerations = nil }), "must not be empty"},
		{"migration unknown generation", mutate(func(c *Contract) { c.Migration.TrustedGenerations = []string{"nope"} }), "references unknown generation"},
		{"require trusted but not trusted", mutate(func(c *Contract) { c.Migration.TrustedGenerations = []string{} }), "must not be empty"},
		{"name collision domain vs generation", mutate(func(c *Contract) {
			c.TrustDomains.DNS[0].Name = "example-root-2026-01"
		}), "collides with"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wantErr(t, test.contract.Validate(), test.wantError)
		})
	}
}

func TestValidateRequireTrustedNeedsGenerationTrusted(t *testing.T) {
	contract := validContract()

	// A second, preparing (not yet signing) generation: valid on its own,
	// and enough to prove migration.trustedGenerations is non-empty
	// without including the generation "edge" (RequireTrusted) actually
	// sits under.
	second := contract.Generations[0]
	second.ID = "example-root-2027-01"
	second.State = GenerationPreparing
	contract.Generations = append(contract.Generations, second)
	contract.Migration.TrustedGenerations = []string{"example-root-2027-01"}

	err := contract.Validate()
	wantErr(t, err, "is not in migration.trustedGenerations, but the domain requires it")
}
