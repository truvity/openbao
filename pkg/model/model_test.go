package model_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/openbao/pkg/model"
)

const (
	// oneEnvironmentPath is the small case a reader meets first: one
	// environment, on the cluster that also runs the server.
	oneEnvironmentPath = "testdata/desired-one-env.yaml"
	examplePath        = "testdata/desired.yaml"
)

// read is one golden, read strictly, so every field it spells is a field
// the model has.
func read(t *testing.T, path string) *model.Desired {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)

	var desired model.Desired
	require.NoError(t, decoder.Decode(&desired))

	return &desired
}

// example is the neutral golden: a whole server's desired state.
func example(t *testing.T) *model.Desired {
	t.Helper()

	return read(t, examplePath)
}

func encode(t *testing.T, desired *model.Desired) []byte {
	t.Helper()

	var out bytes.Buffer

	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	require.NoError(t, encoder.Encode(desired))

	return out.Bytes()
}

// Both examples are valid, and each is written in the model's own
// canonical form: decoding and encoding it again gives the same bytes.
// UPDATE_GOLDEN=1 rewrites them in that form.
func TestExamplesAreValidAndCanonical(t *testing.T) {
	for _, path := range []string{oneEnvironmentPath, examplePath} {
		t.Run(path, func(t *testing.T) {
			desired := read(t, path)
			require.NoError(t, desired.Validate())

			got := encode(t, desired)

			if os.Getenv("UPDATE_GOLDEN") != "" {
				require.NoError(t, os.WriteFile(path, got, 0o644))

				return
			}

			want, err := os.ReadFile(path)
			require.NoError(t, err)

			if !bytes.Equal(want, got) {
				t.Fatalf("%s is not in canonical form; review and rerun with UPDATE_GOLDEN=1", path)
			}
		})
	}
}

// Every refusal, applied to an otherwise valid state. Each must fail for
// its own reason; the substring says which.
func TestValidateRefuses(t *testing.T) {
	dev := func(d *model.Desired) *model.Namespace { return &d.Namespaces[0] }
	pki := func(d *model.Desired) *model.PKIMount { return &dev(d).PKI[0] }
	project := func(d *model.Desired) *model.ProjectNamespace { return &dev(d).Projects[0] }
	projectPKI := func(d *model.Desired) *model.PKIMount { return &project(d).PKI[0] }
	policyNamed := func(d *model.Desired, name string) *model.Policy {
		for i := range dev(d).Policies {
			if dev(d).Policies[i].Name == name {
				return &dev(d).Policies[i]
			}
		}

		t.Fatalf("no policy named %q in the example", name)

		return nil
	}

	for _, tc := range []struct {
		name string
		want string
		edit func(*model.Desired)
	}{
		{"a named root", "have no name", func(d *model.Desired) { d.Root.Name = "root" }},
		{"an unnamed environment", "has no name", func(d *model.Desired) { dev(d).Name = "" }},
		{"a nested namespace", "not a plain name", func(d *model.Desired) { dev(d).Name = "team/dev" }},
		{"a namespace twice", "declared twice", func(d *model.Desired) { d.Namespaces[1].Name = "dev" }},
		{"two mounts on one path", "declares mount", func(d *model.Desired) { dev(d).SSH[0].Path = "kv" }},
		{"an auth mount twice", "auth mount", func(d *model.Desired) { dev(d).Auth[1].Path = "jwt-dev" }},
		{"a policy twice", "declares policy", func(d *model.Desired) { dev(d).Policies[1].Name = "dev:db:client" }},
		{"a group twice", "declares group", func(d *model.Desired) { dev(d).Groups[1].Name = "dev:db:client" }},
		{"a group through a missing door", "no auth mount here", func(d *model.Desired) {
			dev(d).Groups[0].Doors = []string{"jwt-elsewhere"}
		}},
		{"a group with no policy", "carries no policy", func(d *model.Desired) { dev(d).Groups[0].Policies = nil }},
		{"a group with no door", "no door", func(d *model.Desired) { dev(d).Groups[0].Doors = nil }},
		{"a door named twice", "twice", func(d *model.Desired) { dev(d).Groups[0].Doors = []string{"oidc", "oidc"} }},
		{"a policy granting nothing", "grants nothing", func(d *model.Desired) { dev(d).Policies[0].Rules = nil }},
		{"a path named twice", "names path", func(d *model.Desired) {
			p := &dev(d).Policies[4]
			p.Rules[1].Path = p.Rules[0].Path
		}},
		{"a path climbing out", "traverses", func(d *model.Desired) { dev(d).Policies[0].Rules[0].Path = "../sys/*" }},
		{"an unknown capability", "no capability", func(d *model.Desired) { dev(d).Policies[0].Rules[0].Capabilities = []string{"write"} }},
		{"a role with no audience", "binds no audience", func(d *model.Desired) { dev(d).Auth[0].Roles[0].BoundAudiences = nil }},
		{"a role binding nobody", "admits every token", func(d *model.Desired) { dev(d).Auth[0].Roles[0].BoundSubject = "" }},
		{"a role that never expires", "ttl", func(d *model.Desired) { dev(d).Auth[0].Roles[0].TTL = "" }},
		{"a role twice", "declares role", func(d *model.Desired) { dev(d).Auth[0].Roles[1].Name = "external-secrets" }},
		{"an oidc mount with no client", "signs in as no client", func(d *model.Desired) { dev(d).Auth[2].ClientID = "" }},
		{"an oidc role with no redirect", "redirect", func(d *model.Desired) { dev(d).Auth[2].Roles[0].AllowedRedirectURIs = nil }},
		{"a default role that is not there", "defaults to role", func(d *model.Desired) { dev(d).Auth[2].DefaultRole = "admins" }},
		{"a mount with no issuer", "no issuer", func(d *model.Desired) { dev(d).Auth[0].DiscoveryURL = "" }},
		{"an unknown supported algorithm", "not one the JWT plugin signs with", func(d *model.Desired) {
			dev(d).Auth[0].SupportedAlgorithms = []string{"RS256", "made-up"}
		}},
		{"a supported algorithm named twice", "named twice", func(d *model.Desired) {
			dev(d).Auth[0].SupportedAlgorithms = []string{"RS256", "RS256"}
		}},
		{"a supported HMAC algorithm", "not one the JWT plugin signs with", func(d *model.Desired) {
			dev(d).Auth[0].SupportedAlgorithms = []string{"HS256"}
		}},
		{"a supported algorithm of none", "not one the JWT plugin signs with", func(d *model.Desired) {
			dev(d).Auth[0].SupportedAlgorithms = []string{"none"}
		}},
		{"a PKI mount with no issuers", "holds no issuer", func(d *model.Desired) { pki(d).Issuers = nil }},
		{"a default issuer the mount lacks", "defaults to issuer", func(d *model.Desired) { pki(d).DefaultIssuer = "example-other" }},
		{"an issuer with two signers", "exactly one of", func(d *model.Desired) { pki(d).Issuers[0].SelfSigned = true }},
		{"an issuer with none", "exactly one of", func(d *model.Desired) { pki(d).Issuers[0].SignedBy = nil }},
		{"an unknown curve", "unknown key curve", func(d *model.Desired) { pki(d).Issuers[0].KeyCurve = "secp256k1" }},
		{"an unbounded CA", "negative path length", func(d *model.Desired) { pki(d).Issuers[0].MaxPathLength = -1 }},
		{"a signer declared later", "declared before it", func(d *model.Desired) {
			pki(d).Issuers[0].SignedBy = &model.IssuerRef{Namespace: "prod", Mount: "pki", Issuer: "example-prod"}
		}},
		{"a signer in the same mount", "declared before it", func(d *model.Desired) {
			d.Root.PKI[1].Issuers[0].SignedBy = &model.IssuerRef{Mount: "pki-int", Issuer: "example-int"}
		}},
		{"a role on a missing issuer", "does not hold", func(d *model.Desired) { pki(d).Roles[0].Issuer = "example-root" }},
		{"a role signing nothing", "allows no domain", func(d *model.Desired) { pki(d).Roles[0].AllowedDomains = nil }},
		{"a templated role", "not a domain", func(d *model.Desired) { pki(d).Roles[0].AllowedDomains = []string{"{{identity.entity.name}}"} }},
		{"a role usable for nothing", "usable for nothing", func(d *model.Desired) { pki(d).Roles[0].Server = false }},
		{"a role default beyond its maximum", "beyond its own maximum", func(d *model.Desired) { pki(d).Roles[0].TTL = "9000h" }},
		{"a credential role shadowing a role", "declares role", func(d *model.Desired) { pki(d).CredentialRoles[0].Name = "service" }},
		{"a credential role reading nowhere", "no auth mount here", func(d *model.Desired) {
			pki(d).CredentialRoles[0].SubjectMount = "jwt-elsewhere"
		}},
		{"a credential role beyond the ceiling", "credential ceiling", func(d *model.Desired) {
			pki(d).CredentialRoles[0].TTL = "2h"
			pki(d).CredentialRoles[0].MaxTTL = "2h"
		}},
		{"root declaring a project", "hold no project", func(d *model.Desired) {
			d.Root.Projects = []model.ProjectNamespace{{Name: "infra"}}
		}},
		{"a project with no name", "has no name", func(d *model.Desired) { project(d).Name = "" }},
		{"a project with an unsafe name", "not a plain name", func(d *model.Desired) { project(d).Name = "billing/x" }},
		{"a project declared twice", "declares project", func(d *model.Desired) {
			dev(d).Projects = append(dev(d).Projects, *project(d))
		}},
		{"a project sharing a namespace mount's name", "shares its name with a mount", func(d *model.Desired) {
			project(d).Name = dev(d).KV[0].Path
		}},
		{"a project KV mount declared twice", "declares mount", func(d *model.Desired) {
			project(d).KV = append(project(d).KV, project(d).KV[0])
		}},
		{"a project PKI issuer self-signed", "not signed by another issuer", func(d *model.Desired) {
			projectPKI(d).Issuers[0].SignedBy = nil
			projectPKI(d).Issuers[0].SelfSigned = true
		}},
		{"a project PKI credential role", "has no auth mount", func(d *model.Desired) {
			projectPKI(d).CredentialRoles = []model.CredentialRole{{
				Name: "x", Issuer: projectPKI(d).DefaultIssuer, SubjectMount: "jwt-people",
				Client: true, KeyCurve: model.CurveP384, TTL: "1h", MaxTTL: "1h",
			}}
		}},
		{"a project PKI issuer signed by its own root, not its environment", "not an issuer this environment declares directly", func(d *model.Desired) {
			projectPKI(d).Issuers[0].SignedBy = &model.IssuerRef{Mount: "pki-root", Issuer: "example-root"}
		}},
		{"a policy naming a project's undeclared mount", "which the project does not hold", func(d *model.Desired) {
			policyNamed(d, "dev:billing:reader").Rules[0].Path = "billing/pki-none/data/*"
		}},
		{"an environment issuer with no path length left to sign its project's CA", "too few for the", func(d *model.Desired) {
			pki(d).Issuers[0].MaxPathLength = 0
		}},
		{"an environment policy rule that is a bare wildcard", "reaches with a glob", func(d *model.Desired) {
			dev(d).Policies = append(dev(d).Policies, model.Policy{
				Name: "dev:everything", Rules: []model.Rule{{Path: "*", Capabilities: []string{model.CapRead}}},
			})
		}},
		{"an environment policy rule with a prefix glob that could match a project", "reaches with a glob", func(d *model.Desired) {
			dev(d).Policies = append(dev(d).Policies, model.Policy{
				Name: "dev:billing-ish", Rules: []model.Rule{{Path: "bill*/kv/data/*", Capabilities: []string{model.CapRead}}},
			})
		}},
		{"an environment policy rule with a + segment", "reaches with a glob", func(d *model.Desired) {
			dev(d).Policies = append(dev(d).Policies, model.Policy{
				Name: "dev:plus", Rules: []model.Rule{{Path: "+/kv/data/*", Capabilities: []string{model.CapRead}}},
			})
		}},
		{"a project name with a glob character", "not a plain name", func(d *model.Desired) { project(d).Name = "wal*" }},
		{"a policy naming a project this environment no longer declares", "which this environment does not declare", func(d *model.Desired) {
			// "billing" stays a real project name in the model (prod's now,
			// with no mounts of its own), so the rule below is still read as
			// a project reference -- but dev, which the rule is IN, renamed
			// its own.
			project(d).Name = "renamed"
			d.Namespaces[1].Projects = []model.ProjectNamespace{{Name: "billing"}}
		}},
		{"an SSH role for root", "allows root", func(d *model.Desired) {
			r := &dev(d).SSH[0].Roles[0]
			r.AllowedUsers = append(r.AllowedUsers, "root")
		}},
		{"an SSH role for anyone", "pattern or a list", func(d *model.Desired) {
			r := &dev(d).SSH[0].Roles[0]
			r.AllowedUsers, r.DefaultUser = []string{"*"}, "*"
		}},
		{"an SSH role defaulting outside its list", "does not allow", func(d *model.Desired) { dev(d).SSH[0].Roles[0].DefaultUser = "admin" }},
		{"an SSH role with no key id", "no key id", func(d *model.Desired) { dev(d).SSH[0].Roles[0].KeyIDFormat = "" }},
		{"an SSH role beyond the ceiling", "credential ceiling", func(d *model.Desired) { dev(d).SSH[0].Roles[0].MaxTTL = "2h" }},
		{"an SSH mount with no CA key type", "no CA key type", func(d *model.Desired) { dev(d).SSH[0].KeyType = "" }},
		{"a force-command role with permit-pty", "defeats it", func(d *model.Desired) {
			r := &dev(d).SSH[0].Roles[1] // runner: forceCommand set, no extensions
			r.Extensions = []string{"permit-pty"}
		}},
		{"a force-command role with port forwarding", "defeats it", func(d *model.Desired) {
			r := &dev(d).SSH[0].Roles[1]
			r.Extensions = []string{"permit-port-forwarding"}
		}},
		{"an SSH host mount with no CA key type", "no CA key type", func(d *model.Desired) { dev(d).SSHHost[0].KeyType = "" }},
		{"an SSH host mount with no role", "has no role", func(d *model.Desired) { dev(d).SSHHost[0].Roles = nil }},
		{"an SSH host role twice", "declares role", func(d *model.Desired) {
			dev(d).SSHHost[0].Roles = append(dev(d).SSHHost[0].Roles, dev(d).SSHHost[0].Roles[0])
		}},
		{"an SSH host role with no domain", "allows no domain", func(d *model.Desired) { dev(d).SSHHost[0].Roles[0].AllowedDomains = nil }},
		{"an SSH host role with an empty domain", "empty domain", func(d *model.Desired) {
			dev(d).SSHHost[0].Roles[0].AllowedDomains = []string{""}
		}},
		{"an SSH host role with a wildcard domain", "wildcard", func(d *model.Desired) {
			dev(d).SSHHost[0].Roles[0].AllowedDomains = []string{"*"}
		}},
		{"an SSH host role with a templated domain", "template", func(d *model.Desired) {
			dev(d).SSHHost[0].Roles[0].AllowedDomains = []string{"{{identity.entity.name}}"}
		}},
		{"an SSH host role signing nothing", "neither bare domains nor subdomains", func(d *model.Desired) {
			r := &dev(d).SSHHost[0].Roles[0]
			r.AllowBareDomains, r.AllowSubdomains = false, false
		}},
		{"an SSH host role with no key type", "no key type", func(d *model.Desired) { dev(d).SSHHost[0].Roles[0].KeyTypes = nil }},
		{"an SSH host role with no key id", "no key id", func(d *model.Desired) { dev(d).SSHHost[0].Roles[0].KeyIDFormat = "" }},
		{"an SSH host role beyond the 30-day cap", "beyond the host certificate cap", func(d *model.Desired) {
			dev(d).SSHHost[0].Roles[0].MaxTTL = "744h" // 31 days
		}},
		{"a force-command role's sign path granted without denying critical_options", "without denying the critical_options parameter", func(d *model.Desired) {
			policyNamed(d, "dev:ssh:runner").Rules[0].DeniedParameters = nil
		}},
		{"a rule denying an empty parameter", "empty parameter", func(d *model.Desired) {
			policyNamed(d, "dev:ssh:runner").Rules[0].DeniedParameters = []string{""}
		}},
		{"a rule denying a parameter twice", "twice", func(d *model.Desired) {
			policyNamed(d, "dev:ssh:runner").Rules[0].DeniedParameters = []string{"critical_options", "critical_options"}
		}},
		{"an AWS auth mount with no header value", "iamServerIdHeaderValue", func(d *model.Desired) {
			dev(d).AWSAuth[0].IAMServerIDHeaderValue = ""
		}},
		{"an AWS auth mount with no role", "has no role", func(d *model.Desired) { dev(d).AWSAuth[0].Roles = nil }},
		{"an AWS auth role twice", "declares role", func(d *model.Desired) {
			dev(d).AWSAuth[0].Roles = append(dev(d).AWSAuth[0].Roles, dev(d).AWSAuth[0].Roles[0])
		}},
		{"an AWS auth mount on a path a JWT mount already holds", "auth mount", func(d *model.Desired) {
			dev(d).AWSAuth[0].Path = "jwt-dev"
		}},
		{"an AWS auth role with no bound principal", "binds no IAM principal", func(d *model.Desired) {
			dev(d).AWSAuth[0].Roles[0].BoundIAMPrincipalARNs = nil
		}},
		{"an AWS auth role with a wildcard principal", "wildcard pattern", func(d *model.Desired) {
			dev(d).AWSAuth[0].Roles[0].BoundIAMPrincipalARNs = []string{"arn:aws:iam::111122223333:role/*"}
		}},
		{"an AWS auth role with a non-IAM principal", "not an IAM ARN", func(d *model.Desired) {
			dev(d).AWSAuth[0].Roles[0].BoundIAMPrincipalARNs = []string{"not-an-arn"}
		}},
		{"an AWS auth role with no policy", "grants no policy", func(d *model.Desired) {
			dev(d).AWSAuth[0].Roles[0].Policies = nil
		}},
		{"an AWS auth role that never expires", "ttl", func(d *model.Desired) { dev(d).AWSAuth[0].Roles[0].TTL = "" }},
		{"an AWS auth mount with a malformed plugin version", "neither", func(d *model.Desired) {
			dev(d).AWSAuth[0].PluginVersion = "0.1.1"
		}},
		{"a plugin with an unrecognised type", "not one of auth, secret, database", func(d *model.Desired) {
			d.Plugins[0].Type = "kms"
		}},
		{"a plugin with no name", "has no name", func(d *model.Desired) { d.Plugins[0].Name = "" }},
		{"a plugin with no command", "has no command", func(d *model.Desired) { d.Plugins[0].Command = "" }},
		{"a plugin with a malformed sha256", "64 lowercase hex characters", func(d *model.Desired) {
			d.Plugins[0].SHA256 = "not-a-checksum"
		}},
		{"a plugin declared twice", "declared twice", func(d *model.Desired) {
			d.Plugins = append(d.Plugins, d.Plugins[0])
		}},
		{"a KV canary that is a pattern", "not one secret path", func(d *model.Desired) { dev(d).KV[0].Canary = "canary/*" }},
		{"no primary door", "primary door", func(d *model.Desired) { d.Identity.PrimaryDoor = "" }},
		{"metadata writing the door key", "may not set", func(d *model.Desired) { d.Identity.Metadata = map[string]string{"door": "x"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			desired := example(t)
			tc.edit(desired)

			err := desired.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// The bootstrap is validated like everything else, but it is never part
// of what is applied.
func TestAppliedIsRootThenTheEnvironments(t *testing.T) {
	for path, want := range map[string][]string{
		oneEnvironmentPath: {"root", "prod"},
		examplePath:        {"root", "dev", "prod"},
	} {
		desired := read(t, path)

		var names []string
		for _, namespace := range desired.Applied() {
			names = append(names, namespace.Label())
		}

		assert.Equal(t, want, names, path)
	}
}

func TestIdentityNamesAGroupPerDoor(t *testing.T) {
	identity := model.Identity{PrimaryDoor: "jwt-people", Metadata: map[string]string{"source": "directory"}}

	assert.Equal(t, "dev:reader", identity.GroupName("dev:reader", "jwt-people"))
	assert.Equal(t, "dev:reader@oidc", identity.GroupName("dev:reader", "oidc"))
	assert.Equal(t, map[string]string{"source": "directory"}, identity.GroupMetadata("jwt-people"))
	assert.Equal(t, map[string]string{"source": "directory", "door": "oidc"}, identity.GroupMetadata("oidc"))
	assert.Equal(t, map[string]string{"source": "directory"}, identity.Metadata, "GroupMetadata must not write into the shared map")
}

// The policy text is what OpenBAO stores and what a diff compares.
func TestPolicyHCL(t *testing.T) {
	policy := model.Policy{Name: "reader", Rules: []model.Rule{
		{Path: "kv/data/*", Capabilities: []string{"read"}},
		{Path: "kv/metadata/*", Capabilities: []string{"list", "read"}},
	}}

	assert.Equal(t, `path "kv/data/*" {
  capabilities = ["read"]
}

path "kv/metadata/*" {
  capabilities = ["list", "read"]
}
`, policy.HCL())
}

func TestKVLayout(t *testing.T) {
	layout := model.KVLayout{
		{Kind: "apps", Key: "apps/{app}", Properties: []string{"token"}, Writer: "mirror"},
		{Kind: "router-{site}", Key: "router-{site}/auth", Properties: []string{"auth-key"}},
		{Kind: "ci", Key: "ci/signing", Properties: []string{"key"}},
		{Kind: "ci", Key: "ci/registry", Properties: []string{"user", "password"}},
	}

	require.NoError(t, layout.Validate())
	assert.Equal(t, []string{"apps", "router-{site}", "ci"}, layout.Kinds())

	assert.Len(t, layout.SecretsFor("ci"), 2)
	assert.Len(t, layout.SecretsFor("router-east"), 1)
	assert.Empty(t, layout.SecretsFor("router-"))
	assert.Empty(t, layout.SecretsFor("apps-x"))

	row, ok := layout.SecretForKey("apps/web")
	assert.True(t, ok)
	assert.Equal(t, "apps/{app}", row.Key)

	_, ok = layout.SecretForKey("apps/web/extra")
	assert.False(t, ok, "a placeholder is one name, never a path")

	for _, broken := range []model.KVLayout{
		{{Kind: "apps", Key: "other/x", Properties: []string{"p"}}},
		{{Kind: "apps", Key: "apps/x"}},
		{{Kind: "apps", Key: "apps/x", Properties: []string{"p"}}, {Kind: "apps", Key: "apps/x", Properties: []string{"q"}}},
		{{Key: "x/y", Properties: []string{"p"}}},
	} {
		err := broken.Validate()
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "KV layout"), err.Error())
	}
}

// Algorithms is the one place a mount's default resolves: empty names
// DefaultSupportedAlgorithms, and a mount that names its own gets exactly
// those, never the default merged in.
func TestJWTMountAlgorithms(t *testing.T) {
	empty := model.JWTMount{}
	assert.Equal(t, model.DefaultSupportedAlgorithms, empty.Algorithms())

	explicit := model.JWTMount{SupportedAlgorithms: []string{"RS256"}}
	assert.Equal(t, []string{"RS256"}, explicit.Algorithms())
}

// validAWSAuthMount returns an otherwise-valid mount, so each case below
// tests PluginVersion alone.
func validAWSAuthMount() model.AWSAuthMount {
	return model.AWSAuthMount{
		Path:                   "aws",
		IAMServerIDHeaderValue: "example-aws-auth",
		Roles: []model.AWSAuthRole{{
			Name:                  "ec2-host",
			BoundIAMPrincipalARNs: []string{"arn:aws:iam::111122223333:role/example-ec2-host"},
			Policies:              []string{"example"},
			TTL:                   "5m",
			MaxTTL:                "15m",
		}},
	}
}

// PluginVersion is optional; when set, it must be OpenBAO's own "latest"
// sentinel or a v-prefixed semver -- the one shape its catalog stores a
// versioned plugin entry under.
func TestAWSAuthMountPluginVersion(t *testing.T) {
	for _, version := range []string{"", "latest", "v0.1.1", "v1.0.0-rc1", "v1.0.0+build.5"} {
		t.Run("accepts "+version, func(t *testing.T) {
			m := validAWSAuthMount()
			m.PluginVersion = version
			assert.NoError(t, m.Validate())
		})
	}

	for _, version := range []string{"0.1.1", "v1", "v1.2", "V0.1.1", "Latest", " latest"} {
		t.Run("refuses "+version, func(t *testing.T) {
			m := validAWSAuthMount()
			m.PluginVersion = version
			err := m.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "neither")
		})
	}
}

func TestServiceAccountSubject(t *testing.T) {
	assert.Equal(t, "system:serviceaccount:external-secrets:external-secrets",
		model.ServiceAccountSubject("external-secrets", "external-secrets"))
}

func TestProjectPath(t *testing.T) {
	assert.Equal(t, "billing/kv/data/*", model.ProjectPath("billing", "kv", "data/*"))
}

// The example's own project, applied and re-derived: a project namespace
// holds mounts alone, and Validate accepts a policy that reaches into it
// by ProjectPath's shape.
func TestExampleProject(t *testing.T) {
	desired := example(t)
	dev := &desired.Namespaces[0]

	require.Len(t, dev.Projects, 1)
	billing := &dev.Projects[0]
	assert.Equal(t, "billing", billing.Name)
	assert.NotEmpty(t, billing.KV)
	assert.NotEmpty(t, billing.PKI)

	for _, policy := range dev.Policies {
		if policy.Name != "dev:billing:reader" {
			continue
		}

		for _, rule := range policy.Rules {
			assert.True(t, strings.HasPrefix(rule.Path, "billing/kv/"), rule.Path)
		}
	}
}

// TestSignerDepthCountsTheWholeChain is ADR 0001's PKI half: an
// environment's own issuing CA needs MaxPathLength at least 1 to sign its
// project's issuing CA, not 0 -- 0 is accepted only once nothing is
// signed beneath it any more. The message names both issuers, so a
// review knows exactly which CA to widen and which one asked for it.
func TestSignerDepthCountsTheWholeChain(t *testing.T) {
	desired := example(t)
	dev := &desired.Namespaces[0]
	envIssuer := &dev.PKI[0].Issuers[0]
	require.Equal(t, "example-dev", envIssuer.Name)

	require.Equal(t, 1, envIssuer.MaxPathLength, "the golden already carries exactly enough for the one project beneath it")
	require.NoError(t, desired.Validate(), "1 is enough for the one project beneath it")

	envIssuer.MaxPathLength = 0
	err := desired.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too few for the")
	assert.Contains(t, err.Error(), "example-dev", "the signer")
	assert.Contains(t, err.Error(), "example-dev-billing", "the project CA it cannot cover any more")

	// Removing the project it signs is the other way to make 0 correct
	// again: nothing is beneath it any more.
	dev.Projects = nil
	require.NoError(t, desired.Validate())
}

// TestPKIRoleIdentityShape is ADR 0002's role half: a URI SAN alone, never
// mixed with the service shape's DNS fields, standing on its own (the
// example golden carries no identity role yet, so this builds the role
// literal directly rather than editing the shared fixture).
func TestPKIRoleIdentityShape(t *testing.T) {
	base := func() model.PKIRole {
		return model.PKIRole{
			Name:     "identity",
			Issuer:   "example-dev",
			Server:   true,
			Client:   true,
			KeyCurve: model.CurveP384,
			TTL:      "1h",
			MaxTTL:   "1h",
		}
	}

	t.Run("a literal URI SAN validates", func(t *testing.T) {
		role := base()
		role.AllowedURISANs = []string{"spiffe://dev.example.internal/ns/a/sa/b"}
		require.NoError(t, role.Validate())
		assert.True(t, role.IdentityShape())
	})

	t.Run("a templated URI SAN validates", func(t *testing.T) {
		role := base()
		role.AllowedURISANs = []string{
			"spiffe://dev.example.internal/ns/{{identity.entity.aliases.x.metadata.service_account_namespace}}" +
				"/sa/{{identity.entity.aliases.x.metadata.service_account_name}}",
		}
		role.AllowedURISANsTemplate = true
		require.NoError(t, role.Validate())
	})

	t.Run("no domain and no URI SAN signs nothing", func(t *testing.T) {
		role := base()
		require.ErrorContains(t, role.Validate(), "allows no domain and no URI SAN")
		assert.False(t, role.IdentityShape())
	})

	t.Run("an empty URI SAN", func(t *testing.T) {
		role := base()
		role.AllowedURISANs = []string{""}
		require.ErrorContains(t, role.Validate(), "empty URI SAN")
	})

	t.Run("mixing DNS names into an identity role", func(t *testing.T) {
		role := base()
		role.AllowedURISANs = []string{"spiffe://dev.example.internal/ns/a/sa/b"}
		role.AllowedDomains = []string{"dev.example.internal"}
		require.ErrorContains(t, role.Validate(), "mixes allowedDomains into an identity role")
	})

	t.Run("service-shape flags on an identity role", func(t *testing.T) {
		for name, mutate := range map[string]func(*model.PKIRole){
			"allow bare domains": func(r *model.PKIRole) { r.AllowBareDomains = true },
			"allow subdomains":   func(r *model.PKIRole) { r.AllowSubdomains = true },
			"allow wildcards":    func(r *model.PKIRole) { r.AllowWildcards = true },
		} {
			t.Run(name, func(t *testing.T) {
				role := base()
				role.AllowedURISANs = []string{"spiffe://dev.example.internal/ns/a/sa/b"}
				mutate(&role)
				require.ErrorContains(t, role.Validate(), "describe DNS SANs and do not apply")
			})
		}
	})

	t.Run("an untemplated wildcard trust domain signs any caller", func(t *testing.T) {
		role := base()
		role.AllowedURISANs = []string{"spiffe://*/ns/a/sa/b"}
		require.ErrorContains(t, role.Validate(), "without templating it to the caller")
	})

	t.Run("a templated wildcard trust domain is allowed", func(t *testing.T) {
		role := base()
		role.AllowedURISANs = []string{"spiffe://*/ns/a/sa/b"}
		role.AllowedURISANsTemplate = true
		require.NoError(t, role.Validate())
	})

	t.Run("an untemplated wildcard path, trust domain held fixed, is the documented CSI fallback and is allowed", func(t *testing.T) {
		role := base()
		role.AllowedURISANs = []string{"spiffe://dev.example.internal/*"}
		require.NoError(t, role.Validate())
	})

	t.Run("a URI with no host", func(t *testing.T) {
		role := base()
		role.AllowedURISANs = []string{"not-a-uri"}
		require.ErrorContains(t, role.Validate(), "not a URI with a host")
	})
}

// Identity stands alone: with no group anywhere the primary door has
// nothing to name, so it may be left out; with a group it is still required.
func TestIdentityWithoutGroupsNeedsNoPrimaryDoor(t *testing.T) {
	desired := read(t, examplePath)
	desired.Identity.PrimaryDoor = ""

	require.ErrorContains(t, desired.Validate(), "no primary door", "the example has groups")

	for i := range desired.Applied() {
		desired.Applied()[i].Groups = nil
	}

	require.NoError(t, desired.Validate())

	desired.Identity.Metadata = map[string]string{model.MetadataDoorKey: "x"}
	require.ErrorContains(t, desired.Validate(), "may not set")
}

// A mount takes exactly one source of verification keys.
func TestJWTMountKeySources(t *testing.T) {
	edit := func(f func(m *model.JWTMount)) error {
		desired := read(t, examplePath)
		m := &desired.Namespaces[0].Auth[0]
		f(m)

		return desired.Validate()
	}

	key := "-----BEGIN PUBLIC KEY-----\nexample\n-----END PUBLIC KEY-----\n"

	require.NoError(t, edit(func(m *model.JWTMount) { m.DiscoveryURL, m.JWKSURL = "", "https://issuer.example.org/jwks" }))
	require.NoError(t, edit(func(m *model.JWTMount) { m.DiscoveryURL, m.ValidationPubKeys = "", []string{key} }))
	require.ErrorContains(t, edit(func(m *model.JWTMount) { m.JWKSURL = "https://issuer.example.org/jwks" }), "more than one")
	require.ErrorContains(t, edit(func(m *model.JWTMount) { m.DiscoveryURL, m.ValidationPubKeys = "", []string{" "} }), "empty validation")
	require.ErrorContains(t, edit(func(m *model.JWTMount) { m.DiscoveryURL, m.JWKSURL = "", "" }), "no issuer")

	desired := read(t, examplePath)
	oidc := &desired.Namespaces[0].Auth[2]
	oidc.DiscoveryURL, oidc.JWKSURL = "", "https://issuer.example.org/jwks"
	require.ErrorContains(t, desired.Validate(), "needs discoveryUrl")

	m := model.JWTMount{DiscoveryURL: "https://issuer.example.org"}
	assert.Equal(t, "https://issuer.example.org", m.EffectiveBoundIssuer())
	m.BoundIssuer = "https://iss.example.org"
	assert.Equal(t, "https://iss.example.org", m.EffectiveBoundIssuer())
}
