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
			p := &dev(d).Policies[3]
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

func TestServiceAccountSubject(t *testing.T) {
	assert.Equal(t, "system:serviceaccount:external-secrets:external-secrets",
		model.ServiceAccountSubject("external-secrets", "external-secrets"))
}
