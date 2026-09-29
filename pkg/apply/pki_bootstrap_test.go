package apply_test

import (
	"context"
	"testing"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/openbao/pkg/apply"
	"github.com/truvity/openbao/pkg/model"
)

// devPKIMount locates the "dev" namespace's "pki" mount in the shared
// example fixture -- the same one every other apply_test.go test reads,
// so a fixture change that breaks this test breaks the others too rather
// than silently drifting apart.
func devPKIMount(t *testing.T, desired *model.Desired) *model.PKIMount {
	t.Helper()

	for i := range desired.Namespaces {
		if desired.Namespaces[i].Name != "dev" {
			continue
		}

		for j := range desired.Namespaces[i].PKI {
			if desired.Namespaces[i].PKI[j].Path == "pki" {
				return &desired.Namespaces[i].PKI[j]
			}
		}
	}

	t.Fatal(`fixture no longer has a dev namespace "pki" mount`)

	return nil
}

// addSecondIssuer clones mount's first issuer under a new name -- the
// "old CA and new CA on the same mount" shape a migration is, per
// PKIMount's own doc comment.
func addSecondIssuer(mount *model.PKIMount, newName string) {
	clone := mount.Issuers[0]
	clone.Name = newName
	mount.Issuers = append(mount.Issuers, clone)
}

// roleNamed locates a role by name on mount, so the test can point it at
// either issuer without hardcoding its index.
func roleNamed(t *testing.T, mount *model.PKIMount, name string) *model.PKIRole {
	t.Helper()

	for i := range mount.Roles {
		if mount.Roles[i].Name == name {
			return &mount.Roles[i]
		}
	}

	t.Fatalf("mount %q has no role %q", mount.Path, name)

	return nil
}

// TestEnvironmentCARoleMoveIsInPlace is the proof the coordinator asked
// for: a role that moves from one issuer to another keeps the SAME
// Pulumi logical name -- and so the same OpenBAO role object,
// "<mount>/roles/<role>" -- when EnvironmentCARoleRename's mapping is in
// Options.Rename, and a DIFFERENT one (a delete-then-create of that same
// OpenBAO path under a real diff) when it is not. Deploy's mock resource
// monitor does not simulate a diff against prior state -- nothing in
// this repository's test harness does -- so the logical NAME is exactly
// what a real diff keys its create/update/replace decision on, and
// checking it is agreeing to disagree on nothing.
func TestEnvironmentCARoleMoveIsInPlace(t *testing.T) {
	const (
		oldIssuer = "example-dev"
		newIssuer = "example-dev-v2"
		roleName  = "service"
	)

	oldRoleResource := apply.PKIRoleResourceName(oldIssuer, roleName)
	newRoleResource := apply.PKIRoleResourceName(newIssuer, roleName)
	require.NotEqual(t, oldRoleResource, newRoleResource, "the two issuer names must actually differ for this test to mean anything")

	// Before: the role signs with the original issuer, as the fixture
	// already declares it.
	before := example(t)
	beforeMocks, _, err := deploy(t, before, options(), false)
	require.NoError(t, err)

	_, hasOld := beforeMocks.named(oldRoleResource)
	require.True(t, hasOld, "the role must be registered under its pre-move name")

	// After, without the fix: the role now signs with the new issuer
	// (the migration this simulates), and nothing tells Deploy the two
	// resources are the same OpenBAO object.
	afterNoRename := example(t)
	roleNamed(t, devPKIMount(t, afterNoRename), roleName).Issuer = newIssuer
	addSecondIssuer(devPKIMount(t, afterNoRename), newIssuer)

	afterNoRenameMocks, _, err := deploy(t, afterNoRename, options(), false)
	require.NoError(t, err)

	_, stillHasOldName := afterNoRenameMocks.named(oldRoleResource)
	_, hasNewName := afterNoRenameMocks.named(newRoleResource)
	assert.False(t, stillHasOldName, "without the fix, the pre-move name disappears from the desired state -- a real diff deletes it")
	assert.True(t, hasNewName)

	// After, with EnvironmentCARoleRename: the same move, but
	// Options.Rename now maps the role's newly-computed name back to
	// its old one.
	afterWithRename := example(t)
	roleNamed(t, devPKIMount(t, afterWithRename), roleName).Issuer = newIssuer
	addSecondIssuer(devPKIMount(t, afterWithRename), newIssuer)

	opts := options()
	opts.Rename = apply.ComposeRename(apply.EnvironmentCARoleRename(oldIssuer, newIssuer, roleName), nil)

	afterWithRenameMocks, _, err := deploy(t, afterWithRename, opts, false)
	require.NoError(t, err)

	_, keptOldName := afterWithRenameMocks.named(oldRoleResource)
	_, alsoHasNewName := afterWithRenameMocks.named(newRoleResource)
	assert.True(t, keptOldName, "with the fix, the role after the move is still registered under its pre-move name -- an update, not a replace")
	assert.False(t, alsoHasNewName, "the role must be registered under exactly one name")
}

func TestEnvironmentCARoleRename(t *testing.T) {
	assert.Nil(t, apply.EnvironmentCARoleRename("", "new", "identity"), "a cold start (no prior issuer) needs no rename")
	assert.Nil(t, apply.EnvironmentCARoleRename("same", "same", "identity"), "nothing moved")

	got := apply.EnvironmentCARoleRename("old", "new", "identity", "server")
	assert.Equal(t, map[string]string{
		"new-role-identity": "old-role-identity",
		"new-role-server":   "old-role-server",
	}, got)
}

// bootstrapMocks runs fn under a fresh mock resource monitor with a real
// apply.NewProvider, and returns what it registered.
func bootstrapMocks(t *testing.T, fn func(c *pulumi.Context, provider *vault.Provider) error) *mocks {
	t.Helper()

	m := &mocks{}

	err := pulumi.RunErr(func(c *pulumi.Context) error {
		provider, err := apply.NewProvider(c, "openbao", "https://openbao.example.com", apply.Login{
			Mount: "jwt-people", Role: "people",
			Token: func(context.Context) (string, error) { return "login-token", nil },
		})
		if err != nil {
			return err
		}

		return fn(c, provider)
	}, pulumi.WithMocks("example", "bootstrap", m))
	require.NoError(t, err)

	return m
}

func TestBootstrapEnvironmentCAColdStartCreatesMountAndCSR(t *testing.T) {
	var csr pulumi.StringOutput

	m := bootstrapMocks(t, func(c *pulumi.Context, provider *vault.Provider) error {
		var err error
		csr, err = apply.BootstrapEnvironmentCA(c, provider, apply.BootstrapEnvironmentCAOptions{
			Mount: "pki-identity", MountExists: false,
			DefaultLeaseTTL: "1h", MaxLeaseTTL: "1h", MountDescription: "workload identity",
			KeyName: "identity-dev", CommonName: "dev.example.internal Workload Identity CA",
			Organization: "Example Org", KeyCurve: model.CurveP384,
		})

		return err
	})

	require.NotZero(t, csr)

	mount, ok := m.named("pki-identity")
	require.True(t, ok, "a cold start must create the mount, named as Deploy names it")
	assert.True(t, mount.Protect)
	assert.Equal(t, "pki-identity", mount.Inputs["path"])

	request, ok := m.named("identity-dev-csr")
	require.True(t, ok, "the request is named as Deploy names it: <issuer>-csr")
	assert.True(t, request.Protect)
	assert.Equal(t, "identity-dev", request.Inputs["keyName"])
	assert.Contains(t, request.DependsOn, "pki-identity")
}

func TestBootstrapEnvironmentCAExistingMountCreatesOnlyTheRequest(t *testing.T) {
	m := bootstrapMocks(t, func(c *pulumi.Context, provider *vault.Provider) error {
		_, err := apply.BootstrapEnvironmentCA(c, provider, apply.BootstrapEnvironmentCAOptions{
			Mount: "pki-identity", MountExists: true,
			KeyName: "identity-dev", CommonName: "dev.example.internal Workload Identity CA",
			Organization: "Example Org", KeyCurve: model.CurveP384,
		})

		return err
	})

	_, hasMount := m.named("pki-identity")
	assert.False(t, hasMount, "an existing mount is never (re)created")

	_, hasRequest := m.named("identity-dev-csr")
	assert.True(t, hasRequest)
}

func TestBootstrapEnvironmentCARefusals(t *testing.T) {
	base := apply.BootstrapEnvironmentCAOptions{
		Mount: "pki-identity", MountExists: true, KeyName: "identity-dev",
		CommonName: "dev.example.internal Workload Identity CA", KeyCurve: model.CurveP384,
	}

	for name, mutate := range map[string]func(*apply.BootstrapEnvironmentCAOptions){
		"no mount":       func(o *apply.BootstrapEnvironmentCAOptions) { o.Mount = "" },
		"no key name":    func(o *apply.BootstrapEnvironmentCAOptions) { o.KeyName = "" },
		"no common name": func(o *apply.BootstrapEnvironmentCAOptions) { o.CommonName = "" },
		"unknown curve":  func(o *apply.BootstrapEnvironmentCAOptions) { o.KeyCurve = "P-999" },
	} {
		t.Run(name, func(t *testing.T) {
			options := base
			mutate(&options)

			err := pulumi.RunErr(func(c *pulumi.Context) error {
				provider, err := apply.NewProvider(c, "openbao", "https://openbao.example.com", apply.Login{
					Mount: "jwt-people", Role: "people",
					Token: func(context.Context) (string, error) { return "login-token", nil },
				})
				if err != nil {
					return err
				}

				_, err = apply.BootstrapEnvironmentCA(c, provider, options)

				return err
			}, pulumi.WithMocks("example", "bootstrap", &mocks{}))
			require.Error(t, err)
		})
	}
}

func TestComposeRename(t *testing.T) {
	overrides := map[string]string{"new-role-identity": "old-role-identity"}

	// No base: overrides apply, everything else is kept.
	rename := apply.ComposeRename(overrides, nil)
	assert.Equal(t, "old-role-identity", rename("new-role-identity"))
	assert.Equal(t, "unrelated", rename("unrelated"))

	// A base Rename still runs for anything the overrides do not name.
	rename = apply.ComposeRename(overrides, func(name string) string {
		if name == "legacy" {
			return "kept-legacy"
		}

		return name
	})
	assert.Equal(t, "old-role-identity", rename("new-role-identity"), "overrides win over the base")
	assert.Equal(t, "kept-legacy", rename("legacy"))
	assert.Equal(t, "unrelated", rename("unrelated"))
}

// bootstrapBilling is phase A for the fixture's "dev/billing" issuing CA:
// the same mount, key and namespace [Deploy] registers for it.
func bootstrapBilling(t *testing.T, mutate func(*apply.BootstrapEnvironmentCAOptions)) *mocks {
	t.Helper()

	options := apply.BootstrapEnvironmentCAOptions{
		Namespace: "dev/billing", Mount: "pki",
		DefaultLeaseTTL: "1h", MaxLeaseTTL: "1h",
		KeyName: "example-dev-billing", CommonName: "billing.dev.example.internal Issuing CA",
		Organization: "Example Org", KeyCurve: model.CurveP384,
	}
	mutate(&options)

	return bootstrapMocks(t, func(c *pulumi.Context, provider *vault.Provider) error {
		_, err := apply.BootstrapEnvironmentCA(c, provider, options)

		return err
	})
}

// TestBootstrapHandsOverToDeploy is the hand-over proof: the mount and the
// certificate request phase A registers carry the SAME logical names as
// the ones Deploy registers for the same objects, so a phase-B run over
// the phase-A state creates and deletes neither. (The mock monitor does
// not diff against prior state; the logical name is what a real diff
// keys on, exactly as TestEnvironmentCARoleMoveIsInPlace argues.)
func TestBootstrapHandsOverToDeploy(t *testing.T) {
	deployed, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	bootstrapped := bootstrapBilling(t, func(*apply.BootstrapEnvironmentCAOptions) {})

	for _, name := range []string{"dev-billing-pki", "example-dev-billing-csr"} {
		phaseA, ok := bootstrapped.named(name)
		require.True(t, ok, "phase A must register %q", name)

		phaseB, ok := deployed.named(name)
		require.True(t, ok, "Deploy must register %q", name)

		assert.Equal(t, phaseB.Type, phaseA.Type)
		assert.Empty(t, phaseA.Aliases, "no legacy name given, so no alias")

		for _, key := range []string{"path", "namespace", "backend", "keyName", "keyBits", "keyType", "commonName"} {
			if want, has := phaseB.Inputs[key]; has {
				assert.Equal(t, want, phaseA.Inputs[key], "%s: %s", name, key)
			}
		}
	}

	assert.Len(t, bootstrapped.sorted(), 3, "phase A registers the provider, the mount and the request, nothing else")
}

// TestBootstrapHandsOverToDeployWithRename covers Deploy's Options.Rename:
// the same function given to phase A yields the same names.
func TestBootstrapHandsOverToDeployWithRename(t *testing.T) {
	rename := apply.ComposeRename(map[string]string{"example-dev-billing-csr": "legacy-billing-csr"}, nil)

	opts := options()
	opts.Rename = rename

	deployed, _, err := deploy(t, example(t), opts, false)
	require.NoError(t, err)

	bootstrapped := bootstrapBilling(t, func(o *apply.BootstrapEnvironmentCAOptions) { o.Rename = rename })

	_, ok := bootstrapped.named("legacy-billing-csr")
	require.True(t, ok)

	_, ok = deployed.named("legacy-billing-csr")
	require.True(t, ok)

	_, ok = bootstrapped.named("example-dev-billing-csr")
	assert.False(t, ok)
}

// TestBootstrapLegacyResourceNameAliases is the old-name path: a stack
// that phase A created under the previous scheme (the mount as
// "<ResourceName>-mount", the request as "<ResourceName>") keeps its
// state, because those names are aliases of the new ones.
func TestBootstrapLegacyResourceNameAliases(t *testing.T) {
	m := bootstrapBilling(t, func(o *apply.BootstrapEnvironmentCAOptions) { o.ResourceName = "billing-ca" })

	mount, ok := m.named("dev-billing-pki")
	require.True(t, ok)
	assert.Equal(t, []string{"billing-ca-mount"}, mount.Aliases)

	request, ok := m.named("example-dev-billing-csr")
	require.True(t, ok)
	assert.Equal(t, []string{"billing-ca"}, request.Aliases)

	_, oldMount := m.named("billing-ca-mount")
	_, oldRequest := m.named("billing-ca")
	assert.False(t, oldMount || oldRequest, "the old names are aliases, never registered")

	// An existing mount is not the bootstrap's to register or alias.
	m = bootstrapBilling(t, func(o *apply.BootstrapEnvironmentCAOptions) {
		o.ResourceName = "billing-ca"
		o.MountExists = true
	})

	_, hasMount := m.named("dev-billing-pki")
	assert.False(t, hasMount)

	request, ok = m.named("example-dev-billing-csr")
	require.True(t, ok)
	assert.Equal(t, []string{"billing-ca"}, request.Aliases)
}
