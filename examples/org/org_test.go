package org_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/secrets/examples/org"
	"github.com/truvity/secrets/pkg/apply"
	"github.com/truvity/secrets/pkg/model"
	"github.com/truvity/secrets/pkg/pki"
)

const stubChain = "-----BEGIN CERTIFICATE-----\nexample external intermediate\n-----END CERTIFICATE-----\n"

// mocks records what a Deploy registers, as pkg/apply's own tests do: the
// preview and the registration need no server, no cloud account and no
// cluster.
type mocks struct {
	mu    sync.Mutex
	items []string
}

func (m *mocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	m.items = append(m.items, args.TypeToken+" "+args.Name)
	m.mu.Unlock()

	state := args.Inputs.Copy()

	for _, key := range []resource.PropertyKey{"csr", "issuerId", "accessor", "certificate", "certificateBundle", "publicKey"} {
		if _, ok := state[key]; !ok {
			state[key] = resource.NewStringProperty(args.Name + "#" + string(key))
		}
	}

	state["importedIssuers"] = resource.NewArrayProperty([]resource.PropertyValue{resource.NewStringProperty(args.Name + "#imported")})

	return args.Name + "_id", state, nil
}

func (*mocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) { return args.Args, nil }

func (m *mocks) sorted() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := append([]string(nil), m.items...)
	sort.Strings(out)

	return out
}

func options() apply.Options {
	return apply.Options{
		Address: "https://openbao.example.internal:8200",
		Login: apply.Login{
			Mount: "jwt-people", Role: "operators", CACertFile: "/etc/openbao/ca.pem",
			Token: func(context.Context) (string, error) { return "login-token", nil },
		},
		SignedChain: func(model.IssuerRef) (string, error) { return stubChain, nil },
	}
}

func deploy(t *testing.T, desired *model.Desired, preview bool) *mocks {
	t.Helper()

	m := &mocks{}

	err := pulumi.RunErr(func(c *pulumi.Context) error {
		_, err := apply.Deploy(c, desired, options())

		return err
	}, pulumi.WithMocks("example", "org", m), func(info *pulumi.RunInfo) { info.DryRun = preview })
	require.NoError(t, err)

	return m
}

func load(t *testing.T, level int) *org.Layer {
	t.Helper()

	layer, err := org.Load(level)
	require.NoError(t, err, "level %d", level)

	return layer
}

func levels() []int {
	out := make([]int, len(org.Names))
	for i := range out {
		out[i] = i
	}

	return out
}

// golden compares got with the file at path, or rewrites it under
// UPDATE_GOLDEN=1.
func golden(t *testing.T, path string, got []byte) {
	t.Helper()

	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.MkdirAll(path[:strings.LastIndex(path, "/")], 0o755))
		require.NoError(t, os.WriteFile(path, got, 0o644))

		return
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err, "%s (UPDATE_GOLDEN=1 writes it)", path)

	if !bytes.Equal(want, got) {
		t.Fatalf("%s is not what the example derives; review the diff and rerun with UPDATE_GOLDEN=1", path)
	}
}

// Every level loads, and everything it is made of validates: the server
// preset, the desired state (which the spec's own build already checked) and
// the private-PKI contract.
func TestEveryLevelValidates(t *testing.T) {
	for _, level := range levels() {
		layer := load(t, level)

		require.NoError(t, layer.Server.Validate(), "level %d server", level)

		if layer.Contract != nil {
			require.NoError(t, layer.Contract.Validate(), "level %d contract", level)
		}

		if layer.Desired != nil {
			require.NoError(t, layer.Desired.Validate(), "level %d desired state", level)
		}
	}
}

// What each level has and what it has not: the stand-alone proof. A level
// holds exactly the capabilities of the levels up to it, so a level can be
// adopted without any of the ones above.
func TestEachLevelHoldsOnlyItsOwnCapabilities(t *testing.T) {
	type shape struct {
		desired, ssh, awsAuth, plugins, pki, contract, uriDomain, projects bool
	}

	want := map[int]shape{
		0: {},
		1: {desired: true},
		2: {desired: true, ssh: true, awsAuth: true, plugins: true},
		3: {desired: true, ssh: true, awsAuth: true, plugins: true, pki: true, contract: true},
		4: {desired: true, ssh: true, awsAuth: true, plugins: true, pki: true, contract: true, uriDomain: true},
		5: {desired: true, ssh: true, awsAuth: true, plugins: true, pki: true, contract: true, uriDomain: true, projects: true},
	}

	for _, level := range levels() {
		layer := load(t, level)

		got := shape{
			desired:  layer.Desired != nil,
			plugins:  len(layer.Server.Plugins) > 0,
			contract: layer.Contract != nil,
		}

		if layer.Contract != nil {
			got.uriDomain = len(layer.Contract.TrustDomains.URI) > 0
		}

		if layer.Desired != nil {
			all := append([]model.Namespace{layer.Desired.Root}, layer.Desired.Namespaces...)
			for i := range all {
				got.ssh = got.ssh || len(all[i].SSH)+len(all[i].SSHHost) > 0
				got.awsAuth = got.awsAuth || len(all[i].AWSAuth) > 0
				got.pki = got.pki || len(all[i].PKI) > 0
				got.projects = got.projects || len(all[i].Projects) > 0
			}
		}

		assert.Equal(t, want[level], got, "level %d (%s)", level, layer.Name)
	}
}

// The apply, previewed and applied under Pulumi's mocks: no server, no login
// that reaches anywhere. The registered resources are the golden, and each
// level registers nothing of the levels above it.
func TestApplyPreview(t *testing.T) {
	forbidden := map[int][]string{
		1: {"vault:ssh/", "vault:aws/", "vault:pkiSecret/"},
		2: {"vault:pkiSecret/"},
		4: {"vault:index/namespace:Namespace ns-dev-billing"},
	}
	required := map[int][]string{
		1: {"vault:kv/", "vault:jwt/authBackend:"},
		2: {"vault:ssh/secretBackendCa:", "vault:aws/authBackendRole:"},
		3: {"vault:pkiSecret/secretBackendRole:SecretBackendRole example-internal-2026-01-dev-role-server"},
		4: {"vault:pkiSecret/secretBackendRole:SecretBackendRole workload-dev-role-identity"},
		5: {"vault:index/namespace:Namespace ns-dev-billing"},
	}

	for _, level := range levels() {
		layer := load(t, level)
		if layer.Desired == nil {
			continue
		}

		preview := deploy(t, layer.Desired, true).sorted()
		applied := deploy(t, layer.Desired, false).sorted()

		assert.Equal(t, applied, preview, "level %d: a preview registers what an apply does", level)
		require.NotEmpty(t, applied)

		for _, prefix := range forbidden[level] {
			for _, item := range applied {
				assert.False(t, strings.HasPrefix(item, prefix), "level %d registers %q, which belongs to a higher level", level, item)
			}
		}

		for level2, prefixes := range required {
			if level2 != level {
				continue
			}

			for _, prefix := range prefixes {
				var found bool

				for _, item := range applied {
					found = found || strings.HasPrefix(item, prefix)
				}

				assert.True(t, found, "level %d registers nothing like %q", level, prefix)
			}
		}

		got := []byte(strings.Join(applied, "\n") + "\n")
		golden(t, "../../examples/org/"+layer.Name+"/golden/resources.txt", got)
	}
}

// Each level's resource set is a superset of the one below it: nothing a
// lower level declares is dropped or renamed (a rename is a replacement in
// every state that runs the names).
func TestApplyIsLayered(t *testing.T) {
	var below []string

	for _, level := range levels() {
		layer := load(t, level)
		if layer.Desired == nil {
			continue
		}

		now := deploy(t, layer.Desired, true).sorted()
		for _, item := range below {
			assert.Contains(t, now, item, "level %d lost a resource of the level below", level)
		}

		below = now
	}
}

// Phase A of an environment's root-signed CA (level 4): the key and its
// request are made before anything is signed, under the very names the full
// apply gives them once the certificate is committed.
func TestEnvironmentCAPhaseA(t *testing.T) {
	layer := load(t, 4)

	var authority *pki.Authority

	derivation, err := layer.Contract.Derive(org.Environments())
	require.NoError(t, err)

	for i := range derivation.Issuing {
		if derivation.Issuing[i].Environment == "dev" && derivation.Issuing[i].Domain == "workload" {
			authority = &derivation.Issuing[i]
		}
	}

	require.NotNil(t, authority, "dev's workload CA is root-signed")
	require.True(t, authority.External)

	phaseA := &mocks{}

	err = pulumi.RunErr(func(c *pulumi.Context) error {
		provider, err := apply.NewProvider(c, "openbao", "https://openbao.example.internal:8200", options().Login)
		if err != nil {
			return err
		}

		_, err = apply.BootstrapEnvironmentCA(c, provider, apply.BootstrapEnvironmentCAOptions{
			Namespace: "dev", Mount: authority.Mount, MountExists: true,
			KeyName: authority.Issuer, CommonName: authority.CommonName,
			Organization: authority.Organization, KeyCurve: authority.KeyCurve,
		})

		return err
	}, pulumi.WithMocks("example", "org-phase-a", phaseA))
	require.NoError(t, err)

	full := deploy(t, layer.Desired, true).sorted()

	var requests int

	for _, item := range phaseA.sorted() {
		if strings.Contains(item, "IntermediateCertRequest") {
			requests++

			assert.Contains(t, full, item, "phase A's request has the name the full apply gives it")
		}
	}

	assert.Equal(t, 1, requests)
}

// The server preset's HCL at each level. It changes once, at level 2, when
// the aws auth plugin arrives; every other level renders what the level below
// it does.
func TestServerHCL(t *testing.T) {
	var last string

	for _, level := range levels() {
		layer := load(t, level)

		hcl, err := layer.Server.HCL()
		require.NoError(t, err)

		if level == 0 || level == 2 {
			golden(t, "../../examples/org/"+layer.Name+"/golden/server.hcl", []byte(hcl))
		}

		if level != 0 && level != 2 {
			assert.Equal(t, last, hcl, "level %d must not change the server", level)
		}

		last = hcl
	}

	assert.NotContains(t, load(t, 0).Server.Plugins, "aws")
}

// A file a level repeats is its predecessor's plus additions, never a
// rewrite: everything the level below says, the level still says.
func TestEveryFileContainsTheOneBelow(t *testing.T) {
	for _, name := range []string{"spec.yaml", "contract.yaml", "ops.values.yaml", "consumers.values.yaml"} {
		var (
			below any
			from  string
		)

		for _, level := range levels() {
			raw := org.Own(level, name)
			if raw == nil {
				continue
			}

			var now any
			require.NoError(t, yaml.Unmarshal(raw, &now), "%s/%s", org.Names[level], name)

			if below != nil {
				require.NoError(t, contains(now, below, ""), "%s/%s must contain %s/%s", org.Names[level], name, from, name)
			}

			below, from = now, org.Names[level]
		}
	}
}

// contains reports where super lacks something sub has: maps by key, lists
// by element (any element of super may hold it), scalars by value.
func contains(super, sub any, at string) error {
	switch s := sub.(type) {
	case map[string]any:
		m, ok := super.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: want a map", at)
		}

		for key, value := range s {
			have, ok := m[key]
			if !ok {
				return fmt.Errorf("%s.%s is missing", at, key)
			}

			if err := contains(have, value, at+"."+key); err != nil {
				return err
			}
		}

		return nil
	case []any:
		l, ok := super.([]any)
		if !ok {
			return fmt.Errorf("%s: want a list", at)
		}

		for i, value := range s {
			found := false

			for _, candidate := range l {
				if contains(candidate, value, at) == nil {
					found = true

					break
				}
			}

			if !found {
				return fmt.Errorf("%s[%d] is missing", at, i)
			}
		}

		return nil
	default:
		if fmt.Sprint(super) != fmt.Sprint(sub) {
			return fmt.Errorf("%s is %v, want %v", at, super, sub)
		}

		return nil
	}
}

// ---- the chart values and the model agree ---------------------------------

type chartValues struct {
	VaultNamespace string `yaml:"vaultNamespace"`
	Auth           struct {
		MountPath string `yaml:"mountPath"`
	} `yaml:"auth"`
	Stores []struct {
		Name string `yaml:"name"`
	} `yaml:"stores"`
	PKI struct {
		Issuers []struct {
			Name     string `yaml:"name"`
			SignPath string `yaml:"signPath"`
			Role     string `yaml:"role"`
		} `yaml:"issuers"`
	} `yaml:"pki"`
	Snapshot struct {
		BaoRole string `yaml:"baoRole"`
	} `yaml:"snapshot"`
}

func namespaceOf(t *testing.T, desired *model.Desired, name string) *model.Namespace {
	t.Helper()

	if name == "" {
		return &desired.Root
	}

	for i := range desired.Namespaces {
		if desired.Namespaces[i].Name == name {
			return &desired.Namespaces[i]
		}
	}

	t.Fatalf("no namespace %q", name)

	return nil
}

func jwtRole(ns *model.Namespace, mount, role string) *model.Role {
	for i := range ns.Auth {
		if ns.Auth[i].Path != mount {
			continue
		}

		for j := range ns.Auth[i].Roles {
			if ns.Auth[i].Roles[j].Name == role {
				return &ns.Auth[i].Roles[j]
			}
		}
	}

	return nil
}

// Every login the consumers chart's values name exists in the desired state:
// the store's role on the cluster's mount, and each cert-manager issuer's
// role on the same mount, bound to the audience cert-manager asks for and
// able to sign on the path the issuer signs through.
func TestConsumersValuesMatchTheModel(t *testing.T) {
	for _, level := range levels() {
		_, raw, ok := org.Source(level, "consumers.values.yaml")
		if !ok {
			continue
		}

		var values chartValues
		require.NoError(t, yaml.Unmarshal(raw, &values))

		layer := load(t, level)
		ns := namespaceOf(t, layer.Desired, values.VaultNamespace)

		for _, store := range values.Stores {
			role := jwtRole(ns, values.Auth.MountPath, store.Name)
			require.NotNil(t, role, "level %d: store %s has no role on %s", level, store.Name, values.Auth.MountPath)
			assert.Contains(t, role.BoundAudiences, "openbao")
		}

		for _, issuer := range values.PKI.Issuers {
			role := jwtRole(ns, values.Auth.MountPath, issuer.Role)
			require.NotNil(t, role, "level %d: issuer %s has no role %s on %s", level, issuer.Name, issuer.Role, values.Auth.MountPath)
			assert.Equal(t, []string{"vault://" + issuer.Name}, role.BoundAudiences, "cert-manager asks for vault://<issuer name>")

			mount, signRole, _ := strings.Cut(strings.Replace(issuer.SignPath, "/sign/", "\x00", 1), "\x00")
			assert.True(t, signsOn(ns, role, mount, signRole), "level %d: issuer %s cannot sign on %s", level, issuer.Name, issuer.SignPath)
		}
	}
}

func signsOn(ns *model.Namespace, role *model.Role, mount, signRole string) bool {
	for i := range ns.PKI {
		if ns.PKI[i].Path != mount {
			continue
		}

		for j := range ns.PKI[i].Roles {
			if ns.PKI[i].Roles[j].Name != signRole {
				continue
			}

			for _, policy := range role.Policies {
				for i := range ns.Policies {
					if ns.Policies[i].Name != policy {
						continue
					}

					for _, rule := range ns.Policies[i].Rules {
						if rule.Path == mount+"/sign/"+signRole {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// The jobs the ops chart runs log in as roles the desired state declares in
// root, and the PKI proof walks the issuers the derivation names.
func TestOpsValuesMatchTheModel(t *testing.T) {
	for _, level := range levels() {
		_, raw, ok := org.Source(level, "ops.values.yaml")
		if !ok || level == 0 {
			continue
		}

		var values struct {
			Auth struct {
				MountPath string `yaml:"mountPath"`
			} `yaml:"auth"`
			RestoreCheck struct {
				PKI struct {
					Intermediate struct{ Mount, Issuer string } `yaml:"intermediate"`
					Issuing      struct {
						Mount        string `yaml:"mount"`
						IssuerPrefix string `yaml:"issuerPrefix"`
					} `yaml:"issuing"`
					Namespaces []string `yaml:"namespaces"`
				} `yaml:"pki"`
			} `yaml:"restoreCheck"`
			PluginCatalog struct {
				Plugins []struct{ Name, Version string } `yaml:"plugins"`
			} `yaml:"pluginCatalog"`
		}
		require.NoError(t, yaml.Unmarshal(raw, &values))

		layer := load(t, level)

		for _, role := range []string{"openbao-snapshot", "openbao-restore-check"} {
			assert.NotNil(t, jwtRole(&layer.Desired.Root, values.Auth.MountPath, role), "level %d: no root role %s on %s", level, role, values.Auth.MountPath)
		}

		if values.RestoreCheck.PKI.Intermediate.Mount != "" {
			pkiProof := values.RestoreCheck.PKI
			assert.True(t, hasIssuer(&layer.Desired.Root, pkiProof.Intermediate.Mount, pkiProof.Intermediate.Issuer), "level %d: the intermediate", level)

			for _, name := range pkiProof.Namespaces {
				issuing := namespaceOf(t, layer.Desired, name)
				assert.True(t, hasIssuer(issuing, pkiProof.Issuing.Mount, pkiProof.Issuing.IssuerPrefix+"-"+name),
					"level %d: the issuing CA of %s", level, name)
			}
		}

		for _, plugin := range values.PluginCatalog.Plugins {
			var registered bool

			for _, p := range layer.Server.Plugins {
				registered = registered || (p.Name == plugin.Name && p.Version == plugin.Version)
			}

			assert.True(t, registered, "level %d: the catalog watch names %s %s, which the server preset does not register", level, plugin.Name, plugin.Version)
		}
	}
}

func hasIssuer(ns *model.Namespace, mount, issuer string) bool {
	for i := range ns.PKI {
		for j := range ns.PKI[i].Issuers {
			if ns.PKI[i].Path == mount && ns.PKI[i].Issuers[j].Name == issuer {
				return true
			}
		}
	}

	return false
}

// The aws auth mount asks for the plugin version the server preset registers.
func TestHostAuthPluginIsRegistered(t *testing.T) {
	layer := load(t, 2)

	for _, ns := range layer.Desired.Namespaces {
		for _, mount := range ns.AWSAuth {
			var registered bool

			for _, p := range layer.Server.Plugins {
				registered = registered || p.Version == mount.PluginVersion
			}

			assert.True(t, registered, "%s/%s pins plugin %s", ns.Name, mount.Path, mount.PluginVersion)
		}
	}
}
