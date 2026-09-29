package apply_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	"github.com/truvity/openbao/pkg/apply"
	"github.com/truvity/openbao/pkg/model"
)

const (
	// examplePath is the model's neutral golden, applied here.
	examplePath   = "../model/testdata/desired.yaml"
	resourcesPath = "testdata/resources.yaml"
	edgeChainPEM  = "-----BEGIN CERTIFICATE-----\nexample edge intermediate\n-----END CERTIFICATE-----\n"
)

type (
	// registered is one resource as the mocks saw it.
	registered struct {
		Type      string         `yaml:"type"`
		Name      string         `yaml:"name"`
		Protect   bool           `yaml:"protect,omitempty"`
		DependsOn []string       `yaml:"dependsOn,omitempty"`
		Aliases   []string       `yaml:"aliases,omitempty"`
		Inputs    map[string]any `yaml:"inputs"`
	}

	mocks struct {
		mu        sync.Mutex
		resources []registered
	}
)

// NewResource records the registration and answers with distinct outputs,
// so an input taken from another resource's output names that resource.
func (m *mocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	state := args.Inputs.Copy()

	record := registered{Type: args.TypeToken, Name: args.Name, Inputs: args.Inputs.Mappable()}
	if rpc := args.RegisterRPC; rpc != nil {
		record.Protect = rpc.GetProtect()

		for _, urn := range rpc.GetDependencies() {
			record.DependsOn = append(record.DependsOn, urn[strings.LastIndex(urn, "::")+2:])
		}

		sort.Strings(record.DependsOn)

		for _, urn := range rpc.GetAliasURNs() {
			record.Aliases = append(record.Aliases, urn[strings.LastIndex(urn, "::")+2:])
		}

		for _, alias := range rpc.GetAliases() {
			if urn := alias.GetUrn(); urn != "" {
				record.Aliases = append(record.Aliases, urn[strings.LastIndex(urn, "::")+2:])
			} else if spec := alias.GetSpec(); spec != nil {
				record.Aliases = append(record.Aliases, spec.GetName())
			}
		}

		sort.Strings(record.Aliases)
	}

	m.mu.Lock()
	m.resources = append(m.resources, record)
	m.mu.Unlock()

	for _, key := range []resource.PropertyKey{"csr", "issuerId", "accessor", "certificate", "certificateBundle", "publicKey"} {
		if _, ok := state[key]; !ok {
			state[key] = resource.NewStringProperty(args.Name + "#" + string(key))
		}
	}

	state["importedIssuers"] = resource.NewArrayProperty([]resource.PropertyValue{resource.NewStringProperty(args.Name + "#imported")})

	return args.Name + "_id", state, nil
}

func (*mocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

func (m *mocks) sorted() []registered {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := append([]registered(nil), m.resources...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}

		return out[i].Name < out[j].Name
	})

	return out
}

func (m *mocks) named(name string) (registered, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range m.resources {
		if r.Name == name {
			return r, true
		}
	}

	return registered{}, false
}

func example(t *testing.T) *model.Desired {
	t.Helper()

	raw, err := os.ReadFile(examplePath)
	require.NoError(t, err)

	var desired model.Desired
	require.NoError(t, yaml.Unmarshal(raw, &desired))

	return &desired
}

func options() apply.Options {
	return apply.Options{
		Address: "https://openbao.example.com",
		Login: apply.Login{
			Mount:      "jwt-people",
			Role:       "people",
			CACertFile: "/etc/openbao/ca.pem",
			Token:      func(context.Context) (string, error) { return "login-token", nil },
		},
		OIDCClientSecrets: map[string]pulumi.StringInput{"openbao-ui": pulumi.ToSecret(pulumi.String("ui-secret")).(pulumi.StringOutput)},
		SignedChain: func(ref model.IssuerRef) (string, error) {
			if ref != (model.IssuerRef{Mount: "pki-edge", Issuer: "example-edge"}) {
				return "", errors.New("no chain for " + ref.String())
			}

			return edgeChainPEM, nil
		},
	}
}

// deploy runs Deploy under mocks; preview makes it a dry run.
func deploy(t *testing.T, desired *model.Desired, opts apply.Options, preview bool) (*mocks, *apply.Result, error) {
	t.Helper()

	m := &mocks{}

	var result *apply.Result

	err := pulumi.RunErr(func(c *pulumi.Context) error {
		var err error

		result, err = apply.Deploy(c, desired, opts)

		return err
	}, pulumi.WithMocks("example", "openbao-config", m), func(info *pulumi.RunInfo) { info.DryRun = preview })

	return m, result, err
}

// Every resource the example registers -- its type, its logical name, its
// protection, what it waits for and every input -- as a file a pull
// request shows. The names are the adoption contract: a change here is a
// replacement in every state that runs them. UPDATE_GOLDEN=1 rewrites it.
func TestRegisteredResourcesGolden(t *testing.T) {
	m, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	var got bytes.Buffer

	encoder := yaml.NewEncoder(&got)
	encoder.SetIndent(2)
	require.NoError(t, encoder.Encode(m.sorted()))

	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.WriteFile(resourcesPath, got.Bytes(), 0o644))

		return
	}

	want, err := os.ReadFile(resourcesPath)
	require.NoError(t, err)

	if !bytes.Equal(want, got.Bytes()) {
		t.Fatalf("registered resources differ from %s; review and rerun with UPDATE_GOLDEN=1", resourcesPath)
	}
}

// The bootstrap is never applied: the apply logs in through it.
func TestTheBootstrapIsNeverApplied(t *testing.T) {
	m, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	for _, name := range []string{"root-auth-jwt-people", "root-policy-all-openbao-operator", "root-group-all-openbao-operator"} {
		_, found := m.named(name)
		assert.False(t, found, name)
	}

	_, found := m.named("root-group-all-openbao-operator-oidc")
	assert.True(t, found, "the web UI's door into root is the apply's own")
}

func TestResultCarriesTheOutputs(t *testing.T) {
	_, result, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	assert.Equal(t, []string{"dev", "dev/billing", "prod"}, result.Namespaces, "a project's namespace, right after its environment's own")
	assert.Contains(t, result.Certificates, "example-root")
	assert.Len(t, result.Certificates, 1, "only a self-signed issuer is a trust anchor the apply makes")
	assert.Contains(t, result.CertificateRequests, "example-edge")
	assert.Len(t, result.CertificateRequests, 1, "only an external issuer's request leaves")
	assert.Contains(t, result.SSHCAPublicKeys, apply.MountRef{Namespace: "dev", Path: "ssh"})
	assert.Contains(t, result.SSHHostCAPublicKeys, apply.MountRef{Namespace: "dev", Path: "ssh-host"})
	assert.NotNil(t, result.Provider)
}

// A signature waits for its signer, its signer's pinned default and the
// signer mount's URL and CRL configuration: the certificate carries the
// URLs its issuing mount had when it was signed, for its whole life.
func TestASignatureWaitsForTheSignersMaintenance(t *testing.T) {
	m, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	signed, ok := m.named("example-dev-signed")
	require.True(t, ok)
	assert.Subset(t, signed.DependsOn, []string{"example-int-issuer", "pki-int-default", "pki-int-urls", "pki-int-crl", "pki-int-auto-tidy", "example-dev-csr"})
	assert.True(t, signed.Protect)
	assert.Equal(t, "example-int", signed.Inputs["issuerRef"])
	assert.Equal(t, "pki-int", signed.Inputs["backend"])

	// The external issuer's chain is imported as given; nothing signs it.
	imported, ok := m.named("example-edge-import")
	require.True(t, ok)
	assert.Equal(t, edgeChainPEM, imported.Inputs["certificate"])

	_, signedHere := m.named("example-edge-signed")
	assert.False(t, signedHere, "an external issuer is never signed by the apply")
}

// A mount with PluginVersion set is created through the generic
// sys/auth/<path> endpoint instead of vault.AuthBackend -- the only shape
// that carries a pinned catalog version, since pulumi-vault v7's
// AuthBackend has no such input -- and the client configuration and every
// role still wait for it and still address it by the same mount path.
func TestAWSAuthMountWithPluginVersionUsesTheGenericEndpoint(t *testing.T) {
	desired := example(t)
	desired.Namespaces[0].AWSAuth[0].PluginVersion = "v0.1.1"

	m, _, err := deploy(t, desired, options(), false)
	require.NoError(t, err)

	mount, ok := m.named("dev-auth-aws")
	require.True(t, ok)
	assert.Equal(t, "vault:generic/endpoint:Endpoint", mount.Type)
	assert.Contains(t, mount.DependsOn, "plugin-auth-aws")
	assert.Equal(t, "sys/auth/aws", mount.Inputs["path"])
	assert.Equal(t, "dev", mount.Inputs["namespace"])
	assert.Equal(t, true, mount.Inputs["disableRead"])
	assert.Equal(t, false, mount.Inputs["disableDelete"])
	assert.Equal(t, true, mount.Inputs["ignoreAbsentFields"])

	// dataJson is an additional secret output (generic.NewEndpoint wraps
	// it in pulumi.ToSecret itself), so the mock records it as a
	// *resource.Secret, its plaintext one level down.
	secret, ok := mount.Inputs["dataJson"].(*resource.Secret)
	require.True(t, ok, "dataJson must be a secret output")

	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(secret.Element.StringValue()), &body))
	assert.Equal(t, "aws", body["type"])
	assert.Equal(t, "v0.1.1", body["plugin_version"])
	assert.Equal(t, "EC2 hosts that sign in with their own instance role, for a host certificate", body["description"])

	for _, name := range []string{"dev-auth-aws-client", "dev-role-aws-ec2-host"} {
		r, ok := m.named(name)
		require.True(t, ok, name)
		assert.Contains(t, r.DependsOn, "dev-auth-aws", "%s must depend on the Endpoint mount", name)
		assert.Equal(t, "aws", r.Inputs["backend"], "%s must still address the mount by its plain path", name)
	}
}

// The AWS auth mount waits for its plugin's catalog registration: Deploy
// calls plugins() before a single namespace is registered, but that only
// orders this Go program, not the Pulumi deployment it builds. With no
// dependency edge between two independent resources, Pulumi is free to
// create them in either order -- so a fresh apply with no explicit
// DependsOn here could create the mount first and reproduce the exact
// "plugin not found in the catalog: aws" error Desired.Plugins exists to
// prevent.
func TestAWSAuthMountDependsOnItsPlugin(t *testing.T) {
	m, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	mount, ok := m.named("dev-auth-aws")
	require.True(t, ok)
	assert.Contains(t, mount.DependsOn, "plugin-auth-aws")
}

// A mount of a built-in type -- nothing in the example desired state
// declares a plugin named "jwt" -- gets no such dependency: pluginDependency
// is generic over every plugin category and type, and must stay a no-op
// whenever nothing in Desired.Plugins matches.
func TestABuiltinMountGetsNoPluginDependency(t *testing.T) {
	m, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	mount, ok := m.named("dev-auth-jwt-dev")
	require.True(t, ok)

	for _, dep := range mount.DependsOn {
		assert.NotContains(t, dep, "plugin-", "a built-in auth mount should depend on no plugin catalog entry, got %q", dep)
	}
}

// An unconstrained issuer's signature carries no name-constraints
// extension at all, not an empty one.
func TestNoConstraintIsSentEmpty(t *testing.T) {
	m, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	signed, ok := m.named("example-edge-dev-signed")
	require.True(t, ok)

	for _, key := range []string{"permittedDnsDomains", "excludedIpRanges", "permittedEmailAddresses", "permittedUriDomains"} {
		assert.NotContains(t, signed.Inputs, key)
	}
}

// A root resource carries no namespace, an environment's always does, a
// project's carries its full slash-joined path (never its dashed logical
// name), and a leaf role is the one PKI object that is not protected.
func TestNamespacesAndProtection(t *testing.T) {
	m, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	for _, r := range m.sorted() {
		switch {
		// The project's own namespace resource is created IN dev, and its
		// issuer's signature is made by dev's own issuer, in dev -- both
		// carry dev, never dev/billing, the namespace everything else
		// registered inside the project does.
		case r.Name == "ns-dev-billing", r.Name == "example-dev-billing-signed":
			assert.Equal(t, "dev", r.Inputs["namespace"], r.Name)
		case strings.HasPrefix(r.Name, "dev-billing-"), strings.HasPrefix(r.Name, "example-dev-billing"):
			assert.Equal(t, "dev/billing", r.Inputs["namespace"], r.Name)
		case strings.HasPrefix(r.Name, "root-"), strings.HasPrefix(r.Name, "pki-"):
			assert.NotContains(t, r.Inputs, "namespace", r.Name)
		case strings.HasPrefix(r.Name, "dev-"):
			assert.Equal(t, "dev", r.Inputs["namespace"], r.Name)
		}

		if strings.HasPrefix(r.Type, "vault:pkiSecret/") || strings.HasPrefix(r.Type, "vault:ssh/") {
			leafRole := r.Type == "vault:pkiSecret/secretBackendRole:SecretBackendRole" && !strings.Contains(r.Name, "-credential-role-")
			assert.Equal(t, !leafRole, r.Protect, r.Name)
		}
	}
}

func TestRenameKeepsTheCallersNames(t *testing.T) {
	opts := options()
	opts.Rename = func(name string) string {
		if name == "example-int-csr" {
			return "legacy-int-csr"
		}

		return name
	}

	m, _, err := deploy(t, example(t), opts, false)
	require.NoError(t, err)

	_, renamed := m.named("legacy-int-csr")
	_, kept := m.named("example-int-csr")
	assert.True(t, renamed)
	assert.False(t, kept)
}

// BeforeApply runs before the login on an apply, never on a preview, and
// its error stops the apply before anything is registered.
func TestBeforeApply(t *testing.T) {
	var order []string

	opts := options()
	opts.BeforeApply = func(context.Context) error { order = append(order, "before"); return nil }
	opts.Login.Token = func(context.Context) (string, error) { order = append(order, "token"); return "login-token", nil }

	_, _, err := deploy(t, example(t), opts, false)
	require.NoError(t, err)
	assert.Equal(t, []string{"before", "token"}, order)

	order = nil
	_, _, err = deploy(t, example(t), opts, true)
	require.NoError(t, err)
	assert.Equal(t, []string{"token"}, order, "a preview takes no snapshot")

	opts.BeforeApply = func(context.Context) error { return errors.New("snapshot failed") }
	m, _, err := deploy(t, example(t), opts, false)
	require.ErrorContains(t, err, "snapshot failed")
	assert.Empty(t, m.sorted())
}

func TestDeployRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
		edit func(*model.Desired, *apply.Options)
	}{
		{"an invalid model", "primary door", func(d *model.Desired, _ *apply.Options) { d.Identity.PrimaryDoor = "" }},
		{"an http address", "https", func(_ *model.Desired, o *apply.Options) { o.Address = "http://openbao.example.com" }},
		{"no token", "token", func(_ *model.Desired, o *apply.Options) { o.Login.Token = nil }},
		{"an oidc mount without its secret", "OIDCClientSecrets", func(_ *model.Desired, o *apply.Options) { o.OIDCClientSecrets = nil }},
		{"an external issuer without a chain", "SignedChain", func(_ *model.Desired, o *apply.Options) { o.SignedChain = nil }},
		{"an issuer name used twice", "unique across the server", func(d *model.Desired, _ *apply.Options) {
			d.Namespaces[0].PKI[1].Issuers[0].Name = "example-dev"
			d.Namespaces[0].PKI[1].DefaultIssuer = "example-dev"
			d.Namespaces[0].PKI[1].Roles[0].Issuer = "example-dev"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			desired, opts := example(t), options()
			tc.edit(desired, &opts)

			m, _, err := deploy(t, desired, opts, false)
			require.ErrorContains(t, err, tc.want)
			assert.Empty(t, m.sorted(), "nothing is registered before the refusal")
		})
	}
}

// TestIdentityRoleShape is ADR 0002's apply half: an identity role (a URI
// SAN alone) renders the role's own list and template flag rather than
// the always-empty/false the service shape sends, and it turns off
// use_csr_sans, enforce_hostnames and CN validation -- none of which an
// identity role has any business honouring (docs/model.md).
func TestIdentityRoleShape(t *testing.T) {
	desired := example(t)
	dev := &desired.Namespaces[0]
	pki := &dev.PKI[0]

	pki.Roles = append(pki.Roles, model.PKIRole{
		Name:     "identity",
		Issuer:   pki.Roles[0].Issuer,
		Server:   true,
		Client:   true,
		KeyCurve: model.CurveP384,
		TTL:      "1h",
		MaxTTL:   "1h",
		AllowedURISANs: []string{
			"spiffe://dev.example.internal/ns/{{identity.entity.aliases.x.metadata.service_account_namespace}}" +
				"/sa/{{identity.entity.aliases.x.metadata.service_account_name}}",
		},
		AllowedURISANsTemplate: true,
	})
	require.NoError(t, desired.Validate())

	m, _, err := deploy(t, desired, options(), false)
	require.NoError(t, err)

	role, ok := m.named(pki.Roles[0].Issuer + "-role-identity")
	require.True(t, ok)

	assert.Equal(t, []any{
		"spiffe://dev.example.internal/ns/{{identity.entity.aliases.x.metadata.service_account_namespace}}" +
			"/sa/{{identity.entity.aliases.x.metadata.service_account_name}}",
	}, role.Inputs["allowedUriSans"])
	assert.Equal(t, true, role.Inputs["allowedUriSansTemplate"])
	assert.Equal(t, false, role.Inputs["useCsrSans"], "the identity SAN never comes from whatever the CSR itself carries")
	assert.Equal(t, false, role.Inputs["enforceHostnames"], "an identity role has no DNS name to enforce hostname shape on")
	assert.Equal(t, []any{"email", "hostname"}, role.Inputs["cnValidations"],
		"OpenBAO's own default, written explicitly: an empty list here reads back as this same default on every refresh, "+
			"a perpetual diff neither value actually avoids -- requireCn false already makes the field inert either way")
	assert.Equal(t, false, role.Inputs["requireCn"])
	assert.Equal(t, []any{}, role.Inputs["allowedDomains"], "the identity shape carries no DNS domain")
	assert.Equal(t, false, role.Inputs["allowBareDomains"])
	assert.Equal(t, false, role.Inputs["allowSubdomains"])
	assert.Equal(t, false, role.Inputs["allowWildcardCertificates"])
}

func TestLeafKeyBits(t *testing.T) {
	for curve, want := range map[string]int{
		model.CurveP256: 256, // unchanged
		model.CurveP384: 256, // relaxed: OpenBAO reads key_bits as a minimum
		model.CurveP521: 521, // unchanged, never loosened
	} {
		assert.Equal(t, want, apply.LeafKeyBits(curve), curve)
	}

	// The role minimum admits a CSR of at least that many bits, so both
	// P-256 and P-384 leaves pass a P-384 leaf role.
	minimum := apply.LeafKeyBits(model.CurveP384)
	assert.LessOrEqual(t, minimum, model.CurveBits[model.CurveP256])
	assert.LessOrEqual(t, minimum, model.CurveBits[model.CurveP384])
}

// TestLeafRolesAcceptP256AndP384KeepCAKeys: every leaf role Deploy renders
// carries a key_bits minimum both curves satisfy, while every CA key --
// the request for a signed issuer -- is still generated at its own
// contract curve's size.
func TestLeafRolesAcceptP256AndP384KeepCAKeys(t *testing.T) {
	m, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	var roles, requests int

	for _, r := range m.sorted() {
		switch r.Type {
		case "vault:pkiSecret/secretBackendRole:SecretBackendRole":
			roles++

			assert.EqualValues(t, "ec", r.Inputs["keyType"], r.Name)

			if strings.Contains(r.Name, "-credential-role-") {
				assert.EqualValues(t, 384, r.Inputs["keyBits"], "%s: a credential role keeps its exact curve", r.Name)

				continue
			}

			assert.LessOrEqual(t, r.Inputs["keyBits"], float64(256), "%s must accept a P-256 CSR", r.Name)
		case "vault:pkiSecret/secretBackendIntermediateCertRequest:SecretBackendIntermediateCertRequest":
			requests++

			assert.EqualValues(t, 384, r.Inputs["keyBits"], "%s: a CA key keeps the contract curve", r.Name)
		}
	}

	assert.NotZero(t, roles)
	assert.NotZero(t, requests)
}
