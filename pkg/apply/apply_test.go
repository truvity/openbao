package apply_test

import (
	"bytes"
	"context"
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

	assert.Equal(t, []string{"dev", "prod"}, result.Namespaces)
	assert.Contains(t, result.Certificates, "example-root")
	assert.Len(t, result.Certificates, 1, "only a self-signed issuer is a trust anchor the apply makes")
	assert.Contains(t, result.CertificateRequests, "example-edge")
	assert.Len(t, result.CertificateRequests, 1, "only an external issuer's request leaves")
	assert.Contains(t, result.SSHCAPublicKeys, apply.MountRef{Namespace: "dev", Path: "ssh"})
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

// A root resource carries no namespace, an environment's always does, and
// a leaf role is the one PKI object that is not protected.
func TestNamespacesAndProtection(t *testing.T) {
	m, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	for _, r := range m.sorted() {
		switch {
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
