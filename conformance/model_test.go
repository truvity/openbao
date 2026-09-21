package conformance_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/openbao/internal/fakeissuer"
	"github.com/truvity/openbao/internal/replay"
	"github.com/truvity/openbao/pkg/apply"
	"github.com/truvity/openbao/pkg/model"
)

const (
	// oneEnvironmentPath is the model's small example: one environment on
	// the cluster that also runs the server (docs/model.md).
	oneEnvironmentPath = "../pkg/model/testdata/desired-one-env.yaml"
	oneEnvironment     = "prod"
	clusterDoor        = "jwt-cluster"
	peopleDoor         = "jwt-people"
	operatorGroup      = "all:openbao:operator"
	peopleRole         = "people"
	serviceName        = "openbao.example.internal"
)

// TestOneEnvironmentModelApplies applies the one-environment example to a
// real server through the same capture-and-replay path the roster example
// takes. It is the example docs/model.md opens with, and an example
// nothing has applied is a description of one.
//
// The example's issuer is a name the estate supplies; here it is the fake
// one, because OpenBAO fetches an auth mount's discovery document when the
// mount is configured -- which is itself worth proving.
func TestOneEnvironmentModelApplies(t *testing.T) {
	binary := tool(t, "bao")

	issuer, err := fakeissuer.New(nil)
	require.NoError(t, err)
	t.Cleanup(issuer.Close)

	address := devServer(t, binary)
	desired := oneEnvironmentExample(t, issuer.URL)

	opts := apply.Options{
		// Where the PKI mounts publish their URLs; nothing here fetches them.
		Address: "https://openbao.example.com",
		Login:   apply.Login{Mount: peopleDoor, Role: peopleRole, Token: replay.Tokens},
	}

	// The bootstrap is never the apply's: the server's initialisation
	// creates it. Here that is the same translation, as root.
	bootstrap, err := replay.Capture(&model.Desired{Root: desired.Bootstrap, Identity: desired.Identity}, opts)
	require.NoError(t, err)
	require.NoError(t, (&replay.Server{Address: address, Token: rootToken}).Replay(t.Context(), bootstrap))

	token := issuer.Token(fakeissuer.Claims{Subject: operator, Audience: "openbao", Email: operator, Groups: []string{operatorGroup}})

	answer, err := (&replay.Server{Address: address}).Call(t.Context(), http.MethodPost, "", "auth/"+peopleDoor+"/login",
		map[string]any{"role": peopleRole, "jwt": token})
	require.NoError(t, err)

	auth, _ := answer["auth"].(map[string]any)
	require.NotEmpty(t, auth["client_token"], "the operators' door admits the person who applies")

	server := &replay.Server{Address: address, Token: fmt.Sprint(auth["client_token"])}

	resources, err := replay.Capture(desired, opts)
	require.NoError(t, err)
	require.NoError(t, server.Replay(t.Context(), resources), "the whole example applies")

	t.Run("one environment, below root", func(t *testing.T) {
		answer, err := server.Call(t.Context(), http.MethodGet, "", "sys/namespaces?list=true", nil)
		require.NoError(t, err)

		data, _ := answer["data"].(map[string]any)
		assert.Equal(t, []string{oneEnvironment + "/"}, strings2(data["keys"]))
	})

	t.Run("one cluster, one door name in both namespaces", func(t *testing.T) {
		// The consumers' logins land in the environment and the backup
		// jobs' in root, so there is a mount in each -- but one cluster
		// has one ServiceAccount issuer, so both trust the same one and
		// carry the same name (docs/adoption.md, Single cluster).
		for _, namespace := range []string{"", oneEnvironment} {
			answer, err := server.Call(t.Context(), http.MethodGet, namespace, "sys/auth/"+clusterDoor, nil)
			require.NoError(t, err, "no %s mount in namespace %q", clusterDoor, namespace)

			data, _ := answer["data"].(map[string]any)
			assert.Equal(t, "jwt", data["type"])
		}
	})

	t.Run("the restore canary names its own namespace", func(t *testing.T) {
		// What openbao-ops' restore check reads back from a restored
		// snapshot, in every namespace it finds.
		answer, err := server.Call(t.Context(), http.MethodGet, oneEnvironment, "kv/data/restore-canary", nil)
		require.NoError(t, err)

		data, _ := answer["data"].(map[string]any)
		assert.Equal(t, map[string]any{"namespace": oneEnvironment}, data["data"])
	})

	t.Run("the environment's CA signs a service name, and it chains to the root", func(t *testing.T) {
		answer, err := server.Call(t.Context(), http.MethodPost, oneEnvironment, "pki/sign/service",
			map[string]any{"csr": csr(t, elliptic.P384(), serviceName), "common_name": serviceName})
		require.NoError(t, err)

		data, _ := answer["data"].(map[string]any)
		leaf := parseCertificate(t, data["certificate"])
		assert.Equal(t, []string{serviceName}, leaf.DNSNames)
		assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, leaf.ExtKeyUsage)

		intermediates := x509.NewCertPool()
		for _, certificate := range strings2(data["ca_chain"]) {
			intermediates.AddCert(parseCertificate(t, certificate))
		}

		roots := x509.NewCertPool()
		roots.AddCert(rootCertificate(t, server))

		_, err = leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			DNSName:       serviceName,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		require.NoError(t, err, "root -> intermediate -> the environment's issuing CA -> the leaf")
	})
}

// oneEnvironmentExample reads the example strictly and points every door
// at the issuer given: a discovery URL is the estate's, and the harness's
// is the fake one.
func oneEnvironmentExample(t *testing.T, issuerURL string) *model.Desired {
	t.Helper()

	raw, err := os.ReadFile(oneEnvironmentPath)
	require.NoError(t, err)

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)

	var desired model.Desired
	require.NoError(t, decoder.Decode(&desired))
	require.NoError(t, desired.Validate())

	for _, namespace := range append([]*model.Namespace{&desired.Bootstrap, &desired.Root}, namespacePointers(&desired)...) {
		for i := range namespace.Auth {
			namespace.Auth[i].DiscoveryURL = issuerURL
		}
	}

	return &desired
}

func namespacePointers(desired *model.Desired) []*model.Namespace {
	out := make([]*model.Namespace, 0, len(desired.Namespaces))
	for i := range desired.Namespaces {
		out = append(out, &desired.Namespaces[i])
	}

	return out
}

// rootCertificate is the example root's own certificate, the anchor the
// environment's leaves are judged against.
func rootCertificate(t *testing.T, server *replay.Server) *x509.Certificate {
	t.Helper()

	answer, err := server.Call(t.Context(), http.MethodGet, "", "pki-root/issuer/example-root", nil)
	require.NoError(t, err)

	data, _ := answer["data"].(map[string]any)

	return parseCertificate(t, data["certificate"])
}
