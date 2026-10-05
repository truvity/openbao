// Package conformance_test proves ADR 0001
// (docs/decisions/0001-namespaces-are-environment-project.md) against a
// real OpenBAO server: an environment `dev`, two of its projects (`alpha`,
// `beta`), and a second environment `prod` -- none of it applied by hand,
// all of it what pkg/apply registers for the model below.
package conformance_test

import (
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/internal/fakeissuer"
	"github.com/truvity/secrets/internal/replay"
	"github.com/truvity/secrets/pkg/apply"
	"github.com/truvity/secrets/pkg/model"
)

// The names the project example uses.
const (
	projectRootIssuer = "root-ca"
	projectRootMount  = "pki-root"

	projectEnvironment  = "dev"
	projectOtherEnv     = "prod"
	projectDevDoor      = "jwt-dev"
	projectProdDoor     = "jwt-prod"
	projectPeopleRole   = "people"
	projectWorkloadRole = "beta-worker"

	projectAlpha       = "alpha"
	projectBeta        = "beta"
	projectAlphaPolicy = "dev-alpha-rw"
	projectBetaPolicy  = "dev-beta-x"
	projectAlphaGroup  = "dev-alpha-rw"

	projectEnvIssuer   = "dev-ca"
	projectAlphaIssuer = "alpha-ca"
	projectAlphaRole   = "leaf"
	projectLeafName    = "svc.alpha.example.internal"

	projectPerson         = "person@example.com"
	projectBetaWorkerName = "beta-worker"
	projectBetaNamespace  = "apps"
)

// projectExample is the model TestProjectNamespaces applies: env dev with
// projects alpha and beta, and env prod, wired to issuer for both doors.
func projectExample(issuerURL string) *model.Desired {
	root := model.Namespace{
		PKI: []model.PKIMount{{
			Path: projectRootMount, DefaultLeaseTTL: "8760h", MaxLeaseTTL: "8760h",
			DefaultIssuer: projectRootIssuer,
			Issuers: []model.PKIIssuer{{
				Name: projectRootIssuer, CommonName: "Example Root CA", Organization: "Example Org",
				KeyCurve: model.CurveP384, TTL: "8760h", MaxPathLength: 2, SelfSigned: true,
			}},
		}},
	}

	dev := model.Namespace{
		Name: projectEnvironment,
		PKI: []model.PKIMount{{
			Path: "pki", DefaultLeaseTTL: "720h", MaxLeaseTTL: "4380h",
			DefaultIssuer: projectEnvIssuer,
			Issuers: []model.PKIIssuer{{
				Name: projectEnvIssuer, CommonName: "dev Issuing CA", Organization: "Example Org",
				KeyCurve: model.CurveP384, TTL: "4380h", MaxPathLength: 1,
				SignedBy: &model.IssuerRef{Mount: projectRootMount, Issuer: projectRootIssuer},
			}},
		}},
		Projects: []model.ProjectNamespace{
			{
				Name: projectAlpha,
				KV:   []model.KVMount{{Path: "kv", Description: "alpha's own secrets"}},
				PKI: []model.PKIMount{{
					Path: "pki", DefaultLeaseTTL: "1h", MaxLeaseTTL: "24h",
					DefaultIssuer: projectAlphaIssuer,
					Issuers: []model.PKIIssuer{{
						Name: projectAlphaIssuer, CommonName: "alpha Issuing CA", Organization: "Example Org",
						KeyCurve: model.CurveP384, TTL: "720h", MaxPathLength: 0,
						SignedBy: &model.IssuerRef{Namespace: projectEnvironment, Mount: "pki", Issuer: projectEnvIssuer},
					}},
					Roles: []model.PKIRole{{
						Name: projectAlphaRole, Issuer: projectAlphaIssuer,
						AllowedDomains: []string{"alpha.example.internal"}, AllowSubdomains: true,
						Server: true, KeyCurve: model.CurveP384, TTL: "1h", MaxTTL: "24h",
					}},
				}},
			},
			{
				Name: projectBeta,
				KV:   []model.KVMount{{Path: "kv", Description: "beta's own secrets"}},
			},
		},
		Auth: []model.JWTMount{{
			Path: projectDevDoor, DiscoveryURL: issuerURL,
			Roles: []model.Role{
				{
					Name: projectPeopleRole, BoundAudiences: []string{"openbao"},
					UserClaim: "sub", GroupsClaim: "groups", TTL: "15m",
				},
				{
					Name: projectWorkloadRole, BoundAudiences: []string{"openbao"},
					BoundSubject: model.ServiceAccountSubject(projectBetaNamespace, projectBetaWorkerName),
					UserClaim:    "sub", Policies: []string{projectBetaPolicy}, TTL: "15m",
				},
			},
		}},
		Policies: []model.Policy{
			{
				Name: projectAlphaPolicy,
				Rules: []model.Rule{
					{Path: model.ProjectPath(projectAlpha, "kv", "data/*"), Capabilities: []string{model.CapCreate, model.CapRead, model.CapUpdate}},
					{Path: model.ProjectPath(projectAlpha, "kv", "metadata/*"), Capabilities: []string{model.CapList, model.CapRead}},
				},
			},
			{
				Name: projectBetaPolicy,
				Rules: []model.Rule{
					{Path: model.ProjectPath(projectBeta, "kv", "data/x"), Capabilities: []string{model.CapRead}},
				},
			},
		},
		Groups: []model.Group{{Name: projectAlphaGroup, Policies: []string{projectAlphaPolicy}, Doors: []string{projectDevDoor}}},
	}

	prod := model.Namespace{
		Name: projectOtherEnv,
		Auth: []model.JWTMount{{
			Path: projectProdDoor, DiscoveryURL: issuerURL,
			Roles: []model.Role{{
				Name: projectPeopleRole, BoundAudiences: []string{"openbao"},
				UserClaim: "sub", GroupsClaim: "groups", TTL: "15m",
			}},
		}},
	}

	return &model.Desired{
		Root:       root,
		Namespaces: []model.Namespace{dev, prod},
		Identity:   model.Identity{PrimaryDoor: projectDevDoor},
	}
}

// TestProjectNamespaces walks ADR 0001's own proof list, against a real
// server: a people login reaches its project and no sibling's, a workload
// login reaches exactly the one key its policy names, another
// environment's token cannot reach in at all, the project's PKI issues a
// leaf chaining to its environment's CA, and the project namespace holds
// no auth mount of its own.
func TestProjectNamespaces(t *testing.T) {
	binary := tool(t, "bao")

	issuer, err := fakeissuer.New(nil)
	require.NoError(t, err)
	t.Cleanup(issuer.Close)

	address := devServer(t, binary)
	desired := projectExample(issuer.URL)

	opts := apply.Options{
		Address: "https://openbao.example.com",
		Login:   apply.Login{Mount: projectDevDoor, Role: projectPeopleRole, Token: replay.Tokens},
	}

	resources, err := replay.Capture(desired, opts)
	require.NoError(t, err)

	root := &replay.Server{Address: address, Token: rootToken}
	require.NoError(t, root.Replay(t.Context(), resources), "the whole example applies")

	ctx := t.Context()

	login := func(namespace, door, role string, token string) *replay.Server {
		answer, err := (&replay.Server{Address: address}).Call(ctx, http.MethodPost, namespace, "auth/"+door+"/login",
			map[string]any{"role": role, "jwt": token})
		require.NoError(t, err)

		auth, _ := answer["auth"].(map[string]any)
		require.NotEmpty(t, auth["client_token"])

		return &replay.Server{Address: address, Token: fmt.Sprint(auth["client_token"])}
	}

	// (a) a people login at dev, with an env-level policy on alpha's kv,
	// reads and writes dev/alpha/kv and is refused dev/beta/kv -- one
	// login, no second one at the project.
	t.Run("a people login reads and writes its project's kv, and is refused the sibling's", func(t *testing.T) {
		token := issuer.Token(fakeissuer.Claims{
			Subject: projectPerson, Audience: "openbao", Email: projectPerson, Groups: []string{projectAlphaGroup},
		})
		bao := login(projectEnvironment, projectDevDoor, projectPeopleRole, token)

		_, err := bao.Call(ctx, http.MethodPost, projectEnvironment, projectAlpha+"/kv/data/x",
			map[string]any{"data": map[string]any{"v": "1"}})
		require.NoError(t, err, "the policy's create/update on alpha/kv/data/*")

		answer, err := bao.Call(ctx, http.MethodGet, projectEnvironment, projectAlpha+"/kv/data/x", nil)
		require.NoError(t, err, "the policy's read")
		data, _ := answer["data"].(map[string]any)
		inner, _ := data["data"].(map[string]any)
		assert.Equal(t, "1", inner["v"])

		_, err = bao.Call(ctx, http.MethodGet, projectEnvironment, projectBeta+"/kv/data/x", nil)
		requireStatus(t, err, http.StatusForbidden, "no policy names beta's mount")
	})

	// (b) a workload login at dev, with a policy on beta/kv/data/x, reads
	// exactly that key and nothing else in beta.
	t.Run("a workload login reads exactly the one key its policy names", func(t *testing.T) {
		token := issuer.Token(fakeissuer.Claims{
			Subject: model.ServiceAccountSubject(projectBetaNamespace, projectBetaWorkerName), Audience: "openbao",
		})
		bao := login(projectEnvironment, projectDevDoor, projectWorkloadRole, token)

		_, err := root.Call(ctx, http.MethodPost, projectEnvironment, projectBeta+"/kv/data/x",
			map[string]any{"data": map[string]any{"v": "2"}})
		require.NoError(t, err)

		answer, err := bao.Call(ctx, http.MethodGet, projectEnvironment, projectBeta+"/kv/data/x", nil)
		require.NoError(t, err)
		data, _ := answer["data"].(map[string]any)
		inner, _ := data["data"].(map[string]any)
		assert.Equal(t, "2", inner["v"])

		_, err = bao.Call(ctx, http.MethodGet, projectEnvironment, projectBeta+"/kv/data/y", nil)
		requireStatus(t, err, http.StatusForbidden, "the policy names one key, not the mount")

		_, err = bao.Call(ctx, http.MethodGet, projectEnvironment, projectAlpha+"/kv/data/x", nil)
		requireStatus(t, err, http.StatusForbidden, "a workload role carries its own policies, alpha's among them never")
	})

	// (c) a token minted at another environment cannot reach into dev, or
	// any of dev's projects, at all: it is not dev's token, nor a
	// descendant's.
	t.Run("a token from another environment cannot reach in at all", func(t *testing.T) {
		token := issuer.Token(fakeissuer.Claims{Subject: projectPerson, Audience: "openbao", Groups: []string{projectAlphaGroup}})
		other := login(projectOtherEnv, projectProdDoor, projectPeopleRole, token)

		_, err := other.Call(ctx, http.MethodGet, projectEnvironment, projectAlpha+"/kv/data/x", nil)
		requireStatus(t, err, http.StatusForbidden, "a prod token reaching for dev/alpha")

		_, err = other.Call(ctx, http.MethodGet, projectEnvironment, "kv/data/x", nil)
		requireStatus(t, err, http.StatusForbidden, "a prod token reaching for dev itself")
	})

	// (d) the project's own issuing CA signs a leaf that chains through it
	// to the environment's CA, and through that to the root.
	t.Run("the project's PKI issues a leaf chaining to the environment's CA", func(t *testing.T) {
		answer, err := root.Call(ctx, http.MethodPost, projectEnvironment, projectAlpha+"/pki/sign/"+projectAlphaRole,
			map[string]any{"csr": csr(t, elliptic.P384(), projectLeafName), "common_name": projectLeafName})
		require.NoError(t, err)

		data, _ := answer["data"].(map[string]any)
		leaf := parseCertificate(t, data["certificate"])
		assert.Equal(t, []string{projectLeafName}, leaf.DNSNames)

		intermediates := x509.NewCertPool()
		for _, certificate := range strings2(data["ca_chain"]) {
			intermediates.AddCert(parseCertificate(t, certificate))
		}

		envCA, err := root.Call(ctx, http.MethodGet, projectEnvironment, "pki/issuer/"+projectEnvIssuer, nil)
		require.NoError(t, err)
		envData, _ := envCA["data"].(map[string]any)
		intermediates.AddCert(parseCertificate(t, envData["certificate"]))

		rootAnswer, err := root.Call(ctx, http.MethodGet, "", projectRootMount+"/issuer/"+projectRootIssuer, nil)
		require.NoError(t, err)
		rootData, _ := rootAnswer["data"].(map[string]any)

		roots := x509.NewCertPool()
		roots.AddCert(parseCertificate(t, rootData["certificate"]))

		_, err = leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: intermediates, DNSName: projectLeafName,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		require.NoError(t, err, "root -> the environment's issuing CA -> the project's own issuing CA -> the leaf")
	})

	// (e) apply never creates a login inside a project namespace: there is
	// nothing under dev/alpha's sys/auth beyond the namespace's own
	// built-in token store. (The model half of this proof --
	// Namespace.Validate refusing a policy, a role, a group or an auth
	// mount inside a ProjectNamespace -- is a unit test in pkg/model:
	// ProjectNamespace carries no field to write one in at all.)
	t.Run("the project namespace has no auth mount of its own", func(t *testing.T) {
		answer, err := root.Call(ctx, http.MethodGet, projectEnvironment+"/"+projectAlpha, "sys/auth", nil)
		require.NoError(t, err)

		data, _ := answer["data"].(map[string]any)

		for path, entry := range data {
			mount, _ := entry.(map[string]any)
			if fmt.Sprint(mount["type"]) == "jwt" || fmt.Sprint(mount["type"]) == "oidc" {
				t.Fatalf("dev/alpha has an auth mount %s of type %v; a project holds mounts, never a login", path, mount["type"])
			}
		}
	})
}

// TestProjectRuleBreadthRefusedBeforeApply is (e)'s other half: a policy
// rule broad enough to reach every project (a bare `*`) never gets as far
// as the apply at all. Deploy validates the model before it creates
// anything, so the capture below -- the same path a real apply takes --
// produces no resources and only the model's own refusal, on a server
// this test never starts.
func TestProjectRuleBreadthRefusedBeforeApply(t *testing.T) {
	desired := projectExample("https://issuer.example.com")
	dev := &desired.Namespaces[0]
	dev.Policies = append(dev.Policies, model.Policy{
		Name:  "dev:everything",
		Rules: []model.Rule{{Path: "*", Capabilities: []string{model.CapRead}}},
	})

	opts := apply.Options{
		Address: "https://openbao.example.com",
		Login:   apply.Login{Mount: projectDevDoor, Role: projectPeopleRole, Token: replay.Tokens},
	}

	resources, err := replay.Capture(desired, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reaches with a glob")
	assert.Empty(t, resources, "nothing is registered before the refusal")
}
