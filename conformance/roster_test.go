// Package conformance_test proves the access-roster contract
// (docs/integrations/access-roster.md) against a real OpenBAO server: a
// `bao server -dev` configured by exactly what pkg/apply registers for the
// neutral example (examples/roster), trusting a fake issuer shaped like
// access-issuer (internal/fakeissuer).
//
// The server is the `bao` binary on PATH -- the dev shell pins it. Without
// one the test skips, unless OPENBAO_CONFORMANCE=required (which `just
// test`, and so CI, sets), when a missing binary is a failure: a
// conformance test that quietly skipped would prove nothing.
package conformance_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/truvity/openbao/examples/roster"
	"github.com/truvity/openbao/internal/fakeissuer"
	"github.com/truvity/openbao/internal/replay"
	"github.com/truvity/openbao/pkg/apply"
	"github.com/truvity/openbao/pkg/model"
)

const (
	// requireVariable, set to "required", makes a missing `bao` a failure.
	requireVariable = "OPENBAO_CONFORMANCE"
	rootToken       = "conformance-root"
	uiSecret        = "conformance-ui-secret"

	person   = "person@example.com"
	operator = "operator@example.com"
	job      = "ci:example-release"
)

type conformance struct {
	issuer  *fakeissuer.Issuer
	address string
	// operator is the server as the operators' group, logged in through
	// the bootstrap door; root is the dev root token, used only to create
	// that door.
	operator *replay.Server
}

// TestRosterContract applies the example and walks the contract: every
// subtest is one clause of docs/integrations/access-roster.md.
func TestRosterContract(t *testing.T) {
	c := start(t)
	ctx := t.Context()

	t.Run("operators log in to root through the bootstrap door", func(t *testing.T) {
		auth := c.login(t, "", model.RosterMount, c.token(operator, model.RosterAudience, roster.Operators))
		assert.Equal(t, []string{roster.Operators}, strings2(auth["identity_policies"]))
	})

	t.Run("a person's groups become the policies of the same names", func(t *testing.T) {
		auth := c.login(t, roster.Environment, model.RosterMount,
			c.token(person, model.RosterAudience, roster.SSHUser, roster.DBClient, "dev:nothing:here"))

		policies := strings2(auth["identity_policies"])
		slices.Sort(policies)
		assert.Equal(t, []string{roster.DBClient, roster.SSHUser}, policies, "a group OpenBAO holds no policy for is ignored")
		assert.Equal(t, []string{"default"}, strings2(auth["token_policies"]), "the role itself attaches nothing")
	})

	t.Run("ssh/sign/user signs the caller's key for the role's account, keyed by the subject", func(t *testing.T) {
		bao := c.as(t, person, roster.SSHUser)

		public, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		key, err := ssh.NewPublicKey(public)
		require.NoError(t, err)

		answer, err := bao.Call(ctx, http.MethodPost, roster.Environment, roster.SSHMount+"/sign/"+roster.SSHUserRole,
			map[string]any{"public_key": string(ssh.MarshalAuthorizedKey(key))})
		require.NoError(t, err)

		certificate := sshCertificate(t, answer)
		assert.Equal(t, uint32(ssh.UserCert), certificate.CertType)
		assert.Equal(t, []string{roster.SSHUserPrincipal}, certificate.ValidPrincipals)
		// `{{token_display_name}}`: the login's namespace and mount, then
		// the roster subject -- what an sshd log line is read against.
		assert.Equal(t, roster.Environment+"-auth-"+model.RosterMount+"-"+person, certificate.KeyId)
		assert.Equal(t, map[string]string{"permit-pty": ""}, certificate.Extensions)
		assert.Empty(t, certificate.CriticalOptions)
		assert.LessOrEqual(t, time.Duration(certificate.ValidBefore-certificate.ValidAfter)*time.Second, time.Hour+time.Minute)
		assert.Equal(t, key.Marshal(), certificate.Key.Marshal(), "the caller's key, never one made for it")

		caKey := c.sshCA(t)
		assert.Equal(t, caKey.Marshal(), certificate.SignatureKey.Marshal(), "signed by the environment's SSH CA")

		_, err = bao.Call(ctx, http.MethodPost, roster.Environment, roster.SSHMount+"/sign/"+roster.SSHUserRole,
			map[string]any{"public_key": string(ssh.MarshalAuthorizedKey(key)), "valid_principals": "root"})
		requireStatus(t, err, http.StatusBadRequest, "an account the role does not list is refused")
	})

	t.Run("ssh/sign/admin is refused without the admin group", func(t *testing.T) {
		bao := c.as(t, person, roster.SSHUser)

		_, err := bao.Call(ctx, http.MethodPost, roster.Environment, roster.SSHMount+"/sign/"+roster.SSHAdminRole,
			map[string]any{"public_key": newSSHKey(t)})
		requireStatus(t, err, http.StatusForbidden, "the user group does not open the admin role")
	})

	t.Run("pki/sign/db-client signs the caller's own P-384 CSR, for client auth, for an hour", func(t *testing.T) {
		bao := c.as(t, person, roster.DBClient)
		path := roster.PKIMount + "/sign/" + roster.DBClientRole

		answer, err := bao.Call(ctx, http.MethodPost, roster.Environment, path,
			map[string]any{"csr": csr(t, elliptic.P384(), person), "common_name": person})
		require.NoError(t, err)

		data, _ := answer["data"].(map[string]any)
		leaf := parseCertificate(t, data["certificate"])
		assert.Equal(t, person, leaf.Subject.CommonName)
		assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, leaf.ExtKeyUsage)
		assert.LessOrEqual(t, leaf.NotAfter.Sub(leaf.NotBefore), time.Hour+time.Minute)
		assert.Empty(t, leaf.DNSNames)
		assert.Empty(t, leaf.IPAddresses)

		intermediates := x509.NewCertPool()
		intermediates.AddCert(parseCertificate(t, data["issuing_ca"]))

		roots := x509.NewCertPool()
		roots.AddCert(c.rootCA(t))

		_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		require.NoError(t, err, "the certificate chains to the example root")

		_, err = bao.Call(ctx, http.MethodPost, roster.Environment, path,
			map[string]any{"csr": csr(t, elliptic.P384(), "someone-else@example.com"), "common_name": "someone-else@example.com"})
		requireStatus(t, err, http.StatusBadRequest, "a common name that is not the caller's own is refused")

		_, err = bao.Call(ctx, http.MethodPost, roster.Environment, path,
			map[string]any{"csr": csr(t, elliptic.P256(), person), "common_name": person})
		requireStatus(t, err, http.StatusBadRequest, "a key the role does not sign is refused")

		_, err = bao.Call(ctx, http.MethodPost, roster.Environment, roster.PKIMount+"/issue/"+roster.DBClientRole,
			map[string]any{"common_name": person})
		requireStatus(t, err, http.StatusForbidden, "the group signs; it never has a key made for it")
	})

	t.Run("a group OpenBAO holds no policy for logs in and opens nothing", func(t *testing.T) {
		bao := c.as(t, person, "dev:nothing:here")

		_, err := bao.Call(ctx, http.MethodPost, roster.Environment, roster.SSHMount+"/sign/"+roster.SSHUserRole,
			map[string]any{"public_key": newSSHKey(t)})
		requireStatus(t, err, http.StatusForbidden, "no policy, no sign")
	})

	t.Run("the roster door refuses every token it must", func(t *testing.T) {
		foreign, err := c.issuer.ForeignToken(fakeissuer.Claims{Subject: person, Audience: model.RosterAudience, Groups: []string{roster.SSHUser}})
		require.NoError(t, err)

		for name, token := range map[string]string{
			"another audience": c.token(person, "some-other-client", roster.SSHUser),
			"the UI's audience": c.issuer.Token(fakeissuer.Claims{
				Subject: person, Audience: model.RosterUIClient, Groups: []string{roster.SSHUser},
			}),
			"another issuer's key": foreign,
			"expired": c.issuer.Token(fakeissuer.Claims{
				Subject: person, Audience: model.RosterAudience, Groups: []string{roster.SSHUser}, Expiry: time.Now().Add(-10 * time.Minute),
			}),
			"another issuer's name": c.issuer.Token(fakeissuer.Claims{
				Subject: person, Audience: model.RosterAudience, Groups: []string{roster.SSHUser},
				Extra: map[string]any{"iss": "https://elsewhere.example.com"},
			}),
		} {
			t.Run(name, func(t *testing.T) {
				_, err := c.anonymous().Call(ctx, http.MethodPost, roster.Environment, "auth/"+model.RosterMount+"/login",
					map[string]any{"role": model.RosterRole, "jwt": token})
				requireStatus(t, err, http.StatusBadRequest, "refused at login")
			})
		}
	})

	t.Run("the UI door signs the same person in with the same policies", func(t *testing.T) {
		callback := model.UICallback(c.address, model.RosterUIMount)
		authURLFor := func(redirect string) string {
			answer, err := c.anonymous().Call(ctx, http.MethodPost, roster.Environment, "auth/"+model.RosterUIMount+"/oidc/auth_url",
				map[string]any{"role": model.RosterRole, "redirect_uri": redirect})
			require.NoError(t, err)

			data, _ := answer["data"].(map[string]any)

			return fmt.Sprint(data["auth_url"])
		}

		assert.Empty(t, authURLFor("https://elsewhere.example.com/callback"), "a redirect the role does not allow gets no sign-in")

		// The UI asks with its one callback plus `?namespace=`; the mount
		// strips the namespace before matching and carries it in the state.
		authURL, err := url.Parse(authURLFor(callback + "?namespace=" + roster.Environment))
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(authURL.String(), c.issuer.URL+fakeissuer.AuthorizePath), authURL.String())
		assert.Equal(t, model.RosterUIClient, authURL.Query().Get("client_id"))
		assert.Equal(t, callback, authURL.Query().Get("redirect_uri"), "one redirect, with no namespace in it")
		assert.Contains(t, authURL.Query().Get("state"), ",ns="+roster.Environment, "the namespace travels in the state")

		c.issuer.SignIn(fakeissuer.Claims{Subject: person, Email: person, Groups: []string{roster.SSHUser}})

		browser := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := browser.Get(authURL.String())
		require.NoError(t, err)
		_ = response.Body.Close()
		require.Equal(t, http.StatusFound, response.StatusCode)

		back, err := url.Parse(response.Header.Get("Location"))
		require.NoError(t, err)

		// What the UI does with the callback: the namespace from the
		// state, then the callback endpoint in that namespace with the
		// state it issued.
		state, namespace, found := strings.Cut(back.Query().Get("state"), ",ns=")
		require.True(t, found)
		assert.Equal(t, roster.Environment, namespace)

		signedIn, err := c.anonymous().Call(ctx, http.MethodGet, namespace,
			"auth/"+model.RosterUIMount+"/oidc/callback?"+url.Values{"state": {state}, "code": {back.Query().Get("code")}}.Encode(), nil)
		require.NoError(t, err)

		auth, _ := signedIn["auth"].(map[string]any)
		assert.Equal(t, []string{roster.SSHUser}, strings2(auth["identity_policies"]), "through the <group>@oidc identity group")

		bao := &replay.Server{Address: c.address, Token: fmt.Sprint(auth["client_token"])}
		_, err = bao.Call(ctx, http.MethodPost, roster.Environment, roster.SSHMount+"/sign/"+roster.SSHUserRole,
			map[string]any{"public_key": newSSHKey(t)})
		require.NoError(t, err)

		group, err := c.operator.Call(ctx, http.MethodGet, roster.Environment, "identity/group/name/"+url.PathEscape(roster.SSHUser+"@"+model.RosterUIMount), nil)
		require.NoError(t, err)
		groupData, _ := group["data"].(map[string]any)
		assert.Equal(t, "external", groupData["type"])
	})

	t.Run("a job reads its one path through the roster door, and nothing else", func(t *testing.T) {
		_, err := c.operator.Call(ctx, http.MethodPost, roster.Environment, roster.KVMount+"/data/"+roster.ReleaseSecret,
			map[string]any{"data": map[string]any{"key": "example-value"}})
		require.NoError(t, err)

		bao := c.as(t, job, roster.CIRelease)

		answer, err := bao.Call(ctx, http.MethodGet, roster.Environment, roster.KVMount+"/data/"+roster.ReleaseSecret, nil)
		require.NoError(t, err)

		data, _ := answer["data"].(map[string]any)
		assert.Equal(t, map[string]any{"key": "example-value"}, data["data"])

		_, err = bao.Call(ctx, http.MethodGet, roster.Environment, roster.KVMount+"/metadata/"+roster.ReleaseSecret, nil)
		requireStatus(t, err, http.StatusForbidden, "no metadata")

		_, err = bao.Call(ctx, http.MethodGet, roster.Environment, roster.KVMount+"/data/ci/other", nil)
		requireStatus(t, err, http.StatusForbidden, "no other path")

		_, err = c.operator.Call(ctx, http.MethodGet, roster.Environment, "identity/group/name/"+url.PathEscape(roster.CIRelease+"@"+model.RosterUIMount), nil)
		requireStatus(t, err, http.StatusNotFound, "a job's group has no UI door")

		_, err = bao.Call(ctx, http.MethodPost, roster.Environment, "auth/token/revoke-self", nil)
		require.NoError(t, err)

		_, err = bao.Call(ctx, http.MethodGet, roster.Environment, roster.KVMount+"/data/"+roster.ReleaseSecret, nil)
		requireStatus(t, err, http.StatusForbidden, "a revoked login reads nothing")
	})
}

// start runs the issuer and the server, creates the bootstrap door with
// the dev root token, logs in through it as an operator, and applies the
// example as that operator.
func start(t *testing.T) *conformance {
	t.Helper()

	binary := tool(t, "bao")

	issuer, err := fakeissuer.New(map[string]string{model.RosterUIClient: uiSecret})
	require.NoError(t, err)
	t.Cleanup(issuer.Close)

	c := &conformance{issuer: issuer, address: devServer(t, binary)}
	desired := roster.Desired(roster.Params{Issuer: issuer.URL, Address: c.address})

	opts := apply.Options{
		// Where the PKI mounts publish their URLs; nothing here fetches them.
		Address:           "https://openbao.example.com",
		Login:             apply.Login{Mount: model.RosterMount, Role: model.RosterRole, Token: replay.Tokens},
		OIDCClientSecrets: map[string]pulumi.StringInput{model.RosterUIClient: pulumi.String(uiSecret)},
	}

	// The bootstrap is never the apply's: the server's initialisation
	// creates it. Here that is the same translation, as root.
	bootstrap, err := replay.Capture(&model.Desired{Root: desired.Bootstrap, Identity: desired.Identity}, opts)
	require.NoError(t, err)
	require.NoError(t, (&replay.Server{Address: c.address, Token: rootToken}).Replay(t.Context(), bootstrap))

	auth := c.login(t, "", model.RosterMount, c.token(operator, model.RosterAudience, roster.Operators))
	c.operator = &replay.Server{Address: c.address, Token: fmt.Sprint(auth["client_token"])}

	resources, err := replay.Capture(desired, opts)
	require.NoError(t, err)
	require.NoError(t, c.operator.Replay(t.Context(), resources), "the operators' group applies the whole example")

	return c
}

// devServer starts `bao server -dev` on a free local port and waits until
// it answers.
func devServer(t *testing.T, binary string) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	var logs bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	server := exec.CommandContext(ctx, binary, "server", "-dev", "-dev-no-store-token",
		"-dev-root-token-id="+rootToken, "-dev-listen-address="+address)
	server.Env = []string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
	server.Stdout, server.Stderr = &logs, &logs
	require.NoError(t, server.Start())

	t.Cleanup(func() {
		cancel()
		_ = server.Wait()

		if t.Failed() {
			t.Logf("bao server -dev:\n%s", logs.String())
		}
	})

	base := "http://" + address
	deadline := time.Now().Add(30 * time.Second)

	for {
		response, err := http.Get(base + "/v1/sys/health")
		if err == nil {
			_ = response.Body.Close()

			if response.StatusCode == http.StatusOK {
				return base
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("bao server -dev did not come up at %s:\n%s", base, logs.String())
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// token is a token for one audience, as access-issuer's exchange mints it.
func (c *conformance) token(subject, audience string, groups ...string) string {
	return c.issuer.Token(fakeissuer.Claims{Subject: subject, Audience: audience, Email: subject, Groups: groups})
}

// login is `auth/<mount>/login` as role roster, as accessctl makes it.
func (c *conformance) login(t *testing.T, namespace, mount, token string) map[string]any {
	t.Helper()

	answer, err := c.anonymous().Call(t.Context(), http.MethodPost, namespace, "auth/"+mount+"/login",
		map[string]any{"role": model.RosterRole, "jwt": token})
	require.NoError(t, err)

	auth, _ := answer["auth"].(map[string]any)
	require.NotEmpty(t, auth["client_token"])

	return auth
}

// as is the server as somebody logged in to the environment's roster door.
func (c *conformance) as(t *testing.T, subject string, groups ...string) *replay.Server {
	t.Helper()

	auth := c.login(t, roster.Environment, model.RosterMount, c.token(subject, model.RosterAudience, groups...))

	return &replay.Server{Address: c.address, Token: fmt.Sprint(auth["client_token"])}
}

func (c *conformance) anonymous() *replay.Server { return &replay.Server{Address: c.address} }

// sshCA is the environment's SSH CA public key, which is public.
func (c *conformance) sshCA(t *testing.T) ssh.PublicKey {
	t.Helper()

	answer, err := c.operator.Call(t.Context(), http.MethodGet, roster.Environment, roster.SSHMount+"/config/ca", nil)
	require.NoError(t, err)

	data, _ := answer["data"].(map[string]any)
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fmt.Sprint(data["public_key"])))
	require.NoError(t, err)

	return key
}

// rootCA is the example root's certificate, the anchor a database trusts.
func (c *conformance) rootCA(t *testing.T) *x509.Certificate {
	t.Helper()

	answer, err := c.operator.Call(t.Context(), http.MethodGet, "", roster.PKIRootMount+"/issuer/"+roster.RootIssuer, nil)
	require.NoError(t, err)

	data, _ := answer["data"].(map[string]any)

	return parseCertificate(t, data["certificate"])
}

func requireStatus(t *testing.T, err error, status int, why string) {
	t.Helper()

	var apiErr *replay.APIError
	require.ErrorAs(t, err, &apiErr, why)
	require.Equal(t, status, apiErr.Status, "%s: %v", why, err)
}

func newSSHKey(t *testing.T) string {
	t.Helper()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)

	return string(ssh.MarshalAuthorizedKey(key))
}

func sshCertificate(t *testing.T, answer map[string]any) *ssh.Certificate {
	t.Helper()

	data, _ := answer["data"].(map[string]any)
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fmt.Sprint(data["signed_key"])))
	require.NoError(t, err)

	certificate, ok := key.(*ssh.Certificate)
	require.True(t, ok, "a certificate, not a %s", key.Type())

	return certificate
}

// csr is what accessctl sends: a request for a key made on the caller's
// machine, with the common name asked for.
func csr(t *testing.T, curve elliptic.Curve, commonName string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func parseCertificate(t *testing.T, value any) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode([]byte(fmt.Sprint(value)))
	require.NotNil(t, block, "no PEM in %v", value)

	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	return certificate
}

// strings2 reads a JSON list of strings.
func strings2(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))

	for _, item := range list {
		out = append(out, fmt.Sprint(item))
	}

	return out
}
