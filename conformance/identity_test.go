// identity_test.go proves ADR 0002's chain against a real server: a
// workload-identity domain intermediate, minted entirely outside OpenBAO
// by pkg/ceremony (docs/ceremony.md) and carrying only a URI name
// constraint, imported into a real `bao server -dev` as
// docs/ceremony.md's own install step describes (`ChainPEM`,
// `<mount>/intermediate/set-signed`); then an identity role on top of it,
// applied field for field the way pkg/apply/pki.go's pkiRole would render
// one.
//
// This does not go through internal/replay's Capture+Replay for the
// intermediate's own mount and issuer: SignedChain (apply.Options) is
// resolved once, under Pulumi's mocks, before Replay ever asks the real
// server for a CSR -- so the chain it returns must already be valid for
// whatever key the real server is about to generate, which is only true
// across two genuinely separate Pulumi applies sharing real state (the
// production flow docs/ceremony.md describes). The replay harness has no
// state between a Capture and the next one, so it cannot exercise that
// two-phase flow in one shot; this test drives the same ceremony and the
// same OpenBAO endpoints directly instead. The identity ROLE itself is
// proved through pkg/apply in pkg/apply/apply_test.go
// (TestIdentityRoleShape) against Pulumi's mocks; here its exact
// arguments are replayed by hand against a real server so the two
// together cover both halves.
package conformance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/openbao/internal/replay"
	"github.com/truvity/openbao/pkg/apply"
	"github.com/truvity/openbao/pkg/ceremony"
	"github.com/truvity/openbao/pkg/model"
)

const (
	identityMount       = "pki-identity"
	identityRoleName    = "identity"
	identityKeyARN      = "arn:aws:kms:eu-example-1:111122223333:key/mrk-conformance-identity"
	identityTrustDomain = "example.internal"
)

// fakeKMSDouble is an in-memory double for kmssigner.API: a P-384 key that
// signs digests directly, standing in for AWS KMS the way pkg/ceremony's
// own tests do. Private key material stays in this process only; nothing
// here is a real credential.
type fakeKMSDouble struct {
	privateKey *ecdsa.PrivateKey
	publicDER  []byte
}

func newFakeKMSDouble(t *testing.T) *fakeKMSDouble {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	return &fakeKMSDouble{privateKey: privateKey, publicDER: publicDER}
}

func (k *fakeKMSDouble) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{
		KeySpec:           types.KeySpecEccNistP384,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha384},
		PublicKey:         k.publicDER,
	}, nil
}

func (k *fakeKMSDouble) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	signature, err := ecdsa.SignASN1(rand.Reader, k.privateKey, input.Message)
	if err != nil {
		return nil, err
	}

	return &kms.SignOutput{Signature: signature}, nil
}

// TestIdentityIntermediateConformance is requirement 4: a real OpenBAO
// 2.6.2, a URI-constrained identity domain intermediate ceremony-signed
// and imported as an external chain, and an identity role on it. An
// allowed URI issues and x509-verifies with the identity intermediate as
// the only trust anchor a peer needs (ADR 0002: "identity-verifying peers
// trust ONLY the identity intermediate, not the root"); a DNS name and a
// foreign trust domain are both refused.
func TestIdentityIntermediateConformance(t *testing.T) {
	binary := tool(t, "bao")
	address := devServer(t, binary)
	server := &replay.Server{Address: address, Token: rootToken}
	ctx := t.Context()

	// 1. The ceremony, entirely outside OpenBAO: a root and a
	// workload-identity domain intermediate carrying only a URI name
	// constraint (docs/decisions/0002-workload-mtls-service-and-identity-roles.md).
	// The root's key never touches the real server at all -- only the
	// intermediate is installed, as a keyless issuer, exactly as
	// docs/ceremony.md's install step describes.
	kmsClient := newFakeKMSDouble(t)
	notBefore := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)

	rootSpec := ceremony.RootSpec{
		GenerationID: "conformance-identity",
		CommonName:   "Conformance Identity Root",
		NotBefore:    notBefore,
		Lifetime:     87600 * time.Hour,
		MaxPathLen:   1,
	}
	rootResult, err := ceremony.CreateRoot(ctx, kmsClient, rootSpec, ceremony.RootOptions{
		KeyARN: identityKeyARN, ArtifactPath: t.TempDir() + "/root.yaml",
	})
	require.NoError(t, err)
	require.True(t, rootResult.Signed)

	intermediateSpec := ceremony.IntermediateSpec{
		TrustDomain:         "identity",
		GenerationID:        rootSpec.GenerationID,
		CommonName:          "Workload Identity Intermediate CA",
		NotBefore:           notBefore,
		Lifetime:            8760 * time.Hour,
		MaxPathLen:          0,
		PermittedURIDomains: []string{identityTrustDomain},
		RootArtifactPath:    "root.yaml",
		ArtifactPath:        t.TempDir() + "/identity.yaml",
	}

	// 2. The mount, and the CSR generated for real on the real server:
	// only its public key leaves.
	_, err = server.Call(ctx, http.MethodPost, "", "sys/mounts/"+identityMount, map[string]any{"type": "pki"})
	require.NoError(t, err)

	csrAnswer, err := server.Call(ctx, http.MethodPost, "", identityMount+"/intermediate/generate/internal", map[string]any{
		"common_name":          intermediateSpec.CommonName,
		"key_name":             "identity",
		"key_type":             "ec",
		"key_bits":             384,
		"exclude_cn_from_sans": true,
	})
	require.NoError(t, err, "generating the %s intermediate CSR", identityMount)
	csrData, _ := csrAnswer["data"].(map[string]any)
	csrPEM := fmtString(csrData["csr"])
	require.NotEmpty(t, csrPEM)

	// 3. The ceremony signs it -- the same verification and the same
	// deterministic template pkg/ceremony's own tests prove, here against
	// a CSR a real OpenBAO mount produced.
	plan, err := ceremony.PrepareIntermediate(intermediateSpec, rootResult.Artifact, []byte(csrPEM))
	require.NoError(t, err)

	signResult, err := ceremony.SignIntermediate(ctx, kmsClient, plan, ceremony.IntermediateOptions{
		KeyARN: identityKeyARN, ConfirmTemplateSHA256: plan.TemplateSHA256,
	})
	require.NoError(t, err)
	require.True(t, signResult.Signed)

	signed, err := ceremony.VerifySignedIntermediate(intermediateSpec, rootResult.Artifact, signResult.Artifact)
	require.NoError(t, err, "the committed artifact re-verifies offline, the same proof an installer runs")

	// 4. Import: the intermediate followed by the keyless root, exactly
	// docs/ceremony.md's `<mount>/intermediate/set-signed` step.
	_, err = server.Call(ctx, http.MethodPost, "", identityMount+"/intermediate/set-signed", map[string]any{
		"certificate": signed.ChainPEM,
	})
	require.NoError(t, err)

	issuerAnswer, err := server.Call(ctx, http.MethodGet, "", identityMount+"/cert/ca", nil)
	require.NoError(t, err)
	installed, _ := issuerAnswer["data"].(map[string]any)
	assert.Equal(t, signed.Certificate.Raw, parseCertificate(t, installed["certificate"]).Raw,
		"the certificate OpenBAO reports for the mount's issuer is the ceremony's artifact, byte for byte")

	// 5. The identity role, field for field the way pkg/apply/pki.go's
	// pkiRole renders one for an identity-shaped model.PKIRole
	// (TestIdentityRoleShape in pkg/apply proves the same translation
	// under Pulumi's mocks). The trust domain is held fixed and the path
	// wildcarded: the documented CSI fallback shape
	// (docs/model.md#identity-roles), never templated here since this
	// test signs as the mount's root token, which carries no workload
	// identity alias to template against.
	role := model.PKIRole{
		Name:           identityRoleName,
		Server:         true,
		Client:         true,
		KeyCurve:       model.CurveP384,
		TTL:            "1h",
		MaxTTL:         "1h",
		AllowedURISANs: []string{"spiffe://dev." + identityTrustDomain + "/*"},
	}
	require.NoError(t, role.Validate())

	_, err = server.Call(ctx, http.MethodPost, "", identityMount+"/roles/"+identityRoleName, map[string]any{
		"allowed_domains":             []string{},
		"allowed_domains_template":    false,
		"allow_bare_domains":          false,
		"allow_subdomains":            false,
		"allow_glob_domains":          false,
		"allow_wildcard_certificates": false,
		"allow_any_name":              false,
		"allow_ip_sans":               false,
		"allowed_uri_sans":            role.AllowedURISANs,
		"allowed_uri_sans_template":   role.AllowedURISANsTemplate,
		"allowed_other_sans":          []string{},
		"allowed_user_ids":            []string{},
		"allow_localhost":             false,
		"cn_validations":              []string{},
		"require_cn":                  false,
		"use_csr_sans":                false,
		"email_protection_flag":       false,
		"enforce_hostnames":           false,
		"server_flag":                 role.Server,
		"client_flag":                 role.Client,
		"key_type":                    "ec",
		"key_bits":                    apply.LeafKeyBits(role.KeyCurve),
		"ttl":                         role.TTL,
		"max_ttl":                     role.MaxTTL,
		"no_store":                    false,
	})
	require.NoError(t, err)

	sign := func(uriSANs string) (map[string]any, error) {
		return server.Call(ctx, http.MethodPost, "", identityMount+"/sign/"+identityRoleName, map[string]any{
			"csr":      csr(t, elliptic.P384(), ""),
			"uri_sans": uriSANs,
		})
	}

	t.Run("an allowed URI issues and verifies with the identity intermediate as the only trust anchor", func(t *testing.T) {
		answer, err := sign("spiffe://dev." + identityTrustDomain + "/ns/a/sa/b")
		require.NoError(t, err)
		data, _ := answer["data"].(map[string]any)
		leaf := parseCertificate(t, data["certificate"])
		require.Len(t, leaf.URIs, 1)
		assert.Equal(t, "spiffe://dev."+identityTrustDomain+"/ns/a/sa/b", leaf.URIs[0].String())

		// The full chain, to the ceremony root -- never installed on the
		// server, held only by this test, the way an operator's own
		// ceremony artifact is.
		roots := x509.NewCertPool()
		rootCertificate, err := rootResult.Artifact.Certificate()
		require.NoError(t, err)
		roots.AddCert(rootCertificate)
		intermediates := x509.NewCertPool()
		intermediates.AddCert(signed.Certificate)
		_, err = leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		require.NoError(t, err, "root -> identity intermediate -> leaf")

		// ADR 0002: "identity-verifying peers trust ONLY the identity
		// intermediate, not the root." A peer with a trust bundle of just
		// the intermediate -- no root, no chain -- verifies the same leaf.
		identityOnly := x509.NewCertPool()
		identityOnly.AddCert(signed.Certificate)
		_, err = leaf.Verify(x509.VerifyOptions{
			Roots: identityOnly, CurrentTime: time.Now(),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		require.NoError(t, err, "the identity intermediate alone is a sufficient trust bundle")
	})

	t.Run("a DNS name is refused: the role allows no domain", func(t *testing.T) {
		_, err := server.Call(ctx, http.MethodPost, "", identityMount+"/sign/"+identityRoleName, map[string]any{
			"csr":       csr(t, elliptic.P384(), ""),
			"alt_names": "foo." + identityTrustDomain,
		})
		requireStatus(t, err, http.StatusBadRequest, "the identity role carries no allowedDomains")
	})

	t.Run("a foreign trust domain is refused", func(t *testing.T) {
		_, err := sign("spiffe://other.test/ns/a/sa/b")
		requireStatus(t, err, http.StatusBadRequest, "other.test is not dev."+identityTrustDomain)
	})
}

func fmtString(value any) string {
	s, _ := value.(string)
	return s
}
