package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/openbao/pkg/ceremony"
	"github.com/truvity/openbao/pkg/kmssigner"
)

const (
	keyARN    = "arn:aws:kms:eu-example-1:111122223333:key/mrk-example"
	hierarchy = `root:
  generationId: example-root-2026-01
  subject:
    commonName: Example Private Root 2026-01
    organization: Example Org
  notBefore: "2026-01-01T00:00:00Z"
  lifetime: 175200h
  maxPathLen: 3
  artifact: roots/example-root-2026-01.yaml
intermediates:
  - trustDomain: private
    subject:
      commonName: example.internal Intermediate CA
      organization: Example Org
    lifetime: 87600h
    permittedDnsDomains: [example.internal, cluster.local]
    artifact: roots/example-root-2026-01-intermediate-private.yaml
emergencyServer:
  dnsName: openbao.example.internal
`
)

var confirmPattern = regexp.MustCompile(`--confirm-template ([0-9a-f]{64})`)

type fakeKMS struct {
	key       *ecdsa.PrivateKey
	signCalls int
	regions   []string
}

func (f *fakeKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		return nil, err
	}

	return &kms.GetPublicKeyOutput{
		KeySpec:           types.KeySpecEccNistP384,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha384},
		PublicKey:         der,
	}, nil
}

func (f *fakeKMS) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signCalls++
	signature, err := ecdsa.SignASN1(rand.Reader, f.key, input.Message)

	return &kms.SignOutput{Signature: signature}, err
}

func (f *fakeKMS) factory(_ context.Context, region string) (kmssigner.API, error) {
	f.regions = append(f.regions, region)

	return f, nil
}

func setup(t *testing.T) (string, *fakeKMS) {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "roots"), 0o755))
	path := filepath.Join(dir, "pki.yaml")
	require.NoError(t, os.WriteFile(path, []byte(hierarchy), 0o644))

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	return path, &fakeKMS{key: key}
}

func writeCSR(t *testing.T, template *x509.CertificateRequest) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "request.csr")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o600))

	return path
}

func createRoot(t *testing.T, path string, client *fakeKMS) {
	t.Helper()

	var out bytes.Buffer
	require.NoError(t, runCreateRoot(context.Background(), &out, createRootOptions{
		hierarchy: path,
		signing:   signingOptions{keyARN: keyARN, kms: client.factory},
	}))
	assert.Contains(t, out.String(), "generationId: example-root-2026-01")
}

// The whole ceremony against the KMS double: one signature for the root,
// none for a review, one for the confirmed intermediate, none for a rerun,
// and the committed intermediate proves offline.
func TestTheCeremonyEndToEnd(t *testing.T) {
	path, client := setup(t)
	createRoot(t, path, client)
	assert.Equal(t, 1, client.signCalls)
	assert.Equal(t, []string{"eu-example-1"}, client.regions, "the region is the key ARN's")

	csr := writeCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.internal Intermediate CA", Organization: []string{"Example Org"}}})
	base := signIntermediateOptions{hierarchy: path, trustDomain: "private", csrPath: csr, signing: signingOptions{kms: client.factory}}

	var review bytes.Buffer
	printing := base
	printing.printTemplate = true
	require.NoError(t, runSignIntermediate(context.Background(), &review, printing))
	assert.Contains(t, review.String(), "private intermediate certificate template")
	assert.Equal(t, 1, client.signCalls, "a review signs nothing")
	match := confirmPattern.FindStringSubmatch(review.String())
	require.NotNil(t, match, review.String())

	for range 2 {
		var signed bytes.Buffer
		confirming := base
		confirming.confirmTemplate = match[1]
		require.NoError(t, runSignIntermediate(context.Background(), &signed, confirming))
		assert.Contains(t, signed.String(), "proven:")
		assert.Contains(t, signed.String(), "templateSha256: "+match[1])
	}
	assert.Equal(t, 2, client.signCalls, "the rerun verifies and does not sign")

	var verified bytes.Buffer
	chain := filepath.Join(t.TempDir(), "chain.pem")
	require.NoError(t, runVerifyIntermediate(&verified, verifyIntermediateOptions{hierarchy: path, trustDomain: "private", chainOut: chain}))
	assert.Contains(t, verified.String(), "chains to the committed root")
	raw, err := os.ReadFile(chain)
	require.NoError(t, err)
	assert.Equal(t, 2, bytes.Count(raw, []byte("BEGIN CERTIFICATE")))

	require.Error(t, runVerifyIntermediate(&verified, verifyIntermediateOptions{hierarchy: path, trustDomain: "private", chainOut: chain}),
		"the chain is never overwritten")
}

func TestSignIntermediateRefusesAmbiguousInvocations(t *testing.T) {
	path, _ := setup(t)
	base := signIntermediateOptions{hierarchy: path, trustDomain: "private", csrPath: "private.csr"}

	cases := []struct {
		name    string
		mutate  func(*signIntermediateOptions)
		wantErr string
	}{
		{"neither mode", func(*signIntermediateOptions) {}, "choose one"},
		{"both modes", func(o *signIntermediateOptions) { o.printTemplate = true; o.confirmTemplate = "abc" }, "choose one"},
		{"unknown domain", func(o *signIntermediateOptions) { o.printTemplate = true; o.trustDomain = "public" }, "unknown trust domain"},
		{"no root yet", func(o *signIntermediateOptions) { o.printTemplate = true }, "committed root artifact is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			options := base
			tc.mutate(&options)
			var out bytes.Buffer
			err := runSignIntermediate(context.Background(), &out, options)
			require.ErrorContains(t, err, tc.wantErr)
			assert.Empty(t, out.String())
		})
	}
}

// The break-glass refusals that need no credential: one mode, a pinned
// notBefore to sign, and never overwriting a signed leaf -- checked before
// the root key is asked for anything, because every signature is an alarm.
func TestSignEmergencyServerRefusesBeforeSigning(t *testing.T) {
	path, client := setup(t)
	createRoot(t, path, client)
	client.signCalls = 0

	csr := writeCSR(t, &x509.CertificateRequest{DNSNames: []string{"openbao.example.internal"}})
	existing := filepath.Join(t.TempDir(), "already.crt")
	require.NoError(t, os.WriteFile(existing, []byte("x"), 0o600))

	base := signEmergencyServerOptions{hierarchy: path, csrPath: csr, now: fixedNow, outPath: existing, signing: signingOptions{kms: client.factory}}

	cases := []struct {
		name    string
		mutate  func(*signEmergencyServerOptions)
		wantErr string
	}{
		{"neither mode", func(*signEmergencyServerOptions) {}, "choose one"},
		{"both modes", func(o *signEmergencyServerOptions) { o.printTemplate = true; o.confirmTemplate = "abc" }, "choose one"},
		{"no pinned notBefore", func(o *signEmergencyServerOptions) { o.confirmTemplate = "abc" }, "--not-before is required"},
		{"a bad notBefore", func(o *signEmergencyServerOptions) { o.confirmTemplate = "abc"; o.notBefore = "tomorrow" }, "--not-before"},
		{"an existing output", func(o *signEmergencyServerOptions) {
			o.confirmTemplate = "abc"
			o.notBefore = "2026-12-12T11:00:00Z"
		}, "refusing to overwrite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			options := base
			tc.mutate(&options)
			var out bytes.Buffer
			err := runSignEmergencyServer(context.Background(), &out, options)
			require.ErrorContains(t, err, tc.wantErr)
			assert.Empty(t, out.String())
		})
	}
	assert.Zero(t, client.signCalls)
}

// --print-template needs no credential and prints the exact rerun line;
// the rerun signs once and writes the leaf.
func TestSignEmergencyServerPrintsThenSignsTheReviewedTemplate(t *testing.T) {
	path, client := setup(t)
	createRoot(t, path, client)
	client.signCalls = 0

	csr := writeCSR(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "openbao.example.internal"},
		DNSNames: []string{"openbao.example.internal"},
	})

	var review bytes.Buffer
	require.NoError(t, runSignEmergencyServer(context.Background(), &review, signEmergencyServerOptions{
		hierarchy: path, csrPath: csr, printTemplate: true, now: fixedNow,
	}))

	text := review.String()
	assert.Contains(t, text, "signed DIRECTLY by the root")
	assert.Contains(t, text, "openbao.example.internal")
	assert.Contains(t, text, "Example Private Root 2026-01")
	assert.Contains(t, text, "2026-12-19T11:00:00Z (168h0m0s)")
	assert.Regexp(t, `--not-before 2026-12-12T11:00:00Z --confirm-template [0-9a-f]{64}`, text)
	assert.Zero(t, client.signCalls)

	out := filepath.Join(t.TempDir(), "tls.crt")
	var signed bytes.Buffer
	require.NoError(t, runSignEmergencyServer(context.Background(), &signed, signEmergencyServerOptions{
		hierarchy: path, csrPath: csr, notBefore: "2026-12-12T11:00:00Z", confirmTemplate: confirmPattern.FindStringSubmatch(text)[1],
		outPath: out, now: fixedNow, signing: signingOptions{kms: client.factory},
	}))
	assert.Equal(t, 1, client.signCalls)
	assert.Contains(t, signed.String(), "written: "+out)
	assert.FileExists(t, out)
}

func TestCreateRootIsIdempotent(t *testing.T) {
	path, client := setup(t)
	createRoot(t, path, client)
	createRoot(t, path, client)
	assert.Equal(t, 1, client.signCalls)

	root, err := ceremony.LoadRootArtifact(filepath.Join(filepath.Dir(path), "roots", "example-root-2026-01.yaml"))
	require.NoError(t, err)
	assert.Equal(t, keyARN, root.KeyARN)
	assert.FileExists(t, filepath.Join(filepath.Dir(path), "roots", "example-root-2026-01.yaml"+ceremony.AttemptSuffix))
}

func fixedNow() time.Time {
	return time.Date(2026, 12, 12, 11, 0, 42, 0, time.UTC)
}
