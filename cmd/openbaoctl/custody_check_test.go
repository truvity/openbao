package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	contractKeyARN     = "arn:aws:kms:eu-central-1:111122223333:key/mrk-example"
	contractReplicaARN = "arn:aws:kms:eu-north-1:111122223333:key/mrk-example"
	contractRoleARN    = "arn:aws:iam::111122223333:role/example-root-ceremony"
	contractAdminARN   = "arn:aws:iam::111122223333:role/example-root-admin"
	contractProfile    = "example-root@admin"
	otherKeyARN        = "arn:aws:kms:eu-central-1:111122223333:key/mrk-other"
)

func custodyOutputsYAML(replace ...string) string {
	text := `adminRoleArn: ` + contractAdminARN + `
ceremonyRoleArn: ` + contractRoleARN + `
generations:
  example-root-2026-01:
    alias: alias/private-pki/root/example-root-2026-01
    primaryKeyArn: ` + contractKeyARN + `
    primaryRegion: eu-central-1
    replicaKeyArn: ` + contractReplicaARN + `
    replicaRegion: eu-north-1
    ceremonyRoleArn: ` + contractRoleARN + `
`
	for i := 0; i+1 < len(replace); i += 2 {
		text = strings.Replace(text, replace[i], replace[i+1], 1)
	}

	return text
}

func writeCustodyFile(t *testing.T, text string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "custody-outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte(text), 0o644))

	return path
}

func writeCustodyOutputs(t *testing.T) string {
	t.Helper()

	return writeCustodyFile(t, custodyOutputsYAML())
}

// contractRoot is a contract with a committed root, and the intermediate
// options that sign against it: every custody test below varies one input.
func contractRoot(t *testing.T) (signIntermediateOptions, *fakeKMS) {
	t.Helper()

	path, client := setupContract(t)
	createContractRoot(t, path, client)

	csr := writeCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.internal Intermediate CA", Organization: []string{"Example Org"}}})

	return signIntermediateOptions{
		source:      sourceOptions{contract: path, generation: "example-root-2026-01"},
		trustDomain: "private", csrPath: csr, signing: signingOptions{kms: client.factory},
	}, client
}

func review(t *testing.T, options signIntermediateOptions) (string, error) {
	t.Helper()

	options.printTemplate = true

	var out bytes.Buffer
	err := runSignIntermediate(context.Background(), &out, options)

	return out.String(), err
}

func TestCustodyCheckMatchIsPrintedWithTheReview(t *testing.T) {
	options, _ := contractRoot(t)
	options.signing.custodyOutputs = writeCustodyOutputs(t)

	text, err := review(t, options)
	require.NoError(t, err)
	assert.Contains(t, text, "all verified")
	assert.Contains(t, text, contractKeyARN)
	assert.Contains(t, text, "replica region eu-north-1")
	assert.Contains(t, text, "profile "+contractProfile)
	assert.Contains(t, text, "--custody-outputs "+options.signing.custodyOutputs, "the rerun names the same check")
	assert.Regexp(t, confirmPattern, text, "the template hash flow is intact")
}

func TestCustodyCheckSigningAdoptsThePublishedRoleAndProfile(t *testing.T) {
	options, client := contractRoot(t)
	client.signCalls = 0
	options.signing.custodyOutputs = writeCustodyOutputs(t)

	text, err := review(t, options)
	require.NoError(t, err)
	options.confirmTemplate = confirmPattern.FindStringSubmatch(text)[1]

	var out bytes.Buffer
	require.NoError(t, runSignIntermediate(context.Background(), &out, options))
	assert.Equal(t, 1, client.signCalls)
	assert.Contains(t, out.String(), "all verified")
	assert.Equal(t, []string{"eu-central-1"}, client.regions[len(client.regions)-1:])
}

func TestCustodyCheckRefusals(t *testing.T) {
	cases := []struct {
		name    string
		outputs string
		signing func(*signingOptions)
		want    string
	}{
		{
			name: "a different key than the contract's generation publishes",
			outputs: custodyOutputsYAML(
				"primaryKeyArn: "+contractKeyARN, "primaryKeyArn: "+otherKeyARN,
				"replicaKeyArn: "+contractReplicaARN, "replicaKeyArn: arn:aws:kms:eu-north-1:111122223333:key/mrk-other"),
			want: "the key to sign with is " + contractKeyARN + ", but the custody outputs' primary key of generation \"example-root-2026-01\" is " + otherKeyARN,
		},
		{
			name:    "--key-arn that is not the published key",
			outputs: custodyOutputsYAML(),
			signing: func(s *signingOptions) { s.keyARN = "arn:aws:kms:eu-central-1:111122223333:key/mrk-other" },
			want:    "the key to sign with is arn:aws:kms:eu-central-1:111122223333:key/mrk-other",
		},
		{
			name: "an authored generation that is not published",
			outputs: custodyOutputsYAML(
				"generations:\n  example-root-2026-01:", "generations:\n  some-other-root:",
				"root/example-root-2026-01", "root/some-other-root"),
			want: "publish generation \"some-other-root\", which the contract does not author",
		},
		{
			name:    "the wrong primary region",
			outputs: custodyOutputsYAML("primaryRegion: eu-central-1", "primaryRegion: eu-west-1"),
			want:    "is not a multi-region KMS key ARN in eu-west-1",
		},
		{
			name: "a primary region the contract does not author",
			outputs: custodyOutputsYAML(
				contractKeyARN, "arn:aws:kms:eu-west-1:111122223333:key/mrk-example",
				"primaryRegion: eu-central-1", "primaryRegion: eu-west-1"),
			want: "the published primary region is eu-west-1, the contract's custody region is eu-central-1",
		},
		{
			name: "a replica region the contract does not author",
			outputs: custodyOutputsYAML(
				contractReplicaARN, "arn:aws:kms:eu-west-2:111122223333:key/mrk-example",
				"replicaRegion: eu-north-1", "replicaRegion: eu-west-2"),
			want: "the published replica region is eu-west-2, the contract's disaster-recovery region is eu-north-1",
		},
		{
			name:    "a key in another account",
			outputs: strings.NewReplacer("111122223333", "444455556666").Replace(custodyOutputsYAML()),
			want:    "the published key is in account 444455556666, the contract's custody account is 111122223333",
		},
		{
			name:    "--role-arn that is not the ceremony role",
			outputs: custodyOutputsYAML(),
			signing: func(s *signingOptions) { s.roleARN = contractAdminARN },
			want:    "--role-arn is " + contractAdminARN + ", but the custody outputs' ceremony role",
		},
		{
			name:    "a generation's ceremony role that is not the stack's",
			outputs: custodyOutputsYAML("    ceremonyRoleArn: "+contractRoleARN, "    ceremonyRoleArn: "+contractAdminARN),
			want:    "is not the stack's ceremonyRoleArn",
		},
		{
			name:    "one role for both jobs",
			outputs: custodyOutputsYAML("adminRoleArn: "+contractAdminARN, "adminRoleArn: "+contractRoleARN),
			want:    "must be two different roles",
		},
		{
			name:    "--aws-profile that is not the contract's",
			outputs: custodyOutputsYAML(),
			signing: func(s *signingOptions) { s.awsProfile = "someone-elses@admin" },
			want:    "--aws-profile is \"someone-elses@admin\", but the contract's custody profile",
		},
		{
			name:    "an unknown key in the outputs",
			outputs: custodyOutputsYAML() + "surprise: true\n",
			want:    "field surprise not found",
		},
		{
			name:    "primary and replica that are not one key",
			outputs: custodyOutputsYAML(contractReplicaARN, "arn:aws:kms:eu-north-1:111122223333:key/mrk-different"),
			want:    "not the same multi-region key",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			options, client := contractRoot(t)
			client.signCalls = 0
			options.signing.custodyOutputs = writeCustodyFile(t, c.outputs)

			if c.signing != nil {
				c.signing(&options.signing)
			}

			// Refused at the review, and again when signing.
			_, err := review(t, options)
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.want)

			options.confirmTemplate = strings.Repeat("0", 64)

			var out bytes.Buffer
			require.Error(t, runSignIntermediate(context.Background(), &out, options))
			assert.Zero(t, client.signCalls, "a refused check signs nothing")
		})
	}
}

func TestCustodyCheckMissingFileIsRefused(t *testing.T) {
	options, client := contractRoot(t)
	client.signCalls = 0
	options.signing.custodyOutputs = filepath.Join(t.TempDir(), "absent.yaml")

	_, err := review(t, options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absent.yaml")
	assert.Contains(t, err.Error(), "no such file")
	assert.Zero(t, client.signCalls)
}

func TestCustodyCheckIsRequiredWithAContract(t *testing.T) {
	options, client := contractRoot(t)
	client.signCalls = 0

	_, err := review(t, options)
	require.ErrorIs(t, err, errCustodyCheckRequired)

	options.confirmTemplate = strings.Repeat("0", 64)

	var out bytes.Buffer
	require.ErrorIs(t, runSignIntermediate(context.Background(), &out, options), errCustodyCheckRequired)
	assert.Zero(t, client.signCalls)
}

func TestSkipCustodyCheckNeedsAReasonAndIsPrintedInTheReview(t *testing.T) {
	options, client := contractRoot(t)
	client.signCalls = 0
	options.signing.skipCustody = "   "

	_, err := review(t, options)
	require.ErrorContains(t, err, "needs a reason")

	options.signing.skipCustody = "custody outputs not synced yet, drill on a scratch account"
	text, err := review(t, options)
	require.NoError(t, err)
	assert.Contains(t, text, "custody check: SKIPPED, reason: custody outputs not synced yet, drill on a scratch account")
	assert.Contains(t, text, `--skip-custody-check "custody outputs not synced yet, drill on a scratch account"`, "the rerun repeats the skip")

	options.confirmTemplate = confirmPattern.FindStringSubmatch(text)[1]

	var out bytes.Buffer
	require.NoError(t, runSignIntermediate(context.Background(), &out, options))
	assert.Equal(t, 1, client.signCalls)
	assert.Contains(t, out.String(), "SKIPPED, reason: custody outputs not synced yet")
}

func TestCustodyOutputsAndSkipExcludeEachOther(t *testing.T) {
	options, _ := contractRoot(t)
	options.signing.custodyOutputs = writeCustodyOutputs(t)
	options.signing.skipCustody = "because"

	_, err := review(t, options)
	require.ErrorContains(t, err, "exclude each other")
}

func TestCustodyFlagsNeedAContract(t *testing.T) {
	path, client := setup(t)
	createRoot(t, path, client)

	csr := writeCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.internal Intermediate CA", Organization: []string{"Example Org"}}})
	base := signIntermediateOptions{source: sourceOptions{hierarchy: path}, trustDomain: "private", csrPath: csr, printTemplate: true}

	withOutputs := base
	withOutputs.signing.custodyOutputs = writeCustodyOutputs(t)

	var out bytes.Buffer
	require.ErrorContains(t, runSignIntermediate(context.Background(), &out, withOutputs), "need --contract")

	withSkip := base
	withSkip.signing.skipCustody = "why"
	require.ErrorContains(t, runSignIntermediate(context.Background(), &out, withSkip), "need --contract")
}

func TestCustodyCheckGuardsTheEmergencyLeafAndTheRoot(t *testing.T) {
	path, client := setupContract(t)

	var out bytes.Buffer
	// create-root with a key the outputs do not publish signs nothing.
	err := runCreateRoot(context.Background(), &out, createRootOptions{
		source: sourceOptions{contract: path, generation: "example-root-2026-01"},
		signing: signingOptions{
			keyARN: "arn:aws:kms:eu-central-1:111122223333:key/mrk-other", kms: client.factory,
			custodyOutputs: writeCustodyOutputs(t),
		},
	})
	require.ErrorContains(t, err, "the key to sign with is arn:aws:kms:eu-central-1:111122223333:key/mrk-other")
	assert.Zero(t, client.signCalls)

	// and without the check at all.
	err = runCreateRoot(context.Background(), &out, createRootOptions{
		source:  sourceOptions{contract: path, generation: "example-root-2026-01"},
		signing: signingOptions{keyARN: contractKeyARN, kms: client.factory},
	})
	require.ErrorIs(t, err, errCustodyCheckRequired)
	assert.Zero(t, client.signCalls)

	createContractRoot(t, path, client)
	client.signCalls = 0

	csr := writeCSR(t, &x509.CertificateRequest{DNSNames: []string{"emergency.example.internal"}})
	err = runSignEmergencyServer(context.Background(), &out, signEmergencyServerOptions{
		source: sourceOptions{contract: path, generation: "example-root-2026-01"}, dnsName: "emergency.example.internal",
		csrPath: csr, printTemplate: true, now: fixedNow,
	})
	require.ErrorIs(t, err, errCustodyCheckRequired)
}
