package custody

import (
	"encoding/json"
	"fmt"
)

const (
	policyVersionKey      = "Version"
	policyStatementKey    = "Statement"
	policySidKey          = "Sid"
	policyEffectKey       = "Effect"
	policyPrincipalKey    = "Principal"
	policyActionKey       = "Action"
	policyResourceKey     = "Resource"
	policyConditionKey    = "Condition"
	policyStringEqualsKey = "StringEquals"
	policyArnLikeKey      = "ArnLike"
	policyPrincipalARNKey = "aws:PrincipalArn"
	policyAWSKey          = "AWS"
	policyAllow           = "Allow"
	policyVersion         = "2012-10-17"
	kmsDescribeKey        = "kms:DescribeKey"
	kmsSigningAlgorithm   = "kms:SigningAlgorithm"
	ecdsaSHA384           = "ECDSA_SHA_384"
)

var (
	// adminActions is administration without signing, deletion
	// scheduling, grant creation or key-policy writes.
	adminActions = []string{
		"kms:CancelKeyDeletion",
		"kms:CreateAlias",
		"kms:DeleteAlias",
		kmsDescribeKey,
		"kms:DisableKey",
		"kms:EnableKey",
		"kms:GetKeyPolicy",
		// The four the AWS provider reads back after every create and
		// update -- DescribeKey, GetKeyPolicy, GetKeyRotationStatus and
		// ListResourceTags. A key policy that omits one fails the apply
		// AFTER the key exists, which is the worst moment to find out.
		// GetKeyRotationStatus is asked even of a SIGN_VERIFY key, which
		// cannot rotate.
		"kms:GetKeyRotationStatus",
		"kms:ListKeyPolicies",
		"kms:ListResourceTags",
		"kms:ReplicateKey",
		"kms:TagResource",
		"kms:UntagResource",
		"kms:UpdateAlias",
		"kms:UpdateKeyDescription",
		"kms:UpdatePrimaryRegion",
	}
	ceremonyReadActions = []string{kmsDescribeKey, "kms:GetPublicKey"}
)

// arn composes an ARN from its parts. Composed, never written out: this
// package takes every account, region and name as an input.
func arn(partition, service, region, account, resource string) string {
	return "arn:" + partition + ":" + service + ":" + region + ":" + account + ":" + resource
}

// roleTrustPolicy lets exactly the trusted human principals of the account
// assume a custody role.
func roleTrustPolicy(partition, accountID, trustedPrincipalARNPattern string) (string, error) {
	return marshalPolicy(map[string]any{
		policyVersionKey: policyVersion,
		policyStatementKey: []map[string]any{{
			policySidKey:       "ApprovedSSOAdminAssumeRole",
			policyEffectKey:    policyAllow,
			policyPrincipalKey: map[string]any{policyAWSKey: arn(partition, "iam", "", accountID, "root")},
			policyActionKey:    "sts:AssumeRole",
			policyConditionKey: map[string]any{
				policyArnLikeKey: map[string]any{policyPrincipalARNKey: trustedPrincipalARNPattern},
			},
		}},
	})
}

// keyPolicy is the key's own authority, and it is the WHOLE authority: a
// KMS key policy that does not name a principal means no IAM policy can
// grant that principal anything, however privileged it is.
//
// That is why the trusted administrator appears here as well as the admin
// role it may assume. The custody is applied from that session, and the
// AWS provider reads a key's tags and policy straight back after creating
// it -- so a policy naming only the admin role leaves the provider unable
// to finish creating the key it has just made, with the key created and
// the apply failed. It is not a widening: the admin role's trust policy
// admits exactly this pattern, so the same human already holds these
// actions one `sts:AssumeRole` away. Signing, deletion scheduling, grant
// creation and key-policy writes stay out of both.
//
// The account-root statement is the break-glass: it can read and rewrite
// the policy and nothing else, so a policy that locked everyone out can be
// repaired without the key being unrecoverable.
func keyPolicy(partition, accountID, trustedPrincipalARNPattern, adminRoleARN, ceremonyRoleARN string) (string, error) {
	accountRoot := arn(partition, "iam", "", accountID, "root")
	return marshalPolicy(map[string]any{
		policyVersionKey: policyVersion,
		policyStatementKey: []map[string]any{
			{
				policySidKey:       "BreakGlassPolicyRecovery",
				policyEffectKey:    policyAllow,
				policyPrincipalKey: map[string]any{policyAWSKey: accountRoot},
				policyActionKey:    []string{kmsDescribeKey, "kms:GetKeyPolicy", "kms:PutKeyPolicy"},
				policyResourceKey:  "*",
			},
			{
				policySidKey:       "KeyAdministrationWithoutSigningOrDeletion",
				policyEffectKey:    policyAllow,
				policyPrincipalKey: map[string]any{policyAWSKey: adminRoleARN},
				policyActionKey:    adminActions,
				policyResourceKey:  "*",
			},
			{
				policySidKey:       "KeyAdministrationByApprovedSSOAdmin",
				policyEffectKey:    policyAllow,
				policyPrincipalKey: map[string]any{policyAWSKey: accountRoot},
				policyActionKey:    adminActions,
				policyResourceKey:  "*",
				policyConditionKey: map[string]any{
					policyArnLikeKey: map[string]any{policyPrincipalARNKey: trustedPrincipalARNPattern},
				},
			},
			{
				policySidKey:       "ExplicitRootCeremonyRead",
				policyEffectKey:    policyAllow,
				policyPrincipalKey: map[string]any{policyAWSKey: ceremonyRoleARN},
				policyActionKey:    ceremonyReadActions,
				policyResourceKey:  "*",
			},
			{
				policySidKey:       "ExplicitRootCeremonySign",
				policyEffectKey:    policyAllow,
				policyPrincipalKey: map[string]any{policyAWSKey: ceremonyRoleARN},
				policyActionKey:    "kms:Sign",
				policyResourceKey:  "*",
				policyConditionKey: map[string]any{
					policyStringEqualsKey: map[string]any{kmsSigningAlgorithm: ecdsaSHA384},
				},
			},
		},
	})
}

func marshalPolicy(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal policy: %w", err)
	}
	return string(raw), nil
}
