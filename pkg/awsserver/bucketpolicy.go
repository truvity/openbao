package awsserver

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	principalAWS = "AWS"

	polPrincipal = "Principal"

	condPrincipalARN = "aws:PrincipalArn"
	condStringEquals = "StringEquals"
	actListBucket    = "s3:ListBucket"

	denySid = "DenyDeleteObjectVersionFromExternalAccount"

	replicationTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"Service":"s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
)

type (
	// bucketPolicyParams is what the bucket's resource policy is built from.
	bucketPolicyParams struct {
		Partition       string
		BucketName      string
		SourceAccountID string
		BackupAccountID string
		WriterRole      string
		ReaderRole      string
		ListerRoles     []string
		ObjectActions   []string
	}

	policyDocument struct {
		Version   string            `json:"Version"`
		Statement []policyStatement `json:"Statement"`
	}

	policyStatement struct {
		Sid       string         `json:"Sid"`
		Effect    string         `json:"Effect"`
		Principal map[string]any `json:"Principal"`
		Action    any            `json:"Action"`
		Resource  any            `json:"Resource"`
		Condition map[string]any `json:"Condition,omitempty"`
	}
)

func roleARN(partition, account, role string) string {
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, account, role)
}

func rootARN(partition, account string) string {
	return fmt.Sprintf("arn:%s:iam::%s:root", partition, account)
}

func bucketARN(partition, bucket string) string {
	return fmt.Sprintf("arn:%s:s3:::%s", partition, bucket)
}

func exactRole(partition, account, role string) map[string]any {
	return map[string]any{
		condStringEquals: map[string]any{condPrincipalARN: roleARN(partition, account, role)},
	}
}

// buildBucketPolicy constructs the bucket resource policy: the source
// account's writer, reader and listers, and the deny that keeps any other
// account from destroying a version. Only the named roles pass, not the
// whole account: trust principals cannot hold wildcards, so the account root
// is narrowed by an aws:PrincipalArn condition.
func buildBucketPolicy(p bucketPolicyParams) string {
	bucket := bucketARN(p.Partition, p.BucketName)
	source := rootARN(p.Partition, p.SourceAccountID)
	roleCondition := map[string]any{
		"StringLike": map[string]any{condPrincipalARN: roleARN(p.Partition, p.SourceAccountID, p.WriterRole)},
	}

	statements := []policyStatement{
		{
			Sid:       "AllowSourceAccountObjectAccess",
			Effect:    polAllow,
			Principal: map[string]any{principalAWS: source},
			Action:    writerObjectActions(p.ObjectActions),
			Resource:  bucket + "/*",
			Condition: roleCondition,
		},
		{
			Sid:       "AllowSourceAccountListBucket",
			Effect:    polAllow,
			Principal: map[string]any{principalAWS: source},
			Action:    []string{actListBucket, "s3:ListBucketMultipartUploads"},
			Resource:  bucket,
			Condition: roleCondition,
		},
		{
			// Protects immutability: no external account can permanently
			// delete a version.
			Sid:       denySid,
			Effect:    "Deny",
			Principal: map[string]any{principalAWS: "*"},
			Action:    "s3:DeleteObjectVersion",
			Resource:  bucket + "/*",
			Condition: map[string]any{
				"StringNotEquals": map[string]string{"aws:PrincipalAccount": p.BackupAccountID},
			},
		},
	}

	// After the deny, so adding a reader only appends statements.
	if p.ReaderRole != "" {
		cond := exactRole(p.Partition, p.SourceAccountID, p.ReaderRole)
		statements = append(statements,
			policyStatement{
				Sid: "AllowReaderGetObject", Effect: polAllow, Principal: map[string]any{principalAWS: source},
				Action: "s3:GetObject", Resource: bucket + "/*", Condition: cond,
			},
			policyStatement{
				Sid: "AllowReaderListBucket", Effect: polAllow, Principal: map[string]any{principalAWS: source},
				Action: actListBucket, Resource: bucket, Condition: cond,
			},
		)
	}

	statements = append(statements, listerStatements(p.Partition, bucket, p.SourceAccountID, p.ListerRoles)...)

	data, _ := json.MarshalIndent(policyDocument{Version: polDocDate, Statement: statements}, "", "  ")

	return string(data)
}

// buildReplicaPolicy is the replica's resource policy: the delete-version
// deny and one list-only grant per lister.
func buildReplicaPolicy(partition, replica, sourceAccountID, backupAccountID string, listers []string) (string, error) {
	arn := bucketARN(partition, replica)
	statements := []policyStatement{{
		Sid:       denySid,
		Effect:    "Deny",
		Principal: map[string]any{principalAWS: "*"},
		Action:    "s3:DeleteObjectVersion",
		Resource:  arn + "/*",
		Condition: map[string]any{
			"StringNotEquals": map[string]string{"aws:PrincipalAccount": backupAccountID},
		},
	}}
	statements = append(statements, listerStatements(partition, arn, sourceAccountID, listers)...)

	raw, err := json.MarshalIndent(policyDocument{Version: polDocDate, Statement: statements}, "", "  ")

	return string(raw), err
}

// listerStatements is one list-only grant per lister role. The bucket is the
// resource and s3:ListBucket the only action, so no statement here can reach
// an object; the role's own identity policy narrows the prefix.
func listerStatements(partition, bucket, sourceAccountID string, listers []string) []policyStatement {
	statements := make([]policyStatement, 0, len(listers))

	for _, role := range listers {
		statements = append(statements, policyStatement{
			Sid:       "AllowListerListBucket" + sidSuffix(role),
			Effect:    polAllow,
			Principal: map[string]any{principalAWS: rootARN(partition, sourceAccountID)},
			Action:    actListBucket,
			Resource:  bucket,
			Condition: exactRole(partition, sourceAccountID, role),
		})
	}

	return statements
}

// sidSuffix turns a role name into the CamelCase tail of a Sid, which may
// hold letters and digits only.
func sidSuffix(role string) string {
	var b strings.Builder

	upper := true

	for _, r := range role {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			if upper {
				b.WriteString(strings.ToUpper(string(r)))
				upper = false
			} else {
				b.WriteRune(r)
			}
		default:
			upper = true
		}
	}

	return b.String()
}

// writerObjectActions is the writer's object grant: the default set unless
// the caller names its own.
func writerObjectActions(override []string) []string {
	if override != nil {
		return override
	}

	return []string{
		"s3:PutObject",
		"s3:GetObject",
		"s3:DeleteObject",
		"s3:AbortMultipartUpload",
		"s3:ListMultipartUploadParts",
	}
}

// buildKeyPolicy admits the backup account's administrators (key
// management), the source account's writer roles (encrypt and decrypt) and,
// when named, one reader role (decrypt only): the second gate on top of the
// bucket policy.
func buildKeyPolicy(partition, sourceAccountID, backupAccountID, writerRole, readerRole string) string {
	source := rootARN(partition, sourceAccountID)
	statements := []map[string]any{
		{
			polSid:       "BackupAccountKeyAdmin",
			polEffect:    polAllow,
			polPrincipal: map[string]any{principalAWS: rootARN(partition, backupAccountID)},
			polAction:    "kms:*",
			polResource:  "*",
		},
		{
			polSid:       "WorkloadBackupRolesUseKey",
			polEffect:    polAllow,
			polPrincipal: map[string]any{principalAWS: source},
			polAction: []string{
				kmsEncrypt, kmsDecrypt, "kms:ReEncrypt*",
				"kms:GenerateDataKey*", kmsDescribeKey,
			},
			polResource: "*",
			polCondition: map[string]any{
				"StringLike": map[string]any{condPrincipalARN: roleARN(partition, sourceAccountID, writerRole)},
			},
		},
	}

	if readerRole != "" {
		statements = append(statements, map[string]any{
			polSid:       "WorkloadReaderRoleDecrypts",
			polEffect:    polAllow,
			polPrincipal: map[string]any{principalAWS: source},
			polAction:    []string{kmsDecrypt, kmsDescribeKey},
			polResource:  "*",
			polCondition: exactRole(partition, sourceAccountID, readerRole),
		})
	}

	raw, err := json.MarshalIndent(map[string]any{polVersion: polDocDate, polStatement: statements}, "", "  ")
	if err != nil {
		panic(err)
	}

	return string(raw)
}

// buildReplicationPolicy is the replication role's policy: replicate from
// the primary to the replica and use both keys, never IAM writes.
func buildReplicationPolicy(src, dst, srcKey, dstKey string, objectLock bool) (string, error) {
	doc := map[string]any{
		polVersion: polDocDate,
		polStatement: []map[string]any{
			{polEffect: polAllow, polAction: []string{"s3:GetReplicationConfiguration", actListBucket}, polResource: src},
			{polEffect: polAllow, polAction: replicationSourceActions(objectLock), polResource: src + "/*"},
			{polEffect: polAllow, polAction: []string{"s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"}, polResource: dst + "/*"},
			{polEffect: polAllow, polAction: kmsDecrypt, polResource: srcKey},
			{polEffect: polAllow, polAction: []string{"kms:Encrypt", "kms:GenerateDataKey*"}, polResource: dstKey},
		},
	}
	raw, err := json.Marshal(doc)

	return string(raw), err
}

// replicationSourceActions adds the retention reads S3 needs to replicate
// Object-Locked objects; without a lock the list is unchanged.
func replicationSourceActions(objectLock bool) []string {
	actions := []string{
		"s3:GetObjectVersionForReplication",
		"s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging",
	}
	if objectLock {
		actions = append(actions, "s3:GetObjectRetention", "s3:GetObjectLegalHold")
	}

	return actions
}
