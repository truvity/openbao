package awsserver

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	polVersion   = "Version"
	polDocDate   = "2012-10-17"
	polStatement = "Statement"
	polSid       = "Sid"
	polEffect    = "Effect"
	polAllow     = "Allow"
	polAction    = "Action"
	polResource  = "Resource"
	polCondition = "Condition"

	snsPublish     = "sns:Publish"
	kmsEncrypt     = "kms:Encrypt"
	kmsDecrypt     = "kms:Decrypt"
	kmsDescribeKey = "kms:DescribeKey"
)

func jsonDoc(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal policy document: %w", err)
	}

	return string(raw), nil
}

// UnsealPolicy is everything the awskms seal calls, on the key and its
// replica and nothing else.
func UnsealPolicy(keyARN, replicaARN string) (string, error) {
	return jsonDoc(map[string]any{
		polVersion: polDocDate,
		polStatement: []map[string]any{{
			polSid:      "OpenBAOAutoUnseal",
			polEffect:   polAllow,
			polAction:   []string{kmsEncrypt, kmsDecrypt, kmsDescribeKey},
			polResource: []string{keyARN, replicaARN},
		}},
	})
}

// SnapshotPolicy lets the snapshot job write new objects under the given
// prefixes of the bucket and encrypt them. No read, no list, no delete: the
// writer cannot see or remove what it wrote. Each prefix is joined to the
// bucket ARN as "<bucketARN>/<prefix>*", so a prefix is written "raft/",
// without a wildcard.
//
// kms:Decrypt is on the key because S3 needs it for a multipart upload into
// an SSE-KMS bucket (it decrypts the data key to encrypt each part); a
// single PUT needs only GenerateDataKey. The chart keeps uploads below 1GB a
// single PUT, and this keeps a larger one from failing on UploadPart. It
// opens no object: the role still has no s3:GetObject.
func SnapshotPolicy(bucketARN, keyARN string, writePrefixes ...string) (string, error) {
	resources := make([]string, 0, len(writePrefixes))
	for _, p := range writePrefixes {
		resources = append(resources, bucketARN+"/"+p+"*")
	}

	return jsonDoc(map[string]any{
		polVersion: polDocDate,
		polStatement: []map[string]any{
			{
				polSid:      "WriteSnapshots",
				polEffect:   polAllow,
				polAction:   []string{"s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"},
				polResource: resources,
			},
			{
				polSid:      "EncryptSnapshots",
				polEffect:   polAllow,
				polAction:   []string{"kms:GenerateDataKey", kmsEncrypt, kmsDecrypt, kmsDescribeKey},
				polResource: keyARN,
			},
		},
	})
}

// RestoreCheckPolicy lets the restore check find and fetch the snapshots
// under snapshotPrefix, decrypt them with the backup key, and seal its
// scratch copy with the unseal key's replica, so every check proves a
// snapshot opens without the primary region. No write, no delete, no other
// prefix, and not the primary unseal key.
func RestoreCheckPolicy(bucketARN, backupKeyARN, replicaKeyARN, snapshotPrefix string) (string, error) {
	return jsonDoc(map[string]any{
		polVersion: polDocDate,
		polStatement: []map[string]any{
			{
				polSid:      "ListSnapshots",
				polEffect:   polAllow,
				polAction:   "s3:ListBucket",
				polResource: bucketARN,
				polCondition: map[string]any{
					"StringLike": map[string]any{"s3:prefix": []string{snapshotPrefix, snapshotPrefix + "*"}},
				},
			},
			{
				polSid:      "ReadSnapshots",
				polEffect:   polAllow,
				polAction:   "s3:GetObject",
				polResource: bucketARN + "/" + snapshotPrefix + "*",
			},
			{
				polSid:      "DecryptSnapshots",
				polEffect:   polAllow,
				polAction:   []string{kmsDecrypt, kmsDescribeKey},
				polResource: backupKeyARN,
			},
			{
				polSid:      "SealTheScratchCopyWithTheReplica",
				polEffect:   polAllow,
				polAction:   []string{kmsEncrypt, kmsDecrypt, kmsDescribeKey},
				polResource: replicaKeyARN,
			},
		},
	})
}

// SnapshotAgePolicy lists the snapshot prefix in each of the given buckets
// and publishes to the one topic. It reads no object and decrypts nothing.
// The prefix condition keeps a listing role from becoming an inventory of
// the whole bucket.
func SnapshotAgePolicy(topicARN, snapshotPrefix string, bucketARNs ...string) (string, error) {
	return jsonDoc(map[string]any{
		polVersion: polDocDate,
		polStatement: []map[string]any{
			{
				polSid:      "ListOpenBAOSnapshots",
				polEffect:   polAllow,
				polAction:   []string{"s3:ListBucket"},
				polResource: bucketARNs,
				polCondition: map[string]any{
					"StringLike": map[string]any{"s3:prefix": snapshotPrefix + "*"},
				},
			},
			{
				polSid:      "PublishOpenBAOSnapshotAge",
				polEffect:   polAllow,
				polAction:   []string{snsPublish},
				polResource: []string{topicARN},
			},
		},
	})
}

// PublishOnlyPolicy is a watch whose whole AWS need is one alert topic.
// sid is the statement's Sid (letters and digits only).
func PublishOnlyPolicy(sid, topicARN string) (string, error) {
	return jsonDoc(map[string]any{
		polVersion: polDocDate,
		polStatement: []map[string]any{{
			polSid:      sid,
			polEffect:   polAllow,
			polAction:   []string{snsPublish},
			polResource: []string{topicARN},
		}},
	})
}

// SubscriptionSlug turns an e-mail address into a Pulumi-name-safe suffix.
func SubscriptionSlug(address string) string {
	return strings.NewReplacer("@", "-at-", ".", "-").Replace(strings.ToLower(address))
}
