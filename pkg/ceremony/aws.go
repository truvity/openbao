package ceremony

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type (
	// KMSClientOptions is how a ceremony reaches the root key: a shared
	// AWS profile (empty for the default chain), the key's region, and the
	// ceremony role assumed on top of that profile (empty to sign with the
	// profile's own identity).
	KMSClientOptions struct {
		Profile string
		Region  string
		RoleARN string
	}
)

// KMSClient builds the KMS client a ceremony signs with. Nothing else about
// the key is configurable here: the key ARN goes to the ceremony itself, and
// the key policy decides whether the resulting identity may sign.
func KMSClient(ctx context.Context, options KMSClientOptions) (*kms.Client, error) {
	if options.Region == "" {
		return nil, fmt.Errorf("the KMS key's region is required")
	}

	loaders := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(options.Region)}
	if options.Profile != "" {
		loaders = append(loaders, awsconfig.WithSharedConfigProfile(options.Profile))
	}

	baseConfig, err := awsconfig.LoadDefaultConfig(ctx, loaders...)
	if err != nil {
		return nil, fmt.Errorf("load AWS profile %s: %w", options.Profile, err)
	}

	if options.RoleARN != "" {
		assumeRole := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(baseConfig), options.RoleARN)
		baseConfig.Credentials = aws.NewCredentialsCache(assumeRole)
	}

	return kms.NewFromConfig(baseConfig), nil
}

// KeyRegion is the region a KMS key ARN names; a multi-region key's primary
// and replica have one ARN each.
func KeyRegion(keyARN string) (string, error) {
	parsed, err := arn.Parse(keyARN)
	if err != nil {
		return "", fmt.Errorf("key %q is not an ARN: %w", keyARN, err)
	}

	if parsed.Service != "kms" || parsed.Region == "" {
		return "", fmt.Errorf("key %q is not a regional KMS key ARN", keyARN)
	}

	return parsed.Region, nil
}
