package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

// loginRequest is OpenBAO's AWS IAM auth login body (`auth/<mount>/login`,
// `auth_type=iam`): a caller's own signed STS `GetCallerIdentity` request,
// handed over whole so OpenBAO can replay it against AWS and learn who
// signed it -- never a bearer credential of the caller's own. See
// https://openbao.org/api-docs/auth/aws/#login and truvity/openbao's own
// pkg/model.AWSAuthMount doc comment (this tool is that mount's one
// intended caller).
type loginRequest struct {
	Role                 string `json:"role"`
	IAMHTTPRequestMethod string `json:"iam_http_request_method"`
	IAMRequestURL        string `json:"iam_request_url"`
	IAMRequestBody       string `json:"iam_request_body"`
	IAMRequestHeaders    string `json:"iam_request_headers"`
}

// awsLogin builds one [loginRequest]. Its only implementation in
// production is [stsLogin]; renew_test.go's fakeAWSLogin replaces it so
// the renewal logic is tested with no real AWS account, credential or
// network call in reach -- the instance-role credential chain (IMDSv2)
// this tool actually runs under on a real router is the one piece
// nothing in this repository's test suite can stand in for; see this
// package's own doc comment for exactly what that leaves unproved.
type awsLogin interface {
	Login(ctx context.Context, role, serverIDHeader string) (loginRequest, error)
}

const (
	// stsEndpoint and stsSigningRegion are the AWS-global STS endpoint
	// and its signing region -- what OpenBAO's aws auth backend replays
	// a login against by default (no sts_endpoint/sts_region override on
	// AWSAuthMount's client configuration). A regional endpoint would
	// need the mount configured to match; this tool assumes the default.
	stsEndpoint      = "https://sts.amazonaws.com/"
	stsSigningRegion = "us-east-1"
	// stsBody is the one request AWS's IAM auth method ever asks a
	// caller to sign, in the exact wire form OpenBAO forwards to AWS for
	// verification: STS's query-protocol body for GetCallerIdentity, a
	// POST with the parameters as form-encoded content -- never a
	// query-string GET. A SigV4 "presigned URL" (query-string signing,
	// no Authorization header) is the wrong signing mode here: OpenBAO
	// needs to replay an ordinary signed REQUEST, headers and body both,
	// byte for byte.
	stsBody = "Action=GetCallerIdentity&Version=2011-06-15"
)

// stsLogin signs an ordinary (non-presigned) STS GetCallerIdentity POST
// with the process's own AWS credentials -- on an EC2 instance, IMDSv2-
// derived instance-role credentials, resolved by the SDK's default
// credential chain with no code here naming IMDS at all
// (config.LoadDefaultConfig's own EC2 instance-role provider). The
// X-Vault-AWS-IAM-Server-ID header is set on the request BEFORE signing,
// so SigV4 covers it: exactly what a mount pinning
// AWSAuthMount.IAMServerIDHeaderValue checks for on the OpenBAO side
// (truvity/openbao docs/safety.md "AWS IAM auth").
type stsLogin struct{}

func (stsLogin) Login(ctx context.Context, role, serverIDHeader string) (loginRequest, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return loginRequest{}, fmt.Errorf("load AWS config: %w", err)
	}

	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return loginRequest{}, fmt.Errorf("retrieve AWS credentials (IMDSv2 instance role): %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stsEndpoint, strings.NewReader(stsBody))
	if err != nil {
		return loginRequest{}, fmt.Errorf("build STS request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Vault-AWS-IAM-Server-ID", serverIDHeader)

	sum := sha256.Sum256([]byte(stsBody))
	payloadHash := hex.EncodeToString(sum[:])

	if err := v4.NewSigner().SignHTTP(ctx, creds, req, payloadHash, "sts", stsSigningRegion, time.Now()); err != nil {
		return loginRequest{}, fmt.Errorf("sign STS request: %w", err)
	}

	headers := make(map[string][]string, len(req.Header))
	for name, values := range req.Header {
		headers[name] = values
	}

	headerJSON, err := json.Marshal(headers)
	if err != nil {
		return loginRequest{}, fmt.Errorf("encode signed headers: %w", err)
	}

	return loginRequest{
		Role:                 role,
		IAMHTTPRequestMethod: http.MethodPost,
		IAMRequestURL:        base64.StdEncoding.EncodeToString([]byte(stsEndpoint)),
		IAMRequestBody:       base64.StdEncoding.EncodeToString([]byte(stsBody)),
		IAMRequestHeaders:    base64.StdEncoding.EncodeToString(headerJSON),
	}, nil
}
