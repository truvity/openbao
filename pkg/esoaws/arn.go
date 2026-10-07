package esoaws

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	// DefaultPartition is the AWS partition ARNs are built in when the
	// arguments name none.
	DefaultPartition = "aws"
	// DefaultNamespace is where the External Secrets Operator's controller
	// runs in its upstream chart's defaults.
	DefaultNamespace = "external-secrets"
	// DefaultServiceAccount is the controller's ServiceAccount there.
	DefaultServiceAccount = "external-secrets"
	// DefaultAudience is the audience a web-identity token carries for STS,
	// and the one External Secrets requests when a ServiceAccount names none.
	DefaultAudience = "sts.amazonaws.com"
	// MaxInlinePolicySize is IAM's limit on one role's inline policies, in
	// characters. A document above it is refused before anything registers.
	MaxInlinePolicySize = 10240
)

// IdentityMode is how one cluster's External Secrets proves who it is to
// AWS. The modes are mutually exclusive per cluster, and there is no
// default: the zero value is refused wherever a mode is asked for.
type IdentityMode string

const (
	// PodIdentityMode is the mode where the External Secrets controller holds AWS credentials
	// of its own, through EKS Pod Identity (NewClusterIdentity), and assumes
	// each grant's reader role with them. Its stores name no auth.
	PodIdentityMode IdentityMode = "PodIdentity"
	// WebIdentityMode is the mode where nothing on the cluster holds AWS
	// credentials. Each
	// store names its own ServiceAccount, whose token assumes the store's
	// reader role through the cluster's OIDC issuer, registered in the
	// parameters' account.
	WebIdentityMode IdentityMode = "WebIdentity"
)

// podIdentityTagKeys are the session tags EKS Pod Identity sets: the only
// tags a session that assumes a role of this package may carry, so a store
// cannot add its own (External Secrets' sessionTags) to a reader's session.
var podIdentityTagKeys = []string{
	"eks-cluster-arn", "eks-cluster-name", "kubernetes-namespace",
	"kubernetes-service-account", "kubernetes-pod-name", "kubernetes-pod-uid",
}

var (
	accountIDRe = regexp.MustCompile(`^[0-9]{12}$`)
	partitionRe = regexp.MustCompile(`^aws(-[a-z]+)*$`)
	regionRe    = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)+$`)
	// An IAM role name: at most 64 of these characters.
	roleNameRe = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
	// The resource part of a role ARN: "role/", an optional path and the
	// name.
	roleResourceRe = regexp.MustCompile(`^role/[A-Za-z0-9+=,.@_/-]+$`)
	// An issuer's host and path, as an IAM OIDC provider's URL takes them.
	issuerHostPathRe = regexp.MustCompile(`^[A-Za-z0-9.-]+(/[A-Za-z0-9._~%-]+)*$`)
	// A Kubernetes namespace (DNS-1123 label) and ServiceAccount name
	// (DNS-1123 subdomain).
	namespaceRe      = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	serviceAccountRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	// A certificate thumbprint as IAM takes it: SHA-1, hex.
	thumbprintRe = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	// One parameter name or prefix, without the leading slash of a
	// hierarchical name: letters, digits, '.', '-', '_' and '/'.
	parameterRe = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
)

// arn is a parsed Amazon Resource Name.
type arn struct {
	Partition, Service, Region, Account, Resource string
}

func parseARN(s string) (arn, error) {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return arn{}, fmt.Errorf("%q is not an ARN (arn:<partition>:<service>:<region>:<account>:<resource>)", s)
	}

	a := arn{Partition: parts[1], Service: parts[2], Region: parts[3], Account: parts[4], Resource: parts[5]}

	if !partitionRe.MatchString(a.Partition) {
		return arn{}, fmt.Errorf("%q: partition %q is not an AWS partition", s, a.Partition)
	}

	if a.Resource == "" {
		return arn{}, fmt.Errorf("%q names no resource", s)
	}

	return a, nil
}

// parseRoleARN accepts exactly one IAM role ARN: no wildcard anywhere. A
// reader role's ARN is predictable (arn:<partition>:iam::<account>:role/<name>),
// so a list of them can be written before the roles exist, and a pattern
// would trust every role someone later creates under a matching name.
func parseRoleARN(s string) (arn, error) {
	a, err := parseARN(s)
	if err != nil {
		return arn{}, err
	}

	name := strings.TrimPrefix(a.Resource, "role/")

	switch {
	case a.Service != "iam":
		return arn{}, fmt.Errorf("%q is not an IAM ARN", s)
	case a.Region != "":
		return arn{}, fmt.Errorf("%q: an IAM ARN has no region", s)
	case !accountIDRe.MatchString(a.Account):
		return arn{}, fmt.Errorf("%q: account %q is not a 12-digit account id", s, a.Account)
	case strings.ContainsAny(s, "*?"):
		return arn{}, fmt.Errorf("%q: no wildcards; name one role", s)
	case !roleResourceRe.MatchString(a.Resource):
		return arn{}, fmt.Errorf("%q is not a role ARN (role/<path><name>)", s)
	case strings.Contains(a.Resource, "//"):
		return arn{}, fmt.Errorf("%q: empty path segment", s)
	case strings.HasSuffix(name, "/") || !roleNameRe.MatchString(name[strings.LastIndexByte(name, '/')+1:]):
		return arn{}, fmt.Errorf("%q: the role name is not 1 to 64 of A-Z a-z 0-9 +=,.@_-", s)
	}

	return a, nil
}

// parseIssuer accepts an OIDC issuer URL as IAM registers it: https, a
// host, an optional path, nothing else. It returns the URL without its
// scheme, which is how IAM names the provider and its condition keys.
func parseIssuer(raw string) (string, error) {
	u, err := url.Parse(raw)

	switch {
	case err != nil:
		return "", fmt.Errorf("%q is not a URL: %w", raw, err)
	case u.Scheme != "https":
		return "", fmt.Errorf("%q: an issuer is an https URL", raw)
	case u.Host == "" || u.Port() != "" || u.User != nil:
		return "", fmt.Errorf("%q: an issuer is https://<host>[/<path>], with no port or user", raw)
	case u.RawQuery != "" || u.Fragment != "" || strings.Contains(raw, "?") || strings.Contains(raw, "#"):
		return "", fmt.Errorf("%q: an issuer has no query or fragment", raw)
	case strings.HasSuffix(raw, "/"):
		return "", fmt.Errorf("%q: no trailing slash; the issuer must equal the tokens' iss claim", raw)
	case !issuerHostPathRe.MatchString(u.Host + u.Path):
		return "", fmt.Errorf("%q: the host or path has characters an IAM OIDC provider does not take", raw)
	}

	return strings.ToLower(u.Host) + u.Path, nil
}

// parsePermissionsBoundary accepts an empty string or an IAM managed
// policy's ARN.
func parsePermissionsBoundary(s string) error {
	if s == "" {
		return nil
	}

	a, err := parseARN(s)
	if err != nil {
		return fmt.Errorf("PermissionsBoundary: %w", err)
	}

	if a.Service != "iam" || !strings.HasPrefix(a.Resource, "policy/") || strings.Contains(s, "*") {
		return fmt.Errorf("PermissionsBoundary: %q is not an IAM policy ARN", s)
	}

	return nil
}
