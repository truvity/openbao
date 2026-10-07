package esoaws

import (
	"fmt"
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
)

var (
	accountIDRe = regexp.MustCompile(`^[0-9]{12}$`)
	partitionRe = regexp.MustCompile(`^aws(-[a-z]+)*$`)
	regionRe    = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)+$`)
	// An IAM role name: at most 64 of these characters.
	roleNameRe = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
	// The resource part of a role ARN: "role/", an optional path and the
	// name. A pattern may carry '*'.
	rolePatternRe = regexp.MustCompile(`^role/[A-Za-z0-9+=,.@_/*-]+$`)
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

// parseRoleARN accepts an IAM role ARN. With patterns, the role's path and
// name may carry '*', but not before a literal character other than '/':
// "role/*" and "role/a/*" would be any role in the account (or under a
// path), which is the account's whole trust, not a list of readers. The
// partition and the account are never patterns.
func parseRoleARN(s string, patterns bool) (arn, error) {
	a, err := parseARN(s)
	if err != nil {
		return arn{}, err
	}

	switch {
	case a.Service != "iam":
		return arn{}, fmt.Errorf("%q is not an IAM ARN", s)
	case a.Region != "":
		return arn{}, fmt.Errorf("%q: an IAM ARN has no region", s)
	case !accountIDRe.MatchString(a.Account):
		return arn{}, fmt.Errorf("%q: account %q is not a 12-digit account id", s, a.Account)
	case !rolePatternRe.MatchString(a.Resource):
		return arn{}, fmt.Errorf("%q is not a role ARN (role/<path><name>)", s)
	case strings.Contains(a.Resource, "//"):
		return arn{}, fmt.Errorf("%q: empty path segment", s)
	}

	name := strings.TrimPrefix(a.Resource, "role/")

	star := strings.IndexByte(name, '*')
	if star < 0 {
		if strings.HasSuffix(name, "/") || !roleNameRe.MatchString(name[strings.LastIndexByte(name, '/')+1:]) {
			return arn{}, fmt.Errorf("%q: the role name is not 1 to 64 of A-Z a-z 0-9 +=,.@_-", s)
		}

		return a, nil
	}

	if !patterns {
		return arn{}, fmt.Errorf("%q: a wildcard is not allowed here; name one role", s)
	}

	if strings.Trim(name[:star], "/") == "" {
		return arn{}, fmt.Errorf("%q matches every role in account %s; name the roles, or a prefix of their names", s, a.Account)
	}

	return a, nil
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
