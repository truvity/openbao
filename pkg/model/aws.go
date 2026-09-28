package model

import (
	"fmt"
	"strings"
)

// arnPrefix is the one shape [AWSAuthRole.BoundIAMPrincipalARNs] admits:
// a literal IAM role or user ARN, never a pattern.
const arnPrefix = "arn:aws:iam::"

type (
	// AWSAuthMount is one AWS auth backend: a host proves who it is by
	// signing an STS `GetCallerIdentity` request with its own IAM
	// credentials and handing OpenBAO the signed request instead of a
	// bearer token ([AWS's IAM auth
	// method](https://openbao.org/docs/auth/aws/)). This model supports
	// the `iam` auth type only -- never `ec2` (the EC2 instance-metadata
	// variant), which a caller with SSRF into the instance can also read,
	// and which cannot express a login from outside AWS's own metadata
	// service.
	//
	// A login carries no group and joins no identity group: every role on
	// this mount is a WORKLOAD role, the same shape [JWTMount]'s
	// BoundSubject roles are, and is granted through TokenPolicies
	// directly rather than through a group alias.
	AWSAuthMount struct {
		Path        string `yaml:"path"`
		Description string `yaml:"description,omitempty"`
		// IAMServerIDHeaderValue is the value every login's signed request
		// must carry in its `X-Vault-AWS-IAM-Server-ID` header. Required:
		// a mount with no pinned value accepts a `GetCallerIdentity`
		// request signed for ANY other AWS IAM auth mount, anywhere, that
		// the caller can obtain -- pinning it to a value unique to this
		// mount is what stops such a request from being replayed here.
		IAMServerIDHeaderValue string        `yaml:"iamServerIdHeaderValue"`
		Roles                  []AWSAuthRole `yaml:"roles"`
	}

	// AWSAuthRole is one `iam`-type role: it admits a login whose signed
	// request resolves to one of BoundIAMPrincipalARNs, and grants it
	// Policies directly.
	AWSAuthRole struct {
		Name string `yaml:"name"`
		// BoundIAMPrincipalARNs are the IAM role or user ARNs a login may
		// resolve to, spelled out in full: no wildcard. Typically one
		// instance role's ARN.
		BoundIAMPrincipalARNs []string `yaml:"boundIamPrincipalArns"`
		// ResolveAWSUniqueIDs, when true, has OpenBAO resolve each of
		// BoundIAMPrincipalARNs to AWS's own unique ID
		// (`iam:GetRole`/`iam:GetUser`) once, at role-write time, and bind
		// the login to that ID rather than the ARN: a role or user later
		// deleted and recreated under the same name -- a different
		// principal, by AWS's own accounting -- no longer matches. This
		// needs an `iam:GetRole` (or `iam:GetUser`) grant, on the account
		// the ARN names, for whatever AWS credential OpenBAO's own AWS
		// auth CLIENT configuration uses -- a grant that does not exist by
		// virtue of this role alone, and, when the account is not the one
		// OpenBAO itself runs in, is a cross-account grant this model
		// does not create. false keeps the match on the ARN string alone
		// (OpenBAO's own default, before this field's Terraform/OpenTofu
		// provider default of true) -- weaker against a role recreated
		// under the same name, but the recreation is itself an audited
		// IAM change that already needs review, and asking for no new
		// grant is the more conservative default for a role whose
		// account may not be the one OpenBAO's own credential can read.
		ResolveAWSUniqueIDs bool `yaml:"resolveAwsUniqueIds"`
		// Policies are attached to the token directly -- no group, no
		// alias: an AWS login authenticates a host, not a person.
		Policies []string `yaml:"policies"`
		TTL      string   `yaml:"ttl"`
		MaxTTL   string   `yaml:"maxTtl"`
	}
)

// Validate refuses a mount with no path, no pinned server-id header value,
// no role, or the same role name twice.
func (m *AWSAuthMount) Validate() error {
	if strings.TrimSpace(m.Path) == "" {
		return fmt.Errorf("an AWS auth mount has no path")
	}

	if strings.TrimSpace(m.IAMServerIDHeaderValue) == "" {
		return fmt.Errorf("AWS auth mount %q pins no iamServerIdHeaderValue, so a signed login meant for another mount would be accepted here", m.Path)
	}

	if len(m.Roles) == 0 {
		return fmt.Errorf("AWS auth mount %q has no role", m.Path)
	}

	seen := make(map[string]bool, len(m.Roles))

	for i := range m.Roles {
		if err := m.Roles[i].Validate(); err != nil {
			return fmt.Errorf("AWS auth mount %q: %w", m.Path, err)
		}

		if seen[m.Roles[i].Name] {
			return fmt.Errorf("AWS auth mount %q declares role %q twice", m.Path, m.Roles[i].Name)
		}

		seen[m.Roles[i].Name] = true
	}

	return nil
}

// Validate refuses a role with no name, no bound principal, a principal
// that is a wildcard or not an IAM ARN, a role that grants no policy (an
// AWS login that could authenticate but do nothing is a login this model
// refuses to declare, the same as a JWT role would need at least a subject
// or a groups claim), and a lifetime with no end.
func (r *AWSAuthRole) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("an AWS auth role has no name")
	}

	if len(r.BoundIAMPrincipalARNs) == 0 {
		return fmt.Errorf("AWS auth role %q binds no IAM principal, so it could admit any login this mount signs", r.Name)
	}

	for _, arn := range r.BoundIAMPrincipalARNs {
		switch {
		case strings.TrimSpace(arn) == "":
			return fmt.Errorf("AWS auth role %q binds an empty principal", r.Name)
		case strings.Contains(arn, "*"):
			return fmt.Errorf("AWS auth role %q binds %q, which is a wildcard pattern, not a literal ARN", r.Name, arn)
		case !strings.HasPrefix(arn, arnPrefix):
			return fmt.Errorf("AWS auth role %q binds %q, which is not an IAM ARN (%s...)", r.Name, arn, arnPrefix)
		}
	}

	if len(r.Policies) == 0 {
		return fmt.Errorf("AWS auth role %q grants no policy, so a login could authenticate and do nothing", r.Name)
	}

	return lifetime("AWS auth role "+r.Name, r.TTL, r.MaxTTL)
}
