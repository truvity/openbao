package esoaws

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type (
	// ReadersArgs configures NewReaders, which runs in the account that
	// holds the parameters.
	ReadersArgs struct {
		// Name is the component's logical name.
		Name string
		// Provider is the AWS provider of the parameters' account. Required.
		Provider pulumi.ProviderResource
		// AccountID, Region and Partition (empty: DefaultPartition) are the
		// parameters' account and region: every parameter ARN a grant's
		// policy names is built in them, and a parameter given as an ARN
		// must be in them.
		AccountID string
		Region    string
		Partition string
		// Grants are the reader roles, one per grant. At least one.
		Grants []Grant
		// PermissionsBoundary is the boundary policy's ARN put on every
		// reader role; empty sets none.
		PermissionsBoundary string
		// Tags are put on every reader role.
		Tags map[string]string
	}

	// Grant is one reader role: who may assume it, and what it reads.
	Grant struct {
		// Name is the IAM role's name, its logical name, and its key in
		// Readers.RoleARNs. The inline policy is "<Name>-policy".
		Name string
		// Principal is the role allowed to assume this one: a cluster's
		// ClusterIdentity.RoleARN. Exactly one role ARN, no wildcard. The
		// role must exist when the grant is created; IAM refuses a trust in
		// a principal it cannot resolve.
		Principal string
		// Parameters are what the role reads. An entry ending in "/" is a
		// prefix ("/app/config/": every parameter under that path, at any
		// depth, and GetParametersByPath on it); any other entry is one
		// parameter's exact name ("/app/config/token", or "token" for a
		// name outside any hierarchy). An entry may also be the parameter's
		// ARN, which must then be in AccountID and Region. No wildcards, and
		// no prefix of the whole account ("/").
		Parameters []string
		// KMSKeyARN is the customer-managed key the parameters' SecureStrings
		// are encrypted with, if they use one: the role then gets kms:Decrypt
		// on it, through SSM only and for these parameters only. Empty for
		// the account's default aws/ssm key, which needs no grant: its key
		// policy lets any principal of the account decrypt through SSM, and
		// the reader role is in the account. A key in another account works
		// only if its key policy admits the role.
		KMSKeyARN string
	}

	// Readers is the source side: one reader role per grant.
	Readers struct {
		pulumi.ResourceState

		// RoleARNs is each grant's role ARN by grant name: the `role` of the
		// cluster's store for that grant.
		RoleARNs map[string]pulumi.StringOutput
	}

	// parameter is one validated entry of Grant.Parameters: the part of
	// its ARN after "parameter/", which for a prefix ends in "/".
	parameter struct {
		resource string
		prefix   bool
	}
)

func (a ReadersArgs) withDefaults() ReadersArgs {
	if a.Partition == "" {
		a.Partition = DefaultPartition
	}

	return a
}

func (a ReadersArgs) validate() error {
	var errs []error

	if a.Name == "" {
		errs = append(errs, errors.New("args.Name is empty"))
	}

	if a.Provider == nil {
		errs = append(errs, errors.New("args.Provider is nil"))
	}

	if len(a.Grants) == 0 {
		errs = append(errs, errors.New("args.Grants is empty: a source that grants nothing should not be declared"))
	}

	if err := a.validateSource(); err != nil {
		// The grants' checks compare against the source's fields.
		return errors.Join(append(errs, err)...)
	}

	seen := map[string]bool{}

	for i, g := range a.Grants {
		if seen[g.Name] {
			errs = append(errs, fmt.Errorf("args.Grants[%d]: duplicate name %q", i, g.Name))
		}

		seen[g.Name] = true

		if _, err := a.parameters(g); err != nil {
			errs = append(errs, fmt.Errorf("args.Grants[%d] (%s): %w", i, g.Name, err))
		}
	}

	return errors.Join(errs...)
}

// validateSource checks the fields every grant is built in.
func (a ReadersArgs) validateSource() error {
	var errs []error

	if !accountIDRe.MatchString(a.AccountID) {
		errs = append(errs, fmt.Errorf("AccountID %q is not a 12-digit account id", a.AccountID))
	}

	if !regionRe.MatchString(a.Region) {
		errs = append(errs, fmt.Errorf("args.Region %q is not an AWS region", a.Region))
	}

	if !partitionRe.MatchString(a.Partition) {
		errs = append(errs, fmt.Errorf("args.Partition %q is not an AWS partition", a.Partition))
	}

	if err := parsePermissionsBoundary(a.PermissionsBoundary); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// parameters validates a grant against the source and returns its
// parameters, in the order given.
func (a ReadersArgs) parameters(g Grant) ([]parameter, error) {
	var errs []error

	if !roleNameRe.MatchString(g.Name) {
		errs = append(errs, fmt.Errorf("grant.Name %q is not an IAM role name (1 to 64 of A-Z a-z 0-9 +=,.@_-)", g.Name))
	}

	if p, err := parseRoleARN(g.Principal, false); err != nil {
		errs = append(errs, fmt.Errorf("grant.Principal: %w", err))
	} else if p.Partition != a.Partition {
		errs = append(errs, fmt.Errorf("grant.Principal %q is not in partition %s", g.Principal, a.Partition))
	}

	if g.KMSKeyARN != "" {
		if err := a.checkKey(g.KMSKeyARN); err != nil {
			errs = append(errs, err)
		}
	}

	if len(g.Parameters) == 0 {
		errs = append(errs, errors.New("grant.Parameters is empty: a reader that reads nothing should not be declared"))
	}

	out := make([]parameter, 0, len(g.Parameters))

	for i, entry := range g.Parameters {
		p, err := a.parseParameter(entry)
		if err != nil {
			errs = append(errs, fmt.Errorf("grant.Parameters[%d]: %w", i, err))

			continue
		}

		for _, q := range out {
			switch {
			case p == q:
				err = fmt.Errorf("grant.Parameters[%d]: %q is listed twice", i, entry)
			case q.prefix && strings.HasPrefix(p.resource, q.resource):
				err = fmt.Errorf("grant.Parameters[%d]: %q is already covered by the prefix %q", i, entry, "/"+q.resource)
			case p.prefix && strings.HasPrefix(q.resource, p.resource):
				err = fmt.Errorf("grant.Parameters[%d]: the prefix %q covers %q, listed before it", i, entry, "/"+q.resource)
			}
		}

		if err != nil {
			errs = append(errs, err)

			continue
		}

		out = append(out, p)
	}

	return out, errors.Join(errs...)
}

// parseParameter turns one entry of Grant.Parameters into the part of its
// ARN after "parameter/". A hierarchical name's leading slash is not in the
// ARN; a name outside any hierarchy has none to drop.
func (a ReadersArgs) parseParameter(entry string) (parameter, error) {
	resource := entry

	switch {
	case strings.HasPrefix(entry, "arn:"):
		p, err := parseARN(entry)
		if err != nil {
			return parameter{}, err
		}

		if p.Service != "ssm" || !strings.HasPrefix(p.Resource, "parameter/") {
			return parameter{}, fmt.Errorf("%q is not an SSM parameter ARN", entry)
		}

		if p.Partition != a.Partition || p.Account != a.AccountID || p.Region != a.Region {
			return parameter{}, fmt.Errorf("%q is not in this source's account and region (%s, %s): a reader role reads only its own account's parameters",
				entry, a.AccountID, a.Region)
		}

		resource = strings.TrimPrefix(p.Resource, "parameter/")
	case strings.HasPrefix(entry, "/"):
		resource = entry[1:]
	case strings.Contains(entry, "/"):
		return parameter{}, fmt.Errorf("%q: a hierarchical name starts with \"/\"", entry)
	}

	prefix := strings.HasSuffix(entry, "/")

	switch {
	case entry == "":
		return parameter{}, errors.New("empty entry")
	case strings.ContainsAny(resource, "*?"):
		return parameter{}, fmt.Errorf("%q: no wildcards; end a prefix with \"/\" instead", entry)
	case prefix && strings.Trim(resource, "/") == "":
		return parameter{}, fmt.Errorf("%q is a prefix of every parameter in the account; name a path", entry)
	case resource == "" || !parameterRe.MatchString(resource):
		return parameter{}, fmt.Errorf("%q is not a parameter name (letters, digits, '.', '-', '_' and '/')", entry)
	case strings.HasPrefix(resource, "/") || strings.Contains(resource, "//"):
		return parameter{}, fmt.Errorf("%q: empty path segment", entry)
	}

	return parameter{resource: resource, prefix: prefix}, nil
}

// checkKey accepts a KMS key ARN (not an alias: IAM matches a key's ARN) in
// this source's partition and region, where SSM looks for it.
func (a ReadersArgs) checkKey(s string) error {
	k, err := parseARN(s)
	if err != nil {
		return fmt.Errorf("KMSKeyARN: %w", err)
	}

	switch {
	case k.Service != "kms" || !strings.HasPrefix(k.Resource, "key/") || strings.ContainsAny(s, "*?"):
		return fmt.Errorf("KMSKeyARN %q is not a KMS key ARN (key/<id>; an alias is not matched by IAM)", s)
	case !accountIDRe.MatchString(k.Account):
		return fmt.Errorf("KMSKeyARN %q: account %q is not a 12-digit account id", s, k.Account)
	case k.Partition != a.Partition || k.Region != a.Region:
		return fmt.Errorf("KMSKeyARN %q is not in this source's region %s: SSM decrypts with a key in its own region", s, a.Region)
	}

	return nil
}

func (a ReadersArgs) parameterARN(resource string) string {
	return fmt.Sprintf("arn:%s:ssm:%s:%s:parameter/%s", a.Partition, a.Region, a.AccountID, resource)
}

// ReaderTrustPolicy is a reader role's trust document: exactly the one
// principal, for AssumeRole and for the transitive session tags EKS Pod
// Identity sets on the session that assumes it.
func ReaderTrustPolicy(principal string) (string, error) {
	return jsonDoc(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Sid":       "ExternalSecretsOperator",
			"Effect":    "Allow",
			"Principal": map[string]any{"AWS": principal},
			"Action":    []string{"sts:AssumeRole", "sts:TagSession"},
		}},
	})
}

// ReaderPolicy is a grant's permission document, built in the source's
// account and region: GetParameter and GetParameters on each exact
// parameter and under each prefix; GetParametersByPath on the prefixes
// only (the path, and the paths below it); and, with a KMS key, Decrypt on
// that key through SSM in this region for these parameters only. It
// validates the source's account, region and partition and the grant
// first; Name, Provider and the other grants of args are not consulted.
func ReaderPolicy(args ReadersArgs, grant Grant) (string, error) {
	args = args.withDefaults()

	if err := args.validateSource(); err != nil {
		return "", err
	}

	params, err := args.parameters(grant)
	if err != nil {
		return "", err
	}

	var read, byPath []string

	for _, p := range params {
		if !p.prefix {
			read = append(read, args.parameterARN(p.resource))

			continue
		}

		path := strings.TrimSuffix(p.resource, "/")
		read = append(read, args.parameterARN(path+"/*"))
		byPath = append(byPath, args.parameterARN(path), args.parameterARN(path+"/*"))
	}

	statements := []map[string]any{{
		"Sid":      "ReadParameters",
		"Effect":   "Allow",
		"Action":   []string{"ssm:GetParameter", "ssm:GetParameters"},
		"Resource": read,
	}}

	if len(byPath) > 0 {
		statements = append(statements, map[string]any{
			"Sid":      "ReadParametersByPath",
			"Effect":   "Allow",
			"Action":   []string{"ssm:GetParametersByPath"},
			"Resource": byPath,
		})
	}

	if grant.KMSKeyARN != "" {
		suffix := "amazonaws.com"
		if strings.HasPrefix(args.Partition, "aws-cn") {
			suffix = "amazonaws.com.cn"
		}

		statements = append(statements, map[string]any{
			"Sid":      "DecryptParameters",
			"Effect":   "Allow",
			"Action":   []string{"kms:Decrypt"},
			"Resource": grant.KMSKeyARN,
			"Condition": map[string]any{
				"StringEquals": map[string]any{"kms:ViaService": "ssm." + args.Region + "." + suffix},
				"StringLike":   map[string]any{"kms:EncryptionContext:PARAMETER_ARN": read},
			},
		})
	}

	return jsonDoc(map[string]any{"Version": "2012-10-17", "Statement": statements})
}

// NewReaders registers the component and one reader role per grant. It
// registers nothing and returns an error when args are invalid.
func NewReaders(ctx *pulumi.Context, args ReadersArgs, opts ...pulumi.ResourceOption) (*Readers, error) {
	args = args.withDefaults()

	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("esoaws: readers %q: %w", args.Name, err)
	}

	type planned struct {
		grant         Grant
		trust, policy string
	}

	plan := make([]planned, 0, len(args.Grants))

	for _, g := range args.Grants {
		trust, err := ReaderTrustPolicy(g.Principal)
		if err != nil {
			return nil, fmt.Errorf("esoaws: readers %q: grant %s: %w", args.Name, g.Name, err)
		}

		policy, err := ReaderPolicy(args, g)
		if err != nil {
			return nil, fmt.Errorf("esoaws: readers %q: grant %s: %w", args.Name, g.Name, err)
		}

		plan = append(plan, planned{grant: g, trust: trust, policy: policy})
	}

	comp := &Readers{RoleARNs: map[string]pulumi.StringOutput{}}
	if err := ctx.RegisterComponentResource(KindReaders, args.Name, comp, opts...); err != nil {
		return nil, err
	}

	child := []pulumi.ResourceOption{pulumi.Parent(comp), pulumi.Provider(args.Provider)}

	for _, p := range plan {
		roleArgs := &iam.RoleArgs{
			Name:             pulumi.String(p.grant.Name),
			AssumeRolePolicy: pulumi.String(p.trust),
		}
		if args.PermissionsBoundary != "" {
			roleArgs.PermissionsBoundary = pulumi.String(args.PermissionsBoundary)
		}

		if len(args.Tags) > 0 {
			roleArgs.Tags = pulumi.ToStringMap(args.Tags)
		}

		role, err := iam.NewRole(ctx, p.grant.Name, roleArgs, child...)
		if err != nil {
			return nil, fmt.Errorf("esoaws: create role %s: %w", p.grant.Name, err)
		}

		if _, err := iam.NewRolePolicy(ctx, p.grant.Name+"-policy", &iam.RolePolicyArgs{
			Name:   pulumi.String(p.grant.Name),
			Role:   role.Name,
			Policy: pulumi.String(p.policy),
		}, child...); err != nil {
			return nil, fmt.Errorf("esoaws: create inline policy of %s: %w", p.grant.Name, err)
		}

		comp.RoleARNs[p.grant.Name] = role.Arn
	}

	outputs := pulumi.StringMap{}
	for name, arn := range comp.RoleARNs {
		outputs[name] = arn
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{"roleArns": outputs}); err != nil {
		return nil, err
	}

	return comp, nil
}
