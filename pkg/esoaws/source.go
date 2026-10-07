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
		// Clusters are the clusters whose External Secrets read here, each
		// with the one way it proves who it is. Every cluster is used by a
		// grant, and no two share an issuer.
		Clusters []Cluster
		// Grants are the reader roles, one per grant. At least one.
		Grants []Grant
		// PermissionsBoundary is the boundary policy's ARN put on every
		// reader role; empty sets none.
		PermissionsBoundary string
		// Tags are put on every reader role and on a created OIDC provider.
		Tags map[string]string
	}

	// Cluster is one cluster's identity, as the reader roles trust it.
	// Mode is required, and exactly the block it names is set.
	Cluster struct {
		// Name is how grants name the cluster (Grant.Cluster), and part of a
		// created OIDC provider's logical name: lower-case letters, digits
		// and '-'.
		Name string
		// Mode is the cluster's one identity mode. No default.
		Mode IdentityMode
		// PodIdentity is the PodIdentityMode trust: required in that mode,
		// refused in the other.
		PodIdentity *PodIdentity
		// WebIdentity is the WebIdentityMode trust: required in that mode,
		// refused in the other.
		WebIdentity *WebIdentity
	}

	// PodIdentity is the PodIdentity mode's trust: one role principal.
	PodIdentity struct {
		// RoleARN is the cluster's ClusterIdentity.RoleARN: one role ARN, no
		// wildcard. IAM refuses a trust in a role that does not exist yet.
		RoleARN string
	}

	// WebIdentity is the WebIdentity mode's trust: the cluster's
	// ServiceAccount issuer, registered here as an IAM OIDC provider.
	WebIdentity struct {
		// IssuerURL is the cluster's ServiceAccount issuer, exactly as its
		// tokens' iss claim says it: https://<host>[/<path>], no trailing
		// slash. STS fetches its discovery document and keys, so it must be
		// reachable from AWS.
		IssuerURL string
		// Audience is the audience the tokens carry and the reader roles
		// require. Empty: DefaultAudience.
		Audience string
		// ProviderARN is an IAM OIDC provider for IssuerURL that already
		// exists in this account (IAM takes one per URL), registered with
		// Audience among its client ids. Empty: the component creates one.
		ProviderARN string
		// Thumbprints are the issuer certificate's SHA-1 thumbprints for a
		// created provider; empty lets IAM fetch them. Not with ProviderARN.
		Thumbprints []string
	}

	// Grant is one reader role: which cluster may assume it, and what it
	// reads.
	Grant struct {
		// Name is the IAM role's name, its logical name, and its key in
		// Readers.RoleARNs. The inline policy is "<Name>-policy".
		Name string
		// Cluster is the Name of the Cluster whose External Secrets assume
		// the role.
		Cluster string
		// ServiceAccount is the one ServiceAccount whose tokens may assume
		// the role, in a WebIdentity cluster: required there, refused in a
		// PodIdentity cluster (whose controller identity is the principal).
		ServiceAccount *ServiceAccount
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

	// ServiceAccount names one Kubernetes ServiceAccount.
	ServiceAccount struct {
		// Namespace is the ServiceAccount's; empty: DefaultNamespace, where
		// the External Secrets controller runs and only platform
		// administrators create objects.
		Namespace string
		Name      string
	}

	// Readers is the source side: one reader role per grant, and an IAM
	// OIDC provider per WebIdentity cluster that names no existing one.
	Readers struct {
		pulumi.ResourceState

		// RoleARNs is each grant's role ARN by grant name: the `role` of the
		// cluster's store for that grant.
		RoleARNs map[string]pulumi.StringOutput
		// OIDCProviderARNs is each WebIdentity cluster's provider ARN by
		// cluster name, created or given.
		OIDCProviderARNs map[string]pulumi.StringOutput
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

	clusters := make([]Cluster, len(a.Clusters))
	for i, c := range a.Clusters {
		if c.WebIdentity != nil && c.WebIdentity.Audience == "" {
			w := *c.WebIdentity
			w.Audience = DefaultAudience
			c.WebIdentity = &w
		}

		clusters[i] = c
	}

	a.Clusters = clusters

	grants := make([]Grant, len(a.Grants))
	for i, g := range a.Grants {
		if g.ServiceAccount != nil && g.ServiceAccount.Namespace == "" {
			sa := *g.ServiceAccount
			sa.Namespace = DefaultNamespace
			g.ServiceAccount = &sa
		}

		grants[i] = g
	}

	a.Grants = grants

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
		// The checks below compare against the source's fields.
		return errors.Join(append(errs, err)...)
	}

	errs = append(errs, a.validateClusters()...)

	var (
		names    = map[string]bool{}
		accounts = map[string]string{}
		used     = map[string]bool{}
	)

	for i, g := range a.Grants {
		if names[g.Name] {
			errs = append(errs, fmt.Errorf("args.Grants[%d]: duplicate name %q", i, g.Name))
		}

		names[g.Name] = true
		used[g.Cluster] = true

		if err := a.validateGrant(g); err != nil {
			errs = append(errs, fmt.Errorf("args.Grants[%d] (%s): %w", i, g.Name, err))
		}

		if g.ServiceAccount != nil {
			key := g.Cluster + "/" + g.ServiceAccount.Namespace + "/" + g.ServiceAccount.Name
			if other, ok := accounts[key]; ok {
				errs = append(errs, fmt.Errorf("args.Grants[%d] (%s): ServiceAccount %s/%s on cluster %s is grant %s's already; "+
					"External Secrets reads one role per ServiceAccount", i, g.Name, g.ServiceAccount.Namespace, g.ServiceAccount.Name, g.Cluster, other))
			}

			accounts[key] = g.Name
		}
	}

	for i, c := range a.Clusters {
		if c.Name != "" && !used[c.Name] {
			errs = append(errs, fmt.Errorf("args.Clusters[%d]: no grant names cluster %q; drop it", i, c.Name))
		}
	}

	return errors.Join(errs...)
}

// validateSource checks the fields every grant is built in.
func (a ReadersArgs) validateSource() error {
	var errs []error

	if !accountIDRe.MatchString(a.AccountID) {
		errs = append(errs, fmt.Errorf("args.AccountID %q is not a 12-digit account id", a.AccountID))
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

func (a ReadersArgs) validateClusters() []error {
	var (
		errs    []error
		names   = map[string]bool{}
		issuers = map[string]string{}
	)

	for i, c := range a.Clusters {
		if names[c.Name] {
			errs = append(errs, fmt.Errorf("args.Clusters[%d]: duplicate name %q", i, c.Name))
		}

		names[c.Name] = true

		if err := a.validateCluster(c); err != nil {
			errs = append(errs, fmt.Errorf("args.Clusters[%d] (%s): %w", i, c.Name, err))

			continue
		}

		if c.WebIdentity != nil {
			issuer, _ := parseIssuer(c.WebIdentity.IssuerURL)
			if other, ok := issuers[issuer]; ok {
				errs = append(errs, fmt.Errorf("args.Clusters[%d] (%s): issuer %s is cluster %s's already; IAM registers one provider per issuer",
					i, c.Name, c.WebIdentity.IssuerURL, other))
			}

			issuers[issuer] = c.Name
		}
	}

	return errs
}

// validateCluster checks one cluster: its name, its one mode, and that
// mode's settings and no other's.
func (a ReadersArgs) validateCluster(c Cluster) error {
	if !namespaceRe.MatchString(c.Name) {
		return fmt.Errorf("cluster.Name %q is not lower-case letters, digits and '-'", c.Name)
	}

	switch {
	case c.Mode == "":
		return errors.New("cluster.Mode is empty: state the cluster's mode, PodIdentity or WebIdentity; there is no default")
	case c.Mode != PodIdentityMode && c.Mode != WebIdentityMode:
		return fmt.Errorf("cluster.Mode %q is not an identity mode", c.Mode)
	case c.PodIdentity != nil && c.WebIdentity != nil:
		return errors.New("both PodIdentity and WebIdentity are set: the modes are mutually exclusive, " +
			"because a controller identity beside per-store identities is one any store without auth borrows")
	case c.Mode == PodIdentityMode && c.PodIdentity == nil:
		return errors.New("cluster.Mode is PodIdentity but PodIdentity is not set")
	case c.Mode == WebIdentityMode && c.WebIdentity == nil:
		return errors.New("cluster.Mode is WebIdentity but WebIdentity is not set")
	case c.Mode == PodIdentityMode && c.WebIdentity != nil, c.Mode == WebIdentityMode && c.PodIdentity != nil:
		return fmt.Errorf("cluster.Mode is %s, but the other mode's settings are set", c.Mode)
	case c.Mode == PodIdentityMode:
		role, err := parseRoleARN(c.PodIdentity.RoleARN)
		if err != nil {
			return fmt.Errorf("PodIdentity.RoleARN: %w", err)
		}

		if role.Partition != a.Partition {
			return fmt.Errorf("PodIdentity.RoleARN %q is not in partition %s", c.PodIdentity.RoleARN, a.Partition)
		}

		return nil
	}

	w := c.WebIdentity

	issuer, err := parseIssuer(w.IssuerURL)
	if err != nil {
		return fmt.Errorf("WebIdentity.IssuerURL: %w", err)
	}

	var errs []error

	if w.Audience == "" || strings.ContainsAny(w.Audience, "*?") {
		errs = append(errs, fmt.Errorf("WebIdentity.Audience %q is empty or a pattern", w.Audience))
	}

	if w.ProviderARN != "" {
		if want := a.oidcProviderARN(issuer); w.ProviderARN != want {
			errs = append(errs, fmt.Errorf("WebIdentity.ProviderARN %q is not this account's provider for %s (%s)", w.ProviderARN, w.IssuerURL, want))
		}

		if len(w.Thumbprints) > 0 {
			errs = append(errs, errors.New("WebIdentity.Thumbprints are for a created provider; an existing one keeps its own"))
		}
	}

	if len(w.Thumbprints) > 5 {
		errs = append(errs, errors.New("WebIdentity.Thumbprints: IAM takes at most 5"))
	}

	for i, t := range w.Thumbprints {
		if !thumbprintRe.MatchString(t) {
			errs = append(errs, fmt.Errorf("WebIdentity.Thumbprints[%d] %q is not a SHA-1 thumbprint (40 hex digits)", i, t))
		}
	}

	return errors.Join(errs...)
}

func (a ReadersArgs) cluster(name string) (Cluster, bool) {
	for _, c := range a.Clusters {
		if c.Name == name {
			return c, true
		}
	}

	return Cluster{}, false
}

func (a ReadersArgs) oidcProviderARN(issuer string) string {
	return fmt.Sprintf("arn:%s:iam::%s:oidc-provider/%s", a.Partition, a.AccountID, issuer)
}

// validateGrant checks a grant against the source and its cluster: the
// parameters, the key, the policy's size, and the ServiceAccount the
// cluster's mode requires or refuses.
func (a ReadersArgs) validateGrant(g Grant) error {
	var errs []error

	if _, err := ReaderPolicy(a, g); err != nil {
		errs = append(errs, err)
	}

	c, ok := a.cluster(g.Cluster)

	switch {
	case !ok:
		errs = append(errs, fmt.Errorf("grant.Cluster %q is not in args.Clusters", g.Cluster))
	case c.Mode == PodIdentityMode && g.ServiceAccount != nil:
		errs = append(errs, fmt.Errorf("grant.ServiceAccount is set, but cluster %s is PodIdentity: a WebIdentity grant on a PodIdentity cluster; "+
			"its controller's role is the principal, so a ServiceAccount here would read as a restriction it is not", g.Cluster))
	case c.Mode == WebIdentityMode && g.ServiceAccount == nil:
		errs = append(errs, fmt.Errorf("grant.ServiceAccount is required: cluster %s is WebIdentity, and the role trusts one ServiceAccount's tokens", g.Cluster))
	case c.Mode == WebIdentityMode:
		sa := g.ServiceAccount
		if !namespaceRe.MatchString(sa.Namespace) {
			errs = append(errs, fmt.Errorf("grant.ServiceAccount.Namespace %q is not a Kubernetes namespace name", sa.Namespace))
		}

		if !serviceAccountRe.MatchString(sa.Name) {
			errs = append(errs, fmt.Errorf("grant.ServiceAccount.Name %q is not a Kubernetes ServiceAccount name", sa.Name))
		}
	}

	return errors.Join(errs...)
}

// grantParameters validates a grant's name, key and parameters against the
// source and returns its parameters, in the order given.
func (a ReadersArgs) grantParameters(g Grant) ([]parameter, error) {
	var errs []error

	if !roleNameRe.MatchString(g.Name) {
		errs = append(errs, fmt.Errorf("grant.Name %q is not an IAM role name (1 to 64 of A-Z a-z 0-9 +=,.@_-)", g.Name))
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

// ReaderTrustPolicy is a grant's trust document, a function of its
// cluster's mode:
//
//   - PodIdentity: exactly the cluster identity's role, for sts:AssumeRole
//     and for the transitive session tags EKS Pod Identity sets, and no
//     other tag keys;
//   - WebIdentity: sts:AssumeRoleWithWebIdentity from the cluster's OIDC
//     provider, for a token whose subject is the grant's one ServiceAccount
//     and whose audience is the cluster's.
//
// It validates the source, the grant and its cluster first.
func ReaderTrustPolicy(args ReadersArgs, grant Grant) (string, error) {
	args = args.withDefaults()
	grant = args.withGrantDefaults(grant)

	if err := args.validateSource(); err != nil {
		return "", err
	}

	c, ok := args.cluster(grant.Cluster)
	if !ok {
		return "", fmt.Errorf("grant.Cluster %q is not in args.Clusters", grant.Cluster)
	}

	if err := args.validateCluster(c); err != nil {
		return "", fmt.Errorf("cluster %s: %w", c.Name, err)
	}

	if err := args.validateGrant(grant); err != nil {
		return "", err
	}

	statement := map[string]any{"Sid": "ExternalSecretsOperator", "Effect": "Allow"}

	if c.Mode == PodIdentityMode {
		statement["Principal"] = map[string]any{"AWS": c.PodIdentity.RoleARN}
		statement["Action"] = []string{"sts:AssumeRole", "sts:TagSession"}
		statement["Condition"] = map[string]any{"ForAllValues:StringEquals": tagKeysCondition()}
	} else {
		issuer, _ := parseIssuer(c.WebIdentity.IssuerURL)
		statement["Principal"] = map[string]any{"Federated": args.oidcProviderARN(issuer)}
		statement["Action"] = []string{"sts:AssumeRoleWithWebIdentity"}
		statement["Condition"] = map[string]any{"StringEquals": map[string]any{
			issuer + ":sub": "system:serviceaccount:" + grant.ServiceAccount.Namespace + ":" + grant.ServiceAccount.Name,
			issuer + ":aud": c.WebIdentity.Audience,
		}}
	}

	return jsonDoc(map[string]any{"Version": "2012-10-17", "Statement": []map[string]any{statement}})
}

// withGrantDefaults applies the defaults withDefaults applies to args.Grants
// to a grant given on its own.
func (a ReadersArgs) withGrantDefaults(g Grant) Grant {
	return ReadersArgs{Grants: []Grant{g}}.withDefaults().Grants[0]
}

// ReaderPolicy is a grant's permission document, built in the source's
// account and region: GetParameter and GetParameters on each exact
// parameter and under each prefix; GetParametersByPath on the prefixes
// only (the path, and the paths below it); and, with a KMS key, Decrypt on
// that key through SSM in this region for these parameters only. It
// validates the source's account, region and partition and the grant's
// name, parameters and key first; the grant's cluster is not consulted (it
// decides the trust, not the permission). A document over
// MaxInlinePolicySize is an error.
func ReaderPolicy(args ReadersArgs, grant Grant) (string, error) {
	args = args.withDefaults()

	if err := args.validateSource(); err != nil {
		return "", err
	}

	params, err := args.grantParameters(grant)
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

	doc, err := jsonDoc(map[string]any{"Version": "2012-10-17", "Statement": statements})
	if err != nil {
		return "", err
	}

	return doc, checkSize(fmt.Sprintf("grant %s's policy", grant.Name), doc)
}

// NewReaders registers the component, an IAM OIDC provider for each
// WebIdentity cluster that names no existing one, and one reader role per
// grant. It registers nothing and returns an error when args are invalid.
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
		trust, err := ReaderTrustPolicy(args, g)
		if err != nil {
			return nil, fmt.Errorf("esoaws: readers %q: grant %s: %w", args.Name, g.Name, err)
		}

		policy, err := ReaderPolicy(args, g)
		if err != nil {
			return nil, fmt.Errorf("esoaws: readers %q: grant %s: %w", args.Name, g.Name, err)
		}

		plan = append(plan, planned{grant: g, trust: trust, policy: policy})
	}

	comp := &Readers{RoleARNs: map[string]pulumi.StringOutput{}, OIDCProviderARNs: map[string]pulumi.StringOutput{}}
	if err := ctx.RegisterComponentResource(KindReaders, args.Name, comp, opts...); err != nil {
		return nil, err
	}

	child := []pulumi.ResourceOption{pulumi.Parent(comp), pulumi.Provider(args.Provider)}

	// A role's trust names its provider by ARN, which is predictable; the
	// role still waits for a provider created here, or IAM would refuse a
	// principal it cannot resolve.
	waitFor := map[string]pulumi.Resource{}

	for _, c := range args.Clusters {
		if c.Mode != WebIdentityMode {
			continue
		}

		if c.WebIdentity.ProviderARN != "" {
			comp.OIDCProviderARNs[c.Name] = pulumi.String(c.WebIdentity.ProviderARN).ToStringOutput()

			continue
		}

		pa := &iam.OpenIdConnectProviderArgs{
			Url:           pulumi.String(c.WebIdentity.IssuerURL),
			ClientIdLists: pulumi.ToStringArray([]string{c.WebIdentity.Audience}),
		}
		if len(c.WebIdentity.Thumbprints) > 0 {
			pa.ThumbprintLists = pulumi.ToStringArray(c.WebIdentity.Thumbprints)
		}

		if len(args.Tags) > 0 {
			pa.Tags = pulumi.ToStringMap(args.Tags)
		}

		name := args.Name + "-" + c.Name + "-oidc"

		provider, err := iam.NewOpenIdConnectProvider(ctx, name, pa, child...)
		if err != nil {
			return nil, fmt.Errorf("esoaws: create OIDC provider %s: %w", name, err)
		}

		comp.OIDCProviderARNs[c.Name] = provider.Arn
		waitFor[c.Name] = provider
	}

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

		roleOpts := child
		if dep, ok := waitFor[p.grant.Cluster]; ok {
			roleOpts = append(append([]pulumi.ResourceOption{}, child...), pulumi.DependsOn([]pulumi.Resource{dep}))
		}

		role, err := iam.NewRole(ctx, p.grant.Name, roleArgs, roleOpts...)
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

	roles, providers := pulumi.StringMap{}, pulumi.StringMap{}
	for name, arn := range comp.RoleARNs {
		roles[name] = arn
	}

	for name, arn := range comp.OIDCProviderARNs {
		providers[name] = arn
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{"roleArns": roles, "oidcProviderArns": providers}); err != nil {
		return nil, err
	}

	return comp, nil
}
