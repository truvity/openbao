package esoaws

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Pulumi type tokens of the components and their children.
const (
	KindClusterIdentity        = "truvity:secrets/esoaws:ClusterIdentity"
	KindReaders                = "truvity:secrets/esoaws:Readers"
	KindIAMRole                = "aws:iam/role:Role"
	KindIAMRolePolicy          = "aws:iam/rolePolicy:RolePolicy"
	KindPodIdentityAssociation = "aws:eks/podIdentityAssociation:PodIdentityAssociation"
	KindOIDCProvider           = "aws:iam/openIdConnectProvider:OpenIdConnectProvider"

	// ClusterPolicyName is the name of the cluster identity's inline policy.
	ClusterPolicyName = "assume-parameter-readers"
)

type (
	// ClusterIdentityArgs configures NewClusterIdentity, which runs in the
	// cluster's own AWS account. It is the PodIdentity mode's cluster side;
	// the WebIdentity mode has none (see Cluster).
	ClusterIdentityArgs struct {
		// Mode must be PodIdentityMode. It has no default, so a caller
		// states the cluster's mode; a WebIdentity cluster is refused here,
		// because its whole point is that nothing on it holds AWS
		// credentials of its own.
		Mode IdentityMode
		// Name is the IAM role's name, the component's logical name and the
		// stem of the children's: the role "<Name>", its inline policy
		// "<Name>-policy" and the association "<Name>-pia".
		Name string
		// Provider is the AWS provider of the cluster's account and region.
		// Required.
		Provider pulumi.ProviderResource
		// ClusterName is the EKS cluster the association is in; pass the
		// cluster's Name output to order the association after it.
		// ClusterARN and AccountID pin the trust policy to that cluster: the
		// ARN must be an EKS cluster in AccountID. Region, when set, is set
		// on the association and must be the ARN's.
		ClusterName pulumi.StringInput
		ClusterARN  string
		AccountID   string
		Region      string
		// Namespace and ServiceAccount are the External Secrets Operator
		// controller's: the pods that may assume the role. Empty means
		// DefaultNamespace and DefaultServiceAccount.
		Namespace      string
		ServiceAccount string
		// SourceRoles are the reader roles, in the parameters' accounts, the
		// controller may assume: exact role ARNs, no wildcards. A reader
		// role's ARN is arn:<partition>:iam::<account>:role/<grant name>, so
		// the list can be written before the roles exist. This is the role's
		// whole permission.
		SourceRoles []string
		// PermissionsBoundary is the boundary policy's ARN; empty sets none.
		PermissionsBoundary string
		// Tags are put on the role.
		Tags map[string]string
	}

	// ClusterIdentity is the External Secrets Operator's AWS identity on one
	// cluster: an IAM role bound to the controller's ServiceAccount by EKS
	// Pod Identity, allowed nothing but to assume the source accounts'
	// reader roles.
	ClusterIdentity struct {
		pulumi.ResourceState

		// RoleARN is what each reader role trusts (Grant.Principal).
		RoleARN  pulumi.StringOutput
		RoleName pulumi.StringOutput
	}
)

func (a ClusterIdentityArgs) withDefaults() ClusterIdentityArgs {
	if a.Namespace == "" {
		a.Namespace = DefaultNamespace
	}

	if a.ServiceAccount == "" {
		a.ServiceAccount = DefaultServiceAccount
	}

	return a
}

func (a ClusterIdentityArgs) validate() error {
	switch a.Mode {
	case PodIdentityMode:
	case WebIdentityMode:
		return errors.New("args.Mode is WebIdentity: such a cluster has no identity of its own in AWS, so there is nothing to create here; " +
			"declare it in ReadersArgs.Clusters with its issuer, and let each store name its own ServiceAccount")
	case "":
		return errors.New("args.Mode is empty: state the cluster's mode (PodIdentity, the only one with a cluster-side role)")
	default:
		return fmt.Errorf("args.Mode %q is not an identity mode", a.Mode)
	}

	var errs []error

	if a.Provider == nil {
		errs = append(errs, errors.New("args.Provider is nil"))
	}

	if a.ClusterName == nil {
		errs = append(errs, errors.New("ClusterName is nil"))
	}

	if !roleNameRe.MatchString(a.Name) {
		errs = append(errs, fmt.Errorf("args.Name %q is not an IAM role name (1 to 64 of A-Z a-z 0-9 +=,.@_-)", a.Name))
	}

	if !accountIDRe.MatchString(a.AccountID) {
		errs = append(errs, fmt.Errorf("AccountID %q is not a 12-digit account id", a.AccountID))
	}

	if cluster, err := parseARN(a.ClusterARN); err != nil {
		errs = append(errs, fmt.Errorf("ClusterARN: %w", err))
	} else {
		switch {
		case cluster.Service != "eks" || !strings.HasPrefix(cluster.Resource, "cluster/") || strings.Contains(a.ClusterARN, "*"):
			errs = append(errs, fmt.Errorf("ClusterARN %q is not an EKS cluster ARN", a.ClusterARN))
		case cluster.Account != a.AccountID:
			errs = append(errs, fmt.Errorf("ClusterARN %q is not in AccountID %s", a.ClusterARN, a.AccountID))
		case a.Region != "" && cluster.Region != a.Region:
			errs = append(errs, fmt.Errorf("ClusterARN %q is not in Region %s", a.ClusterARN, a.Region))
		}
	}

	if len(a.SourceRoles) == 0 {
		errs = append(errs, errors.New("SourceRoles is empty: an identity that may assume nothing reads nothing"))
	}

	seen := map[string]bool{}

	partition := ""
	if cluster, err := parseARN(a.ClusterARN); err == nil {
		partition = cluster.Partition
	}

	for i, r := range a.SourceRoles {
		if role, err := parseRoleARN(r); err != nil {
			errs = append(errs, fmt.Errorf("SourceRoles[%d]: %w", i, err))
		} else if partition != "" && role.Partition != partition {
			errs = append(errs, fmt.Errorf("SourceRoles[%d]: %q is not in the cluster's partition %s", i, r, partition))
		}

		if seen[r] {
			errs = append(errs, fmt.Errorf("SourceRoles[%d]: duplicate %q", i, r))
		}

		seen[r] = true
	}

	if err := parsePermissionsBoundary(a.PermissionsBoundary); err != nil {
		errs = append(errs, err)
	}

	if len(errs) == 0 {
		if _, err := ClusterPolicy(a.SourceRoles); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func jsonDoc(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal policy document: %w", err)
	}

	return string(raw), nil
}

// ClusterTrustPolicy is the cluster identity's trust document: the EKS Pod
// Identity service may assume the role for this cluster (its account and
// ARN), and only for the one namespace and ServiceAccount. sts:TagSession is
// there because Pod Identity tags every session it opens, and only its own
// tag keys are admitted.
func ClusterTrustPolicy(accountID, clusterARN, namespace, serviceAccount string) (string, error) {
	return jsonDoc(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Sid":       "ExternalSecretsOperator",
			"Effect":    "Allow",
			"Principal": map[string]any{"Service": "pods.eks.amazonaws.com"},
			"Action":    []string{"sts:AssumeRole", "sts:TagSession"},
			"Condition": map[string]any{
				"StringEquals": map[string]any{
					"aws:SourceAccount":                         accountID,
					"aws:RequestTag/kubernetes-namespace":       namespace,
					"aws:RequestTag/kubernetes-service-account": serviceAccount,
				},
				"ArnEquals":                 map[string]any{"aws:SourceArn": clusterARN},
				"ForAllValues:StringEquals": tagKeysCondition(),
			},
		}},
	})
}

// ClusterPolicy is the cluster identity's whole permission: assume the
// given reader roles, in the order given. sts:TagSession goes with it
// because the tags EKS Pod Identity puts on the session are transitive: they
// ride along on the role assumed next, and STS checks the tagging. Only Pod
// Identity's tag keys are allowed, so a store's own session tags are
// refused. A document over MaxInlinePolicySize is an error.
func ClusterPolicy(sourceRoles []string) (string, error) {
	doc, err := jsonDoc(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Sid":       "AssumeParameterReaders",
			"Effect":    "Allow",
			"Action":    []string{"sts:AssumeRole", "sts:TagSession"},
			"Resource":  sourceRoles,
			"Condition": map[string]any{"ForAllValues:StringEquals": tagKeysCondition()},
		}},
	})
	if err != nil {
		return "", err
	}

	return doc, checkSize("the cluster identity's policy", doc)
}

func tagKeysCondition() map[string]any {
	return map[string]any{"aws:TagKeys": podIdentityTagKeys}
}

// checkSize refuses an inline policy IAM would refuse, before anything is
// registered. The documents here are compact JSON, so their length is what
// IAM counts.
func checkSize(what, doc string) error {
	if len(doc) > MaxInlinePolicySize {
		return fmt.Errorf("%s is %d characters, over IAM's %d for inline policies: split the grant or use a prefix",
			what, len(doc), MaxInlinePolicySize)
	}

	return nil
}

// NewClusterIdentity registers the component and its children. It registers
// nothing and returns an error when args are invalid.
func NewClusterIdentity(ctx *pulumi.Context, args ClusterIdentityArgs, opts ...pulumi.ResourceOption) (*ClusterIdentity, error) {
	args = args.withDefaults()

	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("esoaws: cluster identity %q: %w", args.Name, err)
	}

	trust, err := ClusterTrustPolicy(args.AccountID, args.ClusterARN, args.Namespace, args.ServiceAccount)
	if err != nil {
		return nil, fmt.Errorf("esoaws: cluster identity %q: %w", args.Name, err)
	}

	policy, err := ClusterPolicy(args.SourceRoles)
	if err != nil {
		return nil, fmt.Errorf("esoaws: cluster identity %q: %w", args.Name, err)
	}

	comp := &ClusterIdentity{}
	if err := ctx.RegisterComponentResource(KindClusterIdentity, args.Name, comp, opts...); err != nil {
		return nil, err
	}

	child := []pulumi.ResourceOption{pulumi.Parent(comp), pulumi.Provider(args.Provider)}

	roleArgs := &iam.RoleArgs{
		Name:             pulumi.String(args.Name),
		AssumeRolePolicy: pulumi.String(trust),
	}
	if args.PermissionsBoundary != "" {
		roleArgs.PermissionsBoundary = pulumi.String(args.PermissionsBoundary)
	}

	if len(args.Tags) > 0 {
		roleArgs.Tags = pulumi.ToStringMap(args.Tags)
	}

	role, err := iam.NewRole(ctx, args.Name, roleArgs, child...)
	if err != nil {
		return nil, fmt.Errorf("esoaws: create role %s: %w", args.Name, err)
	}

	comp.RoleARN, comp.RoleName = role.Arn, role.Name

	if _, err := iam.NewRolePolicy(ctx, args.Name+"-policy", &iam.RolePolicyArgs{
		Name:   pulumi.String(ClusterPolicyName),
		Role:   role.Name,
		Policy: pulumi.String(policy),
	}, child...); err != nil {
		return nil, fmt.Errorf("esoaws: create inline policy of %s: %w", args.Name, err)
	}

	pia := &eks.PodIdentityAssociationArgs{
		ClusterName:    args.ClusterName,
		Namespace:      pulumi.String(args.Namespace),
		ServiceAccount: pulumi.String(args.ServiceAccount),
		RoleArn:        role.Arn,
	}
	if args.Region != "" {
		pia.Region = pulumi.String(args.Region)
	}

	if _, err := eks.NewPodIdentityAssociation(ctx, args.Name+"-pia", pia, child...); err != nil {
		return nil, fmt.Errorf("esoaws: associate %s/%s: %w", args.Namespace, args.ServiceAccount, err)
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{
		"roleArn":  comp.RoleARN,
		"roleName": comp.RoleName,
	}); err != nil {
		return nil, err
	}

	return comp, nil
}
