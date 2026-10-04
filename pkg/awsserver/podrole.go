package awsserver

import (
	"errors"
	"fmt"
	"slices"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type (
	// PodRoleArgs configures NewPodRole.
	PodRoleArgs struct {
		// Name is the IAM role's name, the component's logical name and the
		// stem of the children's: the role is "<Name>", its inline policy
		// "<Name>-policy" and the association "<Name>-pia" (with several
		// service accounts, "<Name>-pia-<service account>" each).
		Name string
		// Provider is the AWS provider of the cluster's account and region.
		// Required.
		Provider pulumi.ProviderResource
		// ClusterName is the EKS cluster the associations are in; pass the
		// cluster's Name output to order them after it. ClusterARN and
		// AccountID pin the trust policy to that cluster. Region is set on
		// each association when not empty.
		ClusterName pulumi.StringInput
		ClusterARN  string
		AccountID   string
		Region      string
		// Namespace and ServiceAccounts say which pods may assume the role:
		// one association per service account, no repeats.
		Namespace       string
		ServiceAccounts []string
		// PermissionsBoundary is the boundary policy's ARN; empty sets none.
		PermissionsBoundary string
		// PolicyName and Policy are the inline policy.
		PolicyName string
		Policy     pulumi.StringInput
	}

	// PodRole is one Pod Identity role: the IAM role, its inline policy and
	// the associations that bind it to service accounts.
	PodRole struct {
		pulumi.ResourceState

		// RoleARN and RoleName are the role's.
		RoleARN  pulumi.StringOutput
		RoleName pulumi.StringOutput
	}
)

func (a *PodRoleArgs) validate() error {
	var errs []error

	if a.Provider == nil {
		errs = append(errs, errors.New("args.Provider is nil"))
	}

	if a.ClusterName == nil {
		errs = append(errs, errors.New("args.ClusterName is nil"))
	}

	for field, v := range map[string]string{
		"Name": a.Name, "Namespace": a.Namespace, "AccountID": a.AccountID,
		"ClusterARN": a.ClusterARN, "PolicyName": a.PolicyName,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is empty", field))
		}
	}

	if a.Policy == nil {
		errs = append(errs, errors.New("args.Policy is nil"))
	}

	if len(a.ServiceAccounts) == 0 {
		errs = append(errs, errors.New("ServiceAccounts is empty: a role nobody can assume is not an identity"))
	}

	seen := map[string]bool{}

	for i, sa := range a.ServiceAccounts {
		switch {
		case sa == "":
			errs = append(errs, fmt.Errorf("ServiceAccounts[%d] is empty", i))
		case seen[sa]:
			errs = append(errs, fmt.Errorf("ServiceAccounts[%d]: duplicate %q", i, sa))
		}

		seen[sa] = true
	}

	return errors.Join(errs...)
}

// trustPolicy is the trust document: the EKS Pod Identity service may assume
// the role, for this cluster's account and ARN and only for the namespace
// and service accounts. One service account is a string in the condition,
// several are a list, in the order given.
func (a *PodRoleArgs) trustPolicy() (string, error) {
	var sa any = a.ServiceAccounts[0]
	if len(a.ServiceAccounts) > 1 {
		sa = slices.Clone(a.ServiceAccounts)
	}

	return jsonDoc(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Effect":    "Allow",
			"Principal": map[string]any{"Service": "pods.eks.amazonaws.com"},
			"Action":    []string{"sts:AssumeRole", "sts:TagSession"},
			"Condition": map[string]any{
				"StringEquals": map[string]any{
					"aws:SourceAccount":                         a.AccountID,
					"aws:RequestTag/kubernetes-namespace":       a.Namespace,
					"aws:RequestTag/kubernetes-service-account": sa,
				},
				"ArnEquals": map[string]any{
					"aws:SourceArn": a.ClusterARN,
				},
			},
		}},
	})
}

// NewPodRole registers the component and its children. It registers
// nothing and returns an error when args are invalid.
func NewPodRole(ctx *pulumi.Context, args PodRoleArgs, options ...Option) (*PodRole, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("awsserver: pod role %q: %w", args.Name, err)
	}

	trust, err := args.trustPolicy()
	if err != nil {
		return nil, fmt.Errorf("awsserver: pod role %s: %w", args.Name, err)
	}

	s := newSettings(options)
	comp := &PodRole{}

	if err := ctx.RegisterComponentResource(KindPodRole, args.Name, comp, s.opts(KindPodRole, args.Name)...); err != nil {
		return nil, err
	}

	child := func(kind, name string) []pulumi.ResourceOption {
		return s.opts(kind, name, pulumi.Parent(comp), pulumi.Provider(args.Provider))
	}

	roleArgs := &iam.RoleArgs{
		Name:             pulumi.String(args.Name),
		AssumeRolePolicy: pulumi.String(trust),
	}
	if args.PermissionsBoundary != "" {
		roleArgs.PermissionsBoundary = pulumi.String(args.PermissionsBoundary)
	}

	role, err := iam.NewRole(ctx, args.Name, roleArgs, child(KindIAMRole, args.Name)...)
	if err != nil {
		return nil, fmt.Errorf("awsserver: create role %s: %w", args.Name, err)
	}

	comp.RoleARN, comp.RoleName = role.Arn, role.Name

	name := args.Name + "-policy"

	if _, err := iam.NewRolePolicy(ctx, name, &iam.RolePolicyArgs{
		Name:   pulumi.String(args.PolicyName),
		Role:   role.Name,
		Policy: args.Policy,
	}, child(KindIAMRolePolicy, name)...); err != nil {
		return nil, fmt.Errorf("awsserver: create inline policy of %s: %w", args.Name, err)
	}

	for _, sa := range args.ServiceAccounts {
		name := args.Name + "-pia"
		if len(args.ServiceAccounts) > 1 {
			name += "-" + sa
		}

		pia := &eks.PodIdentityAssociationArgs{
			ClusterName:    args.ClusterName,
			Namespace:      pulumi.String(args.Namespace),
			ServiceAccount: pulumi.String(sa),
			RoleArn:        role.Arn,
		}
		if args.Region != "" {
			pia.Region = pulumi.String(args.Region)
		}

		if _, err := eks.NewPodIdentityAssociation(ctx, name, pia, child(KindPodIdentityAssociation, name)...); err != nil {
			return nil, fmt.Errorf("awsserver: associate %s/%s: %w", args.Namespace, sa, err)
		}
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{
		"roleArn":  comp.RoleARN,
		"roleName": comp.RoleName,
	}); err != nil {
		return nil, err
	}

	return comp, nil
}
