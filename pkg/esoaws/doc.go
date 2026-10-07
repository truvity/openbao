// Package esoaws lets the External Secrets Operator on a cluster read AWS
// Systems Manager Parameter Store parameters that live in another AWS
// account, as Pulumi Go components, from caller inputs alone: nothing here
// names a cluster, an account, a region or a parameter, and nothing knows
// which system writes the parameters.
//
// Each cluster has exactly one IdentityMode, with no default; the two are
// mutually exclusive, because an ambient controller identity beside
// per-store identities is one that any store without auth borrows.
//
// PodIdentityMode, for EKS: one cross-account hop from an ambient identity.
//
//	ESO's identity on the cluster   (NewClusterIdentity, in the cluster's account)
//	  -- sts:AssumeRole, the only cross-account call -->
//	one reader role per grant       (NewReaders, in the parameters' account)
//	  -- ssm:GetParameter*, same account -->
//	the granted parameters
//
// WebIdentityMode, for any cluster whose ServiceAccount issuer AWS can
// reach: nothing ambient. Each store names its own ServiceAccount, and
// that ServiceAccount's token assumes the store's reader role directly.
//
//	a store's ServiceAccount token  (signed by the cluster's issuer)
//	  -- sts:AssumeRoleWithWebIdentity, verified by the IAM OIDC provider
//	     NewReaders registers for the cluster -->
//	one reader role per grant, trusting that one ServiceAccount
//	  -- ssm:GetParameter*, same account -->
//	the granted parameters
//
// Either way ESO calls SSM with the reader role's credentials, so the read
// and the decryption of a SecureString happen inside the parameters' own
// account: parameters encrypted with the account's default aws/ssm key are
// readable, and a customer-managed key is needed only when the parameters
// already use one (Grant.KMSKeyARN).
//
// On the cluster, charts/openbao-consumers renders one ClusterSecretStore per
// (cluster, grant) from its awsStores values, in the mode its aws.identity
// names. docs/esoaws.md walks both chains.
//
// # Resources
//
// Each constructor registers one component resource and its children; the
// type and logical name of each are part of this package's contract, because
// together with the parent they are the URN:
//
//	NewClusterIdentity  truvity:secrets/esoaws:ClusterIdentity  <Name>
//	  aws:iam/role:Role                                          <Name>
//	  aws:iam/rolePolicy:RolePolicy                              <Name>-policy
//	  aws:eks/podIdentityAssociation:PodIdentityAssociation      <Name>-pia
//	NewReaders          truvity:secrets/esoaws:Readers          <Name>
//	  aws:iam/openIdConnectProvider:OpenIdConnectProvider        <Name>-<cluster>-oidc
//	  aws:iam/role:Role                                          <grant>
//	  aws:iam/rolePolicy:RolePolicy                              <grant>-policy
//
// The OIDC provider is registered only for a WebIdentity cluster that names
// no existing one (WebIdentity.ProviderARN).
//
// The options a constructor takes go to the component; its children inherit
// them through the parent, and use the Provider the arguments name.
package esoaws
