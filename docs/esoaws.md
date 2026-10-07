# External Secrets reading Parameter Store across accounts

`pkg/esoaws` and the `awsStores` of `charts/openbao-consumers` let the
External Secrets Operator (ESO) on a cluster read AWS Systems Manager
Parameter Store parameters that live in another AWS account. The mechanism
is general: it does not know what writes the parameters or why. Every
particular (accounts, regions, clusters, role names, parameter names) is an
input.

## The chain

```
cluster account                               parameters' account
──────────────────────────────────            ─────────────────────────────────
ESO controller pod
  │ EKS Pod Identity
  ▼
cluster identity role          sts:AssumeRole
  (esoaws.NewClusterIdentity)  ─────────────►  reader role, one per grant
  may assume only SourceRoles  the only cross-   (esoaws.NewReaders)
                               account hop       trusts only the cluster identity
                                                   │ ssm:GetParameter*, kms:Decrypt
                                                   ▼ (same account)
                                                 the granted parameters
```

1. The ESO controller's ServiceAccount (`external-secrets/external-secrets`
   by default) is bound by an EKS Pod Identity association to the
   **cluster identity** role. Its trust admits the Pod Identity service for
   that one cluster (account and cluster ARN) and that one namespace and
   ServiceAccount.
2. For each store, ESO assumes the store's `role`, the **reader role** of
   one grant, with the controller's own credentials. This is the only
   cross-account call. Both sides must agree: the cluster identity may
   assume only the roles in its `SourceRoles`, and a reader role trusts
   only the one principal its grant names.
3. ESO then calls SSM as the reader role, inside the parameters' account.
   The read and the decryption of a SecureString are both same-account calls.

EKS Pod Identity can also chain to a target role by itself (an
association's target role), but an association has one target and ESO
needs one role per store. So the cluster identity stays in its own account,
and ESO assumes each store's role.

## Encryption: the default key is enough

A SecureString is decrypted by SSM, on behalf of the caller, with the key
it was written with. Because the caller is the reader role, which belongs to
the parameters' own account, the account's default `aws/ssm` key works: its
key policy lets any principal of the account use it through SSM, so the
reader role needs no KMS grant at all. (`aws/ssm` cannot be shared with
another account. That is why the reader role lives with the parameters
rather than ESO reading them directly from the cluster's account.)

Set `Grant.KMSKeyARN` only when the parameters are encrypted with a
customer-managed key. The reader role then gets `kms:Decrypt` on that key,
only through SSM in the source's region (`kms:ViaService`) and only for the
granted parameters (`kms:EncryptionContext:PARAMETER_ARN`). The key's own
policy must also admit the role, directly or by delegating to the account's
IAM policies. The key must be in the source's region, and it may be in
another account if its key policy allows that.

## Least privilege

- **The cluster identity** may call `sts:AssumeRole` and `sts:TagSession` on
  its `SourceRoles` and nothing else. It has no SSM or KMS permissions of
  its own. `sts:TagSession` is needed because the session tags EKS Pod
  Identity sets are transitive. An entry may be a pattern
  (`role/eso-reader-a-*`), but a pattern must name some literal part of the
  role: `role/*` is refused.
- **A reader role** may call `ssm:GetParameter` and `ssm:GetParameters` on
  its exact parameters and under its prefixes, and `ssm:GetParametersByPath`
  on its prefixes only. It cannot write anything, and it cannot call
  `ssm:DescribeParameters`. As a result, an ExternalSecret's `find` must
  name a `path` inside a prefix grant. A `find` by name or by tag without a
  path lists the whole account, so it is refused.
- **A grant's parameters** are exact names (`/app/config/token`, or `token`
  outside any hierarchy) or prefixes (`/app/config/`, which covers the path
  at any depth). An entry may also be given as a parameter ARN. Every ARN is
  built in, or must be in, the source's own account and region. These are
  refused: wildcards, `/` alone, empty path segments, duplicates, and an
  entry already covered by a prefix in the same grant.
- An inline policy is limited to 10,240 characters. A grant with a very long
  list of names should use a prefix instead.

## Tenancy: one store per (cluster, grant)

Any namespace that can use a store can read everything its grant reads.
So the unit of access is the grant: one reader role per audience, and one
`ClusterSecretStore` per (cluster, grant), limited by `conditions` to the
namespaces of that audience. As with the OpenBAO reader stores, the chart
refuses an AWS store with no `conditions`. Without them, every namespace on
the cluster could read through it.

## Wiring it up

The order matters. IAM resolves a trust policy's principal when the policy
is written, and refuses one that does not exist. So the cluster identity is
applied first, then the readers that trust it, then the stores. If the
cluster identity is deleted and recreated, apply the readers again: IAM
stored the old role's unique id, not its name.

```go
import "github.com/truvity/secrets/pkg/esoaws"

// In the cluster's account.
id, err := esoaws.NewClusterIdentity(ctx, esoaws.ClusterIdentityArgs{
    Name:        "a-external-secrets",
    Provider:    clusterAccount,
    ClusterName: pulumi.String("a"),
    ClusterARN:  "arn:aws:eks:eu-example-1:111122223333:cluster/a",
    AccountID:   "111122223333",
    Region:      "eu-example-1",
    SourceRoles: []string{"arn:aws:iam::444455556666:role/a-app-config"},
})
ctx.Export("esoRoleArn", id.RoleARN)

// In the parameters' account (another stack, reading esoRoleArn).
readers, err := esoaws.NewReaders(ctx, esoaws.ReadersArgs{
    Name:      "parameter-readers",
    Provider:  sourceAccount,
    AccountID: "444455556666",
    Region:    "eu-example-1",
    Grants: []esoaws.Grant{{
        Name:       "a-app-config",
        Principal:  "arn:aws:iam::111122223333:role/a-external-secrets",
        Parameters: []string{"/app/config/", "/shared/endpoint"},
    }},
})
ctx.Export("readerRoleArns", pulumi.ToStringMapOutput(readers.RoleARNs))
```

The chart values on cluster `a`, one store per grant:

```yaml
awsStores:
  - name: a-app-config
    region: eu-example-1
    role: arn:aws:iam::444455556666:role/a-app-config
    conditions:
      - namespaces: [example-app]
```

| Output | Where | What reads it |
|---|---|---|
| `ClusterIdentity.RoleARN` (registered output `roleArn`), `RoleName` (`roleName`) | the cluster's stack | each `Grant.Principal` |
| `Readers.RoleARNs[<grant>]` (registered output `roleArns`, a map by grant name) | the parameters' stack | the cluster's `SourceRoles`, and `awsStores[].role` |

The reader role ARNs are predictable (`arn:aws:iam::<account>:role/<grant>`),
so the cluster's `SourceRoles` can be written before the readers exist. A
pattern over a shared name prefix keeps the cluster side unchanged as grants
are added.

## Resources

The type and logical name of every resource are part of the package's
contract, as in [awsserver.md](awsserver.md#the-alias-contract). `<N>` is
the `Name` argument and `<G>` a grant's `Name`. A constructor's options go
to its component, and the children inherit them through the parent.

| Constructor | Kind (Pulumi type) | Logical name | Parent |
|---|---|---|---|
| `NewClusterIdentity` | `truvity:secrets/esoaws:ClusterIdentity` (component) | `<N>` | caller's |
| | `aws:iam/role:Role` | `<N>` | the component |
| | `aws:iam/rolePolicy:RolePolicy` (policy name `assume-parameter-readers`) | `<N>-policy` | the component |
| | `aws:eks/podIdentityAssociation:PodIdentityAssociation` | `<N>-pia` | the component |
| `NewReaders` | `truvity:secrets/esoaws:Readers` (component) | `<N>` | caller's |
| | `aws:iam/role:Role` | `<G>` | the component |
| | `aws:iam/rolePolicy:RolePolicy` (policy name `<G>`) | `<G>-policy` | the component |

The policy documents are also exported as functions
(`ClusterTrustPolicy`, `ClusterPolicy`, `ReaderTrustPolicy`,
`ReaderPolicy`), and `pkg/esoaws/testdata` holds them as goldens.

## The chart's name

`awsStores` render in `openbao-consumers` because that chart already holds
the cluster's External Secrets stores and their tenancy rules. These stores
have nothing to do with OpenBAO, so the name no longer describes everything
the chart does. The chart keeps its name for now: a rename changes every
adopter's OCI path and should be a release decision of its own.
