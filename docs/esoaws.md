# External Secrets reading Parameter Store across accounts

`pkg/esoaws` and the `awsStores` of `charts/openbao-consumers` let the
External Secrets Operator (ESO) on a cluster read AWS Systems Manager
Parameter Store parameters that live in another AWS account. The mechanism
is general: it does not know what writes the parameters or why. Every
particular (accounts, regions, clusters, issuers, role names, parameter
names) is an input.

## One identity mode per cluster

A cluster proves who it is in exactly one of two modes. Both the library
(`IdentityMode`) and the chart (`aws.identity`) require you to name the
mode, and neither has a default.

| | `PodIdentity` | `WebIdentity` |
|---|---|---|
| For | EKS | any cluster whose ServiceAccount issuer AWS can reach (self-hosted, and EKS too) |
| What holds AWS credentials | the ESO controller, through EKS Pod Identity | nothing on the cluster, as far as this library is concerned (see below) |
| Cluster side in AWS | `NewClusterIdentity`: a role and a Pod Identity association | nothing |
| Parameters' side | one reader role per grant, trusting the cluster's role | an IAM OIDC provider for the cluster's issuer, and one reader role per grant trusting one ServiceAccount's tokens |
| A store | names its reader `role`, no auth | names its own ServiceAccount (`auth.jwt.serviceAccountRef`), no `role` |
| Admission policy | required, on by default | not needed, off by default |

**The modes are mutually exclusive.** A cluster with an ambient controller
identity next to per-store identities has the weakness of the first and the
cost of the second. Any store that names no auth, by mistake or by intent,
reads as the controller, and that reopens what the admission policy exists
to close. So `NewClusterIdentity` refuses a `WebIdentity` cluster. A
`Cluster` with no mode, or with the other mode's settings, is refused. A
grant that does not fit its cluster's mode is refused. The chart refuses a
store that does not fit `aws.identity`, with a fixture for each mix.

## The chains

### PodIdentity

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
   assume only the exact role ARNs in its `SourceRoles`, and a reader role
   trusts only that cluster's role.
3. ESO then calls SSM as the reader role, inside the parameters' account.

EKS Pod Identity can also chain to a target role by itself (an
association's target role). But an association has one target, and ESO
needs one role per store, so the cluster identity stays in its own account.

### WebIdentity

```
cluster                                       parameters' account
──────────────────────────────────            ─────────────────────────────────
ServiceAccount of one store      sts:AssumeRoleWithWebIdentity
  (external-secrets/<grant SA>)  ────────────────────────────►  reader role, one per grant
  token minted by ESO,           verified by the IAM OIDC        trusts sub = that ServiceAccount,
  signed by the cluster's        provider for the cluster's      aud = the cluster's audience
  ServiceAccount issuer          issuer (NewReaders)               │ ssm:GetParameter*, kms:Decrypt
                                                                   ▼ (same account)
                                                                 the granted parameters
```

1. Each store names its own ServiceAccount in the ESO namespace. ESO reads
   the role from the ServiceAccount's `eks.amazonaws.com/role-arn`
   annotation. It requests a token for that ServiceAccount, with the
   audience from `eks.amazonaws.com/audience` (default `sts.amazonaws.com`),
   and calls `AssumeRoleWithWebIdentity`. The chart renders the
   ServiceAccount with both annotations, and it mounts no token; nothing
   runs as it.
2. STS verifies the token with the IAM OIDC provider registered for the
   cluster's issuer in the parameters' account. `NewReaders` creates the
   provider, or takes an existing one by ARN. The reader role trusts that
   provider only for `<issuer>:sub = system:serviceaccount:<namespace>:<name>`
   and `<issuer>:aud = <audience>`.
3. ESO calls SSM as the reader role, inside the parameters' account.

The store carries no `role` of its own: ESO would assume it on top of the
web identity, and the reader role does not trust itself.

"Nothing on the cluster holds AWS credentials" is true only of what this
library creates. It stays true only if nothing outside it grants the ESO
controller's ServiceAccount AWS rights: no Pod Identity association or IRSA
annotation of its own, and no node role reachable from its pods that may
assume a reader role. If something does, the cluster is in effect in both
modes, and the admission policy is needed again.

The issuer must be reachable from AWS. The cluster's API server signs
ServiceAccount tokens with an `iss` of its `--service-account-issuer`, and
STS fetches that URL's `/.well-known/openid-configuration` and the keys it
points to. On a self-hosted cluster that usually means publishing the
discovery document and the JWKS on a public HTTPS host, such as a static
bucket, and setting the API server's issuer to that URL. `IssuerURL` must
match the tokens' `iss` exactly, with no trailing slash and the host in
lower case (IAM names the provider and its condition keys by the URL as
written). An EKS cluster's
own issuer works too.

## Encryption: the default key is enough

A SecureString is decrypted by SSM, on behalf of the caller, with the key
it was written with. In both modes the caller is the reader role, which
belongs to the parameters' own account. So the account's default `aws/ssm`
key works: its key policy lets any principal of the account use it through
SSM, and the reader role needs no KMS grant. (`aws/ssm` cannot be shared
with another account. That is why the reader role lives with the
parameters, and the trust is the only cross-account hop.)

Set `Grant.KMSKeyARN` only when the parameters are encrypted with a
customer-managed key. The reader role then gets `kms:Decrypt` on that key,
only through SSM in the source's region (`kms:ViaService`) and only for the
granted parameters (`kms:EncryptionContext:PARAMETER_ARN`). The key's own
policy must also admit the role. The key must be in the source's region,
and it may be in another account if its key policy allows that.

## Least privilege

- **The cluster identity** (PodIdentity mode) may call `sts:AssumeRole` and
  `sts:TagSession` on its exact `SourceRoles` and nothing else. It has no
  SSM or KMS permissions of its own. Patterns are refused: reader role ARNs
  are predictable (`arn:aws:iam::<account>:role/<grant>`), and a pattern
  would trust roles that someone creates later.
- **Session tags.** Every trust and policy here that allows `sts:TagSession`
  admits only EKS Pod Identity's six tag keys (`eks-cluster-arn`,
  `eks-cluster-name`, `kubernetes-namespace`, `kubernetes-service-account`,
  `kubernetes-pod-name`, `kubernetes-pod-uid`), through
  `ForAllValues:StringEquals` on `aws:TagKeys`. A store cannot add its own
  tags to a reader's session, and the chart renders no `sessionTags`.
  WebIdentity trusts allow no `sts:TagSession` at all.
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
- **Size.** IAM allows an inline policy up to 10,240 characters. A grant or
  a cluster identity whose policy would be larger is refused before anything
  registers. Use a prefix instead of a long list of names.

## Tenancy: one store per (cluster, grant)

Any namespace that can use a store can read everything its grant reads.
So the unit of access is the grant: one reader role per audience, and one
`ClusterSecretStore` per (cluster, grant), limited by `conditions` to the
namespaces of that audience. A condition must select something: a
non-empty list of namespaces, or a `namespaceSelector` with labels or
expressions. An empty selector selects every namespace, so it is refused.
An `awsStores` expression must use the `In` operator with at least one
value: `NotIn`, `Exists` and `DoesNotExist` select namespaces nobody listed.
`awsStores` take no namespace regexes. An OpenBAO store's regexes must be
anchored (`^...$`), and none may match every namespace.

What each mode guarantees beyond that:

- **PodIdentity.** The controller's identity can assume every reader role
  of the cluster, so the guarantee rests on what may use that identity.
  Only the release's stores may: see [the admission policy](#the-admission-policy).
- **WebIdentity.** Each reader role trusts one ServiceAccount in the ESO
  namespace, and nothing on the cluster holds credentials. A namespaced
  `SecretStore` can reference only a ServiceAccount in its own namespace,
  so a tenant who creates one gets a token whose subject no reader role
  trusts. The guarantee holds as long as nobody but administrators may
  create objects, or ServiceAccount tokens, in the ESO namespace. The
  store's reference must name that namespace: without it, a
  `ClusterSecretStore` resolves the ServiceAccount in each ExternalSecret's
  own namespace. The chart's schema requires the namespace.

## The admission policy

In PodIdentity mode, ESO uses the controller's credentials for any AWS
object that names no auth of its own: a namespaced `SecretStore`, an
`ECRAuthorizationToken` or `STSSessionToken` generator, or a
`ClusterSecretStore`. An empty `auth: {}` counts as no auth. Anyone who may
create a `SecretStore` could set `role` to a reader's ARN and read that
grant from their own namespace. Two controls close that:

1. `aws.admissionPolicy`, a ValidatingAdmissionPolicy that the chart turns
   on by default in `podIdentity` mode (Kubernetes 1.30+). It refuses:
   - an AWS `SecretStore`, an `ECRAuthorizationToken` or `STSSessionToken`,
     or a `ClusterGenerator` wrapping either, without `secretRef` or `jwt`
     auth;
   - an AWS `ClusterSecretStore` that is not one of this release's
     `awsStores`;
   - one of the release's own stores that differs from what the release
     renders. In `podIdentity` mode it must assume exactly the rendered
     `role`, with no `auth`, `additionalRoles`, `sessionTags`,
     `transitiveTagKeys` or `externalID`. In `webIdentity` mode it must read
     as exactly the rendered ServiceAccount, with no `role`, keys or extra
     audiences. A GitOps apply leaves fields it does not declare in place,
     so a store edited or created outside the release would otherwise keep
     them.

   A store with its own keys or its own ServiceAccount is admitted, because
   it reads as itself. An update is judged even while its object waits on a
   finalizer to be deleted, since ESO still reads it. Only a finalizer's
   removal that leaves the spec as it was is let through. One release should
   render a cluster's `awsStores`, since the policy admits only its own. In
   `podIdentity` mode, turning the policy off, dropping `Deny` (the
   `[Warn, Audit]` dry run) or setting `failurePolicy: Ignore` fails the
   render unless `acknowledgeTenantsCanBorrowControllerIdentity: true` says
   so. `just admission-conformance` proves all of it on a real API server,
   against ESO's CRDs.
2. In the upstream ESO chart, `rbac.aggregateToEdit: false` and
   `rbac.aggregateToAdmin: false`. Those settings add create on
   `secretstores`, `externalsecrets` and the generators to every
   namespace's `edit` and `admin` roles. Tenants still need to create
   `ExternalSecret`s, so grant that alone, with your own role.

In WebIdentity mode neither control is needed for these stores. A store with
no auth has no credentials to borrow: the node's role, if the controller can
reach it, is not a principal any reader role trusts. The policy can still be
turned on (`aws.admissionPolicy.enabled: true`) as a second line.
[safety.md](safety.md#an-aws-identity-any-namespace-can-borrow) has the
same in the list of refusals.

## Wiring it up

The order matters. IAM resolves a trust policy's principal when the policy
is written, and refuses one that does not exist. Apply in this order:

- PodIdentity: the cluster identity, then the readers, then the stores.
- WebIdentity: the readers (which create the provider first), then the
  stores.

If a cluster identity is deleted and recreated, apply its readers again:
IAM stored the old role's unique id, not its name.

```go
import "github.com/truvity/secrets/pkg/esoaws"

// PodIdentity, in the cluster's account. Nothing like it exists for a
// WebIdentity cluster.
id, err := esoaws.NewClusterIdentity(ctx, esoaws.ClusterIdentityArgs{
    Mode:        esoaws.PodIdentityMode,
    Name:        "a-external-secrets",
    Provider:    clusterAccount,
    ClusterName: pulumi.String("a"),
    ClusterARN:  "arn:aws:eks:eu-example-1:111122223333:cluster/a",
    AccountID:   "111122223333",
    Region:      "eu-example-1",
    SourceRoles: []string{"arn:aws:iam::444455556666:role/a-app-config"},
})

// In the parameters' account: cluster a on Pod Identity, cluster b on web
// identity.
readers, err := esoaws.NewReaders(ctx, esoaws.ReadersArgs{
    Name:      "parameter-readers",
    Provider:  sourceAccount,
    AccountID: "444455556666",
    Region:    "eu-example-1",
    Clusters: []esoaws.Cluster{
        {Name: "a", Mode: esoaws.PodIdentityMode,
            PodIdentity: &esoaws.PodIdentity{RoleARN: "arn:aws:iam::111122223333:role/a-external-secrets"}},
        {Name: "b", Mode: esoaws.WebIdentityMode,
            WebIdentity: &esoaws.WebIdentity{IssuerURL: "https://oidc.b.example.com"}},
    },
    Grants: []esoaws.Grant{
        {Name: "a-app-config", Cluster: "a", Parameters: []string{"/app/config/", "/shared/endpoint"}},
        {Name: "b-app-config", Cluster: "b", Parameters: []string{"/app/config/"},
            ServiceAccount: &esoaws.ServiceAccount{Name: "eso-b-app-config"}}, // namespace: external-secrets
    },
})
```

The chart values on cluster `a`:

```yaml
aws:
  identity: podIdentity
awsStores:
  - name: a-app-config
    region: eu-example-1
    role: arn:aws:iam::444455556666:role/a-app-config
    conditions:
      - namespaces: [example-app]
```

and on cluster `b`:

```yaml
aws:
  identity: webIdentity
awsStores:
  - name: b-app-config
    region: eu-example-1
    role: arn:aws:iam::444455556666:role/b-app-config
    auth:
      jwt:
        serviceAccountRef:
          name: eso-b-app-config        # = the grant's ServiceAccount
          namespace: external-secrets
    conditions:
      - namespaces: [example-app]
```

| Output | Where | What reads it |
|---|---|---|
| `ClusterIdentity.RoleARN` (registered output `roleArn`), `RoleName` (`roleName`) | the cluster's stack (PodIdentity) | the reader side's `PodIdentity.RoleARN` |
| `Readers.RoleARNs[<grant>]` (`roleArns`, by grant name) | the parameters' stack | `SourceRoles` (PodIdentity), and `awsStores[].role` |
| `Readers.OIDCProviderARNs[<cluster>]` (`oidcProviderArns`, by cluster name) | the parameters' stack | nothing on the cluster; it is there to adopt or share the provider |

All the ARNs are predictable (`arn:aws:iam::<account>:role/<name>`,
`arn:aws:iam::<account>:oidc-provider/<issuer without https://>`), so each
side can be written before the other exists.

## Resources

The type and logical name of every resource are part of the package's
contract, as in [awsserver.md](awsserver.md#the-alias-contract). `<N>` is
the `Name` argument, `<G>` a grant's `Name` and `<C>` a cluster's `Name`. A
constructor's options go to its component, and the children inherit them
through the parent.

| Constructor | Kind (Pulumi type) | Logical name | Parent |
|---|---|---|---|
| `NewClusterIdentity` | `truvity:secrets/esoaws:ClusterIdentity` (component) | `<N>` | caller's |
| | `aws:iam/role:Role` | `<N>` | the component |
| | `aws:iam/rolePolicy:RolePolicy` (policy name `assume-parameter-readers`) | `<N>-policy` | the component |
| | `aws:eks/podIdentityAssociation:PodIdentityAssociation` | `<N>-pia` | the component |
| `NewReaders` | `truvity:secrets/esoaws:Readers` (component) | `<N>` | caller's |
| | `aws:iam/openIdConnectProvider:OpenIdConnectProvider` (a WebIdentity cluster with no `ProviderARN`) | `<N>-<C>-oidc` | the component |
| | `aws:iam/role:Role` | `<G>` | the component |
| | `aws:iam/rolePolicy:RolePolicy` (policy name `<G>`) | `<G>-policy` | the component |

The policy documents are also exported as functions
(`ClusterTrustPolicy`, `ClusterPolicy`, `ReaderTrustPolicy`,
`ReaderPolicy`). `pkg/esoaws/testdata` holds them as goldens, with one
reader trust for each mode.

## The chart's name

`awsStores` render in `openbao-consumers` because that chart already holds
the cluster's External Secrets stores and their tenancy rules. These stores
have nothing to do with OpenBAO, so the name no longer describes everything
the chart does. The chart keeps its name for now: a rename changes every
adopter's OCI path and should be a release decision of its own.
