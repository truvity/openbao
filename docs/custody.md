# Custody of the root key

`pkg/custody` is a Pulumi Go module that creates what a KMS-rooted PKI
needs before its first ceremony, and nothing that signs:

| Per | Resources |
|---|---|
| account | two IAM roles: **admin** (administer the keys; cannot sign, schedule deletion, create grants or write the key policy) and **ceremony** (read the public key and sign, `ECDSA_SHA_384` only) |
| root generation | a multi-region `ECC_NIST_P384` `SIGN_VERIFY` key, its replica in a second region, an alias in each; the keys `Protect` and `RetainOnDelete`, the aliases `Protect`, a 30-day deletion window |
| generation × region | the Sign alarm: an SNS topic with e-mail subscriptions, an EventBridge rule matching CloudTrail's `kms:Sign` on that key, a CloudWatch alarm on the rule |

```go
import "github.com/truvity/openbao/pkg/custody"

keys, err := custody.Deploy(ctx, custody.Args{
    AccountID:                     "111122223333",
    Profile:                       "example-custody",
    TrustedPrincipalARNPattern:    "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_admin_*",
    AdminRoleName:                 "private-pki-root-admin",
    CeremonyRoleName:              "private-pki-root-ceremony",
    PermissionsBoundaryPolicyName: "example-boundary",
    Generations: []custody.Generation{
        {ID: "example-root-2026-01", Region: "eu-example-1", ReplicaRegion: "eu-example-2"},
    },
    Notify: []string{"security@example.com"},
})
// keys.Generations[i].Key.Arn is what `openbaoctl pki create-root --key-arn` takes;
// keys.CeremonyRole.Arn is its --role-arn.
```

Every input is in [reference.md](reference.md#pkgcustody).

## The key policy is the whole authority

A KMS key policy that does not name a principal means no IAM policy can
grant that principal anything. So the policy says everything:

| Statement | Principal | Actions |
|---|---|---|
| `BreakGlassPolicyRecovery` | the account root | `DescribeKey`, `GetKeyPolicy`, `PutKeyPolicy`: a policy that locked everyone out can be repaired, and nothing else |
| `KeyAdministrationWithoutSigningOrDeletion` | the admin role | administration: aliases, enable/disable, tags, description, replication, primary region, cancel deletion, and the four reads the provider needs |
| `KeyAdministrationByApprovedSSOAdmin` | the account root, `ArnLike` the trusted pattern | the same administration, for the session that applies this |
| `ExplicitRootCeremonyRead` | the ceremony role | `DescribeKey`, `GetPublicKey` |
| `ExplicitRootCeremonySign` | the ceremony role | `Sign`, only with `kms:SigningAlgorithm = ECDSA_SHA_384` |

The trusted administrator appears beside the admin role because the
custody is applied from that session and the AWS provider reads a key's
tags and policy back right after creating it: a policy naming only the
admin role leaves the provider unable to finish creating the key it has
just made. It is not a widening -- both roles' trust policies admit
exactly that pattern, so the same person already holds these actions one
`sts:AssumeRole` away. Signing, deletion scheduling, grant creation and
key-policy writes stay out of both.

The administration list includes `GetKeyRotationStatus` and
`ListResourceTags`: the provider asks for both after every create and
update, even of a `SIGN_VERIFY` key that cannot rotate, and a policy that
omits one fails the apply **after** the key exists.

## The Sign alarm

After the ceremony a root key signs two or three times in its life, so
the alarm does not rate-limit, it says "this happened at all". KMS has no
CloudWatch metric for `Sign`, so detection is CloudTrail through
EventBridge; the rule matches the key by every name a caller can use (key
ARN, key id, alias, alias ARN, in `resources` or in `requestParameters`),
and the alarm on the rule's `TriggeredRules` metric is the standing,
visible ALARM state behind the immediate notification. One matched call
in one minute breaches it; missing data, the normal state, does not.

It is duplicated per region because a multi-region key can be signed with
in either, and CloudTrail, EventBridge and CloudWatch are regional.

Two prerequisites are outside the module. Check both before the first
ceremony, or its signature is the one nobody hears:

1. **A multi-region trail logging management events** in the custody
   account. EventBridge emits `AWS API Call via CloudTrail` only where a
   trail records the call.
2. **Every subscription confirmed.** An e-mail subscription is
   `PendingConfirmation` until someone follows the AWS mail, in both
   regions; `aws sns list-subscriptions-by-topic` shows which are.

## Adopting existing custody

`Deploy` registers every resource directly on the caller's context (under
whatever `pulumi.Parent` the caller passes), not inside a component
resource of its own, and every Pulumi name is derived from the inputs:
`provider/aws/<RolesProviderName>`, `provider/aws/<generation>-primary`
and `-replica`, the role names, `<generation>`, `<generation>-alias`,
`<generation>-replica`, `<generation>-replica-alias`, and
`<generation>-sign-alert-<region>-{topic,topic-policy,subscription-<address>,rule,target,alarm}`.
Custody that already runs under those names is adopted with an empty
preview; see [adoption.md](adoption.md#adopting-an-existing-ceremony-and-custody).
A wrapper type would have put itself into every child's URN, and a
changed URN on a protected, retained root key is a replacement nobody
wants to review.
