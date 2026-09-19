package custody

import (
	"fmt"
	"strings"

	awspulumi "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/sns"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Root-key Sign alerting, per generation and per custody region.
//
// What it has to catch is rare on purpose: after the ceremony a root key
// signs two or three times in its life, so the job is not rate limiting,
// it is "this happened at all, tell a human now".
//
// Detection is CloudTrail via EventBridge:
//
//   - KMS publishes no CloudWatch metric for Sign, so there is nothing to
//     alarm on directly.
//   - A trail that delivers to S3 only has no log group for a metric filter
//     to sit on, and this should not require one.
//   - A multi-region trail with management events is what makes `AWS API
//     Call via CloudTrail` events appear on the default bus in BOTH custody
//     regions. That trail is a prerequisite, not something this creates.
//
// So the rule is the detector, and it is duplicated per region because a
// multi-region key can be signed with in either and a rule in one region
// sees nothing of the other. The CloudWatch alarm rides the rule's own
// AWS/Events TriggeredRules metric: it is the standing, visible ALARM
// state, and a second notification behind the immediate one.
//
// Notification is a topic in the custody account beside the key, not an
// organisation-wide alerts topic elsewhere: such a topic may not exist in
// both custody regions, EventBridge documents event buses, not SNS, as the
// cross-region target, and the custody is applied with the custody
// account's own identity. The cost is that the subscriptions are addresses,
// and each one is confirmed by hand once.
const (
	// signAlertPeriodSeconds is one minute: the shortest useful window for
	// an event that should never occur.
	signAlertPeriodSeconds = 60

	snsPublishAction     = "sns:Publish"
	policySourceAccount  = "aws:SourceAccount"
	policyServiceKey     = "Service"
	serviceEvents        = "events.amazonaws.com"
	serviceCloudWatch    = "cloudwatch.amazonaws.com"
	subscriptionProtocol = "email"
)

type (
	// signAlertScope is one key in one region: everything the alert needs
	// to name what it guards.
	signAlertScope struct {
		generation string
		region     string
		alias      string
		keyARN     pulumi.StringOutput
		keyID      pulumi.StringOutput
		provider   *awspulumi.Provider
	}
)

// deploySignAlerts creates the detection and notification path for one key
// in one region: an SNS topic with its subscriptions, the EventBridge rule
// that matches kms:Sign on that key, and a CloudWatch alarm on the rule.
func deploySignAlerts(ctx *pulumi.Context, args Args, scope signAlertScope, extra []pulumi.ResourceOption) error {
	prefix := scope.generation + "-sign-alert-" + scope.region
	name := args.SignAlertPrefix + scope.generation
	tags := args.tags(TagScope{Kind: TagSignAlert, Generation: scope.generation})
	opts := append([]pulumi.ResourceOption{pulumi.Provider(scope.provider)}, extra...)

	topic, err := sns.NewTopic(ctx, prefix+"-topic", &sns.TopicArgs{
		Name:        pulumi.String(name),
		DisplayName: pulumi.String("private PKI root signature"),
		Tags:        tags,
	}, opts...)
	if err != nil {
		return fmt.Errorf("create sign alert topic %s/%s: %w", scope.generation, scope.region, err)
	}

	policy := topic.Arn.ApplyT(func(topicARN string) (string, error) {
		return signAlertTopicPolicy(args.Partition, args.AccountID, topicARN)
	}).(pulumi.StringOutput)

	if _, err := sns.NewTopicPolicy(ctx, prefix+"-topic-policy", &sns.TopicPolicyArgs{
		Arn:    topic.Arn,
		Policy: policy,
	}, opts...); err != nil {
		return fmt.Errorf("create sign alert topic policy %s/%s: %w", scope.generation, scope.region, err)
	}

	for _, address := range args.Notify {
		subscription := prefix + "-subscription-" + subscriptionSlug(address)
		// Email subscriptions are created PendingConfirmation: AWS mails
		// the address and a human clicks once. Nothing here can do that
		// for them.
		if _, err := sns.NewTopicSubscription(ctx, subscription, &sns.TopicSubscriptionArgs{
			Topic:    topic.Arn,
			Protocol: pulumi.String(subscriptionProtocol),
			Endpoint: pulumi.String(address),
		}, opts...); err != nil {
			return fmt.Errorf("subscribe %s to sign alerts %s/%s: %w", address, scope.generation, scope.region, err)
		}
	}

	pattern := pulumi.All(scope.keyARN, scope.keyID).ApplyT(func(values []any) (string, error) {
		return signEventPattern(values[0].(string), values[1].(string), scope.alias, arn(args.Partition, "kms", scope.region, args.AccountID, scope.alias))
	}).(pulumi.StringOutput)

	rule, err := cloudwatch.NewEventRule(ctx, prefix+"-rule", &cloudwatch.EventRuleArgs{
		Name:         pulumi.String(name),
		Description:  pulumi.String("Every kms:Sign with private PKI root " + scope.generation + " in " + scope.region),
		EventPattern: pattern,
		Tags:         tags,
	}, opts...)
	if err != nil {
		return fmt.Errorf("create sign alert rule %s/%s: %w", scope.generation, scope.region, err)
	}

	if _, err := cloudwatch.NewEventTarget(ctx, prefix+"-target", &cloudwatch.EventTargetArgs{
		Rule:     rule.Name,
		Arn:      topic.Arn,
		TargetId: pulumi.String(name),
	}, opts...); err != nil {
		return fmt.Errorf("create sign alert target %s/%s: %w", scope.generation, scope.region, err)
	}

	// One matched event in one minute is already the incident, so the
	// threshold is "more than none" and a single period decides. Missing
	// data is the normal state of this key and must not raise anything.
	if _, err := cloudwatch.NewMetricAlarm(ctx, prefix+"-alarm", &cloudwatch.MetricAlarmArgs{
		Name:               pulumi.String(name),
		Namespace:          pulumi.String("AWS/Events"),
		MetricName:         pulumi.String("TriggeredRules"),
		Dimensions:         pulumi.StringMap{"RuleName": rule.Name},
		Statistic:          pulumi.String("Sum"),
		Period:             pulumi.Int(signAlertPeriodSeconds),
		EvaluationPeriods:  pulumi.Int(1),
		Threshold:          pulumi.Float64(0),
		ComparisonOperator: pulumi.String("GreaterThanThreshold"),
		TreatMissingData:   pulumi.String("notBreaching"),
		ActionsEnabled:     pulumi.Bool(true),
		AlarmActions:       pulumi.Array{topic.Arn},
		AlarmDescription: pulumi.String(
			"private PKI root " + scope.generation + " was used to sign in " + scope.region +
				"; every signature after the ceremony is an incident",
		),
		Tags: tags,
	}, opts...); err != nil {
		return fmt.Errorf("create sign alert alarm %s/%s: %w", scope.generation, scope.region, err)
	}

	return nil
}

// signEventPattern matches kms:Sign on one key, by every name a caller can
// use to reach it. CloudTrail records the key under detail.resources[].ARN,
// and the caller's own spelling under requestParameters.keyId -- which may
// be the key ARN, the bare key id, the alias name or the alias ARN. Both
// anchors are accepted because missing THIS event costs more than an extra
// page: if either one names the root key, a human is told.
func signEventPattern(keyARN, keyID, alias, aliasARN string) (string, error) {
	names := []string{keyARN, aliasARN, keyID, alias}

	return marshalPolicy(map[string]any{
		"source":      []string{"aws.kms"},
		"detail-type": []string{"AWS API Call via CloudTrail"},
		"detail": map[string]any{
			"eventSource": []string{"kms.amazonaws.com"},
			"eventName":   []string{"Sign"},
			"$or": []map[string]any{
				{"resources": map[string]any{"ARN": []string{keyARN, aliasARN}}},
				{"requestParameters": map[string]any{"keyId": names}},
			},
		},
	})
}

// signAlertTopicPolicy lets EventBridge and CloudWatch publish, and keeps
// the account's own grant. A topic policy REPLACES the default one, so the
// owner statement has to be restated or the account loses it.
func signAlertTopicPolicy(partition, accountID, topicARN string) (string, error) {
	owner := arn(partition, "iam", "", accountID, "root")
	fromThisAccount := map[string]any{
		policyStringEqualsKey: map[string]any{policySourceAccount: accountID},
	}

	return marshalPolicy(map[string]any{
		policyVersionKey: policyVersion,
		policyStatementKey: []map[string]any{
			{
				policySidKey:       "OwnerAccountTopicAdministration",
				policyEffectKey:    policyAllow,
				policyPrincipalKey: map[string]any{policyAWSKey: owner},
				policyActionKey: []string{
					"sns:AddPermission",
					"sns:DeleteTopic",
					"sns:GetTopicAttributes",
					"sns:ListSubscriptionsByTopic",
					snsPublishAction,
					"sns:RemovePermission",
					"sns:SetTopicAttributes",
					"sns:Subscribe",
				},
				policyResourceKey: topicARN,
			},
			{
				policySidKey:       "AllowEventBridgePublish",
				policyEffectKey:    policyAllow,
				policyPrincipalKey: map[string]any{policyServiceKey: serviceEvents},
				policyActionKey:    snsPublishAction,
				policyResourceKey:  topicARN,
				policyConditionKey: fromThisAccount,
			},
			{
				policySidKey:       "AllowCloudWatchAlarmPublish",
				policyEffectKey:    policyAllow,
				policyPrincipalKey: map[string]any{policyServiceKey: serviceCloudWatch},
				policyActionKey:    snsPublishAction,
				policyResourceKey:  topicARN,
				policyConditionKey: fromThisAccount,
			},
		},
	})
}

// subscriptionSlug keeps one Pulumi name per address, stable across list
// reordering: an index would rename every subscription below an insert.
func subscriptionSlug(address string) string {
	return strings.NewReplacer("@", "-at-", ".", "-").Replace(address)
}
