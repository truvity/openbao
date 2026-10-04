package awsserver

import (
	"errors"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/sns"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type (
	// AlertTopicArgs configures NewAlertTopic.
	AlertTopicArgs struct {
		// Name is the logical-name stem: the topic is "<Name>-topic" and
		// each subscription "<Name>-subscription-<SubscriptionSlug(email)>".
		Name string
		// TopicName and DisplayName are the SNS topic's.
		TopicName   string
		DisplayName string
		Tags        map[string]string
		// Emails get an e-mail subscription each. The subscriptions are
		// created PendingConfirmation: confirm each through the API with
		// authenticate-on-unsubscribe, so a link-following mail scanner
		// cannot unsubscribe it.
		Emails []string
		// Provider is the AWS provider of the topic's region. Required.
		Provider pulumi.ProviderResource
	}

	// AlertTopic is an SNS topic with its e-mail subscriptions.
	AlertTopic struct {
		Topic         *sns.Topic
		Subscriptions []*sns.TopicSubscription
	}
)

// NewAlertTopic registers an alert topic and its e-mail subscriptions,
// directly (no wrapping component; see NewUnsealKey for why).
func NewAlertTopic(ctx *pulumi.Context, args AlertTopicArgs, options ...Option) (*AlertTopic, error) {
	if args.Name == "" || args.TopicName == "" || args.Provider == nil {
		return nil, errors.New("awsserver: alert topic: Name, TopicName and Provider are required")
	}

	s := newSettings(options)
	out := &AlertTopic{}

	name := args.Name + "-topic"

	topic, err := sns.NewTopic(ctx, name, &sns.TopicArgs{
		Name:        pulumi.String(args.TopicName),
		DisplayName: pulumi.String(args.DisplayName),
		Tags:        pulumi.ToStringMap(args.Tags),
	}, s.opts(KindSNSTopic, name, pulumi.Provider(args.Provider))...)
	if err != nil {
		return nil, fmt.Errorf("awsserver: topic %s: %w", args.TopicName, err)
	}

	out.Topic = topic

	for _, address := range args.Emails {
		name := args.Name + "-subscription-" + SubscriptionSlug(address)

		sub, err := sns.NewTopicSubscription(ctx, name, &sns.TopicSubscriptionArgs{
			Topic:    topic.Arn,
			Protocol: pulumi.String("email"),
			Endpoint: pulumi.String(address),
		}, s.opts(KindSNSTopicSubscription, name, pulumi.Provider(args.Provider))...)
		if err != nil {
			return nil, fmt.Errorf("awsserver: subscribe %s to %s: %w", address, args.TopicName, err)
		}

		out.Subscriptions = append(out.Subscriptions, sub)
	}

	return out, nil
}
