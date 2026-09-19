package custody

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Neutral fixtures: the account is AWS's documented placeholder, the
// regions and addresses are examples.
const (
	testAccount    = "111122223333"
	testGeneration = "example-root-2026-01"
	testPrimary    = "eu-example-1"
	testReplica    = "eu-example-2"
	testPattern    = "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_admin_*"
	testAlertName  = "private-pki-root-sign-" + testGeneration

	primaryKeyARN   = "arn:aws:kms:eu-example-1:111122223333:key/mrk-primary"
	replicaKeyARN   = "arn:aws:kms:eu-example-2:111122223333:key/mrk-primary"
	primaryAliasARN = "arn:aws:kms:eu-example-1:111122223333:alias/private-pki/root/" + testGeneration
	replicaAliasARN = "arn:aws:kms:eu-example-2:111122223333:alias/private-pki/root/" + testGeneration
)

var testNotify = []string{"security@example.com", "platform@example.com"}

func testArgs() Args {
	return Args{
		AccountID:                     testAccount,
		Profile:                       "example-custody",
		TrustedPrincipalARNPattern:    testPattern,
		AdminRoleName:                 "private-pki-root-admin",
		CeremonyRoleName:              "private-pki-root-ceremony",
		PermissionsBoundaryPolicyName: "example-boundary",
		Generations:                   []Generation{{ID: testGeneration, Region: testPrimary, ReplicaRegion: testReplica}},
		Notify:                        testNotify,
		Tags: func(scope TagScope) map[string]string {
			return map[string]string{"scope": string(scope.Kind) + "/" + scope.Generation}
		},
	}
}

type (
	recordedResource struct {
		Type           string
		Name           string
		Inputs         resource.PropertyMap
		Protect        bool
		RetainOnDelete bool
	}

	custodyMocks struct {
		mu        sync.Mutex
		resources []recordedResource
	}

	policyDocument struct {
		Statement []struct {
			Sid       string                    `json:"Sid"`
			Principal map[string]any            `json:"Principal"`
			Action    any                       `json:"Action"`
			Resource  any                       `json:"Resource"`
			Condition map[string]map[string]any `json:"Condition"`
		} `json:"Statement"`
	}

	signPattern struct {
		Source     []string `json:"source"`
		DetailType []string `json:"detail-type"`
		Detail     struct {
			EventSource []string `json:"eventSource"`
			EventName   []string `json:"eventName"`
			Or          []struct {
				Resources *struct {
					ARN []string `json:"ARN"`
				} `json:"resources"`
				RequestParameters *struct {
					KeyID []string `json:"keyId"`
				} `json:"requestParameters"`
			} `json:"$or"`
		} `json:"detail"`
	}
)

func (m *custodyMocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	state := args.Inputs.Copy()
	switch args.TypeToken {
	case "aws:iam/role:Role":
		state[resource.PropertyKey("arn")] = resource.NewStringProperty("arn:aws:iam::111122223333:role/" + args.Name)
		state[resource.PropertyKey("name")] = resource.NewStringProperty(args.Name)
	case "aws:kms/key:Key":
		state[resource.PropertyKey("arn")] = resource.NewStringProperty(primaryKeyARN)
		state[resource.PropertyKey("keyId")] = resource.NewStringProperty("mrk-primary")
	case "aws:kms/replicaKey:ReplicaKey":
		state[resource.PropertyKey("arn")] = resource.NewStringProperty(replicaKeyARN)
		state[resource.PropertyKey("keyId")] = resource.NewStringProperty("mrk-primary")
	case "aws:sns/topic:Topic":
		// The logical name carries the region, the way the provider does;
		// the alert resources are per region and so are their ARNs.
		region := testPrimary
		if strings.Contains(args.Name, testReplica) {
			region = testReplica
		}
		state[resource.PropertyKey("arn")] = resource.NewStringProperty(
			"arn:aws:sns:" + region + ":111122223333:" + args.Inputs["name"].StringValue(),
		)
	}

	recorded := recordedResource{Type: args.TypeToken, Name: args.Name, Inputs: state}
	if args.RegisterRPC != nil {
		recorded.Protect = args.RegisterRPC.GetProtect()
		recorded.RetainOnDelete = args.RegisterRPC.GetRetainOnDelete()
	}
	m.mu.Lock()
	m.resources = append(m.resources, recorded)
	m.mu.Unlock()
	return fmt.Sprintf("%s-id", args.Name), state, nil
}

func (*custodyMocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

func (m *custodyMocks) resourcesByType() map[string][]recordedResource {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := map[string][]recordedResource{}
	for _, item := range m.resources {
		result[item.Type] = append(result[item.Type], item)
	}
	return result
}

func deploy(t *testing.T, args Args) map[string][]recordedResource {
	t.Helper()
	mocks := &custodyMocks{}
	require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := Deploy(ctx, args)
		return err
	}, pulumi.WithMocks("example", "private-pki-root", mocks)))
	return mocks.resourcesByType()
}

func TestKeyPolicySeparatesRecoveryAdministrationAndCeremony(t *testing.T) {
	policy, err := keyPolicy(
		DefaultPartition,
		testAccount,
		testPattern,
		"arn:aws:iam::111122223333:role/private-pki-root-admin",
		"arn:aws:iam::111122223333:role/private-pki-root-ceremony",
	)
	require.NoError(t, err)

	var document policyDocument
	require.NoError(t, json.Unmarshal([]byte(policy), &document))
	require.Len(t, document.Statement, 5)

	statements := map[string]string{}
	conditions := map[string]map[string]map[string]any{}
	principals := map[string]any{}
	for _, statement := range document.Statement {
		raw, err := json.Marshal(statement.Action)
		require.NoError(t, err)
		statements[statement.Sid] = string(raw)
		conditions[statement.Sid] = statement.Condition
		principals[statement.Sid] = statement.Principal[policyAWSKey]
	}
	assert.JSONEq(t, `["kms:DescribeKey","kms:GetKeyPolicy","kms:PutKeyPolicy"]`, statements["BreakGlassPolicyRecovery"])
	assert.Equal(t, "arn:aws:iam::111122223333:root", principals["BreakGlassPolicyRecovery"])
	for _, forbidden := range []string{"kms:Sign", "kms:ScheduleKeyDeletion", "kms:CreateGrant", "kms:PutKeyPolicy", `"kms:*"`} {
		assert.NotContains(t, statements["KeyAdministrationWithoutSigningOrDeletion"], forbidden)
	}
	// The trusted administrator holds the same administration as the role
	// it may assume, and no more: the key policy is the only authority, so
	// a deployer it does not name cannot even read back the tags it wrote.
	assert.Equal(t, statements["KeyAdministrationWithoutSigningOrDeletion"], statements["KeyAdministrationByApprovedSSOAdmin"])
	assert.Equal(t, testPattern, conditions["KeyAdministrationByApprovedSSOAdmin"][policyArnLikeKey][policyPrincipalARNKey])
	assert.JSONEq(t, `["kms:DescribeKey","kms:GetPublicKey"]`, statements["ExplicitRootCeremonyRead"])
	assert.Equal(t, `"kms:Sign"`, statements["ExplicitRootCeremonySign"])
	assert.Equal(t, ecdsaSHA384, conditions["ExplicitRootCeremonySign"][policyStringEqualsKey][kmsSigningAlgorithm])
}

func TestPoliciesComposeArnsInTheGivenPartition(t *testing.T) {
	policy, err := keyPolicy("aws-us-gov", testAccount, testPattern, "admin", "ceremony")
	require.NoError(t, err)
	assert.Contains(t, policy, `"arn:aws-us-gov:iam::111122223333:root"`)

	trust, err := roleTrustPolicy("aws-cn", testAccount, testPattern)
	require.NoError(t, err)
	assert.Contains(t, trust, `"arn:aws-cn:iam::111122223333:root"`)
}

func TestRoleTrustPolicyRestrictsAssumptionToTheTrustedPrincipals(t *testing.T) {
	policy, err := roleTrustPolicy(DefaultPartition, testAccount, testPattern)
	require.NoError(t, err)

	var document struct {
		Statement []struct {
			Principal map[string]string            `json:"Principal"`
			Condition map[string]map[string]string `json:"Condition"`
		} `json:"Statement"`
	}
	require.NoError(t, json.Unmarshal([]byte(policy), &document))
	require.Len(t, document.Statement, 1)
	assert.Equal(t, "arn:aws:iam::111122223333:root", document.Statement[0].Principal[policyAWSKey])
	assert.Equal(t, testPattern, document.Statement[0].Condition[policyArnLikeKey][policyPrincipalARNKey])
}

func TestDeployCreatesProtectedRetainedP384PrimaryAndReplica(t *testing.T) {
	resources := deploy(t, testArgs())

	require.Len(t, resources["aws:kms/key:Key"], 1)
	require.Len(t, resources["aws:kms/replicaKey:ReplicaKey"], 1)
	require.Len(t, resources["aws:kms/alias:Alias"], 2)
	require.Len(t, resources["aws:iam/role:Role"], 2)
	require.Len(t, resources["pulumi:providers:aws"], 3, "one for the roles, one per region of each generation")

	key := resources["aws:kms/key:Key"][0]
	assert.Equal(t, testGeneration, key.Name)
	assert.Equal(t, "ECC_NIST_P384", key.Inputs["customerMasterKeySpec"].StringValue())
	assert.Equal(t, "SIGN_VERIFY", key.Inputs["keyUsage"].StringValue())
	assert.True(t, key.Inputs["multiRegion"].BoolValue())
	assert.Equal(t, float64(DefaultDeletionWindowDays), key.Inputs["deletionWindowInDays"].NumberValue())
	assert.Equal(t, "Private PKI root "+testGeneration+" (multi-region primary)", key.Inputs["description"].StringValue())
	assert.Equal(t, "key/"+testGeneration, key.Inputs["tags"].ObjectValue()["scope"].StringValue())
	assert.True(t, key.Protect)
	assert.True(t, key.RetainOnDelete)

	replica := resources["aws:kms/replicaKey:ReplicaKey"][0]
	assert.True(t, replica.Protect)
	assert.True(t, replica.RetainOnDelete)
	assert.True(t, strings.Contains(replica.Inputs["primaryKeyArn"].StringValue(), ":key/mrk-"))
	assert.Equal(t, key.Inputs["policy"], replica.Inputs["policy"], "the replica carries the primary's policy")

	for _, alias := range resources["aws:kms/alias:Alias"] {
		assert.True(t, alias.Protect)
		assert.Equal(t, "alias/private-pki/root/"+testGeneration, alias.Inputs["name"].StringValue())
	}

	for _, role := range resources["aws:iam/role:Role"] {
		assert.True(t, role.Protect)
		assert.Equal(t, "arn:aws:iam::111122223333:policy/example-boundary", role.Inputs["permissionsBoundary"].StringValue())
		assert.Equal(t, float64(roleMaxSessionSeconds), role.Inputs["maxSessionDuration"].NumberValue())
		assert.Equal(t, "roles/", role.Inputs["tags"].ObjectValue()["scope"].StringValue())
	}

	for _, provider := range resources["pulumi:providers:aws"] {
		assert.True(t, strings.HasPrefix(provider.Name, "provider/aws/"))
		assert.Equal(t, "example-custody", provider.Inputs["profile"].StringValue())
	}
}

func TestDeployAlertsOnEveryRootKeySignInBothRegions(t *testing.T) {
	resources := deploy(t, testArgs())

	require.Len(t, resources["aws:sns/topic:Topic"], 2)
	require.Len(t, resources["aws:sns/topicPolicy:TopicPolicy"], 2)
	require.Len(t, resources["aws:sns/topicSubscription:TopicSubscription"], 2*len(testNotify))
	require.Len(t, resources["aws:cloudwatch/eventRule:EventRule"], 2)
	require.Len(t, resources["aws:cloudwatch/eventTarget:EventTarget"], 2)
	require.Len(t, resources["aws:cloudwatch/metricAlarm:MetricAlarm"], 2)

	// Every address is subscribed, and in both regions.
	subscribed := map[string]int{}
	for _, subscription := range resources["aws:sns/topicSubscription:TopicSubscription"] {
		assert.Equal(t, subscriptionProtocol, subscription.Inputs["protocol"].StringValue())
		subscribed[subscription.Inputs["endpoint"].StringValue()]++
	}
	for _, address := range testNotify {
		assert.Equal(t, 2, subscribed[address], "address %s must be told in both regions", address)
	}

	// One rule per region, each pinned to the key that region can sign
	// with: a rule matching only the primary would leave the replica
	// silent, which is the whole point of doing this twice.
	watched := map[string]bool{}
	for _, rule := range resources["aws:cloudwatch/eventRule:EventRule"] {
		assert.Equal(t, testAlertName, rule.Inputs["name"].StringValue())

		var pattern signPattern
		require.NoError(t, json.Unmarshal([]byte(rule.Inputs["eventPattern"].StringValue()), &pattern))
		assert.Equal(t, []string{"Sign"}, pattern.Detail.EventName)
		require.Len(t, pattern.Detail.Or, 2)
		require.NotNil(t, pattern.Detail.Or[0].Resources)
		for _, arn := range pattern.Detail.Or[0].Resources.ARN {
			watched[arn] = true
		}
	}
	assert.Equal(t, map[string]bool{
		primaryKeyARN:   true,
		primaryAliasARN: true,
		replicaKeyARN:   true,
		replicaAliasARN: true,
	}, watched)

	// Each region's target and alarm publish to that region's topic.
	topicARNs := map[string]bool{}
	for _, topic := range resources["aws:sns/topic:Topic"] {
		assert.Equal(t, testAlertName, topic.Inputs["name"].StringValue())
		topicARNs[topic.Inputs["arn"].StringValue()] = true
	}
	require.Len(t, topicARNs, 2)

	for _, target := range resources["aws:cloudwatch/eventTarget:EventTarget"] {
		assert.True(t, topicARNs[target.Inputs["arn"].StringValue()])
	}

	for _, alarm := range resources["aws:cloudwatch/metricAlarm:MetricAlarm"] {
		assert.Equal(t, "AWS/Events", alarm.Inputs["namespace"].StringValue())
		assert.Equal(t, "TriggeredRules", alarm.Inputs["metricName"].StringValue())
		assert.Equal(t, testAlertName, alarm.Inputs["dimensions"].ObjectValue()["RuleName"].StringValue())
		assert.Equal(t, "Sum", alarm.Inputs["statistic"].StringValue())
		assert.Equal(t, float64(signAlertPeriodSeconds), alarm.Inputs["period"].NumberValue())
		assert.Equal(t, float64(1), alarm.Inputs["evaluationPeriods"].NumberValue())
		// One signature in one minute is already the incident.
		assert.Equal(t, float64(0), alarm.Inputs["threshold"].NumberValue())
		assert.Equal(t, "GreaterThanThreshold", alarm.Inputs["comparisonOperator"].StringValue())
		assert.Equal(t, "notBreaching", alarm.Inputs["treatMissingData"].StringValue())
		assert.True(t, alarm.Inputs["actionsEnabled"].BoolValue())

		actions := alarm.Inputs["alarmActions"].ArrayValue()
		require.Len(t, actions, 1)
		assert.True(t, topicARNs[actions[0].StringValue()])
	}
}

// The pattern was checked against the live API with `aws events
// test-event-pattern`: a Sign on this key matches whether the caller named
// the alias or the ARN, and a Sign on another key or a Decrypt on this one
// does not.
func TestSignEventPatternMatchesEveryNameOfOneKeyAndNoOtherOperation(t *testing.T) {
	raw, err := signEventPattern(primaryKeyARN, "mrk-primary", "alias/private-pki/root/"+testGeneration, primaryAliasARN)
	require.NoError(t, err)

	var pattern signPattern
	require.NoError(t, json.Unmarshal([]byte(raw), &pattern))

	assert.Equal(t, []string{"aws.kms"}, pattern.Source)
	assert.Equal(t, []string{"AWS API Call via CloudTrail"}, pattern.DetailType)
	assert.Equal(t, []string{"kms.amazonaws.com"}, pattern.Detail.EventSource)
	assert.Equal(t, []string{"Sign"}, pattern.Detail.EventName)

	require.Len(t, pattern.Detail.Or, 2)
	require.NotNil(t, pattern.Detail.Or[0].Resources)
	assert.Equal(t, []string{primaryKeyARN, primaryAliasARN}, pattern.Detail.Or[0].Resources.ARN)
	require.NotNil(t, pattern.Detail.Or[1].RequestParameters)
	assert.Equal(t, []string{
		primaryKeyARN,
		primaryAliasARN,
		"mrk-primary",
		"alias/private-pki/root/" + testGeneration,
	}, pattern.Detail.Or[1].RequestParameters.KeyID)
}

func TestSignAlertTopicPolicyKeepsTheOwnerGrantItReplaces(t *testing.T) {
	const topicARN = "arn:aws:sns:eu-example-1:111122223333:" + testAlertName

	policy, err := signAlertTopicPolicy(DefaultPartition, testAccount, topicARN)
	require.NoError(t, err)

	var document policyDocument
	require.NoError(t, json.Unmarshal([]byte(policy), &document))
	require.Len(t, document.Statement, 3)

	byPrincipal := map[string]int{}
	for index, statement := range document.Statement {
		assert.Equal(t, topicARN, statement.Resource)
		if service, ok := statement.Principal[policyServiceKey].(string); ok {
			byPrincipal[service] = index
			assert.Equal(t, snsPublishAction, statement.Action)
			assert.Equal(t, testAccount, statement.Condition[policyStringEqualsKey][policySourceAccount])

			continue
		}
		byPrincipal[statement.Principal[policyAWSKey].(string)] = index
	}
	assert.Contains(t, byPrincipal, "arn:aws:iam::111122223333:root")
	assert.Contains(t, byPrincipal, serviceEvents)
	assert.Contains(t, byPrincipal, serviceCloudWatch)
}

// Rotation is additive: a second generation adds its own keys, providers
// and alarms beside the first, and the roles stay one pair.
func TestDeployKeepsEveryGenerationSideBySide(t *testing.T) {
	args := testArgs()
	args.Generations = append(args.Generations, Generation{ID: "example-root-2027-01", Region: testPrimary, ReplicaRegion: testReplica})
	resources := deploy(t, args)

	assert.Len(t, resources["aws:kms/key:Key"], 2)
	assert.Len(t, resources["aws:kms/replicaKey:ReplicaKey"], 2)
	assert.Len(t, resources["aws:iam/role:Role"], 2)
	assert.Len(t, resources["aws:cloudwatch/metricAlarm:MetricAlarm"], 4)
	assert.Len(t, resources["pulumi:providers:aws"], 5)
}

func TestDeployWithoutOptionalInputs(t *testing.T) {
	args := testArgs()
	args.Profile = ""
	args.PermissionsBoundaryPolicyName = ""
	args.Tags = nil
	args.Notify = nil
	resources := deploy(t, args)

	for _, role := range resources["aws:iam/role:Role"] {
		_, bounded := role.Inputs["permissionsBoundary"]
		assert.False(t, bounded, "no boundary unless one is named")
		_, tagged := role.Inputs["tags"]
		assert.False(t, tagged)
	}
	for _, provider := range resources["pulumi:providers:aws"] {
		_, profiled := provider.Inputs["profile"]
		assert.False(t, profiled)
	}
	assert.Empty(t, resources["aws:sns/topicSubscription:TopicSubscription"])
	assert.Len(t, resources["aws:cloudwatch/metricAlarm:MetricAlarm"], 2, "the alarm stands even with nobody subscribed")
}

func TestDeployRefusals(t *testing.T) {
	for name, mutate := range map[string]func(*Args){
		"no account":           func(a *Args) { a.AccountID = "" },
		"no trusted principal": func(a *Args) { a.TrustedPrincipalARNPattern = "" },
		"one role name twice":  func(a *Args) { a.CeremonyRoleName = a.AdminRoleName },
		"no generation":        func(a *Args) { a.Generations = nil },
		"a duplicate generation": func(a *Args) {
			a.Generations = append(a.Generations, a.Generations[0])
		},
		"one region twice":        func(a *Args) { a.Generations[0].ReplicaRegion = a.Generations[0].Region },
		"a short deletion window": func(a *Args) { a.DeletionWindowDays = 3 },
		"an empty address":        func(a *Args) { a.Notify = []string{""} },
	} {
		t.Run(name, func(t *testing.T) {
			args := testArgs()
			args.Generations = append([]Generation(nil), args.Generations...)
			mutate(&args)
			err := pulumi.RunErr(func(ctx *pulumi.Context) error {
				_, err := Deploy(ctx, args)
				return err
			}, pulumi.WithMocks("example", "private-pki-root", &custodyMocks{}))
			require.Error(t, err)
		})
	}
}
