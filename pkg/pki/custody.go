package pki

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"go.yaml.in/yaml/v3"
)

const (
	keyResourcePrefix  = "key/mrk-"
	roleResourcePrefix = "role/"
	aliasPrefix        = "alias/"
)

type (
	// CustodyOutputs is what the custody side (pkg/custody deployed by
	// Pulumi, or hand-written custody) publishes about the root keys: the
	// public identifiers of each generation's key pair and the roles. It is
	// a plain YAML file synced into the repository that holds the contract,
	// and it is public information -- ARNs and regions, never a credential.
	// [Contract.VerifyCustody] binds it to the contract and to the flags of
	// one signing command before that command may name a key.
	//
	//	adminRoleArn: arn:aws:iam::111122223333:role/root-admin
	//	ceremonyRoleArn: arn:aws:iam::111122223333:role/root-ceremony
	//	generations:
	//	  root-2026-01:
	//	    alias: alias/private-pki/root/root-2026-01
	//	    primaryKeyArn: arn:aws:kms:eu-central-1:111122223333:key/mrk-...
	//	    primaryRegion: eu-central-1
	//	    replicaKeyArn: arn:aws:kms:eu-north-1:111122223333:key/mrk-...
	//	    replicaRegion: eu-north-1
	//	    ceremonyRoleArn: arn:aws:iam::111122223333:role/root-ceremony
	CustodyOutputs struct {
		AdminRoleARN    string                       `yaml:"adminRoleArn"`
		CeremonyRoleARN string                       `yaml:"ceremonyRoleArn"`
		Generations     map[string]CustodyGeneration `yaml:"generations"`
	}

	// CustodyGeneration is one root generation's published key pair.
	CustodyGeneration struct {
		Alias           string `yaml:"alias"`
		PrimaryKeyARN   string `yaml:"primaryKeyArn"`
		PrimaryRegion   string `yaml:"primaryRegion"`
		ReplicaKeyARN   string `yaml:"replicaKeyArn"`
		ReplicaRegion   string `yaml:"replicaRegion"`
		CeremonyRoleARN string `yaml:"ceremonyRoleArn"`
	}

	// CustodyRequest is what one signing command is about to do, to be
	// checked against the published custody. Empty fields were not given.
	CustodyRequest struct {
		// KeyARN is the key the command will sign with: --key-arn, or the
		// committed root artifact's own.
		KeyARN string
		// ArtifactKeyARN is the committed root artifact's keyArn, when one
		// exists (it does not while the root is being created).
		ArtifactKeyARN string
		// RoleARN is the role the command will assume (--role-arn).
		RoleARN string
		// Profile is the AWS shared-config profile (--aws-profile).
		Profile string
	}

	// CustodyVerdict is the outcome of a successful check: what was proven,
	// and the profile, role and key the signing must use.
	CustodyVerdict struct {
		// Proven is one statement per verified fact, for the operator.
		Proven []string
		// Profile, RoleARN and KeyARN are what to sign with: the request's
		// own where it named one (it matched), the published one otherwise.
		Profile string
		RoleARN string
		KeyARN  string
	}
)

// LoadCustodyOutputs reads a custody outputs file strictly (an unknown key
// is an error) and checks it for internal consistency. A missing file is an
// error: custody outputs that are not there prove nothing.
func LoadCustodyOutputs(path string) (*CustodyOutputs, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("custody outputs %s: %w (deploy the custody and sync its outputs, or pass a reason to skip the check)", path, err)
	}

	outputs, err := ParseCustodyOutputs(raw)
	if err != nil {
		return nil, fmt.Errorf("custody outputs %s: %w", path, err)
	}

	return outputs, nil
}

// ParseCustodyOutputs is [LoadCustodyOutputs] over bytes already read.
func ParseCustodyOutputs(raw []byte) (*CustodyOutputs, error) {
	var outputs CustodyOutputs

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)

	if err := decoder.Decode(&outputs); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	if err := outputs.Validate(); err != nil {
		return nil, err
	}

	return &outputs, nil
}

// Validate checks the outputs against themselves: both roles are IAM roles
// of one account and partition and are two different roles, and every
// generation is a multi-region key whose primary and replica are the same
// key in two regions, in that account, with the stack's ceremony role.
func (o *CustodyOutputs) Validate() error {
	admin, err := parseRoleARN(o.AdminRoleARN)
	if err != nil {
		return fmt.Errorf("adminRoleArn: %w", err)
	}

	ceremony, err := parseRoleARN(o.CeremonyRoleARN)
	if err != nil {
		return fmt.Errorf("ceremonyRoleArn: %w", err)
	}

	if admin.AccountID != ceremony.AccountID || admin.Partition != ceremony.Partition {
		return fmt.Errorf("the admin and ceremony roles must be in one AWS account and partition")
	}

	if o.AdminRoleARN == o.CeremonyRoleARN {
		return fmt.Errorf("the admin and ceremony roles must be two different roles " +
			"(the admin role can neither sign nor schedule a deletion, the ceremony role signs)")
	}

	if len(o.Generations) == 0 {
		return fmt.Errorf("at least one generation is required")
	}

	for _, id := range sortedKeys(o.Generations) {
		if err := o.Generations[id].validate(id, o.CeremonyRoleARN, ceremony); err != nil {
			return fmt.Errorf("generation %q: %w", id, err)
		}
	}

	return nil
}

func (g CustodyGeneration) validate(id, ceremonyRoleARN string, ceremonyRole arn.ARN) error {
	if id == "" || !strings.HasPrefix(g.Alias, aliasPrefix) || !strings.HasSuffix(g.Alias, id) {
		return fmt.Errorf("alias %q is not an alias/... ending in the generation ID", g.Alias)
	}

	if g.PrimaryRegion == "" || g.ReplicaRegion == "" || g.PrimaryRegion == g.ReplicaRegion {
		return fmt.Errorf("the primary and replica regions must both be set and differ, got %q and %q", g.PrimaryRegion, g.ReplicaRegion)
	}

	primary, err := parseKeyARN(g.PrimaryKeyARN, g.PrimaryRegion)
	if err != nil {
		return fmt.Errorf("primary key: %w", err)
	}

	replica, err := parseKeyARN(g.ReplicaKeyARN, g.ReplicaRegion)
	if err != nil {
		return fmt.Errorf("replica key: %w", err)
	}

	if primary.Partition != replica.Partition || primary.AccountID != replica.AccountID || primary.Resource != replica.Resource {
		return fmt.Errorf("the primary and replica are not the same multi-region key")
	}

	if primary.Partition != ceremonyRole.Partition || primary.AccountID != ceremonyRole.AccountID {
		return fmt.Errorf("the key's account does not match the custody roles' account")
	}

	if g.CeremonyRoleARN != ceremonyRoleARN {
		return fmt.Errorf("ceremonyRoleArn %q is not the stack's ceremonyRoleArn %q", g.CeremonyRoleARN, ceremonyRoleARN)
	}

	return nil
}

// VerifyCustody is the cross-check every signing command makes before it
// may use a key: the published custody outputs against the authored
// contract, and against what the command is about to do. It fails closed on
// the first disagreement, with a message that names both sides:
//
//   - the outputs are internally consistent ([CustodyOutputs.Validate]);
//   - every authored generation is published, and nothing else is;
//   - for every authored generation the key's account is the authored
//     account, the primary region is the authored region, and the replica
//     region is the authored disaster-recovery region (when the contract
//     states one);
//   - the key about to sign, and the committed root artifact's own, is
//     exactly the published primary key of generationID, in the authored
//     region;
//   - --role-arn, when given, is the published ceremony role, and
//     --aws-profile, when given, is the authored profile.
//
// It reads nothing and calls no service: the outputs are public and the
// check is reproducible by a second reviewer.
func (c *Contract) VerifyCustody(outputs *CustodyOutputs, generationID string, request CustodyRequest) (*CustodyVerdict, error) {
	if outputs == nil {
		return nil, fmt.Errorf("custody outputs are required")
	}

	generation := c.RootGeneration(generationID)
	if generation == nil {
		return nil, fmt.Errorf("pki: unknown root generation %q", generationID)
	}

	if err := outputs.Validate(); err != nil {
		return nil, fmt.Errorf("custody outputs: %w", err)
	}

	proven, err := c.verifyGenerations(outputs)
	if err != nil {
		return nil, err
	}

	published := outputs.Generations[generationID]
	custody := generation.Custody
	var statements []string

	statements = append(statements, proven...)

	if request.KeyARN == "" {
		return nil, fmt.Errorf("custody check: the key to sign with is required")
	}

	if request.KeyARN != published.PrimaryKeyARN {
		return nil, fmt.Errorf("custody check: the key to sign with is %s, but the custody outputs' primary key of generation %q is %s",
			request.KeyARN, generationID, published.PrimaryKeyARN)
	}

	if request.ArtifactKeyARN != "" && request.ArtifactKeyARN != published.PrimaryKeyARN {
		return nil, fmt.Errorf("custody check: the committed root artifact of generation %q names key %s, but the custody outputs' primary key is %s",
			generationID, request.ArtifactKeyARN, published.PrimaryKeyARN)
	}

	statements = append(statements,
		fmt.Sprintf("signing key %s is generation %q's published primary key (alias %s) in %s",
			request.KeyARN, generationID, published.Alias, published.PrimaryRegion))

	if request.ArtifactKeyARN != "" {
		statements = append(statements, "the committed root artifact names that same key")
	}

	verdict := &CustodyVerdict{KeyARN: published.PrimaryKeyARN, RoleARN: published.CeremonyRoleARN, Profile: custody.Profile}

	if request.RoleARN != "" && request.RoleARN != published.CeremonyRoleARN {
		return nil, fmt.Errorf("custody check: --role-arn is %s, but the custody outputs' ceremony role for generation %q is %s",
			request.RoleARN, generationID, published.CeremonyRoleARN)
	}

	statements = append(statements, "signing role "+published.CeremonyRoleARN+" is the published ceremony role")

	if request.Profile != "" && request.Profile != custody.Profile {
		return nil, fmt.Errorf("custody check: --aws-profile is %q, but the contract's custody profile for generation %q is %q",
			request.Profile, generationID, custody.Profile)
	}

	statements = append(statements, "profile "+custody.Profile+" is the contract's custody profile")
	verdict.Proven = statements

	return verdict, nil
}

// verifyGenerations binds every authored generation to its published one.
func (c *Contract) verifyGenerations(outputs *CustodyOutputs) ([]string, error) {
	authored := make([]string, 0, len(c.Generations))
	for i := range c.Generations {
		authored = append(authored, c.Generations[i].ID)
	}

	for _, id := range sortedKeys(outputs.Generations) {
		if !slices.Contains(authored, id) {
			return nil, fmt.Errorf("custody check: the custody outputs publish generation %q, which the contract does not author (authored: %s)",
				id, strings.Join(authored, ", "))
		}
	}

	var proven []string

	for i := range c.Generations {
		generation := &c.Generations[i]

		published, ok := outputs.Generations[generation.ID]
		if !ok {
			return nil, fmt.Errorf("custody check: the custody outputs do not publish authored generation %q", generation.ID)
		}

		primary, err := arn.Parse(published.PrimaryKeyARN)
		if err != nil {
			return nil, fmt.Errorf("custody check: generation %q primary key: %w", generation.ID, err)
		}

		custody := generation.Custody
		if primary.AccountID != custody.AccountID {
			return nil, fmt.Errorf("custody check: generation %q: the published key is in account %s, the contract's custody account is %s",
				generation.ID, primary.AccountID, custody.AccountID)
		}

		if published.PrimaryRegion != custody.Region {
			return nil, fmt.Errorf("custody check: generation %q: the published primary region is %s, the contract's custody region is %s",
				generation.ID, published.PrimaryRegion, custody.Region)
		}

		if custody.DisasterRecovery.Region != "" && published.ReplicaRegion != custody.DisasterRecovery.Region {
			return nil, fmt.Errorf("custody check: generation %q: the published replica region is %s, the contract's disaster-recovery region is %s",
				generation.ID, published.ReplicaRegion, custody.DisasterRecovery.Region)
		}

		statement := fmt.Sprintf("generation %q: account %s, primary region %s", generation.ID, custody.AccountID, custody.Region)
		if custody.DisasterRecovery.Region != "" {
			statement += ", replica region " + custody.DisasterRecovery.Region
		}

		proven = append(proven, statement+" match the contract")
	}

	return proven, nil
}

func parseKeyARN(value, region string) (arn.ARN, error) {
	parsed, err := arn.Parse(value)
	if err != nil || parsed.Service != "kms" || parsed.Region != region || !strings.HasPrefix(parsed.Resource, keyResourcePrefix) {
		return arn.ARN{}, fmt.Errorf("%q is not a multi-region KMS key ARN in %s", value, region)
	}

	return parsed, nil
}

func parseRoleARN(value string) (arn.ARN, error) {
	parsed, err := arn.Parse(value)
	if err != nil || parsed.Service != "iam" || parsed.Region != "" || !strings.HasPrefix(parsed.Resource, roleResourcePrefix) {
		return arn.ARN{}, fmt.Errorf("%q is not an IAM role ARN", value)
	}

	return parsed, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}
