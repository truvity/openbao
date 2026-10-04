package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/truvity/openbao/pkg/model"
)

const (
	operators = "all:openbao:operator"
)

var login = OperatorLogin{Issuer: "https://access.example.test", Group: operators}

func newBootstrap(t *testing.T, logs *bytes.Buffer) (*Bootstrap, *fakeBao, *fakeKeeper) {
	t.Helper()

	fake, api := newFakeBao(t)
	keeper := newFakeKeeper()

	return &Bootstrap{
		API:    api,
		Keeper: keeper,
		Logger: slog.New(slog.NewTextHandler(logs, nil)),
		Poll:   time.Millisecond,
		Now:    func() time.Time { return time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC) },
	}, fake, keeper
}

func TestInitializeStoresEveryShareAndTheRootToken(t *testing.T) {
	bootstrap, fake, keeper := newBootstrap(t, &bytes.Buffer{})

	if err := bootstrap.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	for key, want := range map[string]float64{"secret_shares": 0, "recovery_shares": 5, "recovery_threshold": 3} {
		if fake.initBody[key] != want {
			t.Errorf("init %s = %v, want %v", key, fake.initBody[key], want)
		}
	}

	for n, share := range fake.shares {
		if got := keeper.items[RecoveryItem(n+1)]; got != share {
			t.Errorf("%s holds %q, want share %d", RecoveryItem(n+1), got, n+1)
		}

		if keeper.reveals[RecoveryItem(n+1)] != 1 {
			t.Errorf("%s was read back %d times, want once", RecoveryItem(n+1), keeper.reveals[RecoveryItem(n+1)])
		}
	}

	if keeper.items[RootTokenItem] != fakeRoot {
		t.Error("the root token was not stored")
	}

	if _, left := keeper.items[canaryItem]; left || keeper.creates[canaryItem] != 1 {
		t.Errorf("the canary must be written once and deleted: creates=%d left=%t", keeper.creates[canaryItem], left)
	}
}

func TestInitializeStopsBeforeInitWhenTheKeeperFails(t *testing.T) {
	bootstrap, fake, keeper := newBootstrap(t, &bytes.Buffer{})
	keeper.failAll = true

	err := bootstrap.Initialize(context.Background())
	if err == nil || !strings.Contains(err.Error(), "before anything was initialized") {
		t.Fatalf("Initialize = %v, want the preflight to fail", err)
	}

	if fake.initialized || fake.count("PUT sys/init") != 0 {
		t.Fatal("OpenBAO was initialized although its shares could not have been stored")
	}
}

func TestInitializeRefusesStaleSharesFromAnEarlierInstall(t *testing.T) {
	bootstrap, fake, keeper := newBootstrap(t, &bytes.Buffer{})
	keeper.items[RecoveryItem(2)] = "an old share"

	err := bootstrap.Initialize(context.Background())
	if err == nil || !strings.Contains(err.Error(), RecoveryItem(2)) {
		t.Fatalf("Initialize = %v, want a refusal naming the stale item", err)
	}

	if fake.initialized {
		t.Fatal("OpenBAO was initialized next to stale shares")
	}
}

func TestInitializeRefusesAShamirSeal(t *testing.T) {
	bootstrap, fake, _ := newBootstrap(t, &bytes.Buffer{})
	fake.recoverySeal = false

	if err := bootstrap.Initialize(context.Background()); err == nil || fake.initialized {
		t.Fatalf("Initialize = %v, initialized=%t; want a refusal", err, fake.initialized)
	}
}

func TestInitializeVerifiesAnInitializedInstall(t *testing.T) {
	bootstrap, fake, keeper := newBootstrap(t, &bytes.Buffer{})

	if err := bootstrap.Initialize(context.Background()); err != nil {
		t.Fatalf("first Initialize: %v", err)
	}

	if err := bootstrap.Initialize(context.Background()); err != nil {
		t.Fatalf("second Initialize: %v", err)
	}

	if fake.count("PUT sys/init") != 1 {
		t.Fatalf("init ran %d times, want once", fake.count("PUT sys/init"))
	}

	delete(keeper.items, RecoveryItem(4))

	if err := bootstrap.Initialize(context.Background()); err == nil || !strings.Contains(err.Error(), RecoveryItem(4)) {
		t.Fatalf("Initialize with a share missing = %v, want an error naming it", err)
	}
}

func TestInitializeRetriesAFailedStoreWithoutDuplicating(t *testing.T) {
	bootstrap, _, keeper := newBootstrap(t, &bytes.Buffer{})
	keeper.failCreate[RecoveryItem(3)] = 2

	asked := 0
	bootstrap.Retry = func(context.Context, error) bool {
		asked++

		return true
	}

	if err := bootstrap.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if asked != 2 || keeper.creates[RecoveryItem(3)] != 1 {
		t.Fatalf("asked %d times, created %s %d times; want 2 and 1", asked, RecoveryItem(3), keeper.creates[RecoveryItem(3)])
	}
}

func TestInitializeWithoutRetryExplainsTheWipe(t *testing.T) {
	bootstrap, _, keeper := newBootstrap(t, &bytes.Buffer{})
	keeper.failCreate[RootTokenItem] = 1

	err := bootstrap.Initialize(context.Background())
	if err == nil || !strings.Contains(err.Error(), "delete its three data PVCs") {
		t.Fatalf("Initialize = %v, want the wipe advice", err)
	}
}

func TestConfigureOpensOperatorLoginAndConverges(t *testing.T) {
	bootstrap, fake, _ := newBootstrap(t, &bytes.Buffer{})
	ctx := context.Background()

	if err := bootstrap.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	for range 2 {
		if err := bootstrap.Configure(ctx, login); err != nil {
			t.Fatalf("Configure: %v", err)
		}
	}

	if fake.mounts["jwt-roster/"].Type != "jwt" {
		t.Fatalf("mounts = %v, want jwt-roster/ of type jwt", fake.mounts)
	}

	if fake.authConfig["oidc_discovery_url"] != login.Issuer || fake.authConfig["bound_issuer"] != login.Issuer {
		t.Errorf("auth config = %v", fake.authConfig)
	}

	role := fake.roles[model.RosterRole]
	if audiences := anyStrings(role["bound_audiences"]); len(audiences) != 1 || audiences[0] != "openbao" {
		t.Errorf("bound_audiences = %v, want [openbao]", audiences)
	}

	if role["groups_claim"] != "groups" || role["user_claim"] != "sub" || role["token_max_ttl"] != "15m" {
		t.Errorf("role = %v", role)
	}

	// The same claim mappings the apply declares on every other people
	// role (testdata/model.yaml): root's door is written here, never applied.
	if mappings, _ := role["claim_mappings"].(map[string]any); len(mappings) != 2 || mappings["email"] != "email" || mappings["name"] != "name" {
		t.Errorf("claim_mappings = %v, want email and name", role["claim_mappings"])
	}

	operatorGroup := fake.groups[operators]
	if operatorGroup == nil || operatorGroup.Type != "external" || len(operatorGroup.Policies) != 1 || operatorGroup.Policies[0] != operators {
		t.Fatalf("group = %+v, want an external group carrying the policy of its own name", operatorGroup)
	}

	if operatorGroup.Alias.Name != operators || operatorGroup.Alias.MountAccessor != "auth_jwt_1" {
		t.Errorf("alias = %+v, want the internal group name on the jwt-roster accessor", operatorGroup.Alias)
	}

	// Byte for byte the policy every live install was initialized with.
	want := `path "*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list", "sudo"]
}
`
	if fake.policies[operators] != want {
		t.Errorf("operator policy = %q, want %q", fake.policies[operators], want)
	}

	for _, call := range []string{"POST sys/auth/jwt-roster", "POST identity/group", "POST identity/group-alias"} {
		if fake.count(call) != 1 {
			t.Errorf("%s ran %d times over two runs, want once", call, fake.count(call))
		}
	}
}

func TestConfigureWaitsForEveryVoter(t *testing.T) {
	bootstrap, fake, _ := newBootstrap(t, &bytes.Buffer{})
	fake.voters, fake.votersGrow = 1, true

	if err := bootstrap.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if err := bootstrap.Configure(context.Background(), login); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	if calls := fake.count("GET sys/storage/raft/configuration"); calls != 3 {
		t.Fatalf("raft configuration read %d times, want 3 (1, 2, then 3 voters)", calls)
	}
}

func TestConfigureRefusesToRunUnaudited(t *testing.T) {
	bootstrap, fake, _ := newBootstrap(t, &bytes.Buffer{})
	fake.audit = false

	if err := bootstrap.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	err := bootstrap.Configure(context.Background(), login)
	if err == nil || !strings.Contains(err.Error(), "audit device to-stdout/") {
		t.Fatalf("Configure = %v, want the audit refusal", err)
	}

	if fake.count("POST sys/auth/jwt-roster") != 0 {
		t.Fatal("an auth mount was written without an audit device")
	}
}

func TestRevokeRootWaitsForAnOperatorLogin(t *testing.T) {
	bootstrap, fake, keeper := newBootstrap(t, &bytes.Buffer{})
	ctx := context.Background()

	if err := bootstrap.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if err := bootstrap.Configure(ctx, login); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	err := bootstrap.RevokeRoot(ctx, operators)
	if err == nil || !strings.Contains(err.Error(), "nobody has logged in") {
		t.Fatalf("RevokeRoot = %v, want a refusal until an operator logs in", err)
	}

	if !fake.tokenValid(fakeRoot) || keeper.items[RootTokenItem] == "" {
		t.Fatal("the root token was revoked with no operator able to log in")
	}

	if fake.count("PUT sys/generate-root-token/attempt") != 0 {
		t.Fatal("the drill ran before the login gate passed")
	}
}

func TestRevokeRootDrillsEveryShareThenRevokes(t *testing.T) {
	bootstrap, fake, keeper := newBootstrap(t, &bytes.Buffer{})
	ctx := context.Background()

	if err := bootstrap.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if err := bootstrap.Configure(ctx, login); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	fake.login(operators)

	if err := bootstrap.RevokeRoot(ctx, operators); err != nil {
		t.Fatalf("RevokeRoot: %v", err)
	}

	if fake.minted != 2 {
		t.Errorf("generated %d root tokens, want 2 drills", fake.minted)
	}

	if len(fake.tokens) != 0 {
		t.Errorf("tokens still valid after revocation: %v", fake.tokens)
	}

	for n := 1; n <= DefaultRecoveryShares; n++ {
		if keeper.reveals[RecoveryItem(n)] < 2 {
			t.Errorf("%s was never submitted in a drill", RecoveryItem(n))
		}
	}

	if _, kept := keeper.items[RootTokenItem]; kept || keeper.archived[RootTokenItem] != fakeRoot {
		t.Error("the root token item must be archived, not kept or destroyed")
	}

	if err := bootstrap.RevokeRoot(ctx, operators); err != nil {
		t.Fatalf("RevokeRoot after revocation must have nothing to do: %v", err)
	}

	if fake.minted != 2 {
		t.Fatalf("a second run generated root tokens again: %d", fake.minted)
	}
}

func TestRevokeRootLeavesSomeoneElsesGenerationAlone(t *testing.T) {
	bootstrap, fake, _ := newBootstrap(t, &bytes.Buffer{})
	ctx := context.Background()

	if err := bootstrap.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if err := bootstrap.Configure(ctx, login); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	fake.login(operators)
	fake.generation = &fakeGeneration{nonce: "theirs", otp: "otp-of-exactly-twenty-eight!", submitted: map[string]bool{}}

	if err := bootstrap.RevokeRoot(ctx, operators); err == nil || !strings.Contains(err.Error(), "theirs") {
		t.Fatalf("RevokeRoot = %v, want a refusal naming the foreign attempt", err)
	}

	if fake.generation == nil || fake.generation.nonce != "theirs" || !fake.tokenValid(fakeRoot) {
		t.Fatal("the foreign attempt was canceled or the root token revoked")
	}
}

func TestNothingSecretReachesTheLogOrAnError(t *testing.T) {
	var logs bytes.Buffer

	bootstrap, fake, keeper := newBootstrap(t, &logs)
	ctx := context.Background()

	var failures []error

	bootstrap.Retry = func(_ context.Context, err error) bool {
		failures = append(failures, err)

		return true
	}
	keeper.failCreate[RecoveryItem(1)] = 1

	for _, step := range []func() error{
		func() error { return bootstrap.Initialize(ctx) },
		func() error { return bootstrap.Configure(ctx, login) },
		func() error { fake.login(operators); return bootstrap.RevokeRoot(ctx, operators) },
	} {
		if err := step(); err != nil {
			t.Fatalf("step: %v", err)
		}
	}

	secrets := append([]string{fakeRoot, "s.generated-root-token"}, fake.shares...)
	for _, secret := range secrets {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the log carries a secret: %s", secret)
		}

		for _, failure := range failures {
			if strings.Contains(failure.Error(), secret) {
				t.Errorf("a retry prompt carries a secret: %v", failure)
			}
		}
	}
}

func TestDecodeTokenUndoesTheOneTimePad(t *testing.T) {
	const token, otp = "s.abcdefghijklmnopqrstuvwxyz", "0123456789abcdefghijklmnopqr"

	padded := make([]byte, len(token))
	for i := range token {
		padded[i] = token[i] ^ otp[i]
	}

	encoded := base64.RawStdEncoding.EncodeToString(padded)

	got, err := decodeToken([]byte(encoded), []byte(otp))
	if err != nil || string(got) != token {
		t.Fatalf("decodeToken = %q, %v; want %q", got, err, token)
	}

	if _, err := decodeToken([]byte(encoded), []byte(otp[1:])); err == nil {
		t.Fatal("an OTP of the wrong length must be refused")
	}
}

func TestAPIErrorKeepsTheStatus(t *testing.T) {
	err := error(&APIError{Method: "GET", Path: "sys/audit", Status: 403, Errors: []string{"permission denied"}})

	if !hasStatus(err, 403) || hasStatus(errors.New("GET sys/audit: HTTP 403"), 403) {
		t.Fatal("hasStatus must read the typed error only")
	}
}
