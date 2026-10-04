package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ready brings a fake to the point just before an operator logs in.
func ready(t *testing.T) (*Bootstrap, *fakeBao, *fakeKeeper) {
	t.Helper()

	bootstrap, fake, keeper := newBootstrap(t, &bytes.Buffer{})
	ctx := context.Background()

	require.NoError(t, bootstrap.Initialize(ctx))
	require.NoError(t, bootstrap.Configure(ctx, login))

	return bootstrap, fake, keeper
}

func TestInitializeRefusesBeforeTouchingTheServer(t *testing.T) {
	for name, tc := range map[string]struct {
		arrange func(*Bootstrap, *fakeBao, *fakeKeeper)
		want    string
	}{
		"a stale share of an earlier install": {
			arrange: func(_ *Bootstrap, _ *fakeBao, k *fakeKeeper) { k.items[RecoveryItem(5)] = "old" },
			want:    RecoveryItem(5),
		},
		"a stale root token of an earlier install": {
			arrange: func(_ *Bootstrap, _ *fakeBao, k *fakeKeeper) { k.items[RootTokenItem] = "old" },
			want:    RootTokenItem,
		},
		"a shamir seal, whose shares would unseal the server": {
			arrange: func(_ *Bootstrap, f *fakeBao, _ *fakeKeeper) { f.recoverySeal = false },
			want:    "not an auto-unseal seal",
		},
		"a keeper that cannot be written": {
			arrange: func(_ *Bootstrap, _ *fakeBao, k *fakeKeeper) { k.failAll = true },
			want:    "before anything was initialized",
		},
		"a threshold of one": {
			arrange: func(b *Bootstrap, _ *fakeBao, _ *fakeKeeper) { b.Settings.RecoveryThreshold = 1 },
			want:    "any single share",
		},
		"a threshold above the shares": {
			arrange: func(b *Bootstrap, _ *fakeBao, _ *fakeKeeper) { b.Settings.RecoveryThreshold = 6 },
			want:    "recovery threshold 6",
		},
	} {
		t.Run(name, func(t *testing.T) {
			bootstrap, fake, keeper := newBootstrap(t, &bytes.Buffer{})
			tc.arrange(bootstrap, fake, keeper)

			err := bootstrap.Initialize(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.False(t, fake.initialized, "the server was initialized although the shares could not be kept")
			assert.Zero(t, fake.count("PUT sys/init"))
		})
	}
}

func TestInitializeHonoursTheRecoverySplit(t *testing.T) {
	bootstrap, fake, keeper := newBootstrap(t, &bytes.Buffer{})
	bootstrap.Settings = Settings{RecoveryShares: 3, RecoveryThreshold: 2}

	// The fake always issues five shares: a split that disagrees with the
	// answer is refused with the wipe advice, never half-stored silently.
	err := bootstrap.Initialize(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "init answered 5 recovery shares")
	assert.Contains(t, err.Error(), "delete its three data PVCs")
	assert.EqualValues(t, 3, fake.initBody["recovery_shares"])
	assert.EqualValues(t, 2, fake.initBody["recovery_threshold"])
	assert.NotContains(t, keeper.items, RootTokenItem)
}

func TestConfigureRefusesANonEmptyServerUnlessTold(t *testing.T) {
	for name, tc := range map[string]struct {
		arrange func(*fakeBao)
		allow   bool
		wantErr string
	}{
		"an auth mount beside the door":   {arrange: func(f *fakeBao) { f.mounts["oidc/"] = mount{Type: "oidc"} }, wantErr: "auth/oidc/"},
		"a secrets engine":                {arrange: func(f *fakeBao) { f.secretMounts = map[string]mount{"kv/": {Type: "kv"}} }, wantErr: "kv/"},
		"told it may, an auth mount":      {arrange: func(f *fakeBao) { f.mounts["oidc/"] = mount{Type: "oidc"} }, allow: true},
		"told it may, a secrets engine":   {arrange: func(f *fakeBao) { f.secretMounts = map[string]mount{"kv/": {Type: "kv"}} }, allow: true},
		"nothing but the built-in mounts": {arrange: func(*fakeBao) {}},
	} {
		t.Run(name, func(t *testing.T) {
			bootstrap, fake, _ := newBootstrap(t, &bytes.Buffer{})
			bootstrap.Settings.AllowNonEmpty = tc.allow
			require.NoError(t, bootstrap.Initialize(context.Background()))
			tc.arrange(fake)

			err := bootstrap.Configure(context.Background(), login)
			if tc.wantErr == "" {
				require.NoError(t, err)
				assert.Equal(t, 1, fake.count("POST identity/group"))

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Zero(t, fake.count("POST sys/auth/jwt-roster"), "a mount was written into a non-empty server")
			assert.Zero(t, fake.count("POST identity/group"))
		})
	}
}

// Never revoke root before an operator login is proven to work.
func TestRevokeRootNeverRevokesBeforeAnOperatorLoginIsProven(t *testing.T) {
	for name, tc := range map[string]struct {
		arrange func(*Bootstrap, *fakeBao, *fakeKeeper)
		want    string
	}{
		"nobody has logged in": {
			arrange: func(*Bootstrap, *fakeBao, *fakeKeeper) {},
			want:    "nobody has logged in",
		},
		"the group's alias is missing": {
			arrange: func(_ *Bootstrap, f *fakeBao, _ *fakeKeeper) { f.groups[operators].Alias.ID = "" },
			want:    "or its alias is missing",
		},
		"the group is missing": {
			arrange: func(_ *Bootstrap, f *fakeBao, _ *fakeKeeper) { delete(f.groups, operators) },
			want:    "or its alias is missing",
		},
		"a login proof with a token the door refuses, though a member is on file": {
			arrange: func(b *Bootstrap, f *fakeBao, _ *fakeKeeper) {
				f.login(operators)

				b.OperatorJWT = []byte("a token the door refuses")
			},
			want: "would lock operators out",
		},
		"a login that works but carries no operator policy": {
			arrange: func(b *Bootstrap, f *fakeBao, _ *fakeKeeper) {
				f.loginPolicies = []string{"default"}
				b.OperatorJWT = []byte(fakeJWT)
			},
			want: "not the " + operators + " policy",
		},
		"a share missing from the keeper": {
			arrange: func(_ *Bootstrap, f *fakeBao, k *fakeKeeper) { f.login(operators); delete(k.items, RecoveryItem(2)) },
			want:    RecoveryItem(2),
		},
	} {
		t.Run(name, func(t *testing.T) {
			bootstrap, fake, keeper := ready(t)
			tc.arrange(bootstrap, fake, keeper)

			err := bootstrap.RevokeRoot(context.Background(), operators)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.True(t, fake.tokenValid(fakeRoot), "the root token was revoked with no operator proven")
			assert.NotEmpty(t, keeper.items[RootTokenItem])
			assert.Zero(t, fake.count("PUT sys/generate-root-token/attempt"), "the drill ran before the login gate passed")
		})
	}
}

func TestRevokeRootProvesTheLoginWithTheOperatorsOwnToken(t *testing.T) {
	bootstrap, fake, keeper := ready(t)
	bootstrap.OperatorJWT = []byte(fakeJWT)

	require.NoError(t, bootstrap.RevokeRoot(context.Background(), operators))

	assert.Equal(t, 1, fake.count("POST auth/jwt-roster/login"))
	assert.Equal(t, 2, len(drillSets(5, 3)))
	assert.Empty(t, fake.tokens, "the proof token, the drill tokens and the root token are all revoked")
	assert.Equal(t, fakeRoot, keeper.archived[RootTokenItem])
}

// A token generated by the drill that turns out not to be root must not be
// left behind.
func TestTheDrillRevokesWhatItGeneratedEvenWhenItFails(t *testing.T) {
	bootstrap, fake, _ := ready(t)
	fake.login(operators)
	fake.generatedPolicies = []string{"default"}

	err := bootstrap.RevokeRoot(context.Background(), operators)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not root")

	assert.True(t, fake.tokenValid(fakeRoot), "the bootstrap token must stay while the shares are unproven")
	assert.Len(t, fake.tokens, 1, "the generated token was left valid: %v", fake.tokens)
}

func TestDrillSetsProveEveryShare(t *testing.T) {
	for name, tc := range map[string]struct {
		shares, threshold int
		want              [][]int
	}{
		"five shares, three needed (the default)": {5, 3, [][]int{{1, 2, 3}, {3, 4, 5}}},
		"three shares, two needed":                {3, 2, [][]int{{1, 2}, {2, 3}}},
		"two shares, two needed":                  {2, 2, [][]int{{1, 2}}},
		"seven shares, three needed":              {7, 3, [][]int{{1, 2, 3}, {4, 5, 6}, {5, 6, 7}}},
	} {
		t.Run(name, func(t *testing.T) {
			got := drillSets(tc.shares, tc.threshold)
			assert.Equal(t, tc.want, got)

			proven := map[int]bool{}

			for _, set := range got {
				assert.Len(t, set, tc.threshold)

				for _, n := range set {
					proven[n] = true
				}
			}

			assert.Len(t, proven, tc.shares, "a share was never submitted")
		})
	}
}

// Secret buffers the library owns are zeroed once used.
func TestSecretBuffersAreZeroedOnceUsed(t *testing.T) {
	bootstrap, fake, keeper := ready(t)
	fake.login(operators)

	require.NoError(t, bootstrap.RevokeRoot(context.Background(), operators))

	require.NotEmpty(t, keeper.revealed)
	require.NotEmpty(t, keeper.created)

	for i, buffer := range slices.Concat(keeper.revealed, keeper.created) {
		assert.Equal(t, make([]byte, len(buffer)), buffer, "buffer %d still holds a secret", i)
	}
}

func TestAnErrorNeverCarriesWhatTheServerEchoes(t *testing.T) {
	const token, share = "s.operator-secret-token-123456", "c2hhcmUtdGhhdC1pcy1sb25nLWVub3VnaC10by1iZS1hLXNoYXJl"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{
			"bad request from " + r.Header.Get("X-Vault-Token"),
			"invalid key " + share,
			"a token s.somebody-elses-token-abcdef",
			"permission denied",
		}})
	}))
	t.Cleanup(server.Close)

	api := NewClient(server.URL, server.Client()).WithToken([]byte(token))
	err := api.do(context.Background(), http.MethodGet, "sys/anything", nil, nil)
	require.Error(t, err)

	for _, secret := range []string{token, share, "somebody-elses"} {
		assert.NotContains(t, err.Error(), secret)
	}

	assert.Contains(t, err.Error(), "permission denied", "ordinary messages survive")
	assert.True(t, hasStatus(err, http.StatusBadRequest), "the status is still readable")
}

func TestARecoveryShareThatTheKeeperEchoesIsScrubbed(t *testing.T) {
	bootstrap, fake, keeper := newBootstrap(t, &bytes.Buffer{})
	keeper.failCreate[RecoveryItem(2)] = 1

	var prompts []error

	bootstrap.Retry = func(_ context.Context, err error) bool {
		prompts = append(prompts, err)

		return false
	}

	// Stand in for a keeper whose error text carries the value it was given.
	echo := &echoKeeper{fakeKeeper: keeper, fake: fake}
	bootstrap.Keeper = echo

	err := bootstrap.Initialize(context.Background())
	require.Error(t, err)

	for _, secret := range fake.shares {
		assert.NotContains(t, err.Error(), secret)
	}

	for _, prompt := range prompts {
		for _, secret := range fake.shares {
			assert.NotContains(t, prompt.Error(), secret)
		}
	}
}

// echoKeeper fails a Create with an error that includes the secret.
type echoKeeper struct {
	*fakeKeeper
	fake *fakeBao
}

func (k *echoKeeper) Create(ctx context.Context, title string, secret []byte, notes string) error {
	if k.failCreate[title] > 0 {
		k.failCreate[title]--

		return &echoedError{text: "cannot store " + string(secret)}
	}

	return k.fakeKeeper.Create(ctx, title, secret, notes)
}

type echoedError struct{ text string }

func (e *echoedError) Error() string { return e.text }

func TestSettingsDefaultsAndValidation(t *testing.T) {
	var zero Settings

	assert.Equal(t, 5, zero.shares())
	assert.Equal(t, 3, zero.threshold())
	assert.Equal(t, 3, zero.voters())
	assert.Equal(t, "to-stdout", zero.audit())
	assert.NoError(t, zero.validate())

	for name, bad := range map[string]Settings{
		"no voters":            {Voters: -1},
		"too many shares":      {RecoveryShares: 256, RecoveryThreshold: 3},
		"threshold over":       {RecoveryShares: 3, RecoveryThreshold: 4},
		"one share is a split": {RecoveryShares: 3, RecoveryThreshold: 1},
	} {
		assert.Error(t, bad.validate(), name)
	}

	assert.NoError(t, Settings{RecoveryShares: 1, RecoveryThreshold: 1}.validate(), "a single share is a legitimate dev split")
}

func TestSecretJSONRefusesWhatNeedsEscaping(t *testing.T) {
	for _, value := range []string{`a"b`, `a\b`, "a\nb", "é"} {
		_, err := json.Marshal(secret(value))
		require.Error(t, err)
		assert.NotContains(t, err.Error(), value)
	}

	var got struct {
		A secret `json:"a"`
	}

	require.NoError(t, json.Unmarshal([]byte(`{"a":"abc=="}`), &got))
	assert.Equal(t, "abc==", string(got.A))
	assert.Error(t, json.Unmarshal([]byte(`{"a":"a\\u0041"}`), &got))
	assert.Error(t, json.Unmarshal([]byte(`{"a":5}`), &got))
}

func TestConfigureReadinessAndAuditSettingsAreInputs(t *testing.T) {
	bootstrap, fake, _ := newBootstrap(t, &bytes.Buffer{})
	bootstrap.Settings = Settings{Voters: 1, AuditDevice: "to-file"}
	require.NoError(t, bootstrap.Initialize(context.Background()))

	fake.voters = 1

	err := bootstrap.Configure(context.Background(), login)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit device to-file/", "the audit device is the caller's, not a built-in name")
	assert.True(t, strings.Contains(err.Error(), "not enabled"))
}

func TestNewTLSClientRefusesPlainHTTPAndAnEmptyCA(t *testing.T) {
	_, err := NewTLSClient("http://127.0.0.1:8200", []byte("x"), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https://")

	_, err = NewTLSClient("https://127.0.0.1:8200", []byte("not a certificate"), "")
	require.Error(t, err)
}
