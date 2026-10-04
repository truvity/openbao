package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cancelDuring cancels the returned context when hook says so.
func cancelDuring(fake *fakeBao, hook func(method, path, token string) bool) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	fake.onRequest = func(method, path, token string) {
		if hook(method, path, token) {
			cancel()
		}
	}

	return ctx
}

func secondShare() func(method, path, token string) bool {
	count := 0

	return func(method, path, _ string) bool {
		if method == http.MethodPut && path == generateRootUpdate {
			count++

			return count == 2
		}

		return false
	}
}

func generatedLookup(method, path, token string) bool {
	return method == http.MethodGet && path == "auth/token/lookup-self" && strings.HasPrefix(token, "s.generated")
}

// M1: a cancelled context must not strand a pending generation.
func TestCancellingMidDrillCancelsThePendingGeneration(t *testing.T) {
	bootstrap, fake, keeper := ready(t)
	fake.login(operators)

	ctx := cancelDuring(fake, secondShare())

	err := bootstrap.RevokeRoot(ctx, operators)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, fake.generation, "the open root generation was left behind to block the next run")
	assert.True(t, fake.tokenValid(fakeRoot), "the bootstrap token stays while the shares are unproven")
	assert.NotEmpty(t, keeper.items[RootTokenItem])
}

func TestCancellingAfterTheTokenExistsRevokesIt(t *testing.T) {
	bootstrap, fake, _ := ready(t)
	fake.login(operators)

	ctx := cancelDuring(fake, generatedLookup)

	err := bootstrap.RevokeRoot(ctx, operators)
	require.Error(t, err)
	assert.Len(t, fake.tokens, 1, "a generated root token survived the cancellation: %v", fake.tokens)
	assert.True(t, fake.tokenValid(fakeRoot))
}

func TestACleanupThatFailsIsReportedWithWhatToDo(t *testing.T) {
	t.Run("the generation cannot be cancelled", func(t *testing.T) {
		bootstrap, fake, _ := ready(t)
		fake.login(operators)
		fake.failDeleteAttempt = true

		err := bootstrap.RevokeRoot(cancelDuring(fake, secondShare()), operators)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could NOT be cancelled")
		assert.Contains(t, err.Error(), "generate-root -cancel")
	})

	t.Run("the generated token cannot be revoked", func(t *testing.T) {
		bootstrap, fake, _ := ready(t)
		fake.login(operators)
		fake.failRevokeGenerated = true

		err := bootstrap.RevokeRoot(cancelDuring(fake, generatedLookup), operators)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could NOT be revoked and is still valid")
		assert.Contains(t, err.Error(), "bao token revoke -accessor")
	})
}

func TestADecodeFailureSaysARootTokenExists(t *testing.T) {
	bootstrap, fake, _ := ready(t)
	fake.login(operators)

	fake.badEncoding = true

	err := bootstrap.RevokeRoot(context.Background(), operators)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a root token exists that nobody holds")
	assert.True(t, fake.tokenValid(fakeRoot))
}

// M2: a redirect is an error and carries nothing anywhere.
func TestAClientNeverFollowsARedirect(t *testing.T) {
	var leaked atomic.Int32

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
		assert.Empty(t, r.Header.Get("X-Vault-Token"))
	}))
	t.Cleanup(plain.Close)

	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain.URL+"/v1/steal", status)
		}))

		api := NewClient(tls.URL, tls.Client()).WithToken([]byte("s.root-token-0123456789abcdef"))
		err := api.do(context.Background(), http.MethodPut, "sys/generate-root-token/update",
			map[string]any{"key": secret("share-share-share-share"), "nonce": "n"}, nil)

		tls.Close()

		var apiErr *APIError
		require.ErrorAs(t, err, &apiErr, "status %d", status)
		assert.Equal(t, status, apiErr.Status)
	}

	assert.Zero(t, leaked.Load(), "a redirect target received a request: the token or a share left the TLS connection")
}

func TestAScrubbedErrorDoesNotWrapTheOriginal(t *testing.T) {
	r := &redactor{}
	r.add([]byte("super-secret-value"))

	original := fmt.Errorf("keeper said super-secret-value: %w", context.Canceled)
	err := fmt.Errorf("store: %w", r.scrubErr(original))

	var chain []string

	for e := error(err); e != nil; e = errors.Unwrap(e) {
		chain = append(chain, e.Error())
	}

	for _, link := range chain {
		assert.NotContains(t, link, "super-secret-value", "a chain walk reached the unscrubbed text")
	}

	assert.ErrorIs(t, err, context.Canceled, "the context errors callers branch on survive")
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
}

func TestInitializeSaysWhetherItFoundedTheInstall(t *testing.T) {
	bootstrap, _, _ := newBootstrap(t, &bytes.Buffer{})

	require.NoError(t, bootstrap.Initialize(context.Background()))
	assert.True(t, bootstrap.Founded)

	require.NoError(t, bootstrap.Initialize(context.Background()))
	assert.False(t, bootstrap.Founded, "a verification is not a founding")
}

// L3: the split is recorded and held to.
func TestTheRecoverySplitIsRecordedAndHeldTo(t *testing.T) {
	for name, tc := range map[string]struct {
		arrange func(*Bootstrap, *fakeKeeper)
		want    string
	}{
		"another threshold than the install's": {
			arrange: func(b *Bootstrap, _ *fakeKeeper) { b.Settings.RecoveryThreshold = 2 },
			want:    "initialized with recovery split 5/3",
		},
		"a share beyond the configured ones": {
			arrange: func(_ *Bootstrap, k *fakeKeeper) { k.items[RecoveryItem(6)] = "an unproven share" },
			want:    RecoveryItem(6),
		},
	} {
		t.Run(name, func(t *testing.T) {
			bootstrap, fake, keeper := ready(t)
			fake.login(operators)
			assert.Equal(t, "5/3", keeper.items[SplitItem])

			tc.arrange(bootstrap, keeper)

			err := bootstrap.RevokeRoot(context.Background(), operators)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.True(t, fake.tokenValid(fakeRoot))
			assert.Zero(t, fake.count("PUT sys/generate-root-token/attempt"))

			err = bootstrap.Initialize(context.Background())
			require.Error(t, err, "the verify path holds to the split too")
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	t.Run("an install from before the split was recorded", func(t *testing.T) {
		bootstrap, fake, keeper := ready(t)
		fake.login(operators)
		delete(keeper.items, SplitItem)

		require.NoError(t, bootstrap.RevokeRoot(context.Background(), operators))
	})
}

// L5: init has its own, longer bound, and a lost answer comes with advice.
func TestAnInitWhoseAnswerNeverArrivedSaysTheSharesMayBeLost(t *testing.T) {
	bootstrap, fake, _ := newBootstrap(t, &bytes.Buffer{})
	fake.initDelay = 300 * time.Millisecond
	bootstrap.Settings.InitTimeout = 50 * time.Millisecond

	err := bootstrap.Initialize(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "the server may have initialized anyway")
	assert.Contains(t, err.Error(), "delete its three data PVCs")

	// The server did finish. A re-run finds it initialized and nothing on file:
	// it must not suggest a rekey, which needs the lost shares.
	require.Eventually(t, func() bool { fake.mu.Lock(); defer fake.mu.Unlock(); return fake.initialized }, time.Second, 10*time.Millisecond)

	err = bootstrap.Initialize(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "holds none of its recovery shares")
	assert.Contains(t, err.Error(), "delete its three data PVCs")
	assert.NotContains(t, err.Error(), "rekey")
}

func TestInitGetsALongerBoundThanOtherCalls(t *testing.T) {
	assert.Greater(t, DefaultInitTimeout, RequestTimeout)
	assert.Equal(t, DefaultInitTimeout, Settings{}.initTimeout())
}

func TestTheWipeAdviceNamesTheRightNumberOfVolumes(t *testing.T) {
	b := &Bootstrap{Settings: Settings{Voters: 5}}
	assert.Contains(t, b.wipeAdvice(), "its five data PVCs")

	b.Settings.Voters = 12
	assert.Contains(t, b.wipeAdvice(), "its 12 data PVCs")
}

func TestABootstrapWithoutALoggerOrClockStillRuns(t *testing.T) {
	_, api := newFakeBao(t)
	bootstrap := &Bootstrap{API: api, Keeper: newFakeKeeper()}

	require.NoError(t, bootstrap.Initialize(context.Background()))
}

// L7: every buffer the package allocates for a secret ends up zeroed, the
// ones that never pass through the Keeper included.
func TestEverySecretBufferThePackageAllocatesIsZeroed(t *testing.T) {
	var seen [][]byte

	trackSecret = func(b []byte) { seen = append(seen, b) }

	t.Cleanup(func() { trackSecret = nil })

	bootstrap, fake, _ := ready(t)
	bootstrap.OperatorJWT = []byte(fakeJWT)

	require.NoError(t, bootstrap.RevokeRoot(context.Background(), operators))

	require.Greater(t, len(seen), 30, "the hook saw too few buffers to prove anything")

	var secretBytes int

	for i, buffer := range seen {
		secretBytes += len(buffer)

		assert.Equal(t, make([]byte, len(buffer)), buffer, "buffer %d (%d bytes) was never zeroed", i, len(buffer))
	}

	assert.Positive(t, secretBytes)
	assert.NotEmpty(t, fake.shares)
}
