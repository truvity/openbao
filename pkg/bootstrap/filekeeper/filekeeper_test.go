package filekeeper_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/bootstrap"
	"github.com/truvity/secrets/pkg/bootstrap/filekeeper"
)

var _ bootstrap.Keeper = (*filekeeper.Keeper)(nil)

func identityFile(t *testing.T) (path string, recipient string) {
	t.Helper()

	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	path = filepath.Join(t.TempDir(), "identity.txt")
	require.NoError(t, os.WriteFile(path, []byte(identity.String()+"\n"), 0o600))

	return path, identity.Recipient().String()
}

func TestAnItemRoundTripsAndNeverTouchesTheDiskInTheClear(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	identity, _ := identityFile(t)

	keeper, err := filekeeper.New(dir, nil, identity)
	require.NoError(t, err)

	const secret = "recovery-share-very-secret-value-0123456789"

	require.NoError(t, keeper.Create(ctx, "openbao-recovery-1", []byte(secret), "share 1 of 5"))

	got, err := keeper.Reveal(ctx, "openbao-recovery-1")
	require.NoError(t, err)
	assert.Equal(t, secret, string(got))

	titles, err := keeper.Titles(ctx)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"openbao-recovery-1": true}, titles)

	require.NoError(t, filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		require.NoError(t, err)

		if entry.IsDir() {
			assert.Equal(t, os.FileMode(0o700), entry.Type().Perm()|0o700, path)

			return nil
		}

		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), secret, "%s holds the secret in the clear", path)

		info, err := entry.Info()
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), path)

		return nil
	}))
}

func TestCreateNeverOverwritesAnItem(t *testing.T) {
	ctx := context.Background()
	identity, _ := identityFile(t)

	keeper, err := filekeeper.New(t.TempDir(), nil, identity)
	require.NoError(t, err)

	require.NoError(t, keeper.Create(ctx, "item", []byte("first"), ""))
	require.Error(t, keeper.Create(ctx, "item", []byte("second"), ""))

	got, err := keeper.Reveal(ctx, "item")
	require.NoError(t, err)
	assert.Equal(t, "first", string(got))
}

func TestArchiveMovesAnItemOutOfTheListingButKeepsIt(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	identity, _ := identityFile(t)

	keeper, err := filekeeper.New(dir, nil, identity)
	require.NoError(t, err)

	require.NoError(t, keeper.Create(ctx, "openbao-root-token", []byte("s.token-token-token-token"), "root"))
	require.NoError(t, keeper.Archive(ctx, "openbao-root-token"))

	titles, err := keeper.Titles(ctx)
	require.NoError(t, err)
	assert.Empty(t, titles)

	archived, err := filepath.Glob(filepath.Join(dir, "archive", "openbao-root-token.*.age"))
	require.NoError(t, err)
	assert.Len(t, archived, 1, "archived, not destroyed")

	_, err = keeper.Reveal(ctx, "openbao-root-token")
	assert.Error(t, err)

	require.NoError(t, keeper.Create(ctx, "canary", []byte("x"), ""))
	require.NoError(t, keeper.Delete(ctx, "canary"))
	require.NoError(t, keeper.Delete(ctx, "canary"), "deleting what is gone is not an error")
}

func TestATitleCannotEscapeTheDirectory(t *testing.T) {
	identity, _ := identityFile(t)

	keeper, err := filekeeper.New(t.TempDir(), nil, identity)
	require.NoError(t, err)

	for _, title := range []string{"../escape", "a/b", "", ".hidden", "a b"} {
		assert.Error(t, keeper.Create(context.Background(), title, []byte("x"), ""), title)
	}
}

func TestAnItemIsUnreadableWithoutItsIdentity(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	identity, _ := identityFile(t)

	keeper, err := filekeeper.New(dir, nil, identity)
	require.NoError(t, err)
	require.NoError(t, keeper.Create(ctx, "item", []byte("secret-secret-secret"), ""))

	other, otherRecipient := identityFile(t)
	_ = otherRecipient

	stranger, err := filekeeper.New(dir, nil, other)
	require.NoError(t, err)

	_, err = stranger.Reveal(ctx, "item")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret-secret-secret")
}

func TestNewRefusesWhatCannotWork(t *testing.T) {
	identity, recipient := identityFile(t)

	for name, build := range map[string]func() error{
		"no directory":    func() error { _, err := filekeeper.New("", nil, identity); return err },
		"no identity":     func() error { _, err := filekeeper.New(t.TempDir(), []string{recipient}, ""); return err },
		"a missing file":  func() error { _, err := filekeeper.New(t.TempDir(), nil, "/nonexistent/identity"); return err },
		"a bad recipient": func() error { _, err := filekeeper.New(t.TempDir(), []string{"not-a-key"}, identity); return err },
	} {
		assert.Error(t, build(), name)
	}

	bad := filepath.Join(t.TempDir(), "bad")
	require.NoError(t, os.WriteFile(bad, []byte("AGE-SECRET-KEY-nonsense\n"), 0o600))

	_, err := filekeeper.New(t.TempDir(), nil, bad)
	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), "nonsense"), "the parse error must not echo the key: %v", err)
}

// A typo in the directory must not yield an empty keeper that looks lost.
func TestNewNeverCreatesTheKeeperDirectory(t *testing.T) {
	identity, _ := identityFile(t)
	dir := filepath.Join(t.TempDir(), "keepr")

	_, err := filekeeper.New(dir, nil, identity)
	require.Error(t, err)
	assert.NoDirExists(t, dir, "New created the directory")

	require.NoError(t, filekeeper.Prepare(dir))

	keeper, err := filekeeper.New(dir, nil, identity)
	require.NoError(t, err)
	assert.NotNil(t, keeper)
}
