package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"github.com/truvity/openbao/pkg/bootstrap"
)

// memoryKeeper is a Keeper that holds items in a map.
type memoryKeeper map[string]string

func (m memoryKeeper) Titles(context.Context) (map[string]bool, error) {
	titles := map[string]bool{}
	for title := range m {
		titles[title] = true
	}

	return titles, nil
}

func (m memoryKeeper) Create(_ context.Context, title string, secret []byte, _ string) error {
	m[title] = string(secret)

	return nil
}

func (m memoryKeeper) Reveal(_ context.Context, title string) ([]byte, error) {
	value, ok := m[title]
	if !ok {
		return nil, errors.New("no such item")
	}

	return []byte(value), nil
}

func (m memoryKeeper) Archive(_ context.Context, title string) error { delete(m, title); return nil }
func (m memoryKeeper) Delete(_ context.Context, title string) error  { delete(m, title); return nil }

func runBootstrapCLI(t *testing.T, args ...string) error {
	t.Helper()

	root := &cli.Command{Name: "openbaoctl", Commands: bootstrapCommands(), Writer: &bytes.Buffer{}, ErrWriter: &bytes.Buffer{}}

	return root.Run(context.Background(), append([]string{"openbaoctl"}, args...))
}

func keeperArgs(t *testing.T) []string {
	t.Helper()

	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "id.txt")
	require.NoError(t, os.WriteFile(file, []byte(identity.String()+"\n"), 0o600))

	return []string{"--" + flagKeeperDir, t.TempDir(), "--" + flagAgeIdentity, file}
}

func TestTheBootstrapCommandsRefuseWhatIsUnsafeOrAmbiguous(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"revoke-root without a login proof or the weaker flag": {
			args: []string{"revoke-root", "--" + flagAddr, "https://x", "--" + flagCAFile, "ca", "--" + flagOperatorGroup, "g"},
			want: "needs a login proof",
		},
		"revoke-root with both the proof and the weaker flag": {
			args: []string{"revoke-root", "--" + flagOperatorGroup, "g", "--" + flagOperatorJWT, "t", "--" + flagMembershipOnly},
			want: "contradict",
		},
		"init with no way to reach the server": {
			args: []string{"init"},
			want: "say how to reach the server",
		},
		"init with an address and no CA": {
			args: []string{"init", "--" + flagAddr, "https://127.0.0.1:1"},
			want: "TLS is always verified",
		},
		"init with both ways to connect": {
			args: []string{"init", "--" + flagAddr, "https://x", "--" + flagPortForward, "--" + flagKubeContext, "c"},
			want: "choose one",
		},
		"init port-forward without a TLS server name": {
			args: []string{"init", "--" + flagPortForward, "--" + flagKubeContext, "c"},
			want: "--" + flagTLSServerName + " is required",
		},
		"init port-forward without a kube context": {
			args: []string{"init", "--" + flagPortForward, "--" + flagTLSServerName, "x"},
			want: "--" + flagKubeContext + " is required",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := runBootstrapCLI(t, append(tc.args, keeperArgs(t)...)...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestThereIsNoInsecureTLSFlag(t *testing.T) {
	for _, command := range bootstrapCommands() {
		for _, flag := range command.Flags {
			for _, name := range flag.Names() {
				assert.NotContains(t, name, "insecure-skip", "%s: TLS is always verified", command.Name)
				assert.NotContains(t, name, "tls-skip", command.Name)
			}
		}
	}
}

func TestOnlyOneFlagPrintsSecretsAndItSaysSo(t *testing.T) {
	var loud []string

	for _, command := range bootstrapCommands() {
		for _, flag := range command.Flags {
			for _, name := range flag.Names() {
				if strings.Contains(name, "print") {
					loud = append(loud, command.Name+" --"+name)
				}
			}
		}
	}

	assert.Equal(t, []string{"init --" + flagPrintShares}, loud)
	assert.Contains(t, flagPrintShares, "insecure")
}

func TestPrintSharesWritesThemOnlyWhenCalledAndWarnsOnStderr(t *testing.T) {
	keeper := memoryKeeper{bootstrap.RootTokenItem: "s.root-token-that-must-never-print"}
	for n := 1; n <= 5; n++ {
		keeper[bootstrap.RecoveryItem(n)] = fmt.Sprintf("share-%d-value", n)
	}

	var out, errOut bytes.Buffer

	env := bootstrapEnv{stdout: &out, stderr: &errOut}
	require.NoError(t, printShares(context.Background(), env, keeper, bootstrap.Settings{}))

	for n := 1; n <= 5; n++ {
		assert.Contains(t, out.String(), fmt.Sprintf("%s share-%d-value\n", bootstrap.RecoveryItem(n), n))
	}

	assert.NotContains(t, out.String(), "root-token", "the root token is never printed")
	assert.Contains(t, errOut.String(), "WARNING")
	assert.NotContains(t, errOut.String(), "share-1-value")

	delete(keeper, bootstrap.RecoveryItem(4))

	out.Reset()
	require.Error(t, printShares(context.Background(), env, keeper, bootstrap.Settings{}), "a missing share is a failure, not a silent partial print")
}

func TestReadTokenTrimsAndNeverEchoes(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(file, []byte("header.payload.signature\n"), 0o600))

	got, err := readToken(nil, file)
	require.NoError(t, err)
	assert.Equal(t, "header.payload.signature", string(got))

	got, err = readToken(strings.NewReader("from-stdin\r\n"), "-")
	require.NoError(t, err)
	assert.Equal(t, "from-stdin", string(got))

	_, err = readToken(strings.NewReader("  \n"), "-")
	assert.Error(t, err)

	_, err = readToken(nil, filepath.Join(t.TempDir(), "missing"))
	assert.Error(t, err)
}

// L2: the flag prints what the run just made, never an earlier install's shares.
func TestThePrintFlagPrintsOnlyWhatThisRunCreated(t *testing.T) {
	keeper := memoryKeeper{}
	for n := 1; n <= 5; n++ {
		keeper[bootstrap.RecoveryItem(n)] = fmt.Sprintf("share-%d-value", n)
	}

	for name, tc := range map[string]struct {
		asked, founded bool
		wantPrinted    bool
	}{
		"asked, and this run initialized": {asked: true, founded: true, wantPrinted: true},
		"asked, but only verified":        {asked: true, founded: false},
		"not asked, this run initialized": {asked: false, founded: true},
		"not asked, only verified":        {},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer

			b := &bootstrap.Bootstrap{Founded: tc.founded}
			require.NoError(t, maybePrintShares(context.Background(), bootstrapEnv{stdout: &out, stderr: &errOut}, tc.asked, b, keeper))

			if tc.wantPrinted {
				assert.Contains(t, out.String(), "share-1-value")
			} else {
				assert.Empty(t, out.String(), "shares were printed for an install this run did not create")
			}
		})
	}
}

// R2: only init on an uninitialized server may create the keeper directory.
func TestAMissingKeeperDirectoryIsNeverCreatedForALiveInstall(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"initialized":true}`))
	}))
	t.Cleanup(server.Close)

	ca := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))

	identity := keeperArgs(t)[3]
	missing := filepath.Join(t.TempDir(), "keepr")

	for _, command := range [][]string{
		{"init"},
		{"configure", "--" + flagIssuer, "https://issuer.example", "--" + flagOperatorGroup, "g"},
		{"revoke-root", "--" + flagOperatorGroup, "g", "--" + flagMembershipOnly},
	} {
		args := append(command, "--"+flagAddr, server.URL, "--"+flagCAFile, ca, "--"+flagTLSServerName, "example.com",
			"--"+flagKeeperDir, missing, "--"+flagAgeIdentity, identity)

		err := runBootstrapCLI(t, args...)
		require.Error(t, err, command[0])
		assert.NoDirExists(t, missing, "%s created the keeper directory", command[0])
	}
}
