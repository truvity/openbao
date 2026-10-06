package apply_test

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/truvity/secrets/pkg/apply"
	"github.com/truvity/secrets/pkg/model"
)

func TestRenameFromKeepsOnlyWhatIsListed(t *testing.T) {
	rename := apply.RenameFrom(map[string]string{"new": "old"})
	if got := rename("new"); got != "old" {
		t.Errorf("new = %q, want old", got)
	}

	if got := rename("other"); got != "other" {
		t.Errorf("other = %q, want other", got)
	}

	if got := apply.RenameFrom(nil)("x"); got != "x" {
		t.Errorf("nil map renamed x to %q", got)
	}
}

func TestRosterLoginIsTheRosterDoor(t *testing.T) {
	login := apply.RosterLogin("/tmp/ca.pem", "https://issuer.example")
	if login.Mount != model.RosterMount || login.Role != model.RosterRole || login.CACertFile != "/tmp/ca.pem" || login.Token == nil {
		t.Fatalf("login = %+v", login)
	}
}

func TestWriteCABundleJoinsTrimmedParts(t *testing.T) {
	path, err := apply.WriteCABundle("secrets-test-ca.pem", []byte("A\n\n"), nil, []byte(" B "))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Remove(path) })

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != "A\nB\n" {
		t.Errorf("bundle = %q", got)
	}

	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
}

func secretKubectl(data map[string]string, fail error) apply.Kubectl {
	return func(_ context.Context, args ...string) ([]byte, error) {
		if fail != nil {
			return nil, fail
		}

		for key, value := range data {
			if strings.HasSuffix(args[len(args)-1], "{.data."+key+"}") {
				return []byte(base64.StdEncoding.EncodeToString([]byte(value))), nil
			}
		}

		return nil, nil
	}
}

func TestDeliveredSecretKey(t *testing.T) {
	secret := apply.DeliveredSecret{Namespace: "ns", Name: "n", Hint: "sync it first"}

	got, err := secret.Key(context.Background(), secretKubectl(map[string]string{"k": "s3cr3t"}, nil), "k")
	if err != nil || got != "s3cr3t" {
		t.Fatalf("Key = %q, %v", got, err)
	}

	for name, kubectl := range map[string]apply.Kubectl{
		"absent": secretKubectl(nil, errors.New("not found")),
		"empty":  secretKubectl(nil, nil),
	} {
		_, err := secret.Key(context.Background(), kubectl, "k")
		if err == nil || !strings.Contains(err.Error(), "sync it first") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
