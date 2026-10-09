package estate

import (
	"testing"

	"github.com/truvity/secrets/pkg/builder"
)

func TestGroupGrantsProjectLevels(t *testing.T) {
	in := &Inputs{
		Projects: map[string][]string{"dms": {"devel"}},
		Groups: Groups{
			Name:     func(env, thing, role string) string { return env + ":" + thing + ":" + role },
			Holds:    func(string) bool { return true },
			OpenBAO:  "openbao",
			Writer:   "writer",
			Database: "db", DatabaseClient: "client",
			DBA:      "dba",
			DBLevels: []string{"admin", "read", "ddl"},
		},
		PKI: PKI{DBProjectRole: "db"},
	}

	// Only the roles the contract declares get a grant.
	declared := map[string]bool{"db-dms-admin": true, "db-dms-read": true}
	grants := groupGrants(in, "devel", builder.Sign("pki", "db-client"), func(role string) (builder.Clause, bool) {
		return builder.Sign("pki", role), declared[role]
	})

	have := map[string]bool{}
	for _, g := range grants {
		have[g.Name] = true
	}

	for _, want := range []string{"devel:dms:dba", "devel:dms:admin", "devel:dms:read"} {
		if !have[want] {
			t.Errorf("no grant for %s", want)
		}
	}

	if have["devel:dms:ddl"] {
		t.Error("ddl has no declared role, yet a grant was made")
	}
}
