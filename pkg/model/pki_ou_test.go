package model

import "testing"

func TestValidateOrganizationalUnit(t *testing.T) {
	for _, ok := range []string{"", "dms_admin", "a1", "my-app_admin"} {
		if err := ValidateOrganizationalUnit(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}

	for _, bad := range []string{"Dms", "dms,admin", "dms admin", "1dms", "dms=admin", "a/b", "-dms"} {
		if err := ValidateOrganizationalUnit(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
