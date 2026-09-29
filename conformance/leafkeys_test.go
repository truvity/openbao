// leafkeys_test.go proves against a real server what apply.LeafKeyBits
// relies on: OpenBAO reads an EC role's key_bits as a minimum, so a P-384
// leaf role written with LeafKeyBits signs both a P-256 and a P-384 CSR,
// where the same role written with 384 refuses the P-256 one.
package conformance_test

import (
	"crypto/elliptic"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/openbao/internal/replay"
	"github.com/truvity/openbao/pkg/apply"
	"github.com/truvity/openbao/pkg/model"
)

func TestLeafRoleKeyBitsConformance(t *testing.T) {
	binary := tool(t, "bao")
	server := &replay.Server{Address: devServer(t, binary), Token: rootToken}
	ctx := t.Context()

	_, err := server.Call(ctx, http.MethodPost, "", "sys/mounts/pki", map[string]any{"type": "pki"})
	require.NoError(t, err)
	_, err = server.Call(ctx, http.MethodPost, "", "pki/root/generate/internal", map[string]any{
		"common_name": "Leaf Key Conformance Root", "key_type": "ec", "key_bits": 384, "ttl": "8760h",
	})
	require.NoError(t, err)

	writeRole := func(bits int) {
		_, err := server.Call(ctx, http.MethodPost, "", "pki/roles/leaf", map[string]any{
			"allow_any_name": true, "require_cn": false, "key_type": "ec", "key_bits": bits, "ttl": "1h",
		})
		require.NoError(t, err)
	}

	signWith := func(curve elliptic.Curve) error {
		_, err := server.Call(ctx, http.MethodPost, "", "pki/sign/leaf", map[string]any{
			"csr": csr(t, curve, "leaf.example"), "common_name": "leaf.example",
		})

		return err
	}

	writeRole(apply.LeafKeyBits(model.CurveP384))
	require.NoError(t, signWith(elliptic.P256()), "a P-384 leaf role signs a P-256 CSR")
	require.NoError(t, signWith(elliptic.P384()), "a P-384 leaf role signs a P-384 CSR")

	// The behaviour this replaces: a role written with 384 refuses P-256.
	writeRole(model.CurveBits[model.CurveP384])
	requireStatus(t, signWith(elliptic.P256()), http.StatusBadRequest, "key_bits is a minimum")
	assert.NoError(t, signWith(elliptic.P384()))
}
