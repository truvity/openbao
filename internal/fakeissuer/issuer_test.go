package fakeissuer_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/openbao/internal/fakeissuer"
)

func getJSON(t *testing.T, address string, into any) {
	t.Helper()

	response, err := http.Get(address)
	require.NoError(t, err)

	defer func() { _ = response.Body.Close() }()

	require.Equal(t, http.StatusOK, response.StatusCode)
	require.NoError(t, json.NewDecoder(response.Body).Decode(into))
}

// verify checks a token against the published key set, as a relying party
// does, and returns its claims.
func verify(t *testing.T, issuer *fakeissuer.Issuer, token string) (map[string]any, error) {
	t.Helper()

	var set struct {
		Keys []struct{ N, E, Kid string } `json:"keys"`
	}

	getJSON(t, issuer.URL+fakeissuer.KeysPath, &set)
	require.Len(t, set.Keys, 1)

	n, err := base64.RawURLEncoding.DecodeString(set.Keys[0].N)
	require.NoError(t, err)
	e, err := base64.RawURLEncoding.DecodeString(set.Keys[0].E)
	require.NoError(t, err)

	public := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature); err != nil {
		return nil, err
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(raw, &claims))

	return claims, nil
}

func TestDiscoveryAndTokens(t *testing.T) {
	issuer, err := fakeissuer.New(nil)
	require.NoError(t, err)
	t.Cleanup(issuer.Close)

	var discovery map[string]any
	getJSON(t, issuer.URL+fakeissuer.DiscoveryPath, &discovery)
	assert.Equal(t, issuer.URL, discovery["issuer"])
	assert.Equal(t, issuer.URL+fakeissuer.KeysPath, discovery["jwks_uri"])

	claims, err := verify(t, issuer, issuer.Token(fakeissuer.Claims{
		Subject: "person@example.com", Audience: "openbao", Email: "person@example.com", Groups: []string{"dev:ssh:user"},
	}))
	require.NoError(t, err)
	assert.Equal(t, issuer.URL, claims["iss"])
	assert.Equal(t, "openbao", claims["aud"])
	assert.Equal(t, []any{"dev:ssh:user"}, claims["groups"])

	none, err := verify(t, issuer, issuer.Token(fakeissuer.Claims{Subject: "x", Audience: "openbao"}))
	require.NoError(t, err)
	assert.Equal(t, []any{}, none["groups"], "an empty groups claim is still a list")

	foreign, err := issuer.ForeignToken(fakeissuer.Claims{Subject: "x", Audience: "openbao"})
	require.NoError(t, err)
	_, err = verify(t, issuer, foreign)
	require.Error(t, err, "a foreign token must not verify against the issuer's keys")
}

// The code flow: the browser is sent back with a code, the code is
// redeemed once, by its client, with the client's secret, for an ID token
// carrying the nonce and the groups.
func TestCodeFlow(t *testing.T) {
	issuer, err := fakeissuer.New(map[string]string{"openbao-ui": "s3cret"})
	require.NoError(t, err)
	t.Cleanup(issuer.Close)

	noRedirects := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authorize := issuer.URL + fakeissuer.AuthorizePath + "?" + url.Values{
		"response_type": {"code"}, "scope": {"openid email"}, "client_id": {"openbao-ui"},
		"redirect_uri": {"https://openbao.example.com/cb"}, "state": {"st"}, "nonce": {"n0"},
	}.Encode()

	response, err := noRedirects.Get(authorize)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusUnauthorized, response.StatusCode, "nobody signing in is refused")

	issuer.SignIn(fakeissuer.Claims{Subject: "person@example.com", Groups: []string{"dev:ssh:user"}})

	response, err = noRedirects.Get(authorize)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusFound, response.StatusCode)

	back, err := url.Parse(response.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "st", back.Query().Get("state"))

	redeem := func(secret string) *http.Response {
		request, err := http.NewRequest(http.MethodPost, issuer.URL+fakeissuer.TokenPath, strings.NewReader(url.Values{
			"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")}, "redirect_uri": {"https://openbao.example.com/cb"},
		}.Encode()))
		require.NoError(t, err)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetBasicAuth("openbao-ui", secret)

		response, err := http.DefaultClient.Do(request)
		require.NoError(t, err)

		return response
	}

	wrong := redeem("guess")
	_ = wrong.Body.Close()
	require.Equal(t, http.StatusUnauthorized, wrong.StatusCode)

	good := redeem("s3cret")
	defer func() { _ = good.Body.Close() }()
	require.Equal(t, http.StatusOK, good.StatusCode)

	var tokens struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.NewDecoder(good.Body).Decode(&tokens))

	claims, err := verify(t, issuer, tokens.IDToken)
	require.NoError(t, err)
	assert.Equal(t, "openbao-ui", claims["aud"])
	assert.Equal(t, "n0", claims["nonce"])
	assert.Equal(t, []any{"dev:ssh:user"}, claims["groups"])

	again := redeem("s3cret")
	_ = again.Body.Close()
	assert.Equal(t, http.StatusBadRequest, again.StatusCode, "a code is redeemed once")
}
