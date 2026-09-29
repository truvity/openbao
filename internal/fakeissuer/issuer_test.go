package fakeissuer_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

// jwks is the issuer's published key set, as a relying party fetches it:
// the RS256 key Token signs with and the ES384 one ES384Token does.
type jwks struct {
	Keys []struct{ Kty, Alg, Kid, N, E, Crv, X, Y string } `json:"keys"`
}

func fetchKeys(t *testing.T, issuer *fakeissuer.Issuer) jwks {
	t.Helper()

	var set jwks
	getJSON(t, issuer.URL+fakeissuer.KeysPath, &set)

	return set
}

// verify checks an RS256 token against the published RS256 key, as a
// relying party does, and returns its claims.
func verify(t *testing.T, issuer *fakeissuer.Issuer, token string) (map[string]any, error) {
	t.Helper()

	set := fetchKeys(t, issuer)

	var rsaKey *rsa.PublicKey

	for i := range set.Keys {
		if set.Keys[i].Kty != "RSA" {
			continue
		}

		n, err := base64.RawURLEncoding.DecodeString(set.Keys[i].N)
		require.NoError(t, err)
		e, err := base64.RawURLEncoding.DecodeString(set.Keys[i].E)
		require.NoError(t, err)

		rsaKey = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}

	require.NotNil(t, rsaKey, "the key set names an RSA key")

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, err
	}

	return decodeClaims(t, parts[1])
}

// verifyES384 checks an ES384 token against the published EC key.
func verifyES384(t *testing.T, issuer *fakeissuer.Issuer, token string) (map[string]any, error) {
	t.Helper()

	set := fetchKeys(t, issuer)

	var ecKey *ecdsa.PublicKey

	for i := range set.Keys {
		if set.Keys[i].Kty != "EC" {
			continue
		}

		require.Equal(t, "P-384", set.Keys[i].Crv)

		x, err := base64.RawURLEncoding.DecodeString(set.Keys[i].X)
		require.NoError(t, err)
		y, err := base64.RawURLEncoding.DecodeString(set.Keys[i].Y)
		require.NoError(t, err)

		// The uncompressed SEC1 point ParseUncompressedPublicKey wants: a
		// 0x04 prefix, then X and Y.
		point := append([]byte{0x04}, append(x, y...)...)

		ecKey, err = ecdsa.ParseUncompressedPublicKey(elliptic.P384(), point)
		require.NoError(t, err)
	}

	require.NotNil(t, ecKey, "the key set names an EC key")

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, signature, 96, "an ES384 signature is r and s, each 48 bytes")

	r := new(big.Int).SetBytes(signature[:48])
	s := new(big.Int).SetBytes(signature[48:])

	digest := sha512.Sum384([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(ecKey, digest[:], r, s) {
		return nil, fmt.Errorf("ES384 signature does not verify")
	}

	return decodeClaims(t, parts[1])
}

func decodeClaims(t *testing.T, part string) (map[string]any, error) {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(part)
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

	esClaims, err := verifyES384(t, issuer, issuer.ES384Token(fakeissuer.Claims{
		Subject: "person@example.com", Audience: "openbao", Groups: []string{"dev:ssh:user"},
	}))
	require.NoError(t, err)
	assert.Equal(t, issuer.URL, esClaims["iss"])
	assert.Equal(t, []any{"dev:ssh:user"}, esClaims["groups"])
}

// The code flow: the browser is sent back with a code, the code is
// redeemed once, by its client, with the client's secret, for an ID token
// carrying the nonce and the groups.
func TestCodeFlow(t *testing.T) {
	issuer, err := fakeissuer.New(map[string]fakeissuer.Client{
		"openbao-ui": {Secret: "s3cret", RedirectURIs: []string{"https://openbao.example.com/cb"}},
	})
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

// authorize must refuse a redirect_uri the client did not register, before
// it ever issues a code -- the fix for CodeQL go/unvalidated-url-redirection
// (alert #1, internal/fakeissuer/issuer.go): the endpoint used to redirect
// to whatever the caller passed, once the client_id was merely known.
func TestAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	issuer, err := fakeissuer.New(map[string]fakeissuer.Client{
		"openbao-ui": {Secret: "s3cret", RedirectURIs: []string{"https://openbao.example.com/cb"}},
	})
	require.NoError(t, err)
	t.Cleanup(issuer.Close)

	issuer.SignIn(fakeissuer.Claims{Subject: "person@example.com"})

	noRedirects := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authorize := func(redirectURI string) *http.Response {
		response, err := noRedirects.Get(issuer.URL + fakeissuer.AuthorizePath + "?" + url.Values{
			"response_type": {"code"}, "scope": {"openid"}, "client_id": {"openbao-ui"},
			"redirect_uri": {redirectURI}, "state": {"st"},
		}.Encode())
		require.NoError(t, err)

		return response
	}

	unregistered := authorize("https://evil.example.com/cb")
	_ = unregistered.Body.Close()
	require.Equal(t, http.StatusBadRequest, unregistered.StatusCode,
		"a redirect_uri the client never registered must be refused before a code is issued")

	// The rejected attempt above must not have consumed the pending
	// SignIn: a registered redirect still gets it, proving the refusal
	// happens before authorize touches sign-in state at all.
	registered := authorize("https://openbao.example.com/cb")
	_ = registered.Body.Close()
	assert.Equal(t, http.StatusFound, registered.StatusCode, "a registered redirect_uri still works")
}
