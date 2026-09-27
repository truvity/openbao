// Package fakeissuer is an OIDC issuer in the shape of access-roster's
// access-issuer, small enough to read in one sitting: an RS256 key and an
// ES384 one, a discovery document, a key set naming both, tokens with a
// flat groups claim, and the authorization-code flow a confidential client
// (OpenBAO's web UI door) runs through a browser.
//
// It is a test double. It proves nothing about who a caller is: whoever
// the test says signs in next, signs in. What it is for is the other side
// of the contract -- that OpenBAO, configured by pkg/model and pkg/apply,
// accepts exactly the tokens such an issuer mints and nothing else.
package fakeissuer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

// es384CoordinateSize is the byte length of a P-384 field element: the
// curve's order is just under 2^384, so its coordinates and an ES384
// signature's r and s each take ceil(384/8) = 48 bytes, zero-padded.
const es384CoordinateSize = 48

// Paths the issuer serves under its URL.
const (
	DiscoveryPath = "/.well-known/openid-configuration"
	KeysPath      = "/keys"
	AuthorizePath = "/authorize"
	TokenPath     = "/token"
	UserinfoPath  = "/userinfo"
)

type (
	// Issuer is one running fake issuer.
	Issuer struct {
		// URL is the issuer: the `iss` of every token, and the base of its
		// discovery document.
		URL string

		server *httptest.Server
		key    *rsa.PrivateKey
		keyID  string
		// esKey and esKeyID are the issuer's ES384 (P-384) signing key,
		// published in the JWKS alongside the RS256 one, so a mount that
		// trusts this issuer can be handed either kind of token.
		esKey   *ecdsa.PrivateKey
		esKeyID string
		clients map[string]string

		mu       sync.Mutex
		signIn   *Claims
		codes    map[string]grant
		accesses map[string]map[string]any
	}

	// Claims are what one token says. Subject and Audience are required;
	// a zero Expiry is an hour from now.
	Claims struct {
		Subject  string
		Audience string
		Email    string
		Groups   []string
		Expiry   time.Time
		// Extra claims, merged last: a test that needs a claim this struct
		// does not name, or needs to override one it does.
		Extra map[string]any
	}

	// grant is an authorization code, waiting to be redeemed.
	grant struct {
		claims      Claims
		clientID    string
		redirectURI string
		nonce       string
	}
)

// New starts an issuer. Clients are the confidential clients the token
// endpoint admits for the code flow, id to secret.
func New(clients map[string]string) (*Issuer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("fakeissuer: generate a key: %w", err)
	}

	esKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("fakeissuer: generate an ES384 key: %w", err)
	}

	issuer := &Issuer{
		key:      key,
		keyID:    "fake-1",
		esKey:    esKey,
		esKeyID:  "fake-es384",
		clients:  clients,
		codes:    map[string]grant{},
		accesses: map[string]map[string]any{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+DiscoveryPath, issuer.discovery)
	mux.HandleFunc("GET "+KeysPath, issuer.keys)
	mux.HandleFunc("GET "+AuthorizePath, issuer.authorize)
	mux.HandleFunc("POST "+TokenPath, issuer.token)
	mux.HandleFunc("GET "+UserinfoPath, issuer.userinfo)

	issuer.server = httptest.NewServer(mux)
	issuer.URL = issuer.server.URL

	return issuer, nil
}

// Close stops the issuer.
func (i *Issuer) Close() { i.server.Close() }

// Token signs the claims RS256, with the issuer's key. It is the default:
// what access-issuer signs with today.
func (i *Issuer) Token(claims Claims) string {
	return i.sign(i.key, i.keyID, i.payload(claims))
}

// ES384Token signs the claims ES384, with the issuer's P-384 key. It proves
// the other side of the contract: an issuer that signs ES384 (or ES256)
// rather than RS256 must still be admitted by a mount this library applies.
func (i *Issuer) ES384Token(claims Claims) string {
	return i.signES384(i.payload(claims))
}

// ForeignToken signs the same claims with a key the issuer never published:
// a token that says the right things and is from somebody else.
func (i *Issuer) ForeignToken(claims Claims) (string, error) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("fakeissuer: generate a key: %w", err)
	}

	return i.sign(other, i.keyID, i.payload(claims)), nil
}

// SignIn says who the next browser at the authorization endpoint is. The
// audience is the client the browser was sent by, whatever is set here.
func (i *Issuer) SignIn(claims Claims) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.signIn = &claims
}

func (i *Issuer) payload(claims Claims) map[string]any {
	now := time.Now()

	expiry := claims.Expiry
	if expiry.IsZero() {
		expiry = now.Add(time.Hour)
	}

	payload := map[string]any{
		"iss": i.URL,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"iat": now.Add(-time.Minute).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": expiry.Unix(),
		// access-roster puts groups in every token, and an empty list is
		// still a list.
		"groups": append([]string{}, claims.Groups...),
	}

	if claims.Email != "" {
		payload["email"] = claims.Email
		payload["email_verified"] = true
	}

	for key, value := range claims.Extra {
		payload[key] = value
	}

	return payload
}

func (i *Issuer) sign(key *rsa.PrivateKey, keyID string, payload map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": keyID})
	body, _ := json.Marshal(payload)
	input := encode(header) + "." + encode(body)
	digest := sha256.Sum256([]byte(input))

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		// A 2048-bit key signing a SHA-256 digest cannot fail short of a
		// broken random source, after which nothing here means anything.
		panic(fmt.Sprintf("fakeissuer: sign: %v", err))
	}

	return input + "." + encode(signature)
}

// signES384 signs a JWS the way ES384 requires: not the ASN.1 DER
// ecdsa.Sign produces, but r and s each padded to the curve's coordinate
// size and concatenated raw.
func (i *Issuer) signES384(payload map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "ES384", "typ": "JWT", "kid": i.esKeyID})
	body, _ := json.Marshal(payload)
	input := encode(header) + "." + encode(body)
	digest := sha512.Sum384([]byte(input))

	r, s, err := ecdsa.Sign(rand.Reader, i.esKey, digest[:])
	if err != nil {
		// A P-384 key signing a digest cannot fail short of a broken
		// random source, after which nothing here means anything.
		panic(fmt.Sprintf("fakeissuer: sign ES384: %v", err))
	}

	signature := make([]byte, 2*es384CoordinateSize)
	r.FillBytes(signature[:es384CoordinateSize])
	s.FillBytes(signature[es384CoordinateSize:])

	return input + "." + encode(signature)
}

func (i *Issuer) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                i.URL,
		"authorization_endpoint":                i.URL + AuthorizePath,
		"token_endpoint":                        i.URL + TokenPath,
		"userinfo_endpoint":                     i.URL + UserinfoPath,
		"jwks_uri":                              i.URL + KeysPath,
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256", "ES384"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"grant_types_supported":                 []string{"authorization_code"},
		"claims_supported":                      []string{"sub", "email", "groups"},
	})
}

// keys publishes both signing keys: the RS256 one Token uses and the
// ES384 one ES384Token uses. A relying party that only ever asks for RS256
// tokens simply never matches the second entry by `kid`.
func (i *Issuer) keys(w http.ResponseWriter, _ *http.Request) {
	public := i.key.PublicKey

	// Bytes is the uncompressed SEC1 point: a 0x04 prefix, then X and Y,
	// each already padded to the curve's coordinate size.
	point, err := i.esKey.PublicKey.Bytes()
	if err != nil {
		// A key this package generated itself cannot produce an invalid
		// point.
		panic(fmt.Sprintf("fakeissuer: encode the ES384 public key: %v", err))
	}

	x, y := point[1:1+es384CoordinateSize], point[1+es384CoordinateSize:]

	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{
		{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": i.keyID,
			"n":   encode(public.N.Bytes()),
			"e":   encode(big.NewInt(int64(public.E)).Bytes()),
		},
		{
			"kty": "EC",
			"use": "sig",
			"alg": "ES384",
			"crv": "P-384",
			"kid": i.esKeyID,
			"x":   encode(x),
			"y":   encode(y),
		},
	}})
}

// authorize is the browser's stop at the issuer: whoever SignIn named signs
// in, and the browser is sent back to the client with a code.
func (i *Issuer) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID, redirectURI := query.Get("client_id"), query.Get("redirect_uri")

	if query.Get("response_type") != "code" || !strings.Contains(" "+query.Get("scope")+" ", " openid ") {
		http.Error(w, "not an OpenID code request", http.StatusBadRequest)

		return
	}

	if _, ok := i.clients[clientID]; !ok || redirectURI == "" {
		http.Error(w, "unknown client or no redirect", http.StatusBadRequest)

		return
	}

	i.mu.Lock()
	who := i.signIn
	i.signIn = nil

	if who == nil {
		i.mu.Unlock()
		http.Error(w, "nobody is signing in", http.StatusUnauthorized)

		return
	}

	code := randomString()
	claims := *who
	claims.Audience = clientID
	i.codes[code] = grant{claims: claims, clientID: clientID, redirectURI: redirectURI, nonce: query.Get("nonce")}
	i.mu.Unlock()

	back, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect", http.StatusBadRequest)

		return
	}

	values := back.Query()
	values.Set("code", code)
	values.Set("state", query.Get("state"))
	back.RawQuery = values.Encode()

	http.Redirect(w, r, back.String(), http.StatusFound)
}

// token redeems a code, once, for the client it was issued to, at the
// redirect it was issued for, with the client's secret.
func (i *Issuer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")

		return
	}

	clientID, secret, ok := r.BasicAuth()
	if !ok {
		clientID, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}

	if want, known := i.clients[clientID]; !known || secret != want {
		oauthError(w, http.StatusUnauthorized, "invalid_client")

		return
	}

	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")

		return
	}

	i.mu.Lock()
	code, found := i.codes[r.PostForm.Get("code")]
	delete(i.codes, r.PostForm.Get("code"))
	i.mu.Unlock()

	if !found || code.clientID != clientID || code.redirectURI != r.PostForm.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant")

		return
	}

	payload := i.payload(code.claims)
	if code.nonce != "" {
		payload["nonce"] = code.nonce
	}

	access := randomString()

	i.mu.Lock()
	i.accesses[access] = payload
	i.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     i.sign(i.key, i.keyID, payload),
	})
}

// userinfo answers with the same claims the ID token carried.
func (i *Issuer) userinfo(w http.ResponseWriter, r *http.Request) {
	access := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	i.mu.Lock()
	claims, ok := i.accesses[access]
	i.mu.Unlock()

	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_token")

		return
	}

	writeJSON(w, http.StatusOK, claims)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func encode(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func randomString() string {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)

	return encode(raw)
}
