package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

type (
	// fakeBao is an OpenBAO reduced to the calls the bootstrap makes, with
	// the behavior that matters: tokens are checked, generate-root pads the
	// token with its OTP, and external groups gain members on login.
	fakeBao struct {
		mu sync.Mutex

		initialized  bool
		recoverySeal bool
		audit        bool
		voters       int
		votersGrow   bool
		initBody     map[string]any
		shares       []string
		tokens       map[string]fakeToken
		mounts       map[string]mount
		authConfig   map[string]any
		roles        map[string]map[string]any
		policies     map[string]string
		groups       map[string]*group
		secretMounts map[string]mount
		// generatedPolicies, when set, are what a token generated from the
		// shares carries instead of root: a drill that must clean up after
		// itself.
		generatedPolicies []string
		// loginPolicies, when set, are what an operator login gets instead of
		// the policies of the groups it joins.
		loginPolicies []string
		generation    *fakeGeneration
		calls         []string
		minted        int
	}

	fakeToken struct {
		accessor string
		policies []string
	}

	fakeGeneration struct {
		nonce     string
		otp       string
		submitted map[string]bool
	}

	fakeKeeper struct {
		mu         sync.Mutex
		items      map[string]string
		archived   map[string]string
		failCreate map[string]int
		failAll    bool
		creates    map[string]int
		reveals    map[string]int
		// revealed keeps every buffer Reveal handed out, so a test can prove
		// the library zeroed them.
		revealed [][]byte
		// created keeps every buffer Create was handed, for the same proof.
		created [][]byte
	}
)

const (
	fakeRoot = "s.bootstrap-root-token-000000"
	// fakeJWT is the one operator token the fake issuer's door accepts.
	fakeJWT = "operator-jwt.header.payload.signature"
)

func newFakeBao(t *testing.T) (*fakeBao, *Client) {
	t.Helper()

	fake := &fakeBao{
		recoverySeal: true,
		audit:        true,
		voters:       3,
		tokens:       map[string]fakeToken{},
		mounts:       map[string]mount{"token/": {Type: "token", Accessor: "auth_token_0"}},
		roles:        map[string]map[string]any{},
		policies:     map[string]string{},
		groups:       map[string]*group{},
	}

	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	return fake, NewClient(server.URL, server.Client())
}

func newFakeKeeper() *fakeKeeper {
	return &fakeKeeper{
		items:      map[string]string{},
		archived:   map[string]string{},
		failCreate: map[string]int{},
		creates:    map[string]int{},
		reveals:    map[string]int{},
	}
}

func (f *fakeBao) count(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	n := 0

	for _, c := range f.calls {
		if c == call {
			n++
		}
	}

	return n
}

// login is what a roster login does to an external group: its entity joins.
func (f *fakeBao) login(groupName string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.groups[groupName].MemberEntityIDs = append(f.groups[groupName].MemberEntityIDs, "entity-oleg")
}

func (f *fakeBao) tokenValid(token string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	_, ok := f.tokens[token]

	return ok
}

func (f *fakeBao) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	f.calls = append(f.calls, r.Method+" "+path)

	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)

	unauthenticated := path == "sys/init" || path == "sys/seal-status" || path == "auth/"+"jwt-roster/login"
	if _, ok := f.tokens[r.Header.Get("X-Vault-Token")]; !ok && !unauthenticated {
		reply(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})

		return
	}

	status, answer := f.route(r.Method, path, r.Header.Get("X-Vault-Token"), body)
	reply(w, status, answer)
}

func (f *fakeBao) route(method, path, token string, body map[string]any) (int, any) {
	switch {
	case method == http.MethodGet && path == "sys/init":
		return http.StatusOK, map[string]any{"initialized": f.initialized}
	case method == http.MethodPut && path == "sys/init":
		return f.init(body)
	case method == http.MethodGet && path == "sys/seal-status":
		kind := "awskms"
		if !f.recoverySeal {
			kind = "shamir"
		}

		return http.StatusOK, map[string]any{"type": kind, "recovery_seal": f.recoverySeal, "sealed": !f.initialized}
	case method == http.MethodGet && path == "sys/storage/raft/configuration":
		return f.raft()
	case method == http.MethodGet && path == "sys/audit":
		data := map[string]any{}
		if f.audit {
			data["to-stdout/"] = map[string]any{"type": "file"}
		}

		return http.StatusOK, map[string]any{"data": data}
	case method == http.MethodGet && path == "sys/mounts":
		data := map[string]any{"sys/": mount{Type: "system"}, "cubbyhole/": mount{Type: "cubbyhole"}, "identity/": mount{Type: "identity"}}
		for name, extra := range f.secretMounts {
			data[name] = extra
		}

		return http.StatusOK, map[string]any{"data": data}
	case method == http.MethodPost && path == "auth/jwt-roster/login":
		return f.operatorLogin(body)
	case method == http.MethodGet && strings.HasPrefix(path, "sys/policies/acl/"):
		name := strings.TrimPrefix(path, "sys/policies/acl/")
		held := f.tokens[token]

		if !slices.Contains(held.policies, "root") && !slices.Contains(held.policies, name) {
			return http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}}
		}

		return http.StatusOK, map[string]any{"data": map[string]any{"name": name, "policy": f.policies[name]}}
	case method == http.MethodGet && path == "sys/auth":
		return http.StatusOK, map[string]any{"data": f.mounts}
	case method == http.MethodPost && strings.HasPrefix(path, "sys/auth/"):
		name := strings.TrimPrefix(path, "sys/auth/") + "/"
		f.mounts[name] = mount{Type: fmt.Sprint(body["type"]), Accessor: "auth_jwt_1"}

		return http.StatusNoContent, nil
	case method == http.MethodPost && strings.HasSuffix(path, "/config") && strings.HasPrefix(path, "auth/"):
		f.authConfig = body

		return http.StatusNoContent, nil
	case method == http.MethodPost && strings.Contains(path, "/role/"):
		f.roles[path[strings.LastIndex(path, "/")+1:]] = body

		return http.StatusNoContent, nil
	case method == http.MethodPut && strings.HasPrefix(path, "sys/policies/acl/"):
		f.policies[strings.TrimPrefix(path, "sys/policies/acl/")] = fmt.Sprint(body["policy"])

		return http.StatusNoContent, nil
	case strings.HasPrefix(path, "identity/"):
		return f.identity(method, path, body)
	case strings.HasPrefix(path, "sys/generate-root-token/"):
		status, answer := f.generateRoot(method, path, body)
		if answer == nil || status >= http.StatusBadRequest {
			return status, answer
		}

		return status, map[string]any{"data": answer}
	case method == http.MethodGet && path == "auth/token/lookup-self":
		held := f.tokens[token]

		return http.StatusOK, map[string]any{"data": map[string]any{"accessor": held.accessor, "policies": held.policies}}
	case method == http.MethodPost && path == "auth/token/revoke-self":
		delete(f.tokens, token)

		return http.StatusNoContent, nil
	default:
		return http.StatusNotFound, map[string]any{"errors": []string{"unsupported path " + path}}
	}
}

func (f *fakeBao) init(body map[string]any) (int, any) {
	if f.initialized {
		return http.StatusBadRequest, map[string]any{"errors": []string{"OpenBao is already initialized"}}
	}

	f.initialized = true
	f.initBody = body
	f.shares = nil

	for n := 1; n <= 5; n++ {
		f.shares = append(f.shares, fmt.Sprintf("recovery-share-%d-base64", n))
	}

	f.tokens[fakeRoot] = fakeToken{accessor: "accessor-bootstrap", policies: []string{"root"}}

	return http.StatusOK, map[string]any{"recovery_keys_base64": f.shares, "root_token": fakeRoot}
}

func (f *fakeBao) raft() (int, any) {
	servers := make([]map[string]any, 0, f.voters)
	for range f.voters {
		servers = append(servers, map[string]any{"voter": true})
	}

	if f.votersGrow && f.voters < 3 {
		f.voters++
	}

	return http.StatusOK, map[string]any{"data": map[string]any{"config": map[string]any{"servers": servers}}}
}

func (f *fakeBao) identity(method, path string, body map[string]any) (int, any) {
	switch {
	case method == http.MethodGet && strings.HasPrefix(path, "identity/group/name/"):
		found, ok := f.groups[strings.TrimPrefix(path, "identity/group/name/")]
		if !ok {
			return http.StatusNotFound, nil
		}

		return http.StatusOK, map[string]any{"data": found}
	case method == http.MethodPost && path == "identity/group":
		name := fmt.Sprint(body["name"])
		f.groups[name] = &group{ID: "group-" + name, Type: fmt.Sprint(body["type"]), Policies: anyStrings(body["policies"])}

		return http.StatusOK, map[string]any{"data": map[string]any{"id": f.groups[name].ID}}
	case method == http.MethodPost && strings.HasPrefix(path, "identity/group/name/"):
		found := f.groups[strings.TrimPrefix(path, "identity/group/name/")]
		found.Policies = anyStrings(body["policies"])

		return http.StatusNoContent, nil
	case method == http.MethodPost && (path == "identity/group-alias" || strings.HasPrefix(path, "identity/group-alias/id/")):
		for _, candidate := range f.groups {
			if candidate.ID == body["canonical_id"] {
				candidate.Alias.ID = "alias-1"
				candidate.Alias.Name = fmt.Sprint(body["name"])
				candidate.Alias.MountAccessor = fmt.Sprint(body["mount_accessor"])
			}
		}

		return http.StatusOK, nil
	default:
		return http.StatusNotFound, nil
	}
}

func (f *fakeBao) generateRoot(method, path string, body map[string]any) (int, any) {
	switch {
	case method == http.MethodGet && path == "sys/generate-root-token/attempt":
		return http.StatusOK, f.generationStatus("")
	case method == http.MethodPut && path == "sys/generate-root-token/attempt":
		if f.generation != nil {
			return http.StatusBadRequest, map[string]any{"errors": []string{"root generation already in progress"}}
		}

		f.generation = &fakeGeneration{nonce: "nonce-1", otp: "otp-of-exactly-twenty-eight!", submitted: map[string]bool{}}

		return http.StatusOK, f.generationStatus(f.generation.otp)
	case method == http.MethodDelete && path == "sys/generate-root-token/attempt":
		f.generation = nil

		return http.StatusNoContent, nil
	case method == http.MethodPut && path == "sys/generate-root-token/update":
		return f.submit(body)
	default:
		return http.StatusNotFound, nil
	}
}

func (f *fakeBao) submit(body map[string]any) (int, any) {
	if f.generation == nil || body["nonce"] != f.generation.nonce {
		return http.StatusBadRequest, map[string]any{"errors": []string{"no matching root generation"}}
	}

	key := fmt.Sprint(body["key"])
	valid := false

	for _, share := range f.shares {
		valid = valid || share == key
	}

	if !valid {
		return http.StatusBadRequest, map[string]any{"errors": []string{"invalid recovery key"}}
	}

	f.generation.submitted[key] = true

	if len(f.generation.submitted) < 3 {
		return http.StatusOK, map[string]any{"started": true, "progress": len(f.generation.submitted), "required": 3, "nonce": f.generation.nonce}
	}

	f.minted++
	token := fmt.Sprintf("s.generated-root-token-%05d", f.minted) // as long as the OTP
	policies := []string{"root"}
	if f.generatedPolicies != nil {
		policies = f.generatedPolicies
	}

	f.tokens[token] = fakeToken{accessor: fmt.Sprintf("accessor-generated-%d", f.minted), policies: policies}

	padded := make([]byte, len(token))
	for i := range token {
		padded[i] = token[i] ^ f.generation.otp[i]
	}

	f.generation = nil

	return http.StatusOK, map[string]any{
		"complete": true, "progress": 3, "required": 3, "nonce": "nonce-1",
		"encoded_token": base64.RawStdEncoding.EncodeToString(padded),
	}
}

func (f *fakeBao) generationStatus(otp string) map[string]any {
	if f.generation == nil {
		return map[string]any{"started": false, "required": 3}
	}

	return map[string]any{"started": true, "nonce": f.generation.nonce, "required": 3, "otp": otp, "otp_length": len(f.generation.otp)}
}

func anyStrings(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))

	for _, item := range items {
		out = append(out, fmt.Sprint(item))
	}

	return out
}

func reply(w http.ResponseWriter, status int, answer any) {
	if answer == nil {
		w.WriteHeader(status)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(answer)
}

func (k *fakeKeeper) Titles(context.Context) (map[string]bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	titles := map[string]bool{}
	for title := range k.items {
		titles[title] = true
	}

	return titles, nil
}

func (k *fakeKeeper) Create(_ context.Context, title string, secret []byte, _ string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.failAll {
		return errors.New("account is not signed in")
	}

	if k.failCreate[title] > 0 {
		k.failCreate[title]--

		return errors.New("account is not signed in")
	}

	k.creates[title]++
	k.items[title] = string(secret)
	k.created = append(k.created, secret)

	return nil
}

func (k *fakeKeeper) Reveal(_ context.Context, title string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.reveals[title]++

	secret, ok := k.items[title]
	if !ok {
		return nil, fmt.Errorf("%q isn't an item", title)
	}

	handed := []byte(secret)
	k.revealed = append(k.revealed, handed)

	return handed, nil
}

func (k *fakeKeeper) Archive(_ context.Context, title string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.archived[title] = k.items[title]
	delete(k.items, title)

	return nil
}

func (k *fakeKeeper) Delete(_ context.Context, title string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	delete(k.items, title)

	return nil
}

// operatorLogin is the roster door: a good token joins every aliased external
// group and gets the policies of those groups, as OpenBAO's identity store
// grants them.
func (f *fakeBao) operatorLogin(body map[string]any) (int, any) {
	if body["jwt"] != fakeJWT || body["role"] != "roster" {
		return http.StatusBadRequest, map[string]any{"errors": []string{"permission denied"}}
	}

	var policies []string

	for name, candidate := range f.groups {
		if candidate.Alias.ID != "" {
			candidate.MemberEntityIDs = append(candidate.MemberEntityIDs, "entity-oleg")
			policies = append(policies, name)
		}
	}

	if f.loginPolicies != nil {
		policies = f.loginPolicies
	}

	f.minted++
	token := fmt.Sprintf("s.operator-login-token-%05d", f.minted)
	f.tokens[token] = fakeToken{accessor: fmt.Sprintf("accessor-operator-%d", f.minted), policies: policies}

	return http.StatusOK, map[string]any{"auth": map[string]any{"client_token": token, "policies": policies, "identity_policies": policies}}
}
