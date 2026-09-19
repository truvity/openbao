package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
)

type (
	// Server is an OpenBAO server reached over its HTTP API as one token.
	Server struct {
		// Address is the API's base URL, without a trailing slash.
		Address string
		// Token is sent on every call; empty for none.
		Token string
		// HTTP defaults to http.DefaultClient.
		HTTP *http.Client
	}

	// APIError is a status the server answered with, and what it said.
	APIError struct {
		Method, Path, Namespace string
		Status                  int
		Errors                  []string
	}

	// handler replays one resource: the calls it makes, and the outputs
	// later inputs read, by the output's name (`accessor`, `issuerId`, ...).
	handler func(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error)
)

func (e *APIError) Error() string {
	where := e.Path
	if e.Namespace != "" {
		where = e.Namespace + "/" + e.Path
	}

	return fmt.Sprintf("%s %s: %d %s", e.Method, where, e.Status, strings.Join(e.Errors, "; "))
}

// Replay writes every resource, in order, substituting each placeholder
// for the value the server gave the resource it names. The first failure
// stops it.
func (s *Server) Replay(ctx context.Context, resources []Resource) error {
	values := map[string]string{}

	for _, r := range resources {
		inputs, ok := substitute(unsecret(r.Inputs), values).(map[string]any)
		if !ok {
			return fmt.Errorf("replay: %s has no inputs", r.Name)
		}

		namespace, _ := inputs["namespace"].(string)

		outputs, err := handlers[r.Type](ctx, s, namespace, inputs)
		if err != nil {
			return fmt.Errorf("replay: %s %s: %w", r.Type, r.Name, err)
		}

		for key, value := range outputs {
			if value == "" {
				continue
			}

			if key == "id" {
				values[r.Name+"_id"] = value
			}

			values[r.Name+"#"+key] = value
		}
	}

	return nil
}

// Call makes one request in a namespace and returns the response's body.
// A parameter the server ignored as unrecognised is an error: a replay
// that silently dropped one would prove nothing about it.
func (s *Server) Call(ctx context.Context, method, namespace, path string, body any) (map[string]any, error) {
	var payload io.Reader

	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode %s: %w", path, err)
		}

		payload = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, s.Address+"/v1/"+path, payload)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/json")

	if s.Token != "" {
		request.Header.Set("X-Vault-Token", s.Token)
	}

	if namespace != "" {
		request.Header.Set("X-Vault-Namespace", namespace)
	}

	client := s.HTTP
	if client == nil {
		client = http.DefaultClient
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer func() { _ = response.Body.Close() }()

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var decoded map[string]any
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, fmt.Errorf("%s %s answered %d with no JSON: %s", method, path, response.StatusCode, raw)
		}
	}

	if response.StatusCode >= http.StatusBadRequest {
		apiErr := &APIError{Method: method, Path: path, Namespace: namespace, Status: response.StatusCode}
		for _, message := range asSlice(decoded["errors"]) {
			apiErr.Errors = append(apiErr.Errors, fmt.Sprint(message))
		}

		return decoded, apiErr
	}

	for _, warning := range asSlice(decoded["warnings"]) {
		if text := fmt.Sprint(warning); strings.Contains(text, "unrecognized") {
			return decoded, fmt.Errorf("%s %s: %s", method, path, text)
		}
	}

	return decoded, nil
}

// handlers are the resource types pkg/apply registers.
var handlers = map[string]handler{
	"pulumi:providers:vault": func(context.Context, *Server, string, map[string]any) (map[string]string, error) {
		return nil, nil
	},
	"vault:index/namespace:Namespace":                             namespace,
	"vault:index/policy:Policy":                                   policy,
	"vault:index/mount:Mount":                                     mount,
	"vault:jwt/authBackend:AuthBackend":                           authBackend,
	"vault:jwt/authBackendRole:AuthBackendRole":                   plain("auth/{backend}/role/{roleName}"),
	"vault:identity/group:Group":                                  group,
	"vault:identity/groupAlias:GroupAlias":                        plain("identity/group-alias"),
	"vault:kv/secretV2:SecretV2":                                  kvSecret,
	"vault:ssh/secretBackendCa:SecretBackendCa":                   plain("{backend}/config/ca"),
	"vault:ssh/secretBackendRole:SecretBackendRole":               sshRole,
	"vault:pkiSecret/secretBackendRootCert:SecretBackendRootCert": rootCert,
	"vault:pkiSecret/secretBackendIntermediateCertRequest:SecretBackendIntermediateCertRequest": intermediateRequest,
	"vault:pkiSecret/secretBackendRootSignIntermediate:SecretBackendRootSignIntermediate":       signIntermediate,
	"vault:pkiSecret/secretBackendIntermediateSetSigned:SecretBackendIntermediateSetSigned":     setSigned,
	"vault:pkiSecret/secretBackendIssuer:SecretBackendIssuer":                                   issuer,
	"vault:pkiSecret/secretBackendConfigIssuers:SecretBackendConfigIssuers":                     plain("{backend}/config/issuers"),
	"vault:pkiSecret/secretBackendConfigUrls:SecretBackendConfigUrls":                           plain("{backend}/config/urls"),
	"vault:pkiSecret/secretBackendCrlConfig:SecretBackendCrlConfig":                             plain("{backend}/config/crl"),
	"vault:pkiSecret/backendConfigAutoTidy:BackendConfigAutoTidy":                               plain("{backend}/config/auto-tidy"),
	"vault:pkiSecret/secretBackendRole:SecretBackendRole":                                       plain("{backend}/roles/{name}"),
}

// plain writes the inputs as they are, snake-cased, to a path built from
// some of them; the ones the path uses are not sent again.
func plain(template string) handler {
	return func(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
		path, body := pathFrom(template, in)
		_, err := s.Call(ctx, http.MethodPost, namespace, path, body)

		return nil, err
	}
}

func namespace(ctx context.Context, s *Server, parent string, in map[string]any) (map[string]string, error) {
	path, _ := in["path"].(string)
	_, err := s.Call(ctx, http.MethodPost, parent, "sys/namespaces/"+path, map[string]any{})

	return map[string]string{"id": path}, err
}

func policy(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
	name, _ := in["name"].(string)
	_, err := s.Call(ctx, http.MethodPut, namespace, "sys/policies/acl/"+url.PathEscape(name), map[string]any{"policy": in["policy"]})

	return map[string]string{"id": name}, err
}

// mount enables a secrets engine; the lease and audit arguments are the
// mount's config block.
func mount(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
	path, _ := in["path"].(string)
	body := map[string]any{"type": in["type"], "description": in["description"], "options": in["options"]}
	config := map[string]any{}

	for from, to := range map[string]string{
		"defaultLeaseTtlSeconds":   "default_lease_ttl",
		"maxLeaseTtlSeconds":       "max_lease_ttl",
		"auditNonHmacRequestKeys":  "audit_non_hmac_request_keys",
		"auditNonHmacResponseKeys": "audit_non_hmac_response_keys",
	} {
		if value, ok := in[from]; ok {
			config[to] = value
		}
	}

	body["config"] = config
	_, err := s.Call(ctx, http.MethodPost, namespace, "sys/mounts/"+path, body)

	return map[string]string{"id": path}, err
}

// authBackend enables the JWT/OIDC method, tunes it, writes its config,
// and reads back the accessor the aliases and credential roles name.
func authBackend(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
	path, _ := in["path"].(string)

	if _, err := s.Call(ctx, http.MethodPost, namespace, "sys/auth/"+path, map[string]any{"type": in["type"], "description": in["description"]}); err != nil {
		return nil, err
	}

	if tune, ok := in["tune"].(map[string]any); ok {
		if _, err := s.Call(ctx, http.MethodPost, namespace, "sys/auth/"+path+"/tune", snake(tune)); err != nil {
			return nil, err
		}
	}

	config := map[string]any{}

	for key, value := range in {
		switch key {
		case "path", "type", "description", "namespace", "tune":
		default:
			config[snakeCase(key)] = value
		}
	}

	if _, err := s.Call(ctx, http.MethodPost, namespace, "auth/"+path+"/config", config); err != nil {
		return nil, err
	}

	mounts, err := s.Call(ctx, http.MethodGet, namespace, "sys/auth", nil)
	if err != nil {
		return nil, err
	}

	data, _ := mounts["data"].(map[string]any)
	entry, _ := data[path+"/"].(map[string]any)
	accessor, _ := entry["accessor"].(string)

	if accessor == "" {
		return nil, fmt.Errorf("auth mount %s has no accessor", path)
	}

	return map[string]string{"id": path, "accessor": accessor}, nil
}

func group(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
	answer, err := s.Call(ctx, http.MethodPost, namespace, "identity/group", snake(in))
	if err != nil {
		return nil, err
	}

	data, _ := answer["data"].(map[string]any)
	id, _ := data["id"].(string)

	return map[string]string{"id": id}, nil
}

func kvSecret(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
	var data map[string]any

	raw, _ := in["dataJson"].(string)
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, fmt.Errorf("dataJson: %w", err)
	}

	_, err := s.Call(ctx, http.MethodPost, namespace, fmt.Sprintf("%s/data/%s", in["mount"], in["name"]), map[string]any{"data": data})

	return nil, err
}

// sshRole writes a role; each allowed user key config is one entry of the
// API's key-type-to-lengths map.
func sshRole(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
	path, body := pathFrom("{backend}/roles/{name}", in)
	delete(body, "allowed_user_key_configs")

	lengths := map[string]any{}
	for _, entry := range asSlice(in["allowedUserKeyConfigs"]) {
		config, _ := entry.(map[string]any)
		lengths[fmt.Sprint(config["type"])] = config["lengths"]
	}

	body["allowed_user_key_lengths"] = lengths
	_, err := s.Call(ctx, http.MethodPost, namespace, path, body)

	return nil, err
}

func rootCert(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
	path, body := pathFrom("{backend}/root/generate/{type}", in)

	answer, err := s.Call(ctx, http.MethodPost, namespace, path, body)
	if err != nil {
		return nil, err
	}

	data, _ := answer["data"].(map[string]any)

	return map[string]string{"issuerId": text(data["issuer_id"]), "certificate": text(data["certificate"])}, nil
}

func intermediateRequest(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
	path, body := pathFrom("{backend}/intermediate/generate/{type}", in)

	answer, err := s.Call(ctx, http.MethodPost, namespace, path, body)
	if err != nil {
		return nil, err
	}

	data, _ := answer["data"].(map[string]any)

	return map[string]string{"csr": text(data["csr"])}, nil
}

// signIntermediate signs with the named issuer; the bundle the provider
// exports is the certificate followed by its issuer.
func signIntermediate(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
	template := "{backend}/root/sign-intermediate"
	if _, named := in["issuerRef"]; named {
		template = "{backend}/issuer/{issuerRef}/sign-intermediate"
	}

	path, body := pathFrom(template, in)

	answer, err := s.Call(ctx, http.MethodPost, namespace, path, body)
	if err != nil {
		return nil, err
	}

	data, _ := answer["data"].(map[string]any)
	certificate := text(data["certificate"])

	return map[string]string{
		"certificate":       certificate,
		"certificateBundle": certificate + "\n" + text(data["issuing_ca"]),
	}, nil
}

// issuer names an imported issuer and sets its usage.
func issuer(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
	path, body := pathFrom("{backend}/issuer/{issuerRef}", in)

	answer, err := s.Call(ctx, http.MethodPost, namespace, path, body)
	if err != nil {
		return nil, err
	}

	data, _ := answer["data"].(map[string]any)

	return map[string]string{"issuerId": text(data["issuer_id"])}, nil
}

func setSigned(ctx context.Context, s *Server, namespace string, in map[string]any) (map[string]string, error) {
	path, body := pathFrom("{backend}/intermediate/set-signed", in)

	answer, err := s.Call(ctx, http.MethodPost, namespace, path, body)
	if err != nil {
		return nil, err
	}

	data, _ := answer["data"].(map[string]any)
	imported := asSlice(data["imported_issuers"])

	if len(imported) == 0 {
		return nil, fmt.Errorf("%s imported no issuer", path)
	}

	return map[string]string{"imported": text(imported[0])}, nil
}

// pathFrom fills `{input}` segments of a template and returns the path and
// every other input, snake-cased: the body.
func pathFrom(template string, in map[string]any) (string, map[string]any) {
	used := map[string]bool{"namespace": true}
	path := template

	for key, value := range in {
		placeholder := "{" + key + "}"
		if strings.Contains(path, placeholder) {
			path = strings.ReplaceAll(path, placeholder, url.PathEscape(fmt.Sprint(value)))
			used[key] = true
		}
	}

	body := map[string]any{}

	for key, value := range in {
		if !used[key] {
			body[snakeCase(key)] = value
		}
	}

	return path, body
}

// snake is the inputs snake-cased, less the namespace, which is a header.
func snake(in map[string]any) map[string]any {
	_, body := pathFrom("", in)

	return body
}

// snakeCase turns the provider's argument name into the API's parameter
// name: `allowedDomainsTemplate` is `allowed_domains_template`.
func snakeCase(name string) string {
	var b strings.Builder

	for i, r := range name {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}

			r = unicode.ToLower(r)
		}

		b.WriteRune(r)
	}

	return b.String()
}

// unsecret unwraps a secret input to its value.
func unsecret(value any) any {
	switch v := value.(type) {
	case *resource.Secret:
		return unsecret(v.Element.Mappable())
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, inner := range v {
			out[key] = unsecret(inner)
		}

		return out
	case []any:
		out := make([]any, len(v))
		for i, inner := range v {
			out[i] = unsecret(inner)
		}

		return out
	default:
		return value
	}
}

// substitute replaces every placeholder in every string, longest first, so
// a placeholder that is a prefix of another never matches inside it.
func substitute(value any, values map[string]string) any {
	switch v := value.(type) {
	case string:
		keys := make([]string, 0, len(values))
		for key := range values {
			if strings.Contains(v, key) {
				keys = append(keys, key)
			}
		}

		sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })

		for _, key := range keys {
			v = strings.ReplaceAll(v, key, values[key])
		}

		return v
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, inner := range v {
			out[key] = substitute(inner, values)
		}

		return out
	case []any:
		out := make([]any, len(v))
		for i, inner := range v {
			out[i] = substitute(inner, values)
		}

		return out
	default:
		return value
	}
}

func asSlice(value any) []any {
	slice, _ := value.([]any)

	return slice
}

func text(value any) string {
	s, _ := value.(string)

	return strings.TrimSpace(s)
}
