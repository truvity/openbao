package model

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

type (
	// KVMount is one KV version 2 mount.
	KVMount struct {
		Path        string `yaml:"path"`
		Description string `yaml:"description,omitempty"`
		// Canary is a secret path inside the mount the apply writes as
		// {"namespace": <the namespace's name>}, so a restored snapshot can
		// prove it decrypts data in every namespace. Reserved: nothing else
		// may write it. Empty for none.
		Canary string `yaml:"canary,omitempty"`
	}

	// KVSecret is one secret a reader expects inside a KV mount: Key under
	// the kind's own prefix, holding Properties. A layout is the contract
	// between whoever writes a secret and whoever reads it; the apply does
	// not write secrets, so a layout is checked and consulted, never
	// applied.
	KVSecret struct {
		// Kind is the reader's kind, which is also the policy prefix
		// (`<mount>/data/<kind>/*`). A `{name}` segment stands for one
		// lowercase name: `router-{site}` is one kind per site.
		Kind string `yaml:"kind"`
		// Key is the secret's path inside the mount, under `<kind>/`, with
		// the same placeholders.
		Key        string   `yaml:"key"`
		Properties []string `yaml:"properties"`
		// Writer says who puts the value there, in the estate's own words.
		Writer string `yaml:"writer,omitempty"`
	}

	// KVLayout is every secret a set of readers expects.
	KVLayout []KVSecret
)

// placeholder is a {name} segment of a layout key or kind.
var placeholder = regexp.MustCompile(`\{[a-z]+\}`)

// Validate refuses a mount with no path, and a canary that is not one
// relative secret path.
func (m *KVMount) Validate() error {
	if strings.TrimSpace(m.Path) == "" {
		return fmt.Errorf("a KV mount has no path")
	}

	if m.Canary != "" && (strings.HasPrefix(m.Canary, "/") || strings.Contains(m.Canary, "..") || strings.Contains(m.Canary, "*")) {
		return fmt.Errorf("KV mount %q: canary %q is not one secret path", m.Path, m.Canary)
	}

	return nil
}

// Validate refuses a layout whose key sits outside its kind's prefix (a
// reader's policy would not reach it), a secret with no property, and a key
// declared twice.
func (l KVLayout) Validate() error {
	seen := map[string]bool{}

	for _, secret := range l {
		if strings.TrimSpace(secret.Kind) == "" {
			return fmt.Errorf("KV layout key %q has no kind", secret.Key)
		}

		if !strings.HasPrefix(secret.Key, secret.Kind+"/") || strings.HasSuffix(secret.Key, "/") {
			return fmt.Errorf("KV layout: key %q is outside the kind's prefix %s/", secret.Key, secret.Kind)
		}

		if len(secret.Properties) == 0 {
			return fmt.Errorf("KV layout: key %q holds no property", secret.Key)
		}

		if seen[secret.Key] {
			return fmt.Errorf("KV layout: key %q is declared twice", secret.Key)
		}

		seen[secret.Key] = true
	}

	return nil
}

// SecretsFor returns the rows of one concrete kind ("router-east" matches
// "router-{site}"), or nil for a kind that has none.
func (l KVLayout) SecretsFor(kind string) []KVSecret {
	var out []KVSecret

	for _, secret := range l {
		if placeholderPattern(secret.Kind).MatchString(kind) {
			out = append(out, secret)
		}
	}

	return out
}

// SecretForKey returns the row a concrete key belongs to ("apps/web" is a
// row of "apps/{app}"), and whether there is one.
func (l KVLayout) SecretForKey(key string) (KVSecret, bool) {
	for _, secret := range l {
		if placeholderPattern(secret.Key).MatchString(key) {
			return secret, true
		}
	}

	return KVSecret{}, false
}

// Kinds lists the layout's kinds, in layout order, each once.
func (l KVLayout) Kinds() []string {
	var out []string

	for _, secret := range l {
		if !slices.Contains(out, secret.Kind) {
			out = append(out, secret.Kind)
		}
	}

	return out
}

// placeholderPattern matches a concrete name against a layout pattern, a
// placeholder standing for one lowercase name.
func placeholderPattern(pattern string) *regexp.Regexp {
	parts := placeholder.Split(pattern, -1)
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}

	return regexp.MustCompile("^" + strings.Join(parts, "[a-z0-9-]+") + "$")
}
