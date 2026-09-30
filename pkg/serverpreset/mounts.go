package serverpreset

import (
	"fmt"
	"sort"
	"strings"

	"github.com/truvity/openbao/pkg/model"
)

// awsAuthPlugin is the catalog entry an AWS auth mount resolves to.
const (
	awsAuthKind = "auth"
	awsAuthName = "aws"
	// latestVersion is OpenBAO's own catalog sentinel: it resolves to
	// whichever version is registered, so there is nothing to cross-check.
	latestVersion = "latest"
)

// CheckMounts cross-checks the two ways a plugin reaches the catalog: this
// Config's declarative, VERSIONED entries and the model's
// [model.Desired.Plugins] (registered by the apply under the UNVERSIONED
// key). A mount resolves through exactly one of them, and nothing else
// validates that it can:
//
//   - a mount that pins a plugin version needs a declarative plugin at
//     that exact version (Desired.Plugins entries carry no version, so
//     they can never satisfy a pin);
//   - a mount that pins none needs a Desired.Plugins entry, since a
//     declarative entry is versioned and an unversioned lookup never
//     finds it ("plugin not found in the catalog").
//
// It is opt-in: nothing calls it for you, so an estate that keeps the two
// halves in different repositories adopts it when it holds both.
func (c *Config) CheckMounts(desired *model.Desired) error {
	declared := map[string]bool{}

	for i := range c.Plugins {
		p := &c.Plugins[i]
		if p.Kind == awsAuthKind && p.Name == awsAuthName {
			declared[p.Version] = true
		}
	}

	registered := false

	for i := range desired.Plugins {
		p := &desired.Plugins[i]
		if p.Type == awsAuthKind && p.Name == awsAuthName {
			registered = true
		}
	}

	for _, namespace := range desired.Applied() {
		for i := range namespace.AWSAuth {
			mount := &namespace.AWSAuth[i]
			label := fmt.Sprintf("namespace %q AWS auth mount %q", namespace.Name, mount.Path)

			switch version := mount.PluginVersion; {
			case version == latestVersion:
			case version != "":
				if !declared[version] {
					return fmt.Errorf("%s pins plugin version %q, but no declarative auth/aws plugin has that version (declared: %s); "+
						"Desired.Plugins entries carry no version and cannot satisfy a pin", label, version, versionsOf(declared))
				}
			case !registered:
				return fmt.Errorf("%s pins no plugin version, so it looks up the unversioned catalog key, but Desired.Plugins registers no auth/aws plugin; "+
					"pin pluginVersion to a declarative plugin's version or register the plugin", label)
			}
		}
	}

	return nil
}

func versionsOf(set map[string]bool) string {
	if len(set) == 0 {
		return "none"
	}

	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}

	sort.Strings(out)

	return strings.Join(out, ", ")
}
