package model

import (
	"fmt"
	"strings"
	"time"
)

type (
	// Group is a group's standing in one namespace: the policies it
	// carries and the doors -- people's auth mounts -- it is admitted
	// through. Name is the value the issuer's groups claim carries.
	//
	// OpenBAO gives an identity group ONE alias: writing a second alias
	// with the same canonical_id silently replaces the first. So each door
	// gets its own external identity group ([Identity.GroupName]), aliased
	// on that mount by the group's name and carrying the same policies.
	// Aliasing one group on two mounts would move its first alias to the
	// second mount and lock every login through the first out.
	Group struct {
		Name     string   `yaml:"name"`
		Policies []string `yaml:"policies"`
		Doors    []string `yaml:"doors"`
	}

	// Identity is how groups become identity groups, server-wide.
	Identity struct {
		// PrimaryDoor is the auth mount whose identity groups keep the
		// group's bare name. Through any other door the identity group is
		// `<name>@<door>`.
		PrimaryDoor string `yaml:"primaryDoor"`
		// Metadata is carried by every identity group. An identity group
		// admitted through another door than the primary one also records
		// that door under the key `door`.
		Metadata map[string]string `yaml:"metadata,omitempty"`
	}
)

// MetadataDoorKey is the metadata key naming a secondary door.
const MetadataDoorKey = "door"

// GroupName is the identity group admitting a group through one door.
func (i Identity) GroupName(group, door string) string {
	if door == i.PrimaryDoor {
		return group
	}

	return group + "@" + door
}

// GroupMetadata is the metadata of the identity group for one door.
func (i Identity) GroupMetadata(door string) map[string]string {
	out := make(map[string]string, len(i.Metadata)+1)
	for key, value := range i.Metadata {
		out[key] = value
	}

	if door != i.PrimaryDoor {
		out[MetadataDoorKey] = door
	}

	return out
}

// Validate refuses an identity with no primary door, or metadata that
// would collide with the door key.
func (i Identity) Validate() error {
	if strings.TrimSpace(i.PrimaryDoor) == "" {
		return fmt.Errorf("model: identity names no primary door")
	}

	if _, ok := i.Metadata[MetadataDoorKey]; ok {
		return fmt.Errorf("model: identity metadata may not set %q; the apply writes it", MetadataDoorKey)
	}

	return nil
}

// Validate refuses a group that grants nothing or is admitted nowhere: a
// group with no door has no alias, and so exists without ever being reached.
func (g *Group) Validate() error {
	if strings.TrimSpace(g.Name) == "" {
		return fmt.Errorf("a group has no name")
	}

	if len(g.Policies) == 0 {
		return fmt.Errorf("group %q carries no policy", g.Name)
	}

	if len(g.Doors) == 0 {
		return fmt.Errorf("group %q is admitted through no door", g.Name)
	}

	seen := make(map[string]bool, len(g.Doors))

	for _, door := range g.Doors {
		if seen[door] {
			return fmt.Errorf("group %q names door %q twice", g.Name, door)
		}

		seen[door] = true
	}

	return nil
}

// DurationSeconds parses a Go duration that must be positive and returns
// it in whole seconds, the unit OpenBAO's TTL fields take.
func DurationSeconds(duration string) (int, error) {
	return durationSeconds(duration)
}

func durationSeconds(duration string) (int, error) {
	parsed, err := time.ParseDuration(duration)
	if err != nil {
		return 0, fmt.Errorf("ttl %q: %w", duration, err)
	}

	if parsed <= 0 {
		return 0, fmt.Errorf("ttl %q never expires", duration)
	}

	return int(parsed.Seconds()), nil
}
