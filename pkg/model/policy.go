package model

import (
	"fmt"
	"slices"
	"strings"
)

// Capabilities, spelled as OpenBAO spells them.
const (
	CapCreate = "create"
	CapRead   = "read"
	CapUpdate = "update"
	CapPatch  = "patch"
	CapDelete = "delete"
	CapList   = "list"
	CapSudo   = "sudo"
	CapDeny   = "deny"
)

var capabilities = []string{CapCreate, CapRead, CapUpdate, CapPatch, CapDelete, CapList, CapSudo, CapDeny}

type (
	// Policy is one ACL policy. Its rules are written out in order, so the
	// order is part of the policy's text.
	Policy struct {
		Name  string `yaml:"name"`
		Rules []Rule `yaml:"rules"`
	}

	// Rule is one path stanza. A path is relative to the namespace the
	// policy lives in, except in root, where a namespace's paths are
	// reached as `<namespace>/<path>`.
	Rule struct {
		Path         string   `yaml:"path"`
		Capabilities []string `yaml:"capabilities"`
	}
)

// Validate refuses a policy that grants nothing or names a path twice. The
// second stanza on a path is the one OpenBAO keeps, so a policy that names
// a path twice grants whichever of the two nobody reviewed.
func (p *Policy) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("a policy has no name")
	}

	if len(p.Rules) == 0 {
		return fmt.Errorf("policy %q grants nothing", p.Name)
	}

	seen := make(map[string]bool, len(p.Rules))

	for i := range p.Rules {
		rule := &p.Rules[i]
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("policy %q: %w", p.Name, err)
		}

		if seen[rule.Path] {
			return fmt.Errorf("policy %q names path %q twice", p.Name, rule.Path)
		}

		seen[rule.Path] = true
	}

	return nil
}

// Validate refuses a stanza that grants no capability or one OpenBAO does
// not know, and one whose path climbs out of wherever it is declared.
func (r *Rule) Validate() error {
	if strings.TrimSpace(r.Path) == "" {
		return fmt.Errorf("a rule has no path")
	}

	if strings.Contains(r.Path, "..") {
		return fmt.Errorf("rule path %q traverses upwards", r.Path)
	}

	if strings.ContainsAny(r.Path, "\"\n") {
		return fmt.Errorf("rule path %q contains a quote or a newline", r.Path)
	}

	if len(r.Capabilities) == 0 {
		return fmt.Errorf("rule %q grants no capability", r.Path)
	}

	for _, capability := range r.Capabilities {
		if !slices.Contains(capabilities, capability) {
			return fmt.Errorf("rule %q grants %q, which is no capability", r.Path, capability)
		}
	}

	return nil
}

// HCL renders the policy document OpenBAO stores, stanza by stanza in rule
// order. The text is what a policy diff compares, so it never changes for
// the same rules.
func (p *Policy) HCL() string {
	var b strings.Builder

	for i, rule := range p.Rules {
		if i > 0 {
			b.WriteString("\n")
		}

		quoted := make([]string, 0, len(rule.Capabilities))
		for _, capability := range rule.Capabilities {
			quoted = append(quoted, fmt.Sprintf("%q", capability))
		}

		fmt.Fprintf(&b, "path %q {\n  capabilities = [%s]\n}\n", rule.Path, strings.Join(quoted, ", "))
	}

	return b.String()
}
