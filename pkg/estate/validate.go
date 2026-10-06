package estate

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// storeKinds is a cluster's store kinds, deduplicated and sorted.
//
// A kind is admitted only if the KV layout says where its secrets live
// (Stores.HasLayout): its role and policy both name a KV prefix, so a kind with
// no row would be a grant on a shelf nothing stocks. That one rule also
// keeps out any kind whose secrets stay outside the server.
func storeKinds(in *Inputs, kinds []string) ([]string, error) {
	var out []string

	for _, kind := range kinds {
		if in.Stores.HasLayout == nil || !in.Stores.HasLayout(kind) {
			return nil, fmt.Errorf("estate: store kind %q has no KV layout row, so it reads nothing from OpenBAO", kind)
		}

		if !slices.Contains(out, kind) {
			out = append(out, kind)
		}
	}

	sort.Strings(out)

	return out, nil
}

// writersByName checks writers (or exporters) against the clusters and sorts
// them: valid prefixes, a name used once, every target an environment, and
// the management cluster whose tokens they log in with present.
func writersByName(in *Inputs, writers []Writer, clusters []Cluster, what string) ([]Writer, error) {
	if len(writers) == 0 {
		return nil, nil
	}

	names := map[string]bool{}
	for i := range clusters {
		names[clusters[i].Name] = true
	}

	if !names[in.Management] {
		return nil, fmt.Errorf("estate: no %s cluster for the %ss to log in from", in.Management, what)
	}

	seen := map[string]bool{}

	for _, writer := range writers {
		if err := writer.validate(in.Names.Canary, what); err != nil {
			return nil, err
		}

		if seen[writer.Name] {
			return nil, fmt.Errorf("estate: %s %s is declared twice", what, writer.Name)
		}

		seen[writer.Name] = true

		for env := range writer.Prefixes {
			if !names[env] {
				return nil, fmt.Errorf("estate: %s %s reaches into %s, which is no cluster", what, writer.Name, env)
			}
		}
	}

	out := slices.Clone(writers)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out, nil
}

// Validate holds one writer, or exporter, to its shape (what says which, in
// the refusal): the rule [Build] applies, for an estate that wants it to fail
// where its configuration is loaded and tested instead of where it is built.
func (w Writer) Validate(canary, what string) error { return w.validate(canary, what) }

// validate holds one writer to its shape: a name and a subject, and in every
// environment at least one prefix, each one plain KV path segment that is
// not the restore canary.
func (w *Writer) validate(canary, what string) error {
	if w.Name == "" || w.Subject == "" {
		return fmt.Errorf("estate: %s %+v: name and subject are required", what, *w)
	}

	if len(w.Prefixes) == 0 {
		return fmt.Errorf("estate: %s %s: reaches nowhere", what, w.Name)
	}

	for env, prefixes := range w.Prefixes {
		if len(prefixes) == 0 {
			return fmt.Errorf("estate: %s %s: no prefix in %s", what, w.Name, env)
		}

		for _, prefix := range prefixes {
			if prefix == "" || prefix == canary || strings.ContainsAny(prefix, "/*+.") {
				return fmt.Errorf("estate: %s %s: prefix %q in %s is not one KV product", what, w.Name, prefix, env)
			}
		}
	}

	return nil
}
