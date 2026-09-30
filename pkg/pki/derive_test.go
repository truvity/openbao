package pki

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/openbao/pkg/model"
)

const deriveGolden = "testdata/derive-estate.yaml"

func estateEnvironments() []Environment {
	return []Environment{
		{
			Name:  "dev",
			Zones: map[string]string{"private": "dev.example.private", "origin": "dev.example.net", "identity": "dev.example.private"},
			Catalog: map[string][]string{
				CatalogKey("origin", "origin"): {"*.dev.example.net", "app.dev.example.net"},
			},
		},
		{
			Name:  "prod",
			Zones: map[string]string{"private": "prod.example.private", "origin": "example.net", "identity": "prod.example.private"},
			Catalog: map[string][]string{
				CatalogKey("origin", "origin"): {"app.example.net"},
			},
			// prod's identity CA has not been signed yet.
			PendingCAs: []string{"identity"},
		},
	}
}

// derived is what the golden holds: every authority, and the mounts they
// become.
type derived struct {
	Domains []map[string]any `yaml:"domains"`
	Root    any              `yaml:"rootMounts"`
	Envs    map[string]any   `yaml:"environments"`
}

func TestDeriveEstateGolden(t *testing.T) {
	contract, err := Load("testdata/contract-estate.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	derivation, err := contract.Derive(estateEnvironments())
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	got := derived{Root: derivation.RootMounts(), Envs: map[string]any{}}

	for i := range derivation.Domains {
		got.Domains = append(got.Domains, map[string]any{
			"domain": derivation.Domains[i].Domain, "mount": derivation.Domains[i].Mount,
			"issuer": derivation.Domains[i].Issuer, "artifact": derivation.Domains[i].ArtifactPath,
		})
	}

	for _, environment := range estateEnvironments() {
		mounts, err := derivation.EnvironmentMounts(environment.Name)
		if err != nil {
			t.Fatalf("mounts %s: %v", environment.Name, err)
		}

		artifacts := map[string]string{}

		for i := range derivation.Issuing {
			if derivation.Issuing[i].Environment == environment.Name && derivation.Issuing[i].ArtifactPath != "" {
				artifacts[derivation.Issuing[i].Issuer] = derivation.Issuing[i].ArtifactPath
			}
		}

		got.Envs[environment.Name] = map[string]any{"mounts": mounts, "artifacts": artifacts}
	}

	var out bytes.Buffer

	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)

	if err := encoder.Encode(got); err != nil {
		t.Fatal(err)
	}

	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(deriveGolden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}

		return
	}

	want, err := os.ReadFile(deriveGolden)
	if err != nil {
		t.Fatalf("read golden (UPDATE_GOLDEN=1 writes it): %v", err)
	}

	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("derivation differs from %s; review the change and rerun with UPDATE_GOLDEN=1", deriveGolden)
	}
}

// The names a deployed estate is named after are the derivation's, and they
// are asserted by name here as well as in the golden: a rename is a create
// plus a delete of the same OpenBAO path.
func TestDeriveNamesAreTheAuthoredOnes(t *testing.T) {
	contract, err := Load("testdata/contract-estate.yaml")
	if err != nil {
		t.Fatal(err)
	}

	derivation, err := contract.Derive(estateEnvironments())
	if err != nil {
		t.Fatal(err)
	}

	type key struct{ environment, domain string }

	issuers := map[key]string{}
	mounts := map[key]string{}

	for i := range derivation.Issuing {
		a := &derivation.Issuing[i]
		issuers[key{a.Environment, a.Domain}] = a.Issuer
		mounts[key{a.Environment, a.Domain}] = a.Mount
	}

	for k, want := range map[key]string{
		{"dev", "private"}:  "example-private-2026-09-dev",
		{"prod", "origin"}:  "example-origin-2026-09-prod",
		{"dev", "identity"}: "example-identity-2026-09-dev-root-signed",
	} {
		if issuers[k] != want {
			t.Errorf("%v issuer = %q, want %q", k, issuers[k], want)
		}
	}

	for k, want := range map[key]string{
		{"dev", "private"}:  "pki",
		{"dev", "origin"}:   "pki-origin",
		{"dev", "identity"}: "pki-identity",
	} {
		if mounts[k] != want {
			t.Errorf("%v mount = %q, want %q", k, mounts[k], want)
		}
	}

	if _, ok := issuers[key{"prod", "identity"}]; ok {
		t.Error("prod's identity CA is pending and must derive nothing")
	}

	if len(derivation.Domains) != 2 {
		t.Errorf("domain intermediates = %d, want 2: the identity domain has no shared intermediate", len(derivation.Domains))
	}
}

func TestDeriveRefusesWhatItCannotDeriveWhole(t *testing.T) {
	contract, err := Load("testdata/contract-estate.yaml")
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*Environment){
		"a missing zone":        func(e *Environment) { delete(e.Zones, "private") },
		"an empty catalog role": func(e *Environment) { e.Catalog = nil },
		"a blank zone":          func(e *Environment) { e.Zones["origin"] = " " },
	} {
		environments := estateEnvironments()[:1]
		mutate(&environments[0])

		if _, err := contract.Derive(environments); err == nil {
			t.Errorf("%s: derived", name)
		}
	}
}

func TestEstateContractSpecs(t *testing.T) {
	contract, err := Load("testdata/contract-estate.yaml")
	if err != nil {
		t.Fatal(err)
	}

	const generation = "example-root-2026-09"

	spec, err := contract.EnvironmentCASpec("identity", "dev", "dev.example.private", generation)
	if err != nil {
		t.Fatal(err)
	}

	if spec.TrustDomain != "identity-dev" || spec.SerialNamespace != "example-private-pki" ||
		spec.ArtifactPath != "testdata/pki-roots/example-root-2026-09-identity-dev.yaml" ||
		spec.CommonName != "dev.example.private Workload Identity CA" || spec.MaxPathLen != 0 {
		t.Errorf("environment CA spec = %+v", spec)
	}

	if _, err := contract.URIIntermediateSpec("identity", generation); err == nil ||
		!strings.Contains(err.Error(), "no shared domainIntermediate") {
		t.Errorf("a domain with no shared intermediate has an intermediate spec: %v", err)
	}

	notBefore := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if _, err := contract.EmergencyServerSpec(generation, "openbao.example.private", notBefore); err != nil {
		t.Errorf("a break-glass leaf for a private name: %v", err)
	}
}

func TestApplyMergesIntoAMountTheDesiredStateHolds(t *testing.T) {
	contract, err := Load("testdata/contract-estate.yaml")
	if err != nil {
		t.Fatal(err)
	}

	derivation, err := contract.Derive(estateEnvironments())
	if err != nil {
		t.Fatal(err)
	}

	desired := &model.Desired{
		Root: model.Namespace{PKI: []model.PKIMount{{Path: "pki-example-private", Description: "kept", DefaultIssuer: "retiring",
			Issuers: []model.PKIIssuer{{Name: "retiring"}}}}},
		Namespaces: []model.Namespace{
			{Name: "dev", PKI: []model.PKIMount{{Path: "pki", Description: "kept", DefaultIssuer: "retiring-dev",
				Issuers: []model.PKIIssuer{{Name: "retiring-dev"}}, Roles: []model.PKIRole{{Name: "old"}}}}},
			{Name: "prod"},
		},
	}

	if err := derivation.Apply(desired); err != nil {
		t.Fatal(err)
	}

	root := desired.Root.PKI[0]
	if root.Description != "kept" || root.DefaultIssuer != "retiring" || len(root.Issuers) != 2 || root.Issuers[0].Name != "retiring" {
		t.Errorf("root mount = %+v", root)
	}

	dev := desired.Namespaces[0].PKI
	if len(dev) != 3 || dev[0].DefaultIssuer != "retiring-dev" || len(dev[0].Issuers) != 2 || dev[0].Roles[0].Name != "old" {
		t.Errorf("dev mounts = %+v", dev)
	}

	if len(desired.Namespaces[1].PKI) != 2 {
		t.Errorf("prod mounts = %d, want the private and origin ones (identity is pending)", len(desired.Namespaces[1].PKI))
	}

	orphan := &model.Desired{Root: model.Namespace{}}
	if err := derivation.Apply(orphan); err == nil {
		t.Error("issuing CAs for an environment with no namespace were accepted")
	}
}

// What is derived is a desired state the model accepts as it is: the mounts,
// issuers and roles validate, and every issuer a role names is its mount's.
func TestDerivedMountsValidate(t *testing.T) {
	contract, err := Load("testdata/contract-estate.yaml")
	if err != nil {
		t.Fatal(err)
	}

	derivation, err := contract.Derive(estateEnvironments())
	if err != nil {
		t.Fatal(err)
	}

	for _, mount := range derivation.RootMounts() {
		if err := mount.Validate(); err != nil {
			t.Errorf("root mount %s: %v", mount.Path, err)
		}
	}

	for _, environment := range estateEnvironments() {
		mounts, err := derivation.EnvironmentMounts(environment.Name)
		if err != nil {
			t.Fatal(err)
		}

		for _, mount := range mounts {
			if err := mount.Validate(); err != nil {
				t.Errorf("%s mount %s: %v", environment.Name, mount.Path, err)
			}
		}
	}
}
