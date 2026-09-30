package pki

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/truvity/openbao/pkg/ceremony"
)

// estateFixture is testdata/contract-estate.yaml copied under a temp
// directory, so a ceremony can write its artifacts beside it.
func estateFixture(t *testing.T) (dir string) {
	t.Helper()

	raw, err := os.ReadFile("testdata/contract-estate.yaml")
	if err != nil {
		t.Fatal(err)
	}

	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(dir, "pki-roots"), 0o755); err != nil {
		t.Fatal(err)
	}

	return dir
}

// A domain with no shared intermediate: the root signs each environment's own
// CA, under the estate's own file and issuer names, and a contract read
// through a file system (an embedded configuration tree) proves the same
// artifacts the disk does.
func TestEstateRoundTripThroughDiskAndFS(t *testing.T) {
	dir := estateFixture(t)

	disk, err := Load(filepath.Join(dir, "contract.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	client := newFakeKMS(t)

	rootSpec, err := disk.RootSpec("example-root-2026-09")
	if err != nil {
		t.Fatal(err)
	}

	root := createRootFor(t, client, disk, rootSpec)

	spec, err := disk.EnvironmentCASpec("identity", "dev", "dev.example.private", "example-root-2026-09")
	if err != nil {
		t.Fatal(err)
	}

	if filepath.Base(spec.ArtifactPath) != "example-root-2026-09-identity-dev.yaml" {
		t.Fatalf("artifact = %s", spec.ArtifactPath)
	}

	if signed, err := disk.IntermediateSigned(spec); err != nil || signed {
		t.Fatalf("IntermediateSigned before the ceremony = %v, %v", signed, err)
	}

	if signed, err := disk.EnvironmentCASigned("identity", "dev"); err != nil || signed {
		t.Fatalf("EnvironmentCASigned before the ceremony = %v, %v", signed, err)
	}

	signTestIntermediate(t, client, spec, root)

	if signed, err := disk.IntermediateSigned(spec); err != nil || !signed {
		t.Fatalf("IntermediateSigned after the ceremony = %v, %v", signed, err)
	}

	if signed, err := disk.EnvironmentCASigned("identity", "dev"); err != nil || !signed {
		t.Fatalf("EnvironmentCASigned after the ceremony = %v, %v", signed, err)
	}

	// The same tree, read as if embedded in a repository's cfg/ directory.
	fsContract, err := LoadFS(os.DirFS(dir), "contract.yaml", "cfg")
	if err != nil {
		t.Fatal(err)
	}

	fsSpec, err := fsContract.EnvironmentCASpec("identity", "dev", "dev.example.private", "example-root-2026-09")
	if err != nil {
		t.Fatal(err)
	}

	if want := "cfg/pki-roots/example-root-2026-09-identity-dev.yaml"; fsSpec.ArtifactPath != want {
		t.Fatalf("artifact path = %q, want %q: command-line paths stay relative to the repository", fsSpec.ArtifactPath, want)
	}

	if signed, err := fsContract.IntermediateSigned(fsSpec); err != nil || !signed {
		t.Fatalf("IntermediateSigned through the file system = %v, %v", signed, err)
	}

	proved, err := fsContract.LoadSignedIntermediate(fsSpec)
	if err != nil {
		t.Fatalf("LoadSignedIntermediate through the file system: %v", err)
	}

	if proved.Certificate.Subject.CommonName != "dev.example.private Workload Identity CA" {
		t.Fatalf("common name = %q", proved.Certificate.Subject.CommonName)
	}

	anchors, err := fsContract.TrustAnchors()
	if err != nil || len(anchors) != 1 {
		t.Fatalf("TrustAnchors through the file system = %v, %v", anchors, err)
	}

	prod, err := fsContract.EnvironmentCASpec("identity", "prod", "prod.example.private", "example-root-2026-09")
	if err != nil {
		t.Fatal(err)
	}

	if signed, err := fsContract.IntermediateSigned(prod); err != nil || signed {
		t.Fatalf("prod's CA reads as signed = %v, %v", signed, err)
	}

	empty, err := LoadFS(fstest.MapFS{"contract.yaml": &fstest.MapFile{Data: mustRead(t, filepath.Join(dir, "contract.yaml"))}}, "contract.yaml", "cfg")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := empty.TrustAnchors(); err == nil {
		t.Fatal("a trusted generation with no committed artifact was accepted through the file system")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func TestEstateRefusals(t *testing.T) {
	base := func() *Contract {
		contract, err := Load("testdata/contract-estate.yaml")
		if err != nil {
			t.Fatal(err)
		}

		return contract
	}

	edit := func(f func(*Contract)) *Contract {
		contract := base()
		f(contract)

		return contract
	}

	tests := []struct {
		name string
		c    *Contract
		want string
	}{
		{"neither intermediate nor environment CA", edit(func(c *Contract) { c.uri().EnvironmentCA = nil }), "declares neither domainIntermediate nor environmentCA"},
		{"a half-authored intermediate", edit(func(c *Contract) { c.uri().DomainIntermediate.Name = "half" }), "lifetimes.domainIntermediate"},
		{"domainIntermediate lifetime without an intermediate", edit(func(c *Contract) {
			c.uri().Lifetimes.DomainIntermediate = "87600h"
		}), "has no domainIntermediate"},
		{"a partial root-signed list without an intermediate", edit(func(c *Contract) {
			c.uri().RootSignedEnvironments = []string{"dev"}
		}), "must name every environment"},
		{"environment CA at the root budget", edit(func(c *Contract) { c.uri().EnvironmentCA.MaxPathLen = 3 }), "strictly less than the root's own maxPathLen"},
		{"an issuer name pattern without the environment", edit(func(c *Contract) {
			c.uri().EnvironmentCA.IssuerNamePattern = "example-identity"
		}), "issuerNamePattern must contain"},
		{"an environment CA issuer named like another authority", edit(func(c *Contract) {
			c.dns().DomainIntermediate.Name = "example-identity-2026-09-dev-root-signed"
		}), "is used by both"},
		{"a mount path with a slash", edit(func(c *Contract) { c.dns().Placement.IssuingMount = "a/b" }), "lowercase mount path"},
		{"an unknown description placeholder", edit(func(c *Contract) { c.dns().Placement.DomainMountDescription = "{nope}" }), "placeholder other than"},
		{"the environment in the domain mount's description", edit(func(c *Contract) {
			c.dns().Placement.DomainMountDescription = "{environment}"
		}), "not per environment"},
		{"a credential role with no subject mount", edit(func(c *Contract) { c.dns().CredentialRoles[0].SubjectMount = "" }), "subjectMount is required"},
		{"a credential role that renews", edit(func(c *Contract) { c.dns().CredentialRoles[0].Lifetimes.RenewBefore = "10m" }), "never renewed"},
		{"a credential role named like a leaf role", edit(func(c *Contract) { c.dns().CredentialRoles[0].Name = "private" }), "duplicates role name"},
		{"a credential role that outlives the domain's leaves", edit(func(c *Contract) {
			c.dns().CredentialRoles[0].Lifetimes = LeafLifetimes{Default: "1h", Maximum: "9000h"}
		}), "must satisfy maximum"},
		{"an unknown common-name validation", edit(func(c *Contract) { c.dns().CredentialRoles[0].CNValidations = []string{"phone"} }), "cnValidations"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { wantErr(t, test.c.Validate(), test.want) })
	}
}

func createRootFor(t *testing.T, client *fakeKMS, contract *Contract, spec ceremony.RootSpec) ceremony.RootArtifact {
	t.Helper()

	result, err := ceremony.CreateRoot(context.Background(), client, spec, ceremony.RootOptions{
		KeyARN:       fixtureKeyARN,
		ArtifactPath: contract.RootArtifactPath(spec.GenerationID),
	})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	return result.Artifact
}

func (c *Contract) uri() *URITrustDomain { return &c.TrustDomains.URI[0] }
func (c *Contract) dns() *DNSTrustDomain { return &c.TrustDomains.DNS[0] }
