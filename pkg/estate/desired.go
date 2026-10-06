package estate

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/truvity/secrets/pkg/builder"
	"github.com/truvity/secrets/pkg/model"
	"github.com/truvity/secrets/pkg/pki"
)

type (
	// Desired is the server's whole configuration, as the estate reviews it.
	// Its YAML is the review of a change to an input; [Desired.Model] is what
	// is applied.
	Desired struct {
		// derivation is the library's derivation of the PKI contract
		// (pki.Contract.Derive): the source of every domain intermediate,
		// issuing CA, role and mount the view below records, and of the
		// model's PKI.
		derivation *pki.Derivation
		// built is the library's derivation of everything but the PKI
		// (builder.Spec.Build), which Model joins to the PKI.
		built *builder.Built
		// identityIssuers maps each environment the identity domain reaches
		// to its root-signed CA's issuer name, and identityRoles is the
		// domain's role names: what LegacyResourceNames renames.
		identityIssuers map[string]string
		identityRoles   []string
		// in is what the state was built from.
		in *Inputs
		// PKI is the root-namespace authority chain. Environment issuers
		// are attached to their Namespace entries.
		PKI PrivatePKI `yaml:"pki"`
		// Root is the operators' door: the bootstrap owns it; it is here so
		// the view shows the whole picture.
		Root Namespace `yaml:"root"`
		// RootOIDC is the web UI's door into root, beside the operators'.
		RootOIDC Namespace `yaml:"rootOidc"`
		// RootWorkloads is what else lives in root: the jobs' logins.
		RootWorkloads Namespace `yaml:"rootWorkloads"`
		// Namespaces are the environments, sorted by name.
		Namespaces []Namespace `yaml:"namespaces"`
	}

	// Namespace is one namespace and everything inside it.
	Namespace struct {
		// Name is empty for root.
		Name string `yaml:"name,omitempty"`
		// KV is the KV v2 mount's path, empty where there is none.
		KV string `yaml:"kv,omitempty"`
		// Canary is the KV path the restore check reads back.
		Canary string `yaml:"canary,omitempty"`
		// LegacyPKI is the legacy environment intermediate and its leaf role.
		LegacyPKI *EnvironmentPKI `yaml:"legacyPki,omitempty"`
		// IssuingCAs are this environment's issuing CAs under the contract's
		// root, one per trust domain, with the contract's leaf roles.
		IssuingCAs []IssuingCA `yaml:"issuingCas,omitempty"`
		// SSH is the SSH user CA and its roles.
		SSH []model.SSHMount `yaml:"ssh,omitempty"`
		// SSHHost is the SSH host CA and its roles: a mount of its own,
		// never sharing a key with SSH.
		SSHHost []model.SSHHostMount `yaml:"sshHost,omitempty"`
		// AWSAuth is the host fleets' AWS IAM auth mounts.
		AWSAuth []model.AWSAuthMount `yaml:"awsAuth,omitempty"`
		// Projects are the project namespaces below this one.
		Projects []model.ProjectNamespace `yaml:"projects,omitempty"`
		Auth     []model.JWTMount         `yaml:"auth"`
		Policies []model.Policy           `yaml:"policies"`
		Groups   []model.Group            `yaml:"groups"`
	}
)

// Build derives the desired state. It is pure: the same inputs give the
// same output, sorted, every time.
func Build(in Inputs) (Desired, error) {
	if strings.TrimSpace(in.Roster.Issuer) == "" {
		return Desired{}, fmt.Errorf("estate: no roster issuer")
	}

	if strings.TrimSpace(in.Management) == "" {
		return Desired{}, fmt.Errorf("estate: no management cluster")
	}

	clusters := slices.Clone(in.Clusters)
	sort.Slice(clusters, func(i, j int) bool { return clusters[i].Name < clusters[j].Name })

	writers, err := writersByName(&in, in.Writers, clusters, "writer")
	if err != nil {
		return Desired{}, err
	}

	if _, err := writersByName(&in, in.Exporters, clusters, "exporter"); err != nil {
		return Desired{}, err
	}

	desired := Desired{in: &in}

	for i := range clusters {
		cluster := &clusters[i]
		if strings.TrimSpace(cluster.Issuer) == "" {
			return Desired{}, fmt.Errorf("estate: cluster %s has no OIDC issuer", cluster.Name)
		}

		desired.Namespaces = append(desired.Namespaces, Namespace{
			Name:   cluster.Name,
			KV:     in.Names.KVMount,
			Canary: in.Names.Canary,
		})
	}

	// The PKI first: its cert-manager logins ride each environment's cluster
	// mount, and the database client role signs with the private issuing
	// CA, which exists only once the chain is declared.
	certManager, err := configurePrivatePKI(&desired, &in, clusters)
	if err != nil {
		return Desired{}, err
	}

	spec, err := buildSpec(&in, clusters, writers, &desired, certManager)
	if err != nil {
		return Desired{}, err
	}

	built, err := spec.Build()
	if err != nil {
		return Desired{}, err
	}

	desired.fill(built)

	return desired, nil
}

// Inputs is what the state was built from.
func (d *Desired) Inputs() *Inputs { return d.in }

// fill records the library's derivation and the estate's view of it. The
// mounts' descriptions are the model's (operator-facing text), not the
// view's, which reviews the wiring.
func (d *Desired) fill(built *builder.Built) {
	d.built = built
	d.Root = view(built.Bootstrap)
	d.RootOIDC = view(built.RootUI)
	d.RootWorkloads = view(built.RootJobs)

	for i := range d.Namespaces {
		namespace := &d.Namespaces[i]
		environment := &built.Environments[i]

		namespace.SSH = withoutSSHDescriptions(environment.SSH)
		namespace.SSHHost = slices.Clone(environment.SSHHost)
		namespace.AWSAuth = slices.Clone(environment.AWSAuth)
		namespace.Projects = slices.Clone(environment.Projects)
		namespace.Auth = withoutAuthDescriptions(environment.Auth)
		namespace.Policies = slices.Clone(environment.Policies)
		namespace.Groups = slices.Clone(environment.Groups)
	}
}

// view is a model namespace's auth, policies and groups as [Namespace]
// holds them.
func view(namespace model.Namespace) Namespace {
	return Namespace{Auth: withoutAuthDescriptions(namespace.Auth), Policies: namespace.Policies, Groups: namespace.Groups}
}

func withoutAuthDescriptions(mounts []model.JWTMount) []model.JWTMount {
	out := slices.Clone(mounts)
	for i := range out {
		out[i].Description = ""
	}

	return out
}

func withoutSSHDescriptions(mounts []model.SSHMount) []model.SSHMount {
	out := slices.Clone(mounts)
	for i := range out {
		out[i].Description = ""
	}

	return out
}

// managementIssuer is the management cluster's OIDC issuer.
func managementIssuer(in *Inputs) string {
	for i := range in.Clusters {
		if in.Clusters[i].Name == in.Management {
			return in.Clusters[i].Issuer
		}
	}

	return ""
}

// mergeScopes is two project→environments maps as one: where a project
// holds a KV prefix, whether it runs there or only keeps secrets.
func mergeScopes(runs, secrets map[string][]string) map[string][]string {
	out := make(map[string][]string, len(runs)+len(secrets))
	for name, environments := range runs {
		out[name] = append(out[name], environments...)
	}

	for name, environments := range secrets {
		out[name] = append(out[name], environments...)
	}

	return out
}

// projectsIn is the projects present in one environment, sorted.
func projectsIn(projects map[string][]string, env string) []string {
	var out []string

	for project, environments := range projects {
		if slices.Contains(environments, env) {
			out = append(out, project)
		}
	}

	sort.Strings(out)

	return out
}

// projectNamespaceTenants is the projects that keep secrets of their own in
// one environment that has project namespaces, sorted; none elsewhere.
func projectNamespaceTenants(in *Inputs, env string) []string {
	if !slices.Contains(in.ProjectNamespaces, env) {
		return nil
	}

	return projectsIn(in.ProjectSecrets, env)
}

// render fills a [Text] template.
func render(template, env, project string) string {
	return strings.NewReplacer("{env}", env, "{project}", project).Replace(template)
}
