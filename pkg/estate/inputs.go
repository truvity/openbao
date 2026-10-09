package estate

import (
	"github.com/truvity/secrets/pkg/builder"
	"github.com/truvity/secrets/pkg/model"
	"github.com/truvity/secrets/pkg/pki"
)

type (
	// Inputs is everything the desired state depends on. [Build] is a pure
	// function of it.
	Inputs struct {
		// Management is the cluster the server runs on. Its workloads are the
		// ones that log in to other environments (Writers, Exporters,
		// Service, CrossReads), and its jobs are the ones that act in root.
		Management string `yaml:"management"`
		// Names, Text and Groups are the estate's conventions: every name
		// and description the derivation writes.
		Names  Names  `yaml:"names"`
		Text   Text   `yaml:"text"`
		Groups Groups `yaml:"-"`
		// Roster is the identity provider as every namespace trusts it: the
		// people's doors (pkg/model's roster preset), with what `sys/auth`
		// shows beside each.
		Roster model.Roster `yaml:"roster"`
		// Clusters are the environments, one namespace per cluster.
		Clusters []Cluster `yaml:"clusters"`
		// Projects maps a project to the environments it runs on: there it
		// gets a KV prefix and its database admins the database client role.
		Projects map[string][]string `yaml:"projects,omitempty"`
		// ProjectSecrets maps a project to the environments where it keeps
		// secrets and runs nothing: a KV prefix, no database role.
		ProjectSecrets map[string][]string `yaml:"projectSecrets,omitempty"`
		// ProjectViewers maps a project to the environments where it asked
		// for a viewer. Whether that viewer reads anything is Groups.Holds'
		// answer, not this list's.
		ProjectViewers map[string][]string `yaml:"projectViewers,omitempty"`
		// ProjectNamespaces are the environments in which a project with
		// secrets of its own (ProjectSecrets) gets a namespace of its own,
		// below the environment's: migration proceeds per environment, and
		// one not listed renders as it did before.
		ProjectNamespaces []string `yaml:"projectNamespaces,omitempty"`
		// Writers are the management cluster's workloads that push whole KV
		// prefixes into environment namespaces at run time.
		Writers []Writer `yaml:"writers,omitempty"`
		// Exporters log in the way writers do and are admitted to the data
		// of their prefixes alone: read, create, update and patch.
		Exporters []Writer `yaml:"exporters,omitempty"`
		// Service is one management-cluster service that owns a KV root:
		// what it writes, the inputs the store reads for it, and what it
		// exports for others to read. The zero value declares none.
		Service Service `yaml:"service,omitempty"`
		// CrossReads are the management cluster's store reading one key in
		// another environment's namespace.
		CrossReads []CrossRead `yaml:"crossReads,omitempty"`
		// CISecrets are CI jobs' read-only grants on one KV path each, in the
		// management cluster's namespace.
		CISecrets []builder.SecretGrant `yaml:"ciSecrets,omitempty"`
		// Stores says what a cluster's secret store kinds read.
		Stores Stores `yaml:"stores"`
		// PKI is the private PKI: the authored contract and the legacy chain
		// served beside it.
		PKI PKI `yaml:"pki"`
		// HostFleets are fleets of hosts with no Kubernetes identity (EC2
		// instances behind one IAM role) that sign their own SSH host
		// certificates.
		HostFleets []HostFleet `yaml:"hostFleets,omitempty"`
	}

	// Cluster is one environment's inputs.
	Cluster struct {
		Name string `yaml:"name"`
		// Issuer is the cluster's OIDC issuer: its ServiceAccount tokens are
		// verified against the key set it publishes.
		Issuer string `yaml:"issuer"`
		// Stores are the secret store kinds the cluster runs ([StoreKinds]):
		// one role each on the cluster's mount.
		Stores []string `yaml:"stores,omitempty"`
		// Runners are the CI runner logins the cluster hosts: each signs on
		// the CI SSH role (Names.SSH.CIRole), which only a cluster with
		// Workers has.
		Runners []Runner `yaml:"runners,omitempty"`
		// Workers reports whether the cluster runs the host-signing workers
		// (Names.Workers): the SSH host CA, its role, the CI SSH role and the
		// workers' own login exist only where this is true.
		Workers bool `yaml:"workers,omitempty"`
		// PrivateZone and OriginZone are the environment's two DNS zones,
		// which the PKI contract substitutes for {zone}.
		PrivateZone string `yaml:"privateZone"`
		OriginZone  string `yaml:"originZone"`
		// OriginNames are every name the origin role may sign on this
		// cluster: the edge's hosts, the only bound on that role.
		OriginNames []string `yaml:"originNames,omitempty"`
	}

	// Runner is one CI runner login: a role pinned to the runner's
	// ServiceAccount.
	Runner struct {
		Role    string `yaml:"role"`
		Subject string `yaml:"subject"`
	}

	// Writer is a management-cluster workload that logs in to environment
	// namespaces on the writers' mount (Names.WriterMount) and reaches KV
	// prefixes there, by environment.
	Writer struct {
		Name     string              `yaml:"name"`
		Subject  string              `yaml:"subject"`
		Prefixes map[string][]string `yaml:"prefixes"`
	}

	// Service is one management-cluster service that owns a KV root.
	Service struct {
		// Role is its login's name; Subject its ServiceAccount.
		Role    string `yaml:"role,omitempty"`
		Subject string `yaml:"subject,omitempty"`
		// Root is the KV prefix it owns: never a CI job's to read.
		Root string `yaml:"root,omitempty"`
		// Writes are the prefixes it keeps and exports, by environment: the
		// data's read, create, update and patch, the metadata's list and
		// delete.
		Writes map[string][]string `yaml:"writes,omitempty"`
		// ConfigRole reads the data of ConfigPrefix, the service's inputs, in
		// the environments ConfigIn names.
		ConfigRole   string   `yaml:"configRole,omitempty"`
		ConfigPrefix string   `yaml:"configPrefix,omitempty"`
		ConfigIn     []string `yaml:"configIn,omitempty"`
		// ClientsRole reads the data of ClientsKind/<id> for each of Clients,
		// in the management namespace: the client secrets the service copies.
		ClientsRole string   `yaml:"clientsRole,omitempty"`
		ClientsKind string   `yaml:"clientsKind,omitempty"`
		Clients     []string `yaml:"clients,omitempty"`
		// Exports are the read-only logins over what the service exports,
		// one per consumer.
		Exports []Export `yaml:"exports,omitempty"`
	}

	// Export is one consumer's store login over the data of one prefix the
	// service exports, in the environments it names.
	Export struct {
		Role         string   `yaml:"role"`
		Prefix       string   `yaml:"prefix"`
		Environments []string `yaml:"environments"`
	}

	// CrossRead is the management cluster's store reading one KV key in
	// other environments' namespaces, on the writers' mount.
	CrossRead struct {
		// Role names both the role and its policy.
		Role         string   `yaml:"role"`
		Key          string   `yaml:"key"`
		Environments []string `yaml:"environments"`
	}

	// Stores says what each store kind reads: the whole of its KV prefix,
	// unless Access narrows it.
	Stores struct {
		// HasLayout reports whether the KV layout has a prefix for a kind. A
		// cluster's kind that has none is refused: its role would be a grant
		// on a shelf nothing stocks.
		HasLayout func(kind string) bool `yaml:"-"`
		// Access replaces a kind's read of its whole prefix.
		Access map[string]builder.Access `yaml:"access,omitempty"`
		// PolicyPrefix names the policy behind each kind's role.
		PolicyPrefix string `yaml:"policyPrefix"`
	}

	// HostFleet is one fleet of hosts that sign their own SSH host
	// certificates: an AWS IAM auth login bound to its instance role and a
	// host role allowing one domain.
	HostFleet struct {
		Environment string `yaml:"environment"`
		// Name tells the fleet from the others in its environment.
		Name string `yaml:"name"`
		// Domain is the one domain its host role allows.
		Domain string `yaml:"domain"`
		// Bare also admits the domain itself, and Subdomains (default true)
		// the names below it. Unset, the role allows the subdomains only;
		// `bare: true` with `subdomains: false` allows exactly one name.
		Bare            bool   `yaml:"bare,omitempty"`
		Subdomains      *bool  `yaml:"subdomains,omitempty"`
		InstanceRoleARN string `yaml:"instanceRoleArn"`
		// AuthRole, SigningRole and Policy are the fleet's own login role,
		// host role and the policy joining them.
		AuthRole    string `yaml:"authRole"`
		SigningRole string `yaml:"signingRole"`
		Policy      string `yaml:"policy"`
		// ServerID is the server-id header the environment's AWS auth mount
		// requires.
		ServerID string `yaml:"serverId"`
		// HostnamePatterns scope clients' trust of the host CA. Nothing in
		// the model reads them; they are carried for the clients' render.
		HostnamePatterns []string `yaml:"hostnamePatterns,omitempty"`
	}

	// Names are the estate's names for what the derivation writes.
	Names struct {
		// KVMount is every environment's KV v2 mount; Canary the path in it
		// the restore check reads back.
		KVMount string `yaml:"kvMount"`
		Canary  string `yaml:"canary"`
		// OperatorKV is root's operators-only KV mount.
		OperatorKV string `yaml:"operatorKv"`
		// Operators is the operators' group (the bootstrap's).
		Operators string `yaml:"operators"`
		// ClusterMountPrefix prefixes a cluster's name to make its JWT
		// mount; WriterMount is the management cluster's mount in another
		// namespace, RootMount its mount in root.
		ClusterMountPrefix string `yaml:"clusterMountPrefix"`
		WriterMount        string `yaml:"writerMount"`
		RootMount          string `yaml:"rootMount"`
		// StoreSubject is the store controller's ServiceAccount subject, the
		// same on every cluster.
		StoreSubject string `yaml:"storeSubject"`
		// TokenTTL is a job's, a runner's and a cert-manager login's token
		// life; NamespaceTokenTTL a store's, a writer's and a person's.
		TokenTTL          string `yaml:"tokenTtl"`
		NamespaceTokenTTL string `yaml:"namespaceTokenTtl"`
		// CredentialMaxTTL caps every credential role.
		CredentialMaxTTL string `yaml:"credentialMaxTtl"`
		// Metadata is what every identity group carries.
		Metadata map[string]string `yaml:"metadata,omitempty"`
		Jobs     Jobs              `yaml:"jobs"`
		SSH      SSHNames          `yaml:"ssh"`
		Workers  Workers           `yaml:"workers"`
		HostAuth HostAuthNames     `yaml:"hostAuth"`
	}

	// Jobs are the root namespace's jobs, on the management cluster's root
	// mount.
	Jobs struct {
		RestoreCheck   Job `yaml:"restoreCheck"`
		Snapshot       Job `yaml:"snapshot"`
		RootGeneration Job `yaml:"rootGeneration"`
		PluginCatalog  Job `yaml:"pluginCatalog"`
		// PluginType and PluginName are the one catalog entry the
		// plugin-catalog watch reads.
		PluginType string `yaml:"pluginType"`
		PluginName string `yaml:"pluginName"`
	}

	// Job is one job's login: its role, its ServiceAccount, its policy.
	Job struct {
		Role    string `yaml:"role"`
		Subject string `yaml:"subject"`
		Policy  string `yaml:"policy"`
	}

	// SSHNames are the SSH engines' names and shape.
	SSHNames struct {
		Shape builder.SSHShape `yaml:"shape"`
		// Mount is the user CA's mount and CAKeyType its key; HostMount and
		// HostKeyType the host CA's.
		Mount       string `yaml:"mount"`
		CAKeyType   string `yaml:"caKeyType"`
		HostMount   string `yaml:"hostMount"`
		HostKeyType string `yaml:"hostKeyType"`
		// UserRole and UserPrincipal are the placeholder role that keeps the
		// user CA alive where no CI role does.
		UserRole      string `yaml:"userRole"`
		UserPrincipal string `yaml:"userPrincipal"`
		// CIRole, CIPrincipal and CIForceCommand are the runners' role.
		CIRole         string `yaml:"ciRole"`
		CIPrincipal    string `yaml:"ciPrincipal"`
		CIForceCommand string `yaml:"ciForceCommand"`
	}

	// Workers are the host-signing workers' names: their own login, the
	// policy it carries and the host role it signs with.
	Workers struct {
		LoginRole string   `yaml:"loginRole"`
		Subject   string   `yaml:"subject"`
		TTL       string   `yaml:"ttl"`
		Policy    string   `yaml:"policy"`
		HostRole  string   `yaml:"hostRole"`
		Domains   []string `yaml:"domains"`
	}

	// HostAuthNames are the host fleets' AWS IAM auth mount.
	HostAuthNames struct {
		Mount         string `yaml:"mount"`
		PluginVersion string `yaml:"pluginVersion"`
		TTL           string `yaml:"ttl"`
	}

	// Text is the descriptions the derivation writes, as templates: {env}
	// is the environment and {project} the project.
	Text struct {
		OperatorKV    string `yaml:"operatorKv"`
		EnvironmentKV string `yaml:"environmentKv"`
		ProjectKV     string `yaml:"projectKv"`
		SSHUser       string `yaml:"sshUser"`
		// SSHHostWorkers describes the host CA where the workers run,
		// SSHHostFleets where only host fleets sign on it.
		SSHHostWorkers string `yaml:"sshHostWorkers"`
		SSHHostFleets  string `yaml:"sshHostFleets"`
		HostAuth       string `yaml:"hostAuth"`
		// LegacyRoot, LegacyParent and LegacyEnvironment describe the
		// legacy chain's mounts.
		LegacyRoot        string `yaml:"legacyRoot"`
		LegacyParent      string `yaml:"legacyParent"`
		LegacyEnvironment string `yaml:"legacyEnvironment"`
		// IdentityBootstrap describes an environment identity CA's mount
		// before the CA is signed.
		IdentityBootstrap string `yaml:"identityBootstrap"`
	}

	// Groups is how the estate names the groups people and jobs hold, and
	// which of them hold an OpenBAO policy at all.
	Groups struct {
		// Name is a group's name from its environment, thing and role.
		Name func(env, thing, role string) string
		// Holds reports whether a group holds a policy here. A project
		// group the derivation would grant is skipped where it does not:
		// the same predicate decides who may exchange for the group.
		Holds func(group string) bool
		// OpenBAO and Writer are the thing and role of the environment's
		// writer group.
		OpenBAO string
		Writer  string
		// SSH, SSHUser, Database and DatabaseClient are the credential
		// groups' things and roles.
		SSH            string
		SSHUser        string
		Database       string
		DatabaseClient string
		// Deployer and Approver write a project's secrets, Viewer reads
		// them, and DBA signs database client certificates.
		Deployer string
		Approver string
		Viewer   string
		DBA      string
		// DBLevels are the roles of a project's database groups
		// ({env}:{project}:{level}), each signing with its own credential
		// role (PKI.DBProjectRole). Empty = none.
		DBLevels []string
	}

	// PKI is the private PKI's inputs.
	PKI struct {
		// Contract is the authored contract (pkg/pki).
		Contract *pki.Contract `yaml:"-"`
		// Private, Origin and Identity name the contract's trust domains.
		Private  string `yaml:"private"`
		Origin   string `yaml:"origin"`
		Identity string `yaml:"identity"`
		// OriginRole is the origin domain's role Cluster.OriginNames feed.
		OriginRole string `yaml:"originRole"`
		// Signed reports, by environment, whether its root-signed identity
		// CA is committed yet. Until it is, the environment renders nothing
		// of the identity domain.
		Signed map[string]bool `yaml:"signed,omitempty"`
		// ClusterIssuers names the cert-manager issuer of each trust domain:
		// the login role, and with PolicyPrefix and AudiencePrefix its
		// policy and audience.
		ClusterIssuers map[string]string `yaml:"clusterIssuers"`
		PolicyPrefix   string            `yaml:"policyPrefix"`
		AudiencePrefix string            `yaml:"audiencePrefix"`
		// Subject is cert-manager's ServiceAccount subject.
		Subject string `yaml:"subject"`
		// DBClientRole is the private domain's credential role database
		// clients sign with; RestoreRole the role the restore check issues
		// from.
		DBClientRole string `yaml:"dbClientRole"`
		// DBProjectRole is the prefix of the per-project, per-level
		// credential roles: {DBProjectRole}-{project}-{level}. Empty = none.
		DBProjectRole string `yaml:"dbProjectRole,omitempty"`
		RestoreRole   string `yaml:"restoreRole"`
		// Legacy is the self-signed chain still served beside the contract's.
		Legacy Legacy `yaml:"legacy"`
		// LegacyRoleIssuers maps an environment to the issuer whose name its
		// identity roles' Pulumi resources still carry, where a role moved
		// onto a new issuer as the same object.
		LegacyRoleIssuers map[string]string `yaml:"legacyRoleIssuers,omitempty"`
		// BootstrapSuffix ends the name of an environment identity CA's
		// bootstrap request: <identity mount>-<env><suffix>-csr.
		BootstrapSuffix string `yaml:"bootstrapSuffix"`
	}

	// Legacy is the self-signed chain: a root, an intermediate, and one
	// environment intermediate with one leaf role in every environment.
	Legacy struct {
		// Organization is what its certificates carry.
		Organization string       `yaml:"organization"`
		Root         PKIAuthority `yaml:"root"`
		Parent       PKIAuthority `yaml:"parent"`
		// Domain is the private DNS domain: an environment's intermediate is
		// constrained to <env>.<Domain>.
		Domain string `yaml:"domain"`
		// Mount and TTL are each environment intermediate's.
		Mount string `yaml:"mount"`
		TTL   string `yaml:"ttl"`
		// LeafRole is its one leaf role, LeafPolicy and LeafAudience
		// cert-manager's login to it.
		LeafRole     string `yaml:"leafRole"`
		LeafPolicy   string `yaml:"leafPolicy"`
		LeafAudience string `yaml:"leafAudience"`
		LeafTTL      string `yaml:"leafTtl"`
		LeafMaxTTL   string `yaml:"leafMaxTtl"`
	}
)
