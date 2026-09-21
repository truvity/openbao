// Package roster is a neutral, complete example of an OpenBAO server whose
// people and jobs sign in through an access-roster issuer
// (docs/integrations/access-roster.md): the operators' door in root, and
// one environment namespace whose internal groups sign SSH user
// certificates, sign database client certificates and read KV secrets.
//
// One project's secrets are here too, as a team keeps them
// (../../docs/team-secrets.md): its engineers read its prefix, its
// deployers and approvers write it.
//
// It is the state the conformance test (conformance/roster_test.go) applies
// to a real server and signs against, and desired.yaml beside it is its
// golden, so the example a reader copies is the one that is proven.
package roster

import "github.com/truvity/openbao/pkg/model"

// The names the example uses, which the conformance test asserts against.
const (
	// Operators is the internal group whose members replace the root
	// token.
	Operators = "all:openbao:operator"
	// Environment is the one environment namespace.
	Environment = "dev"

	// SSHUser, SSHAdmin, DBClient and Reader are people's groups, admitted
	// through both doors; CIRelease is a job's, admitted through the roster
	// door alone.
	SSHUser   = Environment + ":ssh:user"
	SSHAdmin  = Environment + ":ssh:admin"
	DBClient  = Environment + ":db:client"
	Reader    = Environment + ":openbao:reader"
	CIRelease = "ci-release"

	// SSHMount and PKIMount are the credential engines, at the paths
	// accessctl calls by default; KVMount holds the environment's secrets.
	SSHMount = "ssh"
	PKIMount = "pki"
	KVMount  = "kv"
	// SSHUserRole and SSHAdminRole are the SSH roles, DBClientRole the
	// database client credential role: accessctl's defaults for
	// `credential ssh`, `credential ssh --role admin` and `credential db`.
	SSHUserRole  = "user"
	SSHAdminRole = "admin"
	DBClientRole = "db-client"
	// SSHUserPrincipal and SSHAdminPrincipal are the one OS account each
	// SSH role signs for.
	SSHUserPrincipal  = "example"
	SSHAdminPrincipal = "example-admin"
	// ReleaseSecret is the KV path the CI job reads.
	ReleaseSecret = "ci/release"

	// Project is the one project whose secrets a team shares, and
	// ProjectViewer, ProjectDeployer and ProjectApprover the three groups
	// that reach its prefix: the viewer reads it, the other two write it.
	Project         = "orders"
	ProjectViewer   = Environment + ":" + Project + ":viewer"
	ProjectDeployer = Environment + ":" + Project + ":deployer"
	ProjectApprover = Environment + ":" + Project + ":approver"
	// ProjectSecret is one repository's secret under the project's prefix:
	// what the values are for, the repository, and then the variable.
	ProjectSecret = Project + "/local-dev/checkout/API_TOKEN"

	// RootIssuer and EnvironmentIssuer are the credential chain: a root in
	// root's PKIRootMount, and the environment's issuing CA it signs.
	PKIRootMount      = "pki-root"
	RootIssuer        = "example-root"
	EnvironmentIssuer = "example-dev"
)

// Params are the two particulars of an installation.
type Params struct {
	// Issuer is the access-roster issuer's URL.
	Issuer string
	// Address is OpenBAO's URL as a browser reaches it: the UI's callback
	// lives under it.
	Address string
}

// Desired is the example's whole state.
func Desired(p Params) *model.Desired {
	ui := &model.RosterUI{RedirectURIs: []string{model.UICallback(p.Address, model.RosterUIMount)}}

	// Operators' tokens are short: in root only operators log in, and a
	// root-namespace token reaches everything below it.
	operators := model.Roster{Issuer: p.Issuer, TTL: "15m", UI: ui}
	people := model.Roster{Issuer: p.Issuer, TTL: "1h", UI: ui}

	root := operators.RootUI(Operators)
	root.PKI = []model.PKIMount{{
		Path:            PKIRootMount,
		Description:     "the example root; signs the environment's issuing CA only",
		DefaultLeaseTTL: "8760h",
		MaxLeaseTTL:     "8760h",
		DefaultIssuer:   RootIssuer,
		Issuers: []model.PKIIssuer{{
			Name: RootIssuer, CommonName: "Example Root CA", Organization: "Example Org",
			KeyCurve: model.CurveP384, TTL: "8760h", MaxPathLength: 1, SelfSigned: true,
		}},
	}}

	namespace := model.Namespace{
		Name: Environment,
		KV:   []model.KVMount{{Path: KVMount, Description: "the environment's secrets"}},
		PKI: []model.PKIMount{{
			Path:            PKIMount,
			Description:     "the environment's credential certificates",
			DefaultLeaseTTL: "1h",
			MaxLeaseTTL:     "720h",
			DefaultIssuer:   EnvironmentIssuer,
			Issuers: []model.PKIIssuer{{
				Name: EnvironmentIssuer, CommonName: "Example Dev Issuing CA", Organization: "Example Org",
				KeyCurve: model.CurveP384, TTL: "4380h", MaxPathLength: 0,
				SignedBy: &model.IssuerRef{Mount: PKIRootMount, Issuer: RootIssuer},
			}},
			// The caller's own subject, as its roster login recorded it, and
			// nobody else's: accessctl sends a CSR for an ECDSA P-384 key.
			CredentialRoles: []model.CredentialRole{{
				Name: DBClientRole, Issuer: EnvironmentIssuer, SubjectMount: model.RosterMount,
				CNValidations: []string{model.CNValidationEmail}, Client: true,
				KeyCurve: model.CurveP384, TTL: "1h", MaxTTL: "1h",
			}},
		}},
		SSH: []model.SSHMount{{
			Path:        SSHMount,
			Description: "the environment's SSH user CA",
			KeyType:     "ed25519",
			Roles:       []model.SSHRole{sshRole(SSHUserRole, SSHUserPrincipal), sshRole(SSHAdminRole, SSHAdminPrincipal)},
		}},
		Auth: people.Doors(),
	}

	grant := func(policy model.Policy, group model.Group) {
		namespace.Policies = append(namespace.Policies, policy)
		namespace.Groups = append(namespace.Groups, group)
	}

	grant(people.Grant(DBClient, sign(PKIMount, DBClientRole)))
	grant(people.Grant(Reader,
		model.Rule{Path: KVMount + "/data/*", Capabilities: []string{model.CapRead}},
		model.Rule{Path: KVMount + "/metadata/*", Capabilities: []string{model.CapList, model.CapRead}}))
	// The project's three groups, on one prefix: a repository is a path
	// segment inside it, so onboarding one grants nothing new.
	grant(people.Grant(ProjectApprover, writeProject(Project)...))
	grant(people.Grant(ProjectDeployer, writeProject(Project)...))
	grant(people.Grant(ProjectViewer, readProject(Project)...))
	grant(people.Grant(SSHAdmin, sign(SSHMount, SSHAdminRole)))
	grant(people.Grant(SSHUser, sign(SSHMount, SSHUserRole)))
	// One read of one path, nothing else: no metadata, no list.
	grant(people.JobGrant(CIRelease, model.Rule{Path: KVMount + "/data/" + ReleaseSecret, Capabilities: []string{model.CapRead}}))

	return &model.Desired{
		Bootstrap:        operators.Bootstrap(Operators),
		Root:             root,
		Namespaces:       []model.Namespace{namespace},
		Identity:         people.Identity(map[string]string{"source": "example issuer"}),
		CredentialMaxTTL: "1h",
	}
}

// sshRole signs for one account, ed25519 keys, a terminal and nothing else,
// with the login's display name -- the roster subject -- as the key id.
func sshRole(name, principal string) model.SSHRole {
	return model.SSHRole{
		Name: name, AllowedUsers: []string{principal}, DefaultUser: principal,
		KeyTypes: []string{"ed25519"}, KeyIDFormat: "{{token_display_name}}",
		Extensions: []string{"permit-pty"}, TTL: "30m", MaxTTL: "1h",
	}
}

// readProject is a project's prefix, read: the values, and the metadata
// that lets a person list the names -- `read` on the data path alone tells
// nobody what is there to read. The `data/` and `metadata/` segments are
// KV v2's API paths, not the ones `bao kv` prints: a policy written on
// `kv/<project>/*` grants nothing at all.
func readProject(project string) []model.Rule {
	return []model.Rule{
		{Path: KVMount + "/data/" + project + "/*", Capabilities: []string{model.CapRead}},
		{Path: KVMount + "/metadata/" + project + "/*", Capabilities: []string{model.CapList, model.CapRead}},
	}
}

// writeProject is the same prefix, written: a new secret needs `create`
// and a new version of one `update`. Neither `delete` nor the metadata's
// destroy is here -- retiring a value is rarer than writing one, and a
// destroyed version does not come back.
func writeProject(project string) []model.Rule {
	return []model.Rule{
		{Path: KVMount + "/data/" + project + "/*", Capabilities: []string{model.CapCreate, model.CapRead, model.CapUpdate}},
		{Path: KVMount + "/metadata/" + project + "/*", Capabilities: []string{model.CapList, model.CapRead}},
	}
}

// sign is `update` on one sign path: all a credential group may do.
func sign(mount, role string) model.Rule {
	return model.Rule{Path: mount + "/sign/" + role, Capabilities: []string{model.CapUpdate}}
}
