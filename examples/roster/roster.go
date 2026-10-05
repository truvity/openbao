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

import "github.com/truvity/secrets/pkg/model"

// The names the example uses, which the conformance test asserts against.
const (
	// Operators is the internal group whose members replace the root
	// token.
	Operators = "all:openbao:operator"
	// Environment is the one environment namespace.
	Environment = "dev"

	// SSHUser, SSHAdmin, SSHBackup, DBClient and Reader are people's
	// groups, admitted through both doors; CIRelease is a job's, admitted
	// through the roster door alone.
	SSHUser   = Environment + ":ssh:user"
	SSHAdmin  = Environment + ":ssh:admin"
	SSHBackup = Environment + ":ssh:backup"
	DBClient  = Environment + ":db:client"
	Reader    = Environment + ":openbao:reader"
	CIRelease = "ci-release"

	// SSHMount and PKIMount are the credential engines, at the paths
	// accessctl calls by default; KVMount holds the environment's secrets;
	// SSHHostMount is the host CA, on a mount of its own so its key is
	// never the one SSHMount signs users with.
	SSHMount     = "ssh"
	SSHHostMount = "ssh-host"
	PKIMount     = "pki"
	KVMount      = "kv"
	// SSHUserRole and SSHAdminRole are the SSH roles, DBClientRole the
	// database client credential role: accessctl's defaults for
	// `accessctl bao ssh -mode=ca`, the same with `-role=admin`, and
	// `accessctl pg`/`accessctl psql`. SSHBackupRole forces one command --
	// no interactive session, no forwarding. SSHHostRole signs the one
	// host name a machine may prove it is.
	SSHUserRole   = "user"
	SSHAdminRole  = "admin"
	SSHBackupRole = "backup"
	SSHHostRole   = "host"
	DBClientRole  = "db-client"
	// SSHUserPrincipal and SSHAdminPrincipal are the one OS account each
	// SSH role signs for; SSHBackupCommand is the one command
	// SSHBackupRole's certificates carry as their forced command.
	SSHUserPrincipal   = "example"
	SSHAdminPrincipal  = "example-admin"
	SSHBackupPrincipal = "backup"
	SSHBackupCommand   = "/usr/local/bin/backup-agent run"
	// SSHHostDomain is the one host name SSHHostRole signs -- a machine's
	// own workload login, never a person, asks for it.
	SSHHostDomain = "builds.example"
	// HostAgentDoor, HostAgentRole and HostAgentServiceAccount are the
	// workload login a host uses to sign its own certificate: an existing
	// mechanism (a Kubernetes pod's projected ServiceAccount token on a
	// jwt role bound to that ServiceAccount), not a new auth method. Its
	// policy grants update on exactly ssh-host/sign/host.
	HostAgentDoor           = "jwt-cluster"
	HostAgentRole           = "host-agent"
	HostAgentAudience       = "vault://host-agent"
	HostAgentServiceAccount = "host-agent"
	HostAgentNamespace      = "openbao"
	HostAgentPolicy         = "ssh-host-agent-sign"
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
	// what the values are for, then the repository -- the KV entry itself,
	// one secret whose fields are its variables, each named after one.
	ProjectSecret = Project + "/local-dev/checkout"

	// RootIssuer and EnvironmentIssuer are the credential chain: a root in
	// root's PKIRootMount, and the environment's issuing CA it signs.
	PKIRootMount      = "pki-root"
	RootIssuer        = "example-root"
	EnvironmentIssuer = "example-dev"

	// Partner is the one project NAMESPACE this example gives dev: a
	// different organisation's own mounts, isolated at the namespace level
	// rather than by policy path alone (ADR 0001) -- side by side with
	// Project ("orders" above), which stays a policy path because every
	// one of its groups belongs to the operators' own organisation.
	// PartnerReader reaches Partner's own kv by ProjectPath, from the
	// environment; nobody logs in "at" Partner -- there is no auth mount
	// to log in through.
	Partner       = "partner"
	PartnerReader = Environment + ":" + Partner + ":reader"
	// PartnerIssuer is Partner's own issuing CA, signed by EnvironmentIssuer
	// -- never a self-signed or external one, and never root's issuer
	// directly.
	PartnerIssuer = "example-dev-partner"
	// PartnerLeaf signs one service name inside Partner's own mount, to
	// prove the chain root -> EnvironmentIssuer -> PartnerIssuer -> leaf.
	PartnerLeaf        = "service"
	PartnerServiceName = "svc.partner.example.internal"
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
			// MaxPathLength 2: the environment's own issuing CA below it
			// (1) plus Partner's issuing CA below THAT (another 1) --
			// this model's own signer-depth check counts the whole
			// remaining chain, not just the next hop.
			KeyCurve: model.CurveP384, TTL: "8760h", MaxPathLength: 2, SelfSigned: true,
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
				// MaxPathLength 1: this issuer signs Partner's own issuing
				// CA below it, and nothing signs a further CA below
				// THAT -- a path length of 0 would refuse it, both at
				// Validate (Desired.validateSignerDepth) and, if it ever
				// got that far, at OpenBAO's own sign-intermediate call.
				KeyCurve: model.CurveP384, TTL: "4380h", MaxPathLength: 1,
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
		// Partner is nested one level below Environment: its own kv and
		// its own issuing CA, signed by EnvironmentIssuer above -- never
		// a login, a policy, a group or an SSH mount of its own (ADR
		// 0001; ProjectNamespace has no field to write one in).
		Projects: []model.ProjectNamespace{{
			Name: Partner,
			KV:   []model.KVMount{{Path: KVMount, Description: "the partner's own secrets"}},
			PKI: []model.PKIMount{{
				Path:            PKIMount,
				Description:     "the partner's own issuing CA, signed by the environment's own issuer",
				DefaultLeaseTTL: "1h",
				MaxLeaseTTL:     "24h",
				DefaultIssuer:   PartnerIssuer,
				Issuers: []model.PKIIssuer{{
					Name: PartnerIssuer, CommonName: "Partner Issuing CA", Organization: "Example Org",
					KeyCurve: model.CurveP384, TTL: "720h", MaxPathLength: 0,
					SignedBy: &model.IssuerRef{Namespace: Environment, Mount: PKIMount, Issuer: EnvironmentIssuer},
				}},
				Roles: []model.PKIRole{{
					Name: PartnerLeaf, Issuer: PartnerIssuer,
					AllowedDomains: []string{"partner.example.internal"}, AllowSubdomains: true,
					Server: true, KeyCurve: model.CurveP384, TTL: "1h", MaxTTL: "24h",
				}},
			}},
		}},
		SSH: []model.SSHMount{{
			Path:        SSHMount,
			Description: "the environment's SSH user CA",
			KeyType:     "ed25519",
			Roles: []model.SSHRole{
				sshRole(SSHUserRole, SSHUserPrincipal),
				sshRole(SSHAdminRole, SSHAdminPrincipal),
				sshBackupRole(),
			},
		}},
		// A host CA, never the user CA's key: one line
		// (`@cert-authority <domains> <key>`) lets every client trust
		// every host this role signs for, instead of pinning each host's
		// own key.
		SSHHost: []model.SSHHostMount{{
			Path:        SSHHostMount,
			Description: "the environment's SSH host CA; never the same key as the user CA",
			KeyType:     "ed25519",
			Roles: []model.SSHHostRole{{
				Name: SSHHostRole, AllowedDomains: []string{SSHHostDomain},
				AllowBareDomains: true, AllowSubdomains: false,
				KeyTypes: []string{"ed25519"}, KeyIDFormat: "{{token_display_name}}",
				TTL: "24h", MaxTTL: "168h",
			}},
		}},
		Auth: append(people.Doors(), model.JWTMount{
			// A host proves itself the same way any workload does: a
			// projected ServiceAccount token, on a role bound to that
			// ServiceAccount, whose policy grants nothing but
			// ssh-host/sign/host. No new auth method for this.
			Path:         HostAgentDoor,
			Description:  "the cluster's ServiceAccount tokens; a host signs its own certificate",
			DiscoveryURL: p.Issuer,
			Roles: []model.Role{{
				Name:           HostAgentRole,
				BoundAudiences: []string{HostAgentAudience},
				BoundSubject:   model.ServiceAccountSubject(HostAgentNamespace, HostAgentServiceAccount),
				UserClaim:      "sub",
				Policies:       []string{HostAgentPolicy},
				TTL:            "15m",
			}},
		}),
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
	// Partner is a namespace, not a prefix: the rule below names it and
	// its own mount explicitly (model.ProjectPath), the only way in from
	// the environment (ADR 0001).
	grant(people.Grant(PartnerReader,
		model.Rule{Path: model.ProjectPath(Partner, KVMount, "data/*"), Capabilities: []string{model.CapRead}},
		model.Rule{Path: model.ProjectPath(Partner, KVMount, "metadata/*"), Capabilities: []string{model.CapList, model.CapRead}}))
	grant(people.Grant(SSHAdmin, sign(SSHMount, SSHAdminRole)))
	grant(people.Grant(SSHBackup, signForced(SSHMount, SSHBackupRole)))
	grant(people.Grant(SSHUser, sign(SSHMount, SSHUserRole)))
	// One read of one path, nothing else: no metadata, no list.
	grant(people.JobGrant(CIRelease, model.Rule{Path: KVMount + "/data/" + ReleaseSecret, Capabilities: []string{model.CapRead}}))
	// The host agent's policy is attached to its workload role directly
	// (no group, no door: a workload role carries its own policies), so it
	// is appended beside the people-and-jobs grants above rather than
	// through `grant`, which also writes an identity group this role has
	// no use for.
	namespace.Policies = append(namespace.Policies, model.Policy{
		Name:  HostAgentPolicy,
		Rules: []model.Rule{sign(SSHHostMount, SSHHostRole)},
	})

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

// sshBackupRole signs for the one account that runs the backup command,
// with that command forced: no terminal, no forwarding, so the certificate
// is worth nothing beyond the one thing it is for.
func sshBackupRole() model.SSHRole {
	return model.SSHRole{
		Name: SSHBackupRole, AllowedUsers: []string{SSHBackupPrincipal}, DefaultUser: SSHBackupPrincipal,
		KeyTypes: []string{"ed25519"}, KeyIDFormat: "{{token_display_name}}",
		ForceCommand: SSHBackupCommand, TTL: "15m", MaxTTL: "30m",
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

// signForced is sign, on a force-command role's own path: the grant also
// denies critical_options outright, which is the only way OpenBAO honours
// the role's forced command unconditionally (model.SSHRole.ForceCommand,
// docs/safety.md) -- without it, a caller who supplies any critical_options
// of their own replaces the role's default instead of being denied.
func signForced(mount, role string) model.Rule {
	rule := sign(mount, role)
	rule.DeniedParameters = []string{"critical_options"}

	return rule
}
