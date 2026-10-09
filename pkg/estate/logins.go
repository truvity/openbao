package estate

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/truvity/secrets/pkg/builder"
	"github.com/truvity/secrets/pkg/model"
)

// Which inputs make which entry of the library's contracts (pkg/builder).
// What a login, a grant or an SSH role IS -- the role, the policy, the rules,
// the checks that refuse a bad one -- is pkg/builder's; this file decides
// which ones an estate's inputs declare.

// buildSpec is the whole non-PKI desired state as the library's contract.
func buildSpec(in *Inputs, clusters []Cluster, writers []Writer, desired *Desired, certManager map[string][]builder.Workload) (*builder.Spec, error) {
	jobs, err := rootJobs(in, clusters, desired)
	if err != nil {
		return nil, err
	}

	spec := &builder.Spec{
		Roster:           in.Roster,
		Operators:        in.Names.Operators,
		OperatorsTTL:     in.Names.TokenTTL,
		Metadata:         in.Names.Metadata,
		CredentialMaxTTL: in.Names.CredentialMaxTTL,
		Root: builder.Root{
			Jobs: jobs,
			// The operators-only mount: no writer, no canary, no policy
			// naming a path inside it beyond the bootstrap's own `*`.
			KV: []model.KVMount{{Path: in.Names.OperatorKV, Description: in.Text.OperatorKV}},
		},
	}

	for i := range clusters {
		cluster := &clusters[i]

		environment, err := environmentSpec(in, cluster, writers, desired, certManager[cluster.Name])
		if err != nil {
			return nil, err
		}

		spec.Environments = append(spec.Environments, environment)
	}

	return spec, nil
}

// clusterTrust is a cluster's own workload mount, whose only decision is
// which issuer it trusts. Every such mount reads the same, in every namespace
// and in root: who those tokens are and what they may do is the roles'
// business.
func clusterTrust(in *Inputs, mount, issuer string) builder.Trust {
	return builder.Trust{
		Mount:       mount,
		Description: "tokens minted by cluster " + strings.TrimPrefix(mount, in.Names.ClusterMountPrefix),
		Issuer:      issuer,
	}
}

// environmentSpec is one environment's namespace as the library's contract:
// its KV, the cluster's workload mount with one role per store, the
// management cluster's workloads that reach into it, and the groups that
// reach it.
func environmentSpec(in *Inputs, cluster *Cluster, writers []Writer, desired *Desired, certManager []builder.Workload) (builder.Environment, error) {
	env := cluster.Name

	environment := builder.Environment{
		Name: env,
		KV: model.KVMount{
			Path:        in.Names.KVMount,
			Description: render(in.Text.EnvironmentKV, env, ""),
			Canary:      in.Names.Canary,
		},
		// Projects with secrets of their own get a namespace of their own,
		// in the environments that have reached that phase.
		Projects: tenantProjects(in, projectNamespaceTenants(in, env)),
	}

	local, err := localWorkloads(in, cluster)
	if err != nil {
		return builder.Environment{}, err
	}

	remote := remoteWorkloads(in, env, writers)
	trust := clusterTrust(in, in.Names.ClusterMountPrefix+env, cluster.Issuer)

	// The management cluster's workloads log in on its mount: in its own
	// namespace that is the cluster's own mount, elsewhere a mount of its
	// own beside it, declared only if somebody logs in on it.
	trust.Workloads = local

	if env == in.Management {
		trust.Workloads = append(trust.Workloads, remote...)
	}

	trust.Workloads = append(trust.Workloads, certManager...)
	environment.Trusts = []builder.Trust{trust}

	if env != in.Management {
		writerTrust := clusterTrust(in, in.Names.WriterMount, managementIssuer(in))
		writerTrust.Optional = true
		writerTrust.Workloads = remote
		environment.Trusts = append(environment.Trusts, writerTrust)
	}

	environment.SSH = sshSpec(in, cluster, hasFleets(in.HostFleets, env))

	if err := fleetLogins(in, &environment, env); err != nil {
		return builder.Environment{}, err
	}

	dbClient, err := dbClientRole(in, desired, env)
	if err != nil {
		return builder.Environment{}, err
	}

	environment.Grants = groupGrants(in, env, dbClient, func(role string) (builder.Clause, bool) {
		return credentialSign(in, desired, env, role)
	})

	if env == in.Management {
		environment.Secrets = slices.Clone(in.CISecrets)
	}

	environment.Reserved = reservations(in, env, writers)

	return environment, nil
}

// localWorkloads are the logins on the cluster's own mount: one per store,
// the service's readers, the CI runners, and the host-signing workers.
func localWorkloads(in *Inputs, cluster *Cluster) ([]builder.Workload, error) {
	env := cluster.Name

	kinds, err := storeKinds(in, cluster.Stores)
	if err != nil {
		return nil, err
	}

	var out []builder.Workload

	for _, kind := range kinds {
		out = append(out, builder.Workload{
			Role:    kind,
			Subject: in.Names.StoreSubject,
			TTL:     in.Names.NamespaceTokenTTL,
			Policy:  in.Stores.PolicyPrefix + kind,
			Access:  storeAccess(in, kind),
		})
	}

	out = append(out, serviceReaders(in, env)...)

	// The CI runners' logins: one role per runner, pinned to its
	// ServiceAccount, carrying nothing but the CI SSH role's policy. A
	// runner signs one certificate for the workers' account per job.
	ciPolicy := in.Groups.Name(env, in.Groups.SSH, in.Names.SSH.CIRole)
	if len(cluster.Runners) > 0 && !cluster.Workers {
		return nil, fmt.Errorf("estate: cluster %s has runner logins and no workers, so no %s role to sign on", env, in.Names.SSH.CIRole)
	}

	runners := slices.Clone(cluster.Runners)
	sort.Slice(runners, func(i, j int) bool { return runners[i].Role < runners[j].Role })

	for _, runner := range runners {
		if strings.TrimSpace(runner.Role) == "" || strings.TrimSpace(runner.Subject) == "" {
			return nil, fmt.Errorf("estate: cluster %s has a runner login with no role or subject", env)
		}

		out = append(out, builder.Workload{Role: runner.Role, Subject: runner.Subject, TTL: in.Names.TokenTTL, Policy: ciPolicy})
	}

	// The workers' own login, where they run: update on exactly their host
	// role's sign path and nothing else.
	if cluster.Workers {
		workers := &in.Names.Workers
		out = append(out, builder.Workload{
			Role:    workers.LoginRole,
			Subject: workers.Subject,
			TTL:     workers.TTL,
			Policy:  workers.Policy,
			Access:  builder.Access{builder.Sign(in.Names.SSH.HostMount, workers.HostRole)},
		})
	}

	return out, nil
}

// storeAccess is one store kind's read-only policy: the whole kind's KV
// prefix, data and metadata, unless Stores.Access narrows it.
func storeAccess(in *Inputs, kind string) builder.Access {
	if access, ok := in.Stores.Access[kind]; ok {
		return slices.Clone(access)
	}

	return builder.Access{builder.Read(kind)}
}

// StoreAccess is what one store kind's role may read.
func (in *Inputs) StoreAccess(kind string) builder.Access { return storeAccess(in, kind) }

// serviceReaders are the store's logins over the service's inputs, the
// client secrets it copies, and each consumer's export: a role of their own
// beside the kinds', because each reads a narrower path than a kind would.
func serviceReaders(in *Inputs, env string) []builder.Workload {
	service := &in.Service

	var out []builder.Workload

	read := func(role string, paths ...string) {
		rules := make([]model.Rule, 0, len(paths))
		for _, path := range paths {
			rules = append(rules, model.Rule{Path: in.Names.KVMount + "/data/" + path, Capabilities: []string{model.CapRead}})
		}

		out = append(out, builder.Workload{
			Role:    role,
			Subject: in.Names.StoreSubject,
			TTL:     in.Names.NamespaceTokenTTL,
			Access:  builder.Access{{Op: builder.OpRules, Rules: rules}},
		})
	}

	if slices.Contains(service.ConfigIn, env) {
		read(service.ConfigRole, service.ConfigPrefix+"/*")
	}

	if env == in.Management && len(service.Clients) > 0 {
		paths := make([]string, 0, len(service.Clients))
		for _, id := range service.Clients {
			paths = append(paths, service.ClientsKind+"/"+id)
		}

		read(service.ClientsRole, paths...)
	}

	for _, export := range service.Exports {
		if slices.Contains(export.Environments, env) {
			read(export.Role, export.Prefix+"/*")
		}
	}

	return out
}

// remoteWorkloads are what the management cluster's ServiceAccounts do
// inside another environment's namespace: the writers push their prefixes,
// the service keeps its own, the exporters write data, and the store reads
// one key across.
func remoteWorkloads(in *Inputs, env string, writers []Writer) []builder.Workload {
	var out []builder.Workload

	for _, writer := range writers {
		prefixes := writer.Prefixes[env]
		if len(prefixes) == 0 {
			continue
		}

		access := make(builder.Access, 0, len(prefixes))
		for _, prefix := range prefixes {
			access = append(access, builder.Push(prefix))
		}

		out = append(out, builder.Workload{Role: writer.Name, Subject: writer.Subject, TTL: in.Names.NamespaceTokenTTL, Access: access})
	}

	if workload, ok := serviceLogin(in, env); ok {
		out = append(out, workload)
	}

	// The exporters are admitted to the DATA of their prefixes alone: read,
	// create, update and patch, never list or delete, and no metadata path.
	// A rule is spelled out because no builder clause is narrower than a
	// push.
	for _, exporter := range in.Exporters {
		prefixes := exporter.Prefixes[env]
		if len(prefixes) == 0 {
			continue
		}

		rules := make([]model.Rule, 0, len(prefixes))
		for _, prefix := range prefixes {
			rules = append(rules, model.Rule{
				Path:         in.Names.KVMount + "/data/" + prefix + "/*",
				Capabilities: []string{model.CapCreate, model.CapPatch, model.CapRead, model.CapUpdate},
			})
		}

		out = append(out, builder.Workload{
			Role:    exporter.Name,
			Subject: exporter.Subject,
			TTL:     in.Names.NamespaceTokenTTL,
			Access:  builder.Access{{Op: builder.OpRules, Rules: rules}},
		})
	}

	// The management cluster's store reads one key here, minted and held in
	// this environment, rather than a writer pushing a value into it. The
	// identity is the store controller's ServiceAccount, the same subject on
	// every cluster; the policy is read on exactly that key.
	if env != in.Management {
		for _, read := range in.CrossReads {
			if !slices.Contains(read.Environments, env) {
				continue
			}

			out = append(out, builder.Workload{
				Role:    read.Role,
				Subject: in.Names.StoreSubject,
				TTL:     in.Names.NamespaceTokenTTL,
				Access:  builder.Access{builder.Key(read.Key)},
			})
		}
	}

	return out
}

// serviceLogin is the service's own login in one environment: a policy that
// is the DATA of what it owns there (read, create, update, patch) and the
// metadata's list and delete. Nothing under its inputs: the service reads
// them as files, delivered by the store.
func serviceLogin(in *Inputs, env string) (builder.Workload, bool) {
	prefixes := in.Service.Writes[env]
	if len(prefixes) == 0 {
		return builder.Workload{}, false
	}

	rules := make([]model.Rule, 0, 2*len(prefixes))

	for _, prefix := range prefixes {
		rules = append(rules,
			model.Rule{
				Path:         in.Names.KVMount + "/data/" + prefix + "/*",
				Capabilities: []string{model.CapCreate, model.CapPatch, model.CapRead, model.CapUpdate},
			},
			model.Rule{
				Path:         in.Names.KVMount + "/metadata/" + prefix + "/*",
				Capabilities: []string{model.CapDelete, model.CapList},
			},
		)
	}

	return builder.Workload{
		Role:    in.Service.Role,
		Subject: in.Service.Subject,
		TTL:     in.Names.NamespaceTokenTTL,
		Access:  builder.Access{{Op: builder.OpRules, Rules: rules}},
	}, true
}

// sshSpec is the environment's SSH engines: the user CA and its one machine
// role -- where the cluster runs the workers, the forced-command CI role,
// with a host CA of its own; elsewhere the placeholder user role -- or, where
// only host fleets sign host certificates, a host CA beside the placeholder.
// Never a key shared between the two: a key clients trust for hosts must
// never also be a key sshd trusts for users.
//
// The placeholder is the one role that keeps the user mount valid (the model
// refuses a mount with no role), and so keeps the environment's CA key,
// which deleting the mount would destroy. Where the CI role exists it keeps
// the mount alive by itself.
func sshSpec(in *Inputs, cluster *Cluster, fleets bool) *builder.SSH {
	env, names := cluster.Name, &in.Names.SSH

	ssh := &builder.SSH{
		Shape: names.Shape,
		User:  &builder.SSHUser{Mount: names.Mount, Description: render(in.Text.SSHUser, env, ""), KeyType: names.CAKeyType},
	}

	// One principal per role, and the principal is the HOST's account. Who
	// may sign is the policy's business.
	if !cluster.Workers {
		ssh.User.Roles = []builder.SSHUserRole{{
			Name:      names.UserRole,
			Principal: names.UserPrincipal,
			Policy:    in.Groups.Name(env, in.Groups.SSH, in.Groups.SSHUser),
		}}
	}

	switch {
	case cluster.Workers:
		ssh.User.Roles = append(ssh.User.Roles, builder.SSHUserRole{
			Name:         names.CIRole,
			Principal:    names.CIPrincipal,
			ForceCommand: names.CIForceCommand,
			Policy:       in.Groups.Name(env, in.Groups.SSH, names.CIRole),
		})
		ssh.Host = &builder.SSHHost{
			Mount:       names.HostMount,
			Description: render(in.Text.SSHHostWorkers, env, ""),
			KeyType:     names.HostKeyType,
			Roles:       []builder.SSHHostRole{{Name: in.Names.Workers.HostRole, Domains: in.Names.Workers.Domains, Bare: true}},
		}
	case fleets:
		ssh.Host = &builder.SSHHost{Mount: names.HostMount, Description: render(in.Text.SSHHostFleets, env, ""), KeyType: names.HostKeyType}
	}

	return ssh
}

func hasFleets(fleets []HostFleet, env string) bool {
	return slices.ContainsFunc(fleets, func(f HostFleet) bool { return f.Environment == env })
}

// fleetLogins adds one environment's host fleets: a login on the
// namespace's AWS IAM auth mount bound to each fleet's own instance role --
// the login a ServiceAccount token cannot give an EC2 instance -- and a host
// role it may then sign with, allowed only its own domain, on the same host
// CA the workers use where one is declared.
//
// Every fleet in one environment shares that environment's AWS auth mount
// and its host CA; the auth role, the host role and the sign policy are per
// fleet, so one fleet can never ask for another's names.
func fleetLogins(in *Inputs, environment *builder.Environment, env string) error {
	for i := range in.HostFleets {
		fleet := &in.HostFleets[i]
		if fleet.Environment != env {
			continue
		}

		if strings.TrimSpace(fleet.InstanceRoleARN) == "" {
			return fmt.Errorf("estate: %s has a host fleet with no instance role ARN", env)
		}

		if strings.TrimSpace(fleet.Name) == "" || strings.TrimSpace(fleet.Domain) == "" {
			return fmt.Errorf("estate: %s has a host fleet with no name or domain", env)
		}

		if environment.HostAuth == nil {
			environment.HostAuth = &builder.HostAuth{
				Mount: in.Names.HostAuth.Mount,
				// A plugin the server registers as a versioned catalog entry
				// is only found by its version.
				PluginVersion: in.Names.HostAuth.PluginVersion,
				Description:   render(in.Text.HostAuth, env, ""),
				// Unique per namespace, so a signed login captured for
				// another environment's mount is refused here.
				ServerID: fleet.ServerID,
				TTL:      in.Names.HostAuth.TTL,
			}
		}

		environment.HostLogins = append(environment.HostLogins, builder.HostLogin{
			Role:            fleet.AuthRole,
			InstanceRoleARN: fleet.InstanceRoleARN,
			SigningRole:     fleet.SigningRole,
			Domain:          fleet.Domain,
			Policy:          fleet.Policy,
		})
	}

	return nil
}

// dbClientRole is what the database client credential signs with: the
// contract's database client role on the environment's private issuing CA,
// whose mount the derivation decided. What is added here is who may sign.
func dbClientRole(in *Inputs, desired *Desired, env string) (builder.Clause, error) {
	for i := range desired.Namespaces {
		namespace := &desired.Namespaces[i]
		if namespace.Name != env {
			continue
		}

		for j := range namespace.IssuingCAs {
			issuing := &namespace.IssuingCAs[j]
			if issuing.TrustDomain != in.PKI.Private {
				continue
			}

			if !slices.ContainsFunc(issuing.CredentialRoles, func(r CredentialRole) bool { return r.Name == in.PKI.DBClientRole }) {
				return builder.Clause{}, fmt.Errorf("estate: %s: the PKI contract declares no %s credential role on the %s trust domain",
					env, in.PKI.DBClientRole, in.PKI.Private)
			}

			return builder.Sign(issuing.Mount, in.PKI.DBClientRole), nil
		}
	}

	return builder.Clause{}, fmt.Errorf("estate: %s has no private issuing CA to sign database clients with", env)
}

// credentialSign is the clause that signs with a credential role of the
// environment's private issuing CA, and whether the contract declares it.
func credentialSign(in *Inputs, desired *Desired, env, role string) (builder.Clause, bool) {
	for i := range desired.Namespaces {
		namespace := &desired.Namespaces[i]
		if namespace.Name != env {
			continue
		}

		for j := range namespace.IssuingCAs {
			issuing := &namespace.IssuingCAs[j]
			if issuing.TrustDomain != in.PKI.Private {
				continue
			}

			if slices.ContainsFunc(issuing.CredentialRoles, func(r CredentialRole) bool { return r.Name == role }) {
				return builder.Sign(issuing.Mount, role), true
			}
		}
	}

	return builder.Clause{}, false
}

// groupGrants are the groups people hold in one environment.
//
// The writer reaches everything, every project's own namespace included.
// A project's own prefix is reached by three roles: deployers and approvers
// write it; a viewer reads it. Each is checked against Groups.Holds, the
// predicate the identity provider admits the group by, so the two cannot
// drift apart; a project with a namespace of its own is addressed there.
//
// The database client role admits the UNION of the environment's client
// group and every project's DBA group, on the one sign path: the
// certificate names only its holder, and each database maps its own
// holders.
//
// A project's level groups ({env}:{project}:{level}, Groups.DBLevels) each
// sign with ONE role of their own, {PKI.DBProjectRole}-{project}-{level},
// whose pinned OU names the database role the certificate opens. Only
// where the contract declares that role: a project without it has no such
// group grant.
func groupGrants(in *Inputs, env string, dbClient builder.Clause, signs func(role string) (builder.Clause, bool)) []builder.Grant {
	groups := &in.Groups
	grants := []builder.Grant{{Name: groups.Name(env, groups.OpenBAO, groups.Writer), Access: builder.Access{builder.All()}}}

	for _, project := range projectsIn(mergeScopes(in.Projects, in.ProjectSecrets), env) {
		for _, role := range []struct {
			name  string
			write bool
		}{{groups.Deployer, true}, {groups.Approver, true}, {groups.Viewer, false}} {
			name := groups.Name(env, project, role.name)
			if !groups.Holds(name) {
				continue
			}

			grants = append(grants, builder.Grant{Name: name, Access: builder.Access{builder.Secrets(project, role.write)}})
		}
	}

	grants = append(grants, builder.Grant{Name: groups.Name(env, groups.Database, groups.DatabaseClient), Access: builder.Access{dbClient}})

	for _, project := range projectsIn(in.Projects, env) {
		dba := groups.Name(env, project, groups.DBA)
		if !groups.Holds(dba) {
			continue
		}

		grants = append(grants, builder.Grant{Name: dba, Access: builder.Access{dbClient}})

		for _, level := range groups.DBLevels {
			group := groups.Name(env, project, level)
			if !groups.Holds(group) || in.PKI.DBProjectRole == "" {
				continue
			}

			if clause, ok := signs(fmt.Sprintf("%s-%s-%s", in.PKI.DBProjectRole, project, level)); ok {
				grants = append(grants, builder.Grant{Name: group, Access: builder.Access{clause}})
			}
		}
	}

	return grants
}

// reservations are the KV prefixes in one environment that are not a CI
// job's to read: the restore canary, a writer's or exporter's prefix, and
// the service's root.
func reservations(in *Inputs, env string, writers []Writer) []builder.Reservation {
	out := []builder.Reservation{{Prefix: in.Names.Canary, Owner: "the restore canary"}}

	for _, writer := range writers {
		for _, prefix := range writer.Prefixes[env] {
			out = append(out, builder.Reservation{Prefix: prefix, Owner: writer.Name})
		}
	}

	// An exporter's prefix is as much its own as a writer's; one both own is
	// reserved once (the writer's).
	for _, exporter := range in.Exporters {
		for _, prefix := range exporter.Prefixes[env] {
			if !slices.ContainsFunc(out, func(r builder.Reservation) bool { return r.Prefix == prefix }) {
				out = append(out, builder.Reservation{Prefix: prefix, Owner: exporter.Name})
			}
		}
	}

	if len(in.Service.Writes[env]) > 0 {
		out = append(out, builder.Reservation{Prefix: in.Service.Root, Owner: in.Service.Role})
	}

	return out
}

// rootJobs is the jobs' logins in root: the management cluster's tokens, one
// role per job pinned to its ServiceAccount, and a policy each. The snapshot
// job reads the Raft snapshot; the restore check lists namespaces and reads
// each one's canary and every trusted chain; the root-generation watch reads
// whether a root-token ceremony is open; the plugin-catalog watch reads the
// one plugin the server registers.
func rootJobs(in *Inputs, clusters []Cluster, desired *Desired) (builder.Trust, error) {
	for i := range clusters {
		cluster := &clusters[i]
		if cluster.Name != in.Management {
			continue
		}

		jobs := &in.Names.Jobs
		trust := clusterTrust(in, in.Names.RootMount, cluster.Issuer)
		trust.Workloads = []builder.Workload{
			job(in, jobs.RestoreCheck, restoreCheckAccess(in, desired)),
			job(in, jobs.Snapshot, builder.Access{builder.Rules(builder.SnapshotRule())}),
			job(in, jobs.RootGeneration, builder.Access{builder.Rules(builder.RootGenerationRule())}),
			job(in, jobs.PluginCatalog, builder.Access{builder.Rules(builder.PluginCatalogRule(jobs.PluginType, jobs.PluginName))}),
		}

		return trust, nil
	}

	return builder.Trust{}, fmt.Errorf("estate: no %s cluster to take snapshots from", in.Management)
}

// job is a root job's role: its ServiceAccount's tokens, one policy.
func job(in *Inputs, j Job, access builder.Access) builder.Workload {
	return builder.Workload{Role: j.Role, Subject: j.Subject, TTL: in.Names.TokenTTL, Policy: j.Policy, Access: access}
}

// restoreCheckAccess is what the restore check reads: every namespace's
// canary, and the authority of every mount whose chain is trusted. Both
// chains, because both are trusted: a restore that proves only the chain
// being retired proves nothing about the one taking over.
func restoreCheckAccess(in *Inputs, desired *Desired) builder.Access {
	legacy := &in.PKI.Legacy
	access := builder.Access{
		builder.Rules(builder.NamespacesRule()),
		builder.CA("", legacy.Root.Mount, legacy.Root.IssuerName),
		builder.CA("", legacy.Parent.Mount, legacy.Parent.IssuerName),
	}

	for i := range desired.PKI.Domains {
		domain := &desired.PKI.Domains[i]
		access = append(access, builder.CA("", domain.Mount, domain.IssuerName))
	}

	for i := range desired.Namespaces {
		namespace := &desired.Namespaces[i]
		access = append(access, builder.Canary(namespace.Name, namespace.KV, namespace.Canary))

		if environment := namespace.LegacyPKI; environment != nil {
			access = append(access,
				builder.CA(namespace.Name, environment.Mount, environment.IssuerName),
				builder.Rules(
					model.Rule{Path: namespace.Name + "/" + environment.Mount + "/cert/*", Capabilities: []string{model.CapRead}},
					model.Rule{Path: namespace.Name + "/" + environment.Mount + "/issue/" + in.PKI.RestoreRole, Capabilities: []string{model.CapUpdate}},
				),
			)
		}

		for j := range namespace.IssuingCAs {
			issuing := &namespace.IssuingCAs[j]
			access = append(access, builder.CA(namespace.Name, issuing.Mount, issuing.IssuerName))
		}
	}

	return access
}

// tenantProjects is one project namespace per tenant, each with a KV v2
// mount and nothing else: a project namespace holds mounts alone.
func tenantProjects(in *Inputs, tenants []string) []builder.Project {
	out := make([]builder.Project, 0, len(tenants))

	for _, project := range tenants {
		out = append(out, builder.Project{
			Name: project,
			KV:   model.KVMount{Path: in.Names.KVMount, Description: render(in.Text.ProjectKV, "", project)},
		})
	}

	return out
}
