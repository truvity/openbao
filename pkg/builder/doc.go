// Package builder derives an OpenBAO server's desired state -- everything
// but its PKI -- from declarative contracts, one per engine, and writes it
// as a [model.Desired] for pkg/apply.
//
// The model ([github.com/truvity/secrets/pkg/model]) says WHAT a server is
// configured with. This package says what a platform's rows MEAN in it: a
// cluster's workload that reads one prefix is a login on that cluster's JWT
// mount pinned to one ServiceAccount, and the one policy it carries; a group
// that deploys a project is a policy named after the group and the group
// admitted through the roster's doors; a fleet of hosts that sign their own
// host certificates is an AWS IAM role, a host role and the policy joining
// them. The consuming estate keeps only its rows and a thin adapter mapping
// them onto a [Spec]; the shapes, the names of the parts, the ordering that
// makes the output stable and the checks that refuse a bad contract are
// here.
//
// The contracts, one file each:
//
//   - [Access] and [Clause] (access.go): what a policy grants, as KV
//     clauses (read, write, push, one key, a project's secrets, everything),
//     signing clauses and the system paths OpenBAO's own jobs need. The
//     Access is the KV contract: it decides which ACL stanzas a grant is.
//   - [Trust] and [Workload] (workload.go): the clusters whose ServiceAccount
//     tokens a namespace accepts, and the machine identities that log in on
//     each: the auth contract.
//   - [Grant] and [SecretGrant] (identity.go): the groups people and jobs
//     hold, and how an internal group name becomes an identity group.
//   - [SSH], [HostAuth] and [HostLogin] (ssh.go): the SSH user CA, the host
//     CA, and the fleets that sign their own host certificates.
//   - [Environment] (environment.go) and [Root] (root.go): one namespace and
//     the root namespace, composed from the above; [Spec] (spec.go) is the
//     whole state, and [Spec.Build] writes it.
//
// Plugins are the model's ([model.Plugin]), carried by [Spec.Plugins]; a
// server that registers its plugins itself names none, and only needs
// [PluginCatalogRule] for the job that watches the catalog.
//
// The PKI is pkg/pki's: [github.com/truvity/secrets/pkg/pki.Derivation.Apply]
// joins its mounts to what [Spec.Build] returns, and a workload that carries
// a PKI role's sign path is an ordinary [Workload] whose Access is a
// [Sign].
//
// Nothing here names an estate: every name is a field of the spec, and
// docs/builder.md is the reference.
package builder
