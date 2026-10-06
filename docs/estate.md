# The estate layer

[`pkg/builder`](builder.md) writes logins, policies, groups and SSH engines
from declarative contracts, and [`pkg/pki`](pki.md) derives the PKI from an
authored contract. `pkg/estate` is the layer above both, for the common
shape of one OpenBAO server that serves several Kubernetes clusters: it
decides **which inputs make which contract entry**, and writes the whole
desired state.

```
your facts ──binder──▶ estate.Inputs ──Build──▶ estate.Desired ──Model──▶ model.Desired ──▶ pkg/apply
(clusters, projects,    (this page)              │ (the review)                 (what is applied)
 writers, grants, PKI)                           └── LegacyResourceNames ──▶ apply.Options.Rename
```

A consuming repository keeps its facts and a binder that fills
`estate.Inputs`; nothing else. The derivation, its order, its refusals and
the names of everything it adopts are here.

Nothing here names an estate. Every mount, role, policy, subject, group,
lifetime and description is an input; the example estate in
[`pkg/estate/estate_test.go`](../pkg/estate/estate_test.go) uses made-up
names, and its goldens are
[`testdata/desired.yaml`](../pkg/estate/testdata/desired.yaml) (the view),
[`testdata/model.yaml`](../pkg/estate/testdata/model.yaml) (the model) and
[`testdata/renames.yaml`](../pkg/estate/testdata/renames.yaml) (the adopted
names).

## What one environment gets

Each `Cluster` is one namespace, named after the cluster:

| Input | Becomes |
|---|---|
| `Cluster.Issuer` | a JWT mount `<ClusterMountPrefix><cluster>` trusting the cluster's tokens |
| `Cluster.Stores` | one role per store kind on that mount, pinned to `Names.StoreSubject`, with a policy `<Stores.PolicyPrefix><kind>` reading the kind's whole KV prefix, or what `Stores.Access` narrows it to. A kind `Stores.HasLayout` does not know is refused |
| `Cluster.Runners` | one role per CI runner, carrying the CI SSH role's policy. Only a cluster with `Workers` has that role; runners elsewhere are refused |
| `Cluster.Workers` | the host-signing workers: an SSH host CA with their host role, the CI SSH role in place of the placeholder user role, and the workers' own login that signs on it |
| `Writers`, `Exporters`, `Service`, `CrossReads` | the management cluster's workloads in this namespace, on `Names.WriterMount` (declared only if someone logs in on it): writers push whole prefixes, exporters write data alone, the service keeps and exports its own root, and the store reads one key across |
| `HostFleets` | an AWS IAM auth mount (once per environment) with each fleet's login bound to its instance role, a host role allowing its one domain, and the policy joining them |
| `Projects`, `ProjectSecrets`, `ProjectViewers` | grants for each project's deployer and approver groups (write) and viewer group (read), each admitted only if `Groups.Holds` says so; project namespaces where `ProjectNamespaces` names the environment |
| `CISecrets` | in the management namespace only: one read-only policy per path, refusing a path a writer, exporter, the service or the restore canary owns |

The environment's writer group reaches everything; its database client
group and every project's DBA group sign on the private domain's
`PKI.DBClientRole`.

## Root

`Names.Jobs` are the root jobs on `Names.RootMount`: the snapshot, the
restore check (every canary and every trusted chain), the root-generation
watch and the plugin-catalog watch. The operators' door is the bootstrap's
and is never applied; the web UI's door and `Names.OperatorKV` are.

## The PKI

`PKI.Contract` is a `pkg/pki` contract; `PKI.Private`, `PKI.Origin` and
`PKI.Identity` name its trust domains. Each environment substitutes its
`PrivateZone` or `OriginZone` for `{zone}`, and the origin role signs
`Cluster.OriginNames`. Every issuing CA gets a cert-manager login named
after `PKI.ClusterIssuers[domain]`. An environment whose identity CA is not
`PKI.Signed` yet renders nothing of the identity domain.

`PKI.Legacy` is a self-signed chain still served beside the contract's: a
root, an intermediate, and an environment intermediate with one leaf role in
every namespace. The contract's authorities join the same mounts where the
contract places them there.

## Adopting existing state

`Desired.LegacyResourceNames` maps the Pulumi name `pkg/apply` would give a
resource to the name state already holds: the legacy chain's resources
(named after their mounts), the restore role on the legacy environment
mount, each identity CA's bootstrap request (`IdentityBootstrapCSRName`),
and the identity roles of an environment `PKI.LegacyRoleIssuers` names. Pass
it to `apply.RenameFrom`, and the first preview after adopting is empty.

## Store kinds

`StoreKinds(facts, rules)` says which store kinds a cluster runs: each
`StoreRule` whose conditions hold (a switch that is on, the management
cluster, a cluster list, one kind per tailnet, a client secret held on
another cluster), in the order of the rules. The rules are the estate's
data; the facts come from what the cluster runs.
