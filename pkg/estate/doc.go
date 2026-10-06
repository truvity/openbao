// Package estate derives the whole desired state of one OpenBAO server that
// serves several Kubernetes clusters -- one namespace per environment, the
// root namespace's jobs and doors, and the private PKI -- from typed inputs,
// and writes it both as an estate view ([Desired], the review of a change)
// and as the model pkg/apply converges on ([Desired.Model]).
//
// The layers below it are the library's other packages: pkg/builder writes
// logins, policies, groups and SSH engines from declarative contracts, and
// pkg/pki derives the PKI from an authored contract. This package is the
// layer above: which inputs make which contract entry. A cluster's secret
// stores are one workload each on the cluster's JWT mount; the management
// cluster's writers, exporters and service log in to every environment they
// reach; CI runners, host-signing workers and EC2 host fleets get the SSH
// roles they sign with; the groups people hold become grants; and the PKI
// contract's authorities, with a legacy chain still served beside them,
// become mounts, cert-manager logins and credential roles.
//
// Nothing here names an estate. Every mount, role, policy, subject, group,
// lifetime and description is a field of [Inputs] -- [Names], [Text],
// [Groups] and [PKI] carry the conventions -- so the consuming repository
// keeps only its facts and a thin binder filling the inputs. [StoreKinds]
// evaluates the rules that say which store kinds a cluster runs, and
// pkg/estate/stack is the Pulumi program that applies the result; this
// package links no Pulumi, so a configuration loader can build and review
// the state alone.
package estate
