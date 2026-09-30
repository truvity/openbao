# The private-PKI contract

[ceremony.md](ceremony.md) is the mechanism: a KMS root, its intermediates,
the offline print-template/confirm-template ceremony, the `.attempt`
reservation. `pkg/pki` is the layer above it that a consuming estate would
otherwise have to write for itself: the AUTHORED POLICY -- how many root
generations exist and their custody, which trust domains sit below them,
which leaf roles each domain offers per environment, and the invariants
that keep the whole hierarchy self-consistent as it grows. `Load` and
`Validate` carry those invariants; `Contract`'s methods turn the policy
into the `ceremony.RootSpec` / `IntermediateSpec` / `EmergencyServerSpec`
values `pkg/ceremony` signs from.

`pkg/pki` is also the one place the contract becomes a
[`model.Desired`](model.md): `Contract.Derive` turns it, with the few facts a
contract cannot know, into every domain intermediate, issuing CA, leaf role
and credential role an estate serves -- with the mount, issuer and role
names a deployed estate is already registered under ([Deriving the desired
state](#deriving-the-desired-state)). An estate needs no PKI logic of its
own beside the contract file and its own legacy state.

Nothing in `pkg/pki` signs anything or holds a credential. A program that
already has its own contract shape can skip this package and build those
three spec types directly, exactly as `pkg/pki` itself does; this package
exists so most consuming estates do not have to.

## The contract file

```yaml
schemaVersion: 1

global:
  immutable: true
  keyAlgorithm: ECDSA
  keyCurve: P-384
  signatureAlgorithm: ECDSA_SHA_384
  minimumTlsVersion: TLS1.3
  # A leaf role's OWN key curve may differ from keyCurve -- every CA above
  # it still signs with keyCurve regardless -- only for a caller whose
  # client cannot be told to generate anything else. See "Two curves" below.
  additionalLeafKeyCurves: [P-256]

rootGenerations:
  - id: example-root-2026-01
    lifetime: 175200h # 20 years; never re-signed once created
    certificate:
      notBefore: "2026-01-01T00:00:00Z"
      subject: { commonName: Example Private Root 2026-01, organization: Example Org }
      maxPathLen: 3           # domain intermediate -> environment CA -> project CA -> leaf
    custody:
      provider: aws-kms
      accountId: "111122223333"
      profile: example-root@admin
      region: eu-central-1
      trustedPrincipalArnPattern: "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_role-admin_*"
      disasterRecovery: { mode: multi-region-replica, region: eu-north-1 }
    state: active

trustDomains:
  dns:
    - name: private
      suffix: example.internal
      rootGeneration: example-root-2026-01
      domainIntermediate:
        name: example-private-2026-01
        subject: { commonName: example.internal Intermediate CA, organization: Example Org }
        keyCurve: P-384
        maxPathLen: 2
        permittedDnsDomains: [example.internal, cluster.local]
      lifetimes: &standard { domainIntermediate: 87600h, clusterIntermediate: 26280h, leafDefault: 720h, leafMaximum: 2160h, renewBefore: 240h }
      roles:
        - name: server
          names: { source: environment-zone, patterns: ["{zone}"], bare: true, subdomains: true }
          usage: { server: true, client: true }
          keyCurve: P-384
          lifetimes: { default: 720h, maximum: 2160h, renewBefore: 240h }
    - name: origin
      suffix: example.com
      rootGeneration: example-root-2026-01
      requireTrusted: true      # this generation MUST be in migration.trustedGenerations
      domainIntermediate:
        name: example-origin-2026-01
        subject: { commonName: example.com Origin Intermediate CA, organization: Example Org }
        keyCurve: P-384
        maxPathLen: 2            # no permittedDnsDomains: unconstrained, limited by role policy alone
      lifetimes: *standard
      roles:
        - name: origin
          names: { source: catalog, bare: true, subdomains: false }
          usage: { server: true, client: false }
          keyCurve: P-384
          allowWildcardCertificates: true   # only legal with source: catalog
          lifetimes: { default: 720h, maximum: 2160h, renewBefore: 240h }
  uri:
    - name: identity
      rootGeneration: example-root-2026-01
      domainIntermediate:
        name: example-identity-2026-01
        subject: { commonName: Workload Identity Intermediate CA, organization: Example Org }
        keyCurve: P-384
        maxPathLen: 2
        permittedUriDomains: [.example.internal]   # every environment's SPIFFE trust domain is a subdomain of this
      lifetimes: { domainIntermediate: 87600h, clusterIntermediate: 26280h, leafDefault: 1h, leafMaximum: 24h, renewBefore: 10m }
      environments: [dev, prod]
      role:
        name: identity
        uriSanPattern: "spiffe://{zone}/*"
        usage: { server: true, client: true }
        keyCurve: P-256
        lifetimes: { default: 1h, maximum: 24h, renewBefore: 10m }
      environmentCA:
        keyCurve: P-384
        maxPathLen: 0
        commonNameSuffix: Workload Identity CA
      rootSignedEnvironments: [dev]

alerts:
  enabled: false
  thresholds: { rootGeneration: 43800h, domainIntermediate: 17520h, clusterIntermediate: 4320h, leaf: 240h }

signAlerts:
  notify: [security@example.org]

migration:
  trustedGenerations: [example-root-2026-01]
```

A contract that declares no trust domain at all (just root custody) may
leave out `alerts`, `signAlerts.notify`, `migration.trustedGenerations` and
`disasterRecovery`: they serve trust domains. Whatever such a contract does
state is still checked, and with any trust domain they are all required as
above. `alerts.enabled` still may not be `true`.

The example omits the fields that place and name what the contract
declares -- they are all optional, and defaults exist -- and are described in
[Placement, names and credential roles](#placement-names-and-credential-roles)
below. [`pkg/pki/testdata/contract-estate.yaml`](../pkg/pki/testdata/contract-estate.yaml)
is a contract that spells every one of them, the shape of an estate that
adopted the package over a PKI that was already deployed.

`serialNamespace` (top level, optional, default `private-pki`) prefixes the
label every deterministic serial is derived from. The example omits it
because the default is right for a new root; an estate whose root already
exists must set it to the prefix that root was created with, and never
change it afterwards ([adoption.md](adoption.md)).

`Load` reads it strictly (an unknown key is an error) and calls `Validate`,
which carries every invariant below. `ArtifactDir` (default `pki-roots`,
relative to the contract file's own directory) is where `pkg/ceremony`'s
artifacts and `.attempt` files live -- see [ceremony.md](ceremony.md) for
their shape; `pkg/pki` names them (`Contract.RootArtifactPath`,
`IntermediateArtifactName`) but never reads their bytes except through
`pkg/ceremony`'s own strict, offline verification.

## Two shapes of trust domain

**`trustDomains.dns`** is the ordinary shape: a suffix, an optional DNS
name constraint on the domain intermediate, and a list of leaf roles. A
role's `names.source` is one of:

- `environment-zone` -- patterns contain `{zone}`, substituted per
  environment by the caller (this contract never authors a zone, so it is
  never a second owner of one);
- `static` -- an authored, literal domain (or domain below it), the same
  for every environment;
- `catalog` -- the caller supplies the allowed names at render time (an
  external list this contract does not own). **Only a `catalog` role may
  set `allowWildcardCertificates: true`**: the caller's catalog IS the
  declared list, so nothing can ask for a wildcard the catalog does not
  already name, which an authored pattern can never guarantee.

**`trustDomains.uri`** is a workload-identity shape (a URI name constraint
instead of a DNS one): no DNS suffix, no per-role name patterns, one role
signing a URI SAN alone, and an **explicit per-environment allow-list**
(`environments`) rather than "every environment automatically" -- adding a
name to that list is the entire change needed to reach another
environment; nothing else in a consumer's desired-state code should
special-case which environment it is building for.

## Placement, names and credential roles

A trust domain's authorities live in mounts, and what the mounts are called
is deployed state: a mount that changes path is a new mount and the old one
is deleted with its CAs. So the paths are authored once, in the contract,
and every consumer reads them from there. All are optional.

| Field (DNS and URI domains) | Meaning | Default |
|---|---|---|
| `domainMount` | the root-namespace mount that holds the domain intermediate; two domains may name one mount, which is then created once and holds each intermediate as a further issuer | `pki-<domain name>` |
| `issuingMount` | the mount, inside every environment's namespace, that holds that environment's issuing CA and roles | `pki-<domain name>` |
| `domainMountDescription`, `issuingMountDescription` | what `sys/mounts` shows; templates over `{commonName}`, `{domain}` and, for the issuing mount only, `{environment}` | a generic sentence |
| `issuingCA.commonNameSuffix` | an issuing CA's subject is the environment's `{zone}` value and this | `Issuing CA` |

The issuer under a domain intermediate is named
`<domainIntermediate.name>-<environment>`; its path length is one less than
the intermediate's, its lifetime is `lifetimes.clusterIntermediate`, and its
name constraint is the environment's zone plus whatever the intermediate
permits beside the domain's suffix (a domain whose intermediate is
unconstrained gives an unconstrained issuing CA). A role's `allowedDomains`
are its `names` resolved for the environment.

**`credentialRoles`** (a DNS domain) are roles on each environment's issuing
CA that sign a caller's own CSR -- a person's database client certificate,
never a workload's: `name`, `subjectMount` (the auth mount in the same
namespace whose alias name the common name must equal), `cnValidations`
(`email` or `hostname`), `usage`, `keyCurve`, and `lifetimes` (`default` and
`maximum`; `renewBefore` is refused, a credential is minted for one use and
must sit inside the domain's own leaf lifetimes). Nothing grants them: which
groups may sign with one is the consumer's policy.

## Per-environment identity CAs, and why

A URI trust domain's ordinary shape is one shared intermediate
(`domainIntermediate`) that signs one issuing CA per environment. `pkg/pki`
also supports a stronger shape: `environmentCA` + `rootSignedEnvironments`
lets any subset of `environments` have their OWN issuing CA signed
**directly by the root**, one level shorter than the shared intermediate,
with nothing of its own below it (`maxPathLen` strictly less than the
domain intermediate's).

The reason is a real OpenBAO limitation, not a preference: OpenBAO 2.6.2
drops `permitted_uri_domains` when IT signs a CA certificate
([openbao/openbao#4104](https://github.com/openbao/openbao/issues/4104)),
so an issuing CA the shared intermediate signs carries no URI constraint at
all -- every environment's issuing CA trusts every other environment's
SPIFFE IDs, and only the OpenBAO *role* (not the certificate) keeps an
environment to its own trust domain. Signing that CA directly with the KMS
root instead avoids the bug entirely: this package's own ceremony sets URI
constraints correctly, so an environment's root-signed CA carries an EXACT
constraint to that one environment's trust domain (no leading dot, unlike
the shared intermediate's subtree constraint), and cryptographically cannot
mint another environment's identities. `EnvironmentCA.CommonNameSuffix` is
authored once (e.g. `Workload Identity CA`); the subject and the one URI
constraint are derived per environment from the value the caller passes in
(`Contract.EnvironmentCASpec`), never authored per environment.

Migrating an environment from the shared intermediate to its own
root-signed CA is a two-phase ceremony, the same shape the domain
intermediate's own birth is (below): nothing downstream may treat the new
CA as live until its artifact is committed, and the OLD issuer keeps
signing, unconditionally, until every leaf it ever issued has expired.

**No shared intermediate at all.** A URI domain whose every environment has
its own root-signed CA has nothing to put a shared intermediate under, so
`domainIntermediate` (and `lifetimes.domainIntermediate`) may be left out
entirely -- a half-authored intermediate is refused. Every environment is
then root-signed: `rootSignedEnvironments` may be omitted (or must equal
`environments`), `environmentCA.maxPathLen` is checked against the root's own
path length instead of the intermediate's, and the lifetime ordering is
root > cluster intermediate > leaf. The domain declares no intermediate to
sign, so `URIIntermediateSpec` refuses it and only `EnvironmentCASpec`
applies.

`EnvironmentCA.IssuerNamePattern` names the OpenBAO issuer (and key) of each
environment's root-signed CA (it must contain `{environment}`; the default is
`<domain name>-<environment>`), for the same reason `ArtifactPattern` exists:
an estate that adopted deployed CAs keeps the names they carry, because the
apply's resources are named after the issuer.

`EnvironmentCA.ArtifactPattern` names the per-environment CA's committed
artifact when the library default (`<generation>-intermediate-<domain
name>-<environment>.yaml`) is not what an estate's ceremony already used
before adopting this package: `{generation}` and `{environment}` are
substituted (the pattern must contain `{environment}`, or two
environments' CAs would collide onto the same file), so an existing,
already-signed artifact needs no rename to be read by `Contract` methods.

## Two curves

Every CA in a hierarchy signs with `global.keyCurve` (P-384), without
exception, and each CA's key is generated at exactly that size. A LEAF
role is different: OpenBAO 2.6.2 treats a PKI role's `key_bits` as a
**minimum** for an EC role, not a target (a P-256 request against a role
holding 384 is refused outright, "role requires a minimum of a 384-bit
key", never downgraded), so `pkg/apply` writes a P-384 leaf role with
`key_bits` 256 (`apply.LeafKeyBits`): it signs a P-256 AND a P-384 leaf,
which is what a first certificate from a default cert-manager
`Certificate` (see `charts/openbao-consumers`, default P-384) or a
fixed-curve client such as a CSI driver both need. A role declared P-256
also carries 256, and a P-521 role keeps 521; the role never accepts an
RSA key. A credential role (`db-client` and its kind, a person's own
client certificate) is not a workload leaf and keeps its exact curve. `global.additionalLeafKeyCurves` still allow-lists a leaf role
whose declared curve is not `keyCurve`, and `Validate` refuses any leaf
curve that is neither `keyCurve` nor in that list.

## The two-phase ceremony

Every domain intermediate (and every environment's root-signed CA) is
signed exactly once, offline, from a CSR OpenBAO produces and a template
this package derives from the contract:

1. **Phase A -- additive only.** Before anything is signed, the mount and
   the unsigned key must already exist so OpenBAO can produce a CSR
   ([pkg/apply](../pkg/apply)'s desired state cannot declare an `External`
   issuer that has nothing to import yet -- `SignedChain` is called
   synchronously for every `External` issuer while the program builds its
   resources). A consumer therefore creates the mount and the CSR OUTSIDE
   the generic `apply.Deploy` path the first time, with
   `apply.BootstrapEnvironmentCA` (`MountExists: false` reaching a
   root-signed CA from a cold start, with no prior issuing CA at all;
   `true` for an environment moving from a shared domain intermediate's
   issuing CA to its own root-signed one, where the mount already
   exists), exports the CSR it returns as a Pulumi output, and stops
   there. It registers the mount and the request under the names
   `Deploy` will give them (`<namespace>-<mount>` and `<issuer>-csr`), so
   phase B adopts both with no create and no delete; pass the same
   `Options.Rename` to both.
2. Someone runs `Contract.DNSIntermediateSpec` / `URIIntermediateSpec` /
   `EnvironmentCASpec` to build the `ceremony.IntermediateSpec`, then
   `ceremony.PrepareIntermediate` + `--print-template` to review the exact
   certificate and its hash, and once confirmed, `ceremony.SignIntermediate`
   with the KMS root, after the key, role, regions and generation have been
   cross-checked against the custody outputs ([the custody
   cross-check](#the-custody-cross-check)). The result is committed under
   `ArtifactDir`, next to its `.attempt` reservation.
3. **Phase B -- the artifact gates everything downstream.**
   `Contract.LoadSignedIntermediate` proves the committed artifact against
   the contract and the committed root, offline, and returns the chain
   `pkg/apply` imports through an `External` issuer's `SignedChain`
   callback. `IntermediateSigned(spec)` is the gate: nothing that depends
   on this intermediate (an environment issuing CA below it, a leaf role,
   a trust bundle entry) should render until it reports `true`.

```go
contract, err := pki.Load("private-pki.yaml")

// Phase B, once the CSR from phase A has been signed and committed:
spec, err := contract.DNSIntermediateSpec("private", "example-root-2026-01")
signed, err := contract.LoadSignedIntermediate(spec)
// signed.ChainPEM is what pkg/apply's Options.SignedChain returns for
// this issuer; signed.Proof is one line per property re-derived and
// checked, for an installer's log.
```

**Moving a role in place, not replacing it.** When an environment moves
from a shared intermediate's issuing CA to its own root-signed one, its
identity role still signs the same shape of leaf -- the SAME OpenBAO
object, `<mount>/roles/<role>` -- only under a different issuer.
`pkg/apply`'s own resource-naming scheme derives a role's Pulumi logical
name from the issuer it signs with
(`apply.PKIRoleResourceName(issuer, role)`), so pointing the role at the
new issuer, with nothing else, changes that name: Pulumi registers a NEW
logical resource for it and, seeing the OLD one no longer declared,
deletes it -- and the delete reaches the same OpenBAO path the create
just wrote, since the role's own name (as OpenBAO sees it, not the
Pulumi logical one) never changed. `apply.EnvironmentCARoleRename(oldIssuer,
newIssuer, roleNames...)` returns the `Options.Rename` entries that
prevent this -- merge them with `apply.ComposeRename` into whatever
Rename a caller already builds. Pass `oldIssuer = ""` for an environment
reaching its root-signed CA from a cold start: there is no prior role to
move, and `EnvironmentCARoleRename` returns nil.

The root itself is a one-time ceremony
(`Contract.RootSpec` + `ceremony.CreateRoot`), never repeated for an
existing generation: `CreateRoot` re-verifies an existing artifact instead
of signing again, so a rerun (a redeploy, a new team member's first apply)
is always safe.

### The custody cross-check

`openbaoctl pki create-root`, `sign-intermediate` (which also signs an
environment's own CA, `--environment`/`--zone`) and `sign-emergency-server`
take the key, the role and the profile as flags, so a mistyped ARN, a
generation's neighbour or a key in the wrong region would otherwise reach
KMS. With `--contract` they therefore check the flags against the
**custody outputs** the custody side publishes -- a public YAML file
(`pki.LoadCustodyOutputs`; the shape `pkg/custody`'s Pulumi exports
naturally take) synced next to the contract:

```yaml
adminRoleArn: arn:aws:iam::111122223333:role/root-admin
ceremonyRoleArn: arn:aws:iam::111122223333:role/root-ceremony
generations:
  example-root-2026-01:
    alias: alias/private-pki/root/example-root-2026-01
    primaryKeyArn: arn:aws:kms:eu-central-1:111122223333:key/mrk-...
    primaryRegion: eu-central-1
    replicaKeyArn: arn:aws:kms:eu-north-1:111122223333:key/mrk-...
    replicaRegion: eu-north-1
    ceremonyRoleArn: arn:aws:iam::111122223333:role/root-ceremony
```

```sh
openbaoctl pki sign-intermediate --contract private-pki.yaml --generation example-root-2026-01 \
  --trust-domain private --csr private.csr --custody-outputs custody-outputs.yaml \
  --print-template
```

`--custody-outputs FILE` verifies, offline and before anything is reserved
or signed (`Contract.VerifyCustody`), and refuses with both sides named on
the first disagreement:

- the outputs are consistent with themselves: two different IAM roles (admin
  and ceremony) in one account; per generation an alias ending in the
  generation ID, two different regions, a multi-region key in each that is
  the same key, in the roles' account, with the stack's ceremony role;
- every generation the contract authors is published, and no other one is;
- for every authored generation: the key's account is the authored
  `custody.accountId`, the primary region is `custody.region`, and the
  replica region is `custody.disasterRecovery.region` (when the contract
  states one);
- the key about to sign -- `--key-arn`, or the committed root artifact's --
  is exactly the published primary key of `--generation`, and so is the
  root artifact's `keyArn`;
- `--role-arn`, when given, is the published ceremony role, and
  `--aws-profile`, when given, is the contract's `custody.profile`. Neither
  needs to be given: the published role and the authored profile are used
  when it is not, so the command cannot sign with a role or profile of its
  own choosing.

What was verified is printed with the template review (`--print-template`
needs no credential, and neither does this check) and again with the signing
result, and the rerun line `--print-template` prints repeats the flag. The
template hash flow is unchanged: the hash is over the certificate, not over
this check.

The check is **required** with `--contract`, because a contract always
declares custody. `--skip-custody-check "<reason>"` signs without it (a
drill on a scratch account, custody outputs not synced yet); the reason must
not be blank, is printed with the review as `custody check: SKIPPED`,
repeated in the rerun line, and logged as a warning when signing. It is
recorded in the terminal and the log of the ceremony, not in the artifact
(an artifact has no room for it, and its content is what the hash covers),
so name the reason in the commit that adds the artifact. The two flags
exclude each other. `--hierarchy` declares no custody, so both flags are
refused there rather than ignored.

## Break-glass

`Contract.EmergencyServerSpec(generationID, dnsName, notBefore)` derives
the break-glass declaration for the one moment OpenBAO cannot issue its own
serving certificate: the generation must be `active` AND already in
`migration.trustedGenerations` (a leaf of a root nobody trusts restores
nothing), and `dnsName` must sit under a `dns` trust domain that
`requireTrusted`. Nothing is ever committed to the artifact directory for
this leaf -- see [ceremony.md](ceremony.md#break-glass) for the signing
steps.

## Deriving the desired state

```go
contract, err := pki.LoadFS(cfg.Content, "private-pki.yaml", "cfg")

derivation, err := contract.Derive([]pki.Environment{{
    Name:  "dev",
    Zones: map[string]string{"private": "dev.example.internal", "origin": "dev.example.com", "identity": "dev.example.internal"},
    Catalog: map[string][]string{pki.CatalogKey("origin", "origin"): originHosts},
    PendingCAs: nil,
}})

err = derivation.Apply(desired) // a *model.Desired
```

`Derive` needs what a contract does not author: per environment, the value
each trust domain substitutes for `{zone}` (`Environment.Zones`, keyed by
trust domain), the allowed names of every `catalog` role
(`Environment.Catalog`, keyed by `pki.CatalogKey(domain, role)`; an empty
answer is refused -- a role that could sign nothing), and the URI domains
whose root-signed CA for that environment is not committed yet
(`Environment.PendingCAs`; nothing is derived for one, and its mount and
key come from `apply.BootstrapEnvironmentCA` until the artifact exists).
Every environment gets every DNS domain; a URI domain reaches only the
environments it lists. It refuses a domain declared below a generation that
is not the active one.

The result is a `Derivation`: `Domains` (the domain intermediates, `external`
issuers whose committed artifact is at `ArtifactPath`) and `Issuing` (each
environment's issuing CA with its leaf roles and credential roles), and the
model's mounts built from them --

- `RootMounts()`: one mount per `domainMount`, the first authority creating
  it and the rest joining it as further issuers; the intermediate's lease is
  its lifetime.
- `EnvironmentMounts(env)`: the environment's `issuingMount`s; a mount's
  lease bounds are the longest default and longest maximum any role on it
  declares.
- `Apply(desired)`: adds both to a `model.Desired`. A mount the desired
  state already holds -- the mount a retiring chain lives in, while both are
  trusted -- keeps its own description, lease bounds and default issuer and
  receives the derived issuers and roles after what it has.

Each derived issuer carries the name constraint its shape implies (DNS or
URI subtrees, and no IP address at all), `signedBy` its domain intermediate
or `external` when the root signs it, and every derived role names its
issuer. Because the names come only from the contract, a consumer that
applies the result is registered under the names its contract spells; the
worked example's derivation is
[`pkg/pki/testdata/derive-estate.yaml`](../pkg/pki/testdata/derive-estate.yaml).

### Reading a contract from a file system

`Load` reads from disk. `LoadFS(fsys, name, dir)` reads the contract from a
file system that is not the working directory -- an embedded configuration
tree -- where `dir` is that file system's root relative to the working
directory (`cfg` for a repository that keeps its configuration in `cfg/`).
`ArtifactPath` still names paths a command run from the repository root can
open (`cfg/pki-roots/...`), while `TrustAnchors`, `IntermediateSigned` and
`LoadSignedIntermediate` read the committed artifacts through `fsys`, so a
render and a ceremony agree on one fact from one file. `LoadSignedIntermediateAt`
proves the artifacts of a checkout on disk instead.

### Adopting a deployed estate: the schema stays at version 1

Everything above is additive: every field is optional, and a contract that
validated before validates and derives the same now. The schema version is
therefore unchanged. An estate that already has its own contract file maps
it by field, not by rewriting anything it has signed:

- one map of trust domains becomes the two lists (`trustDomains.dns[]` with
  a `name`, `trustDomains.uri[]`), and the per-domain fixed shape becomes
  what the domain declares;
- `permittedDNSDomains` is `permittedDnsDomains`, `minimumTLSVersion` is
  `minimumTlsVersion`; a root's `artifactPath` becomes the contract's
  `artifactDir` (its `<generation>.yaml` name is fixed);
- a name source `cluster-local` is `static` and `gateway-catalog` is
  `catalog`;
- an existing serial label is `serialNamespace`, existing artifact names are
  `environmentCA.artifactPattern`, and existing issuer names are
  `environmentCA.issuerNamePattern` and the domain intermediates' own
  `name`; existing mounts and their descriptions are `domainMount`,
  `issuingMount` and the description templates.

## Trust anchors and the distributed bundle

`Contract.TrustAnchors()` resolves `migration.trustedGenerations` to the
committed root certificate of each one, re-deriving and checking every
public property (self-signed, subject, fingerprint) rather than trusting
the file on the strength of its path. This is the one list a distributed
trust bundle (a `ConfigMap`, a `Secret`, a client's own trust store) should
be built from -- a generation named in the contract before its ceremony ran
is a promise nothing can keep, so `TrustAnchors` fails rather than
returning an incomplete bundle.

## What this package deliberately does not do

- **No estate-specific glue.** Which environments exist, which AWS
  account's Pulumi stack output resolves to a generation's KMS key ARN, what
  zone an environment has and what names an external catalog supplies (the
  inputs of `Derive`) -- all of that is a consuming estate's own
  configuration, read by the program that calls this package. `pkg/pki` only carries the invariants that hold
  for ANY estate's private PKI.
- **No fixed role list.** A DNS trust domain may declare any set of roles;
  this package does not require an estate to offer exactly some fixed list
  in some fixed order. An estate that wants that as a POLICY (its own
  cross-validation, on top of `Validate`) is expected to enforce it in its
  own thin wrapper, the same way `Global.AdditionalLeafKeyCurves` lets a
  contract admit an exception without this package silently allowing every
  curve everywhere.
- **No OpenBAO login, no Pulumi resource, no policy.** `Derive` produces
  the PKI half of a desired state ([pkg/model](../pkg/model)); applying it
  ([pkg/apply](../pkg/apply)), the login cert-manager (or anything else)
  signs in with, and which groups may sign with which role are the calling
  program's. See [model.md](model.md) and [ceremony.md](ceremony.md).

See [adoption.md](adoption.md#adopting-an-existing-ceremony-and-custody)
for adopting a hierarchy that predates this package, and CHANGELOG.md for
what changed release to release.
