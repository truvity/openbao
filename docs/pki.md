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
   with the KMS root. The result is committed under `ArtifactDir`, next to
   its `.attempt` reservation.
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

## Break-glass

`Contract.EmergencyServerSpec(generationID, dnsName, notBefore)` derives
the break-glass declaration for the one moment OpenBAO cannot issue its own
serving certificate: the generation must be `active` AND already in
`migration.trustedGenerations` (a leaf of a root nobody trusts restores
nothing), and `dnsName` must sit under a `dns` trust domain that
`requireTrusted`. Nothing is ever committed to the artifact directory for
this leaf -- see [ceremony.md](ceremony.md#break-glass) for the signing
steps.

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
  account's Pulumi stack output resolves to a generation's KMS key ARN, how
  a role's `environment-zone` pattern gets a real zone substituted -- all
  of that is a consuming estate's own configuration, read by the program
  that calls this package. `pkg/pki` only carries the invariants that hold
  for ANY estate's private PKI.
- **No fixed role list.** A DNS trust domain may declare any set of roles;
  this package does not require an estate to offer exactly some fixed list
  in some fixed order. An estate that wants that as a POLICY (its own
  cross-validation, on top of `Validate`) is expected to enforce it in its
  own thin wrapper, the same way `Global.AdditionalLeafKeyCurves` lets a
  contract admit an exception without this package silently allowing every
  curve everywhere.
- **No OpenBAO login, no Pulumi resource.** Building the desired state
  ([pkg/model](../pkg/model)) and applying it ([pkg/apply](../pkg/apply))
  from a contract's roles and environments is the calling program's job;
  see [model.md](model.md) and [ceremony.md](ceremony.md) for those layers.

See [adoption.md](adoption.md#adopting-an-existing-ceremony-and-custody)
for adopting a hierarchy that predates this package, and CHANGELOG.md for
what changed release to release.
