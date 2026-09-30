# The KMS-rooted CA ceremony

A private PKI whose root key lives in AWS KMS and never leaves it, and
whose intermediates' keys live in OpenBAO and never leave it. The root key
signs a handful of certificates in its life, each on purpose, each once:

```
<root generation>                         self-signed in KMS, P-384, committed as an artifact
├── <trust domain> intermediate           key in an OpenBAO PKI mount; CSR out, certificate back
│   └── (environment issuing CAs, leaves: OpenBAO's, not the ceremony's)
└── break-glass server leaf               only when OpenBAO cannot issue its own; never committed
```

`pkg/ceremony` is the mechanism; `openbaoctl pki` is the command over it.
The custody the key needs (key policy, roles, the Sign alarm) is
[custody.md](custody.md). A program that holds its own contract (a
consuming estate's configuration) builds `ceremony.RootSpec`,
`IntermediateSpec` and `EmergencyServerSpec` directly and calls the same
functions; `openbaoctl` reads them from a hierarchy file or, with `--contract`, from a `pkg/pki` contract ([reference.md](reference.md#openbaoctl)). [pkg/pki](pki.md)
is that contract layer, written once so most estates do not have to: root
generations and their custody, the trust domains and per-environment
leaf roles below them, and the invariants that keep the hierarchy
consistent as it grows.

## The hierarchy file

```yaml
# pki.yaml -- artifact paths are relative to this file
root:
  generationId: example-root-2026-01
  subject: { commonName: Example Private Root 2026-01, organization: Example Org }
  notBefore: "2026-01-01T00:00:00Z"
  lifetime: 175200h              # 20 years
  maxPathLen: 3                  # intermediate -> issuing CA -> project CA -> leaf
  artifact: roots/example-root-2026-01.yaml
intermediates:
  - trustDomain: private
    subject: { commonName: example.internal Intermediate CA, organization: Example Org }
    lifetime: 87600h
    permittedDnsDomains: [example.internal, cluster.local]
    artifact: roots/example-root-2026-01-intermediate-private.yaml
  - trustDomain: origin
    subject: { commonName: example.com Origin Intermediate CA, organization: Example Org }
    lifetime: 87600h             # no constraint: limited by OpenBAO role policy
    artifact: roots/example-root-2026-01-intermediate-origin.yaml
  - trustDomain: identity
    subject: { commonName: Workload Identity Intermediate CA, organization: Example Org }
    lifetime: 87600h
    permittedUriDomains: [example.internal]   # every environment's SPIFFE trust domain is a subdomain of this
    artifact: roots/example-root-2026-01-intermediate-identity.yaml
emergencyServer:
  dnsName: openbao.example.internal
  # lifetime: 168h               # the default; at most 720h
```

An intermediate starts with the root's `notBefore` and its path length is
one less than the root's. `serialNamespace` (default `private-pki`)
prefixes the label every deterministic serial is derived under; an existing
root is re-verified only under the namespace it was created with, so never
change it once a root exists. The file is read strictly: an unknown key is
an error. The full field list is in [reference.md](reference.md#hierarchy-file).

### Choosing the shape

| Choice | Take | Why |
|---|---|---|
| curve | P-384, `ECDSA_SHA_384`, fixed | one curve end to end; KMS `ECC_NIST_P384` |
| root name constraint | none | a root that lives 20 years must not encode today's zone list |
| intermediate name constraint | where the names are yours alone | re-issuable under the same root; the constrained one also excludes every IP |
| `maxPathLen` | the depth you will need, bounded | each layer is exactly one less than its parent, so a leaf-level CA cannot mint a sub-CA |

**A workload-identity domain intermediate carries `permittedUriDomains`
alone -- no `permittedDnsDomains`.** It sits beside the DNS-constrained
domain intermediates, signed by the same root, and per-environment
identity issuing CAs go underneath it
([ADR 0002](decisions/0002-workload-mtls-service-and-identity-roles.md)).
`IntermediateTemplate` marks the whole name-constraints extension
critical and excludes every IP whenever either subtree is set, and
`verifyIntermediate` checks whichever the spec authored -- DNS, URI, both
or (for an intermediate limited by OpenBAO role policy alone, like
`origin` above) neither. The URI constraint is minted here, never by
OpenBAO's own root or intermediate generation endpoints, which is worth
restating from [model.md](model.md#pki-mounts-issuers-roles): OpenBAO
2.6.2 silently ignores `permitted_uri_domains` on those endpoints, the
same way it already ignores `excludedIpRanges`.

> **Custody cross-check.** With `--contract`, every command below that
> signs (`create-root`, `sign-intermediate`, `sign-emergency-server`) also
> takes `--custody-outputs <file>` (the custody side's published key, region,
> replica and role) and refuses to go on when the key, its region or replica,
> the generation, the role or the profile disagree with it or with the
> contract; `--skip-custody-check "<reason>"` is the printed, logged
> exception. See [pki.md](pki.md#the-custody-cross-check).

## 1. The root

The KMS key must exist first ([custody.md](custody.md)), and its Sign
alarm must be proven to reach somebody: the ceremony is itself a Sign and
will raise it.

```sh
openbaoctl pki create-root --hierarchy pki.yaml \
  --key-arn <the generation's primary key ARN> \
  --aws-profile <admin profile> --role-arn <ceremony role ARN>
```

The command reads the KMS public key (P-384, `SIGN_VERIFY`, `ECDSA_SHA_384`
or it refuses), builds the template -- deterministic serial, SKI and AKI
the SHA-256[:20] of the public key, the authored subject, validity, path
length and constraint -- exclusively creates and fsyncs
`<artifact>.attempt`, and only then asks KMS for one digest signature. It
verifies the result against the template and writes the artifact without
overwrite:

```yaml
generationId: example-root-2026-01
keyArn: <the key ARN>
certificatePem: |
  -----BEGIN CERTIFICATE-----
  ...
fingerprintSha256: <upper-case hex>
subjectKeyIdentifier: <upper-case hex>
notAfter: "2045-12-27T00:00:00Z"
```

Commit both files. A rerun that finds a valid artifact verifies it and
signs nothing. `--import-certificate root.pem` records a root produced in
an earlier controlled ceremony: it is verified exactly like a fresh one
(self-signature, KMS key match, serial, validity, path length, key
identifiers, algorithm, and exactly the authored name constraint) and
nothing is signed.

## 2. The domain intermediates

Each intermediate's key is generated inside its OpenBAO PKI mount
(`<mount>/intermediate/generate/internal`, with `exclude_cn_from_sans`),
and what leaves the mount is a CSR with exactly the authored subject and
no alternative name. Export it from where it was generated, never from a
chat.

**Dry run first, and let a second person repeat it.** It needs no
credential:

```sh
openbaoctl pki sign-intermediate --hierarchy pki.yaml \
  --trust-domain private --csr private.csr --print-template
```

It prints every field that will be in the certificate and a `template
sha256`: the SHA-256 of the exact TBSCertificate the root key would sign.
Nothing in it depends on the signer, so two people with the same branch
and CSR get the same hash. Check that the subject is the authored one, the
issuer is the root, the name constraints are what the domain should carry,
and the validity sits inside the root's. Both write the hash down; it is
the only thing the signing run accepts.

**Sign, once per domain:**

```sh
openbaoctl pki sign-intermediate --hierarchy pki.yaml \
  --trust-domain private --csr private.csr \
  --confirm-template <the sha256> \
  --aws-profile <admin profile> --role-arn <ceremony role ARN>
```

The command rebuilds the template and refuses a hash that is not its hash
**before** it reserves anything (a typo costs nothing), checks that the
KMS public key is the key behind the committed root, reserves
`<artifact>.attempt`, signs once, proves the result and writes the
artifact. It prints one line per property proven:

- the signed body's SHA-256 is the confirmed hash;
- the signature verifies with the root key and the certificate chains to
  the committed root;
- the public key is the CSR's (the private half never left OpenBAO), the
  SKI derives from it, the issuer and AKI name the root;
- subject, deterministic serial and validity match the template;
- `CA:TRUE` with the path length one below the root's; key usage exactly
  `certSign, crlSign`;
- the name constraints exactly as authored, or no extension at all.

`--key-arn` defaults to the root artifact's `keyArn`; the region is read
from the ARN. Commit the artifact and its reservation with the root.

## 3. Installing an intermediate

Nothing here signs or needs a KMS credential. Prove the committed artifact
against the hierarchy and the root, and get the chain OpenBAO takes:

```sh
openbaoctl pki verify-intermediate --hierarchy pki.yaml \
  --trust-domain private --chain-out private-chain.pem
bao write <mount>/intermediate/set-signed certificate=@private-chain.pem
```

The chain is the intermediate followed by the root: the root arrives as a
keyless issuer, which is what lets OpenBAO serve a complete `ca_chain` for
every leaf below. A program that installs through its own tooling (a
Pulumi program, a controller) calls `ceremony.LoadSignedIntermediate` and
hands over `ChainPEM`: a swapped, edited or stale artifact then fails the
preview, not the apply. After installing, the certificate OpenBAO reports
for the issuer must be the artifact's, byte for byte.

## 4. The break-glass server certificate

For the two moments OpenBAO cannot issue its own serving certificate: it
has expired (cert-manager can no longer reach OpenBAO to renew it), or no
OpenBAO exists yet (a new cluster, or a restore onto one). The root signs
**one** leaf, **directly**, for the one `emergencyServer.dnsName`, for a
week. Every OpenBAO client already trusts the root, so the leaf verifies
everywhere the normal chain does; cert-manager replaces it through
OpenBAO as soon as OpenBAO answers.

A leaf from the root rather than an emergency intermediate: the same one
signature and the same alarm either way, but an intermediate would put a
CA key on a laptop that could sign any name for its whole life. This key
serves one name for a week. The root publishes no revocation, so the
lifetime is the bound.

```sh
# 1. Key and request, on the operator's machine, in a private directory.
umask 077; d=$(mktemp -d)
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes \
  -keyout "$d/tls.key" -out "$d/openbao.csr" \
  -subj "/CN=openbao.example.internal" -addext "subjectAltName=DNS:openbao.example.internal"

# 2. The template, reviewed by a second person (prints --not-before and the hash).
openbaoctl pki sign-emergency-server --hierarchy pki.yaml --csr "$d/openbao.csr" --print-template

# 3. Sign. THE SIGN ALARM FIRES: tell whoever receives it first.
openbaoctl pki sign-emergency-server --hierarchy pki.yaml --csr "$d/openbao.csr" \
  --not-before <printed> --confirm-template <sha256> --out "$d/tls.crt" \
  --aws-profile <admin profile> --role-arn <ceremony role ARN>

# 4. Install: writes (or replaces) tls.crt, tls.key and ca.crt in the
#    Secret the server mounts, keeping the Secret itself -- its type and
#    cert-manager's annotations, when it already exists.
openbaoctl pki install-emergency-server \
  --certificate "$d/tls.crt" --private-key "$d/tls.key" --ca-bundle <the root's certificate PEM> \
  --namespace <the server's namespace> --kubeconfig <kubeconfig> --kube-context <context>
```

`install-emergency-server` refuses before it touches the cluster: a leaf
that does not chain to `--ca-bundle` alone, a key that is not the leaf's,
one that is a CA, or one that is expired or lives past the 30-day
break-glass cap. `--kube-context` is required -- there is no
current-context fallback, because the one thing a break-glass write must
confirm is the cluster, and a laptop's current context is often the wrong
one. It prints what it is about to write -- the resolved context and API
server, the Secret, its keys, the certificate's subject, names, validity
and fingerprint -- and never the key, then requires `--yes` or a typed
confirmation before writing. With the chart's
`tlsReload` sidecar the server serves the new certificate within minutes
(nothing here reloads it: that sidecar watches the files it just wrote).
Nothing is committed: both the leaf and the Secret write are incident
artifacts. `sign-emergency-server` refuses an existing `--out` before it
signs, because a signature whose output cannot be written is an alarm for
nothing.

### On a new or restored cluster, this runs before OpenBAO's first sync

The two moments this section opens with are not symmetric. On a running
cluster with an expired certificate, the Secret already exists --
`install-emergency-server` only replaces its data. On a new cluster, or a
restore onto one, **no OpenBAO has ever answered, so the Secret does not
exist, and whatever issuer normally requests through OpenBAO cannot issue
until something does.** Steps 1-4 above must run, and the Secret must
exist, **before** a GitOps controller's first sync of whatever installs
the server: a consuming estate's cluster-bootstrap runbook should say
exactly where in its ordering this belongs. Getting this backwards is the
same outage either way: the issuer retries against an OpenBAO that cannot
answer, on its own backoff, indefinitely.

### The yearly drill: the real KMS root, once, by hand

Every rehearsal that runs in CI or on a schedule -- `just
rehearse-bootstrap-tls` (`openbao`'s own conformance suite) and the
weekly restore-check -- signs with a **local stand-in signer**: the same
`kmssigner.API` double `pkg/ceremony`'s own tests use, never a KMS
credential. That proves the mechanism (the template, the install, the
listener, the handoff to a normal issuer) but never that an operator can
actually drive steps 1-4 against the **real** KMS root, with a real
two-person review, under real custody controls (the Sign alarm actually
reaching someone, the ceremony role actually being assumable).

Once a year, run steps 1-4 for real, against a non-production
hierarchy: generate a throwaway root generation (`create-root`), sign a
break-glass leaf for a throwaway name with the real KMS ceremony role,
install it as this section describes, confirm a client verifies it
against the root alone, and confirm the Sign alarm arrived. Record the
date and who ran it in the consuming estate's restore runbook, with the
next one due one year later. **A real bootstrap must still re-sign the
leaf before its 7 days lapse** -- the drill proves the mechanism works,
not that a 7-day-old leaf from last year's drill is still good.

## What never to do

- **Never delete or rename an `.attempt` reservation** to try again. A
  root reservation with no artifact means the generation is burnt: author
  a new generation with a new KMS key. An intermediate's burns only that
  CSR: have OpenBAO generate a fresh key and CSR (a different serial) and
  sign that.
- **Never sign a hash you did not review.** The confirm step exists so the
  root key signs only bytes a second person has derived independently.
- **Never pass `--` to `go run` before the flags** if you run the command
  from source: the flag parser reads it as "stop parsing", the required
  flags never arrive, and the refusal at the signing step looks like a
  failure worth retrying.
