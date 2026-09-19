# OpenBAO and access-roster

How an OpenBAO server trusts an [access-roster](https://github.com/truvity/access-roster)
issuer, end to end: people, CI jobs and operators sign in with the
issuer's tokens, the token's `groups` claim decides which policies they
hold, and `accessctl credential` turns that into short-lived SSH and X.509
certificates. Nothing is stored: no OpenBAO token, no client secret on a
laptop, no long-lived key.

This page is the contract. Both sides implement it: this repository's
`pkg/model` preset ([`model.Roster`](#the-preset)) and its apply on the
OpenBAO side; access-issuer, `accessctl` and the GitHub Action on the
issuer side, whose own page is
[access-roster's docs/integrations/openbao.md](https://github.com/truvity/access-roster/blob/master/docs/integrations/openbao.md).
Any OIDC issuer that meets [the issuer side](#1-the-issuer-side) works the
same way; access-roster is the reference.

**It is tested.** [`conformance/roster_test.go`](../../conformance/roster_test.go)
starts a real `bao server -dev`, configures it with exactly what
`pkg/apply` registers for the neutral example
([`examples/roster`](../../examples/roster/roster.go), its golden
[`desired.yaml`](../../examples/roster/desired.yaml)), points it at a fake
issuer shaped like access-issuer, and walks every clause below: the
operators' login, the groups-to-policies mapping, an SSH and a database
certificate signed the way `accessctl` asks, the web UI's code flow across
namespaces, a CI job's read, and the refusals marked tested in
[failure modes](#7-failure-modes).

Without a `bao` binary the test skips; `just test` sets
`OPENBAO_CONFORMANCE=required`, so in the dev shell and in CI (where
devbox pins `openbao`) a missing server is a failure, never a silent skip.

```
             the issuer                                 OpenBAO, namespace {env}
 person ──sign-in──▶ session
        ──exchange──▶ token aud=openbao ──login──▶ auth/jwt-roster  role roster
 CI job ──GitHub OIDC──▶ (same exchange)             groups claim ─▶ identity groups ─▶ policies
                                                     ssh/sign/<role>   pki/sign/<role>   kv/data/<path>
 browser ──code flow as openbao-ui──────────────▶ auth/oidc  (the UI's door, same groups)
```

## 1. The issuer side

What an issuer must provide. access-issuer provides all of it.

- **Discovery.** `<issuer>/.well-known/openid-configuration` and the key
  set it names, reachable **from OpenBAO**: the mount fetches both when it
  is configured and when keys rotate. Tokens are signed RS256 (the JWT
  plugin's default; access-issuer signs nothing else).
- **`iss` equal to the issuer URL, byte for byte.** It is the mount's
  bound issuer. A trailing slash on one side and not the other is a
  refused login.
- **Claims.** `sub` (a person's is their email address; a job's or a
  workload's is whatever the issuer calls it), `email`, and **`groups`**:
  flat, one string per internal group, in every token the issuer mints,
  including ID tokens. No `groups` scope is asked for.
- **Two clients** (in access-roster's policy file, two `clients` rows):

  | Client | Kind | Who uses it | Token life |
  |---|---|---|---|
  | `openbao` | exchange | `accessctl` (people, on a laptop) and CI jobs: an RFC 8693 token exchange for audience `openbao`, presented at `auth/jwt-roster/login` | short: it is only ever presented at the login, and OpenBAO's own TTL governs the session after it (15 minutes is the reference) |
  | `openbao-ui` | confidential, authorization code | OpenBAO's web UI, through the `oidc` mount: OpenBAO holds the secret server-side and redeems the code itself | the sign-in only |

  `openbao-ui` registers one redirect URI, `<OpenBAO address>/ui/vault/auth/oidc/oidc/callback`
  (`model.UICallback`), for every namespace. Its client secret is an input
  of the apply (`apply.Options.OIDCClientSecrets`), never desired state:
  the issuer delivers it where the apply runs.

- **`requires`: who may be issued a token at all.** A client's `requires`
  names the internal groups any one of which admits somebody; outside
  them the exchange (and the UI's sign-in) is refused **before OpenBAO is
  reached**. List every group OpenBAO holds a policy for, plus the
  operators' group.

  **The two rows' `requires` are the same list**, less the groups only
  jobs hold (those go on `openbao` alone: a job has no browser). They are
  two doors to one set of identity groups; a group admitted through one
  and refused at the other reads as a broken UI rather than as a policy.
  Keep the two lists equal by a test in the estate that owns the policy
  file, not by review.

## 2. The OpenBAO side: two doors per namespace

Root and every environment namespace get the same two auth mounts. The
tree is one level (root, then `{env}`), so the namespace a person logs in
to is the environment's name.

**`jwt-roster`** — people and jobs, from the CLI and from CI:

| Setting | Value |
|---|---|
| `oidc_discovery_url`, `bound_issuer` | the issuer URL |
| role | `roster`, the only one: the groups claim decides the rest |
| `bound_audiences` | `[openbao]` |
| `user_claim` | `sub`: the entity alias is named after the subject |
| `groups_claim` | `groups` |
| `token_policies` | none: the identity groups carry the policies |
| `token_ttl` = `token_max_ttl` | short; the reference uses 15 minutes in root, an hour in an environment |

**`oidc`** — the web UI's door, beside it:

| Setting | Value |
|---|---|
| `type` | `oidc`; listed on the UI's sign-in page (`listing_visibility: unauth`) |
| `oidc_client_id`, `oidc_client_secret` | `openbao-ui` and its secret |
| `default_role` | `roster`, the same name, of type `oidc` |
| `bound_audiences` | `[openbao-ui]`: an ID token is issued to the UI's client |
| `user_claim`, `groups_claim`, TTL | the same as `jwt-roster`'s, so a person gets the same token either way |
| `allowed_redirect_uris` | the one callback above |
| `oidc_scopes` | `profile`, `email` (OpenBAO adds `openid`) |
| `namespace_in_state` | `true` |

**`namespace_in_state`** is what lets one redirect URI serve every
namespace. The UI asks for a sign-in URL with its callback plus
`?namespace=<ns>`; the mount strips the parameter before matching the
allowed redirects, and appends `,ns=<ns>` to the OIDC `state` instead. On
the way back the UI reads the namespace out of the state and completes
the callback in that namespace. The issuer never sees a namespace.

### The preset

`pkg/model` builds both doors, and the grants and operators' door below,
from one value. The zero value of every optional field is the name above;
the issuer and the lifetime are always said out loud.

```go
people := model.Roster{
    Issuer: "https://id.example.com",
    TTL:    "1h",
    UI: &model.RosterUI{RedirectURIs: []string{
        model.UICallback("https://openbao.example.com", model.RosterUIMount),
    }},
}

namespace := model.Namespace{Name: "dev", Auth: people.Doors()}   // jwt-roster, oidc
policy, group := people.Grant("dev:ssh:user",
    model.Rule{Path: "ssh/sign/user", Capabilities: []string{model.CapUpdate}})
desired.Identity = people.Identity(nil)                           // jwt-roster is primary
```

| API | Returns |
|---|---|
| `Roster{Issuer, TTL, Audience, GroupsClaim, UserClaim, ClaimMappings, Mount, Role, Description, UI}` | the issuer as OpenBAO trusts it; defaults `openbao`, `groups`, `sub`, `jwt-roster`, `roster` |
| `RosterUI{Mount, ClientID, RedirectURIs, Scopes, Description}` | the UI's door; defaults `oidc`, `openbao-ui`, `profile email`; redirect URIs required |
| `Roster.Door()`, `UIDoor()`, `Doors()`, `DoorPaths()` | the mounts, as `model.JWTMount`s, and their paths |
| `Roster.Grant(group, rules...)` | a policy named after the group and the group admitted through every door |
| `Roster.JobGrant(group, rules...)` | the same, through `jwt-roster` alone |
| `Roster.Identity(metadata)` | `model.Identity` with `jwt-roster` as the primary door |
| `Roster.Bootstrap(operators)`, `RootUI(operators)` | [the operators' door](#4-the-operators-door) |
| `OperatorPolicy(name)`, `UICallback(address, mount)` | every capability on `*`; the UI's callback URL |

The doors are ordinary `model.JWTMount`s, validated like any other: a
door with no issuer, no TTL or a UI with no redirect is refused before
anything is applied.

## 3. Groups become identity groups become policies

The token's `groups` are internal group names, and **OpenBAO binds them
as they are**: for each group it holds a policy for, an external identity
group of the same name, aliased on `jwt-roster` by that name, carries the
policy. The name is the whole mapping; nothing re-maps it.

- **One identity group per door.** OpenBAO gives an identity group one
  alias; a second alias silently replaces the first. So the UI's door has
  its own identity group, `<group>@oidc`, aliased on `oidc` by the same
  name and carrying the same policies ([model.md](../model.md#groups-and-doors)).
- **A policy per group, named after it.** `dev:ssh:user` holds `update`
  on `ssh/sign/user`; `dev:db:client` on `pki/sign/db-client`;
  `dev:openbao:reader` reads `kv/data/*`. `Roster.Grant` makes the pair.
  An estate's names follow access-roster's
  [naming rule](https://github.com/truvity/access-roster/blob/master/docs/design/trust.md#naming):
  `{env}:{thing}:{role}`, `{env}:{project}:{role}`, `all:{thing}:{role}`.
- **A group OpenBAO knows nothing about is ignored.** The login succeeds
  with the `default` policy alone, and every call it then makes is a 403.
- **A job's group is admitted through `jwt-roster` only** (`JobGrant`):
  its policy is one read of one path, and it has no `@oidc` twin.
- The role attaches no policy of its own, so **who holds a group is
  decided in one place**: the issuer's policy file.

## 4. The operators' door

The root namespace's `jwt-roster` is the door the operators, and the apply
itself, log in through. Its group (`all:openbao:operator` in the example)
carries `OperatorPolicy`: every capability on `*`, which in root reaches
every namespace below it. It replaces the root token.

- **It is not the apply's.** An apply that owned the door it logs in
  through could lock itself out halfway, so the model declares it as
  `Desired.Bootstrap` (`Roster.Bootstrap(operators)`) and `pkg/apply`
  never touches it. The server's initialisation creates it once with the
  initial root token — the auth mount and its config, the role, the
  policy, the external group and its alias — and the root token is
  revoked after the first operator login succeeds.
- **The apply logs in through it**: `apply.Login{Mount: model.RosterMount,
  Role: model.RosterRole, Token: <an operator's exchanged token>}`.
- **The operators' web UI door in root** is ordinary desired state
  (`Roster.RootUI(operators)`): the `oidc` mount and the operators' group
  admitted through it, carrying the bootstrap's policy by name.
- Root's token TTL is the operator session's whole life: keep it short.

## 5. Credentials: what `accessctl credential` calls

One exchange, one login, **one** `sign`, then `auth/token/revoke-self`.
Every kind signs a key made on the caller's machine, so no role needs to
offer `issue`, and `accessctl` never sends a TTL: the role's `ttl` and
`max_ttl` are the whole answer.

| Command | Call (in namespace `--env`) | What is sent | What the role must be |
|---|---|---|---|
| `credential ssh` | `ssh/sign/user` | an **ed25519** public key; `valid_principals` only if `--principal` asked | user certificates only; `allowed_users` spelled out, never root; `allowed_user_key_lengths` admitting ed25519; `key_id_format` `{{token_display_name}}`; no user-chosen key ids; extensions no wider than needed |
| `credential ssh --role admin` | `ssh/sign/admin` | the same | a second role for the account that administers a host, granted to a separate group |
| `credential db` | `pki/sign/db-client` | a CSR for an **ECDSA P-384** key, common name = the subject, and `common_name` again in the body | `key_type ec`, `key_bits 384`; the one allowed name is the caller's own alias name on `jwt-roster` (`allowed_domains` = `{{identity.entity.aliases.<accessor>.name}}`, templated, bare); `cn_validations email`; client auth only; `no_store` |
| `credential client` | `pki/sign/client` | the same key and CSR, plus any `--uri-san` | the installation's: client auth, the SAN its consumer matches on |

`model.SSHRole` and `model.CredentialRole` are exactly the first three,
with everything they do not allow spelled out by the apply; the example
declares `user`, `admin` and `db-client`. A machine `client` role with URI
SANs is not modelled.

- **The key id** of an SSH certificate is the login's display name:
  `<namespace>-auth-jwt-roster-<subject>`. An sshd log line is read
  against the issuer's audit trail by it.
- **Where.** `--env <env>` is the namespace; `--namespace` or
  `BAO_NAMESPACE` (then `VAULT_NAMESPACE`) overrides it. `--address` or
  `BAO_ADDR` (then `VAULT_ADDR`) names the server. `--mount`,
  `--login-role` and `--audience` override `jwt-roster`, `roster` and
  `openbao`.
- **A private root.** `--ca-cert <bundle>` or `BAO_CACERT` (then
  `VAULT_CACERT`) adds a PEM bundle to the system's roots for the OpenBAO
  connection alone (accessctl 1.16.2 and later).
- **The policy is `update` on the sign path and nothing else**: no `read`
  or `list` on a role or configuration path.
- **Lifetimes** are capped by `Desired.CredentialMaxTTL`: the model
  refuses an SSH or credential role above it.

## 6. CI jobs

A job logs in through the same `jwt-roster` door with its **own** identity,
exchanged; nothing is stored in the repository or the runner.

1. The job has `permissions: id-token: write` and asks GitHub for an OIDC
   token **for the issuer's own URL** as the audience.
2. It exchanges that token at the issuer for audience `openbao`. The
   issuer's `ci` rules (repository, ref, event, workflow) put the job in
   its groups, and the `openbao` client's `requires` admits it or not.
   `accessctl token --audience openbao` does both steps in a job;
   access-roster's GitHub Action writes only `k8s:` and `aws:` audiences,
   so for OpenBAO the job runs `accessctl`.
3. `auth/jwt-roster/login` with `role=roster` in the namespace, the one
   read (or one `sign`: `accessctl credential` runs unchanged in a job, and
   `--identity` writes the SSH certificate to disk, since a job has no
   agent), then `auth/token/revoke-self`.

```sh
token=$(accessctl token --issuer "$ISSUER" --audience openbao)
login=$(jq -n --arg jwt "$token" '{role: "roster", jwt: $jwt}' |
  curl -fsS -H "X-Vault-Namespace: dev" -X POST --data @- "$BAO_ADDR/v1/auth/jwt-roster/login")
```

[truvity/ci-workflows' `openbao-secrets` action](https://github.com/truvity/ci-workflows/tree/master/.github/actions/openbao-secrets)
is exactly this, with masking and the revoke, reading one KV path into
step outputs. The job's group is a `JobGrant`: `read` on
`kv/data/<path>`, no metadata, no list, no wildcard.

## 7. Failure modes

How each failure shows up, and where. The rows marked tested are
reproduced by the conformance test, which pins the status; the messages
are OpenBAO 2.6's. `accessctl` maps statuses to exit codes: `4` for a
refusal (the issuer's, or OpenBAO's 403), `5` for unreachable or a 5xx,
`1` otherwise, with OpenBAO's own sentence.

| Symptom | Where | Cause | Fix | Tested |
|---|---|---|---|---|
| `accessctl` exit `4`, "that audience is not granted to you", before OpenBAO | the issuer's exchange | the caller holds none of the `openbao` client's `requires` | grant the group in the issuer's policy, or add it to `requires` | — |
| the UI's sign-in ends on the issuer's refusal page | the issuer's sign-in | none of `openbao-ui`'s `requires`: the two lists drifted | make them equal again | — |
| login `400` "error validating token: invalid audience (aud) claim" | `auth/jwt-roster/login` | a token for another client — the UI's, or one exchanged with the wrong `--audience` | exchange for `openbao` | yes |
| login `400` "invalid issuer (iss) claim" | the login | `iss` differs from the bound issuer: a trailing slash, another host name | set the discovery URL to the issuer's `iss` exactly | yes |
| login `400` "error verifying token signature" | the login | a token from another issuer, or keys OpenBAO has not fetched | check the discovery URL; OpenBAO must reach the key set | yes |
| login `400` "token is expired" | the login | the exchanged token outlived its cap, or clock skew | exchange afresh; `accessctl` does on every run | yes |
| the apply fails writing `auth/<mount>/config` with `400` | the apply | OpenBAO cannot fetch the discovery document | network path from OpenBAO to the issuer, and its TLS trust | — |
| login succeeds, then every call is `403` "permission denied" (`accessctl` exit `4`) | the sign or read | the group is not in the token, or OpenBAO holds no identity group for it (a group it does not know is ignored), or it is admitted through the other door only | grant the group; `Roster.Grant` admits it through both doors | yes |
| `400` "common name … not allowed by this role" | `pki/sign/db-client` | a common name that is not the caller's own subject | ask for your own; the role signs nobody else | yes |
| `400` "role requires a minimum of a 384-bit key" | `pki/sign/<role>` | a key the role does not sign | `accessctl` sends P-384; a hand-made CSR must too | yes |
| `400` "… is not a valid value for valid_principals" | `ssh/sign/<role>` | an account the role does not list | the role's `allowed_users` is the list; use the other role for the other account | yes |
| `404` (`accessctl`: "does not exist: the mount or the role has not been created in this namespace") | the sign | the wrong `--env` or `--namespace`, or a role the installation does not have | check the namespace; the apply creates the roles | — |
| the UI's sign-in button does nothing (an empty `auth_url`) | `auth/oidc/oidc/auth_url` | the callback is not an allowed redirect: the address in the model is not the one the browser uses | `model.UICallback` with the address browsers reach | yes |
| the UI's callback fails with `invalid_client` at the issuer | the code redemption | the `oidc` mount holds a stale client secret | re-apply with the issuer's current secret | — |
| `accessctl` exit `5` with "a private root? pass --ca-cert" | the TLS handshake | OpenBAO's certificate chains to a root the system does not know | `--ca-cert` or `BAO_CACERT` | — |
| the apply cannot log in | the operators' door | the bootstrap was never created, or the caller is not in the operators' group | run the initialisation; grant the group | — |
