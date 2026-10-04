# Bootstrapping a fresh server: `pkg/bootstrap` and `openbaoctl`

A freshly installed OpenBAO is uninitialized. Taking it to its first operator
login, and then retiring the root token that made that login possible, is the
one moment in an install's life that handles **recovery shares and a root
token**. This package does that, once and carefully, and leaves custody of the
secrets to the caller.

```text
uninitialized --init--> initialized --configure--> operators can log in --revoke-root--> no root token
                          (shares + root token        (door, policy, group)    (shares proven, then revoked)
                           to the Keeper)
```

Everything here is idempotent: each step run again verifies or converges and
changes nothing else.

## The steps

| Step | Library | `openbaoctl` | What it does |
|---|---|---|---|
| Initialize | `Bootstrap.Initialize` | `init` | Verifies the Keeper (write, read back, delete a canary), refuses a seal whose shares would be unseal keys and stale items of an earlier install, initializes with `secret_shares: 0` (auto-unseal: only the recovery key is split), stores every share and the root token and reads each back. On an initialized server it only checks every share is on file. |
| Configure | `Bootstrap.Configure` | `configure` | With the root token: waits for an unsealed server with a leader and every Raft voter, refuses an unaudited one and a non-empty one, then converges the operators' door: a JWT auth mount on the roster issuer, its one role, the operator policy and an external identity group aliased on that mount (`model.Roster.Bootstrap`). |
| Revoke the root token | `Bootstrap.RevokeRoot` | `revoke-root` | Refuses until an operator login is proven (below), then generates a root token from the recovery shares (the generate-root drill: sets of shares chosen so **every** share is submitted at least once), revoking each generated token at once, and only then revokes the bootstrap token and archives its Keeper item. |
| Readiness | `Bootstrap.Ready` | (inside `configure`) | Unsealed, a leader, `Settings.Voters` Raft voters. |
| Audit check | (inside `configure`) | | The declarative audit device (`Settings.AuditDevice`, default `to-stdout`) must be enabled; it comes from the server configuration, never the API. |
| Rebuild drill | `RestoreDrill` | `drill start`, `forward`, `stop` | A scratch pod built from the weekly restore check's own pod spec that restores the newest snapshot into a throwaway server, for an operator to inspect a copy of the data. No secret passes through it. |
| Connection | `PortForward`, `NewTLSClient` | `--addr` + `--ca-file`, or `--port-forward` | TLS is always verified, against a CA you name, for a name the certificate holds. There is no insecure mode. |

`init` also records the recovery split it used as the non-secret item
`openbao-recovery-split` (`5/3`). `revoke-root` and a verifying `init` refuse
settings that disagree with it, and refuse keeper items numbered past the
configured shares, so a share is never left out of the drill. An install from
before the split was recorded has no such item and only gets the second check.

Root generation is authenticated since OpenBAO v2.6, so the drill runs on the
bootstrap root token while it still exists; a drill after revocation is an
operator's.

## Using it

As a library, with the estate's facts as inputs:

```go
b := &bootstrap.Bootstrap{
    API:      client,            // bootstrap.NewTLSClient or PortForward.Connect
    Keeper:   myKeeper,          // yours: where the secrets live
    Logger:   logger,
    Poll:     5 * time.Second,
    Now:      time.Now,
    Settings: bootstrap.Settings{Voters: 3, Description: "my cluster"},
}

err := b.Initialize(ctx)
err = b.Configure(ctx, bootstrap.OperatorLogin{Issuer: issuerURL, Group: "ops:operators"})
b.OperatorJWT = token // a roster token for the OpenBAO audience; the caller owns the slice
err = b.RevokeRoot(ctx, "ops:operators")
```

`Settings` defaults: five shares, a threshold of three, three voters, audit
device `to-stdout`, a five minute readiness wait. `OperatorLogin` defaults: a
15 minute token and claim mappings `email` and `name`.

As a command, with the reference file/age Keeper:

```sh
openbaoctl init         --addr https://127.0.0.1:8200 --ca-file ca.pem --tls-server-name openbao.example.internal \
                        --keeper-dir ./keeper --age-identity-file ./age-identity.txt
openbaoctl configure    ...same connection and keeper flags... \
                        --issuer https://issuer.example --operator-group ops:operators
openbaoctl revoke-root  ...same connection and keeper flags... \
                        --operator-group ops:operators --operator-jwt-file ./operator.jwt
openbaoctl drill start    --kube-context <context> --namespace openbao
openbaoctl drill forward  --kube-context <context> --namespace openbao
openbaoctl drill stop     --kube-context <context> --namespace openbao
```

`--addr` must be the bootstrap node (the first Raft voter), never a load balancer
or a follower: an uninitialized follower that has not joined reports "not
initialized", and initializing it would found a second cluster. The client never
follows a redirect (a 3xx is an error), so a token or a share cannot be re-sent
to wherever an answer points.

Before a pod is ready no Service has an endpoint, so `--port-forward` (with
`--kube-context`, `--namespace`, `--pod`, `--tls-secret`) reaches the first
voter through `kubectl port-forward` and reads the **public** `ca.crt` of the
serving Secret; nothing else is used (kubectl does fetch the whole Secret to
filter it, so that kubeconfig can read the private key: use a narrowly-scoped one).
`--tls-server-name` and `--kube-context` are required with it. The forward is its own process group (and on Linux the kernel SIGTERMs it if openbaoctl dies, SIGKILL included; on other systems a SIGKILLed openbaoctl leaves the `kubectl port-forward` running: kill it by hand) and outlives the caller's cancellation: it ends only when the command's cleanups are done, so a Ctrl-C does not cut the tunnel the cleanups need.

### Printing the shares

The shares are **never printed**. `init --insecure-print-recovery-shares-to-stdout`
prints them to stdout once, after they are stored and read back, with a warning
on stderr, and only in the run that initialized the server (`Bootstrap.Founded`):
on an install that was initialized earlier it prints nothing, for the one case where they must be moved into a custody this tool
does not reach. Do not use it in a shared terminal, a CI log or a recorded
session. The root token is never printed under any flag.

### Revoking root: the proof

`revoke-root` demands a proof that an operator can log in **now**:
`--operator-jwt-file` (a roster token for the OpenBAO audience, `-` for stdin)
is used to log in through the door, and the login must return the operator
policy and be able to read it; that token is revoked at once.
`--membership-evidence-only` (library: leave `Bootstrap.OperatorJWT` empty)
settles for a member already on file in the operator group, which shows someone
logged in once, not that the door works today. Prefer the proof.

## The Keeper

```go
type Keeper interface {
    Titles(ctx) (map[string]bool, error)                          // names only, no secret
    Create(ctx, title string, secret []byte, notes string) error  // must fail if it exists
    Reveal(ctx, title string) ([]byte, error)
    Archive(ctx, title string) error                              // out of Titles, still recoverable
    Delete(ctx, title string) error                               // only the preflight canary
}
```

Items: `openbao-recovery-1` .. `openbao-recovery-N`, `openbao-root-token`, and the
transient `openbao-init-canary`. The Keeper must not log, print, cache or put a
secret in an error; `Create` must not retain its slice (the package zeroes it
afterwards); `Reveal` returns a slice the package owns and zeroes.

`pkg/bootstrap/filekeeper` is the reference: one age-encrypted file per item
(0600, directory 0700), refusing to overwrite, archiving into `archive/`.
**It is a reference, not a vault.** A share stored next to the identity that
decrypts it is not protected; where the age identity lives and who can read it
is your custody decision. A password manager or a hardware-backed store is the
production answer, behind this same interface.

## Threat model

What this code defends, against whom, and what it does not.

**Assets.** The recovery shares (any threshold of them reconstruct the recovery
key and can generate a root token), the root token (everything), the operator's
login token (everything the operator policy grants).

**In scope.**

- *A mistake that loses the shares or locks every operator out.* The rules
  below (preflight, read-back, no revoke before a proven login, drill before
  revoke) exist for this, and each has a test.
- *Secrets leaking into places that outlive the run:* a log line, an error
  message (which ends up in CI output, a ticket, a chat), a process argument, a
  file. See the secret flows.
- *A server error that echoes a secret.* Messages are scrubbed.
- *A half-done step.* An open generate-root attempt, or a drill-generated root
  token whose check failed, is cancelled or revoked before the error returns,
  including after Ctrl-C or SIGTERM: `openbaoctl` turns those into context
  cancellation, and the cleanups run on a context of their own (30 seconds,
  independent of the caller's). A cleanup that fails is part of the returned
  error, with the command to run by hand. The first Ctrl-C starts the cleanups; a second one is swallowed until they finish (30 seconds at most), so wait. SIGHUP, SIGINT and SIGTERM all start the cleanups. A SIGKILL, or a power loss, runs
  nothing: an open generation then blocks the next run until it is cancelled
  with `bao operator generate-root -cancel`, and a generated root token
  survives until revoked by accessor.
- *The init call's answer lost.* `init` gets its own, longer bound (five
  minutes). If no answer arrives it asks the server again: still uninitialized
  means nothing was lost and no advice to wipe is given; now initialized means
  this run's shares are lost and the wipe advice follows. A *re-run* that finds
  an initialized server with nothing on file gives **no** wipe advice at all
  (it is almost certainly the wrong keeper): see "Recovering from a failed
  init".

**Out of scope, by design.**

- *A compromised host or process.* An attacker who can read this process's
  memory, ptrace it, or read the Keeper's decryption key has the shares. Go
  cannot zero a `string` or an HTTP header, and the runtime may copy a slice
  before it is zeroed: zeroing is best effort, narrowing the window, not a
  guarantee.
- *The Keeper's own security.* It is the caller's.
- *A malicious OpenBAO server.* It hands out the shares and could hand out
  bad ones; the read-back and the drill prove they are the server's shares,
  not that the server is honest. TLS verifies the server is the one named.
- *The issuer.* An attacker who can mint a roster token for the operator group
  is an operator; that is the roster's security, not this package's.

## Secret flows

Where each secret lives, and for how long.

| Secret | Born | Lives in | Dies |
|---|---|---|---|
| Recovery shares | OpenBAO's `PUT sys/init` answer | decoded straight into `[]byte` (never a `string`); the Keeper gets a copy for `Create` and another for `Reveal`; the redactor holds a copy so no error can carry it | each buffer is zeroed as soon as its item is stored and read back, on every exit path; later steps `Reveal` one share at a time, submit it, and zero it |
| Root token | the same answer | the same, then a `[]byte` per later step that reads it from the Keeper | zeroed when the step ends; revoked at the end of `revoke-root`; the Keeper item archived |
| Drill token (generated root) | `sys/generate-root-token/update`, padded with a one-time pad | decoded into `[]byte`; the OTP is zeroed after | revoked right after its check (and on any failure after it exists) |
| Operator login token | the proof login | a `[]byte` in the client | revoked after one read of its own policy |
| Operator JWT | the caller | the caller's slice (`OperatorJWT`) | the caller zeroes it; the CLI zeroes the buffer it read |

Never: a log line (the package logs counts, names and states, no value), a
process argument (the request bodies carry secrets; they go in the body, and the
CLI takes a file, not a flag value), an environment variable, a file other than
through the Keeper, an error message (scrubbed of every secret the run has seen
and of anything token- or share-shaped), the CLI's stdout (except the
documented loud flag for the shares).

HTTP request and response buffers this package owns are zeroed after use. The
`net/http` and `crypto/tls` internals, the token as an `X-Vault-Token` header
string and the age library's internals are outside that, which is why the
threat model excludes a compromised process.

## Invariants and the tests that prove them

| Invariant | Enforced in | Proven by |
|---|---|---|
| Never revoke root before an operator login is proven | `RevokeRoot`: the group and its alias must exist and a login (or, weaker, a member on file) must be shown, before any drill and before any revoke | `TestRevokeRootNeverRevokesBeforeAnOperatorLoginIsProven` (six refusals: nobody logged in, no alias, no group, a login the door refuses, a login without the operator policy, a missing share), `TestRevokeRootWaitsForAnOperatorLogin`, conformance `TestFreshServerLifecycle` (no proof, a stranger's token, a wrong audience: the root token still works after each), `TestRevokeRootProvesTheLoginWithTheOperatorsOwnToken` |
| The shares are proven before the root token goes | `RevokeRoot` runs the drill sets, every share submitted at least once, and revokes the bootstrap token only after all of them succeed | `TestRevokeRootDrillsEveryShareThenRevokes`, `TestDrillSetsProveEveryShare`, conformance (real root generation on 2.6 and 2.7) |
| A drill never leaves a root token behind | the generated token is revoked on every path after it exists; an open attempt is cancelled | `TestTheDrillRevokesWhatItGeneratedEvenWhenItFails`, `TestRevokeRootLeavesSomeoneElsesGenerationAlone` (a foreign attempt is not touched) |
| Refuse a non-empty install unless told | `Initialize` refuses stale Keeper items (an earlier install's shares) and an initialized server is only verified; `Configure` refuses mounts beyond the door unless `Settings.AllowNonEmpty` / `--allow-non-empty` | `TestInitializeRefusesBeforeTouchingTheServer`, `TestInitializeRefusesStaleSharesFromAnEarlierInstall`, `TestConfigureRefusesANonEmptyServerUnlessTold`, conformance `TestFreshServerRefusesANonEmptyServerUnlessTold` |
| Shares cannot be lost to a Keeper that does not work | the canary preflight runs before `sys/init`; every item is read back; a failed store gets the wipe advice | `TestInitializeStopsBeforeInitWhenTheKeeperFails`, `TestInitializeRetriesAFailedStoreWithoutDuplicating`, `TestInitializeWithoutRetryExplainsTheWipe` |
| Shares are never unseal keys | `Initialize` refuses a seal that is not an auto-unseal seal, and always asks for `secret_shares: 0` | `TestInitializeRefusesAShamirSeal` |
| Never an unaudited configure | the audit device must be enabled before any write | `TestConfigureRefusesToRunUnaudited` |
| Wait for the whole cluster | `Configure` waits for every voter | `TestConfigureWaitsForEveryVoter` |
| Secret buffers are zeroed | `[]byte` end to end, `clear` after use, on every exit path | `TestSecretBuffersAreZeroedOnceUsed` (Keeper-side buffers) and `TestEverySecretBufferThePackageAllocatesIsZeroed` (every buffer the package allocates for a secret, through a test-only hook), `TestSecretJSONRefusesWhatNeedsEscaping` |
| Nothing secret reaches a log or an error | the package logs no value; errors are scrubbed | `TestNothingSecretReachesTheLogOrAnError`, `TestAnErrorNeverCarriesWhatTheServerEchoes`, `TestARecoveryShareThatTheKeeperEchoesIsScrubbed`, conformance (every byte every command printed is searched for every share and the root token) |
| The shares are printed only on request, and never the root token | one flag with a loud name, on `init` only | `TestOnlyOneFlagPrintsSecretsAndItSaysSo`, `TestPrintSharesWritesThemOnlyWhenCalledAndWarnsOnStderr`, conformance `TestFreshServerPrintsSharesOnlyWhenAsked` |
| TLS is always verified | no insecure flag; a non-`https` address is refused | `TestThereIsNoInsecureTLSFlag`, `TestTheBootstrapCommandsRefuseWhatIsUnsafeOrAmbiguous` |
| A cancelled context strands nothing | cleanups on `context.WithoutCancel` with their own timeout; failures reported | `TestCancellingMidDrillCancelsThePendingGeneration`, `TestCancellingAfterTheTokenExistsRevokesIt`, `TestACleanupThatFailsIsReportedWithWhatToDo`, `TestRestoreDrillStartDeletesThePodItCreatedWhenItFails` |
| Nothing is sent anywhere but the named server | the client never follows a redirect | `TestAClientNeverFollowsARedirect` |
| A scrubbed error cannot be unwrapped into the secret | `scrubbed` does not wrap | `TestAScrubbedErrorDoesNotWrapTheOriginal` |
| The recovery split is held to | `openbao-recovery-split`, extra-share check | `TestTheRecoverySplitIsRecordedAndHeldTo` |
| A lost init answer is not silent | own init timeout, advice on no answer | `TestAnInitWhoseAnswerNeverArrivedSaysTheSharesMayBeLost` |
| The print flag cannot dump an old install | `Bootstrap.Founded` | `TestThePrintFlagPrintsOnlyWhatThisRunCreated`, conformance `TestFreshServerPrintsSharesOnlyWhenAsked` |
| The server-side membership gate | conformance with `--membership-evidence-only` | `TestFreshServerRevokesOnMembershipEvidenceOnlyOnceSomeoneLoggedIn` |
| The file Keeper never writes a secret in the clear | age encryption; 0600/0700; refuses overwrite and path-like titles | `pkg/bootstrap/filekeeper` tests |

The conformance tests (`conformance/bootstrap_test.go`) run in CI's
`server-config` job on OpenBAO 2.6.2 and 2.7.0 with `OPENBAO_BAO_BINARY`: a
real `bao server` (TLS on loopback, one Raft voter, a declarative audit
device) on a **static seal**, an auto-unseal seal that needs no cloud account,
so initialization splits a recovery key exactly as a cloud KMS seal does. They
drive the real `openbaoctl` against a fake roster issuer. Offline.

## Recovering from a failed init

**Never wipe on a guess.** An initialized server and an empty keeper is, almost
always, the wrong keeper: a typo in `--keeper-dir`, another machine, an expired
session. `init` says so and gives no wipe advice then; check the keeper location
first. `openbaoctl` also refuses to create a missing keeper directory for any
step except `init` on a server that is not initialized yet.

The one wipe candidate is an install this very run initialized: `init` saw the
server uninitialized, sent the init call, got no answer, and then asked again
and found it initialized. Only then does it say the recovery shares are lost.
The server holds no data yet, so the way out is to wipe it and start again:
scale the StatefulSet to zero, delete its data PVCs, let the controller
recreate them, archive the `openbao-*` items in the Keeper, and run `init`
again. If storing a share failed after a successful init, the same applies.
If the server cannot be asked afterwards, the error says to confirm with the
owner that it was initialized only just now before touching anything.

If only recording the split failed, the shares and the root token are stored:
run `init` again with `--record-recovery-split` (library:
`Settings.RecordSplit`), which writes the item when every configured share is on
file and none is beyond them. Until it exists the later steps cannot hold to the
split.

## Adopting it from an estate

An estate keeps its own `Keeper` (a password manager, say) and its own
constants, and calls `Initialize`, `Configure` and `RevokeRoot` with them as
`Settings` and `OperatorLogin`. The estate's old copy of this logic should stay
callable until a rebuild drill has run end to end on a scratch copy; this
package changes no state on its own and holds no estate names.
