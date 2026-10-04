// Package bootstrap takes a freshly installed OpenBAO from uninitialized to
// its first operator login, retires the root token that made that possible,
// and proves the recovery shares on the way.
//
// The steps, in order, each safe to run again:
//
//  1. [Bootstrap.Initialize] initializes the server once and hands the
//     recovery shares and the root token to a [Keeper].
//  2. [Bootstrap.Configure] opens the operators' door (a JWT mount on the
//     roster issuer, the operator policy and an external identity group)
//     with that root token.
//  3. [Bootstrap.RevokeRoot] refuses until an operator has logged in through
//     the door, reconstructs the recovery key from the shares twice (the
//     generate-root drill, so every share is proven), and only then revokes
//     the root token.
//
// # Custody
//
// The package never persists a secret and never logs one. The recovery shares
// and the root token live in this process's memory from OpenBAO's answer until
// the [Keeper] has stored them and read them back; later steps read them back
// from the Keeper. Where a Keeper keeps them (a password manager, an
// age-encrypted file, a hardware token) is the caller's decision and the
// caller's responsibility. docs/bootstrap.md has the threat model and the
// whole secret flow.
//
// Secret buffers are []byte and are zeroed once used, as far as Go allows: a
// string, an HTTP header value and the net/http internals cannot be zeroed,
// so the guarantee is "the buffers this package owns", not "no copy exists in
// the process". Errors that reach a caller or a log are scrubbed of every
// secret the package has seen and of anything shaped like a token.
//
// A [Bootstrap] is not safe for concurrent use.
package bootstrap
