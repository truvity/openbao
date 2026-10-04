package bootstrap

import (
	"context"
	"fmt"
)

const (
	// RootTokenItem holds the bootstrap root token until RevokeRoot.
	RootTokenItem = "openbao-root-token"
	// canaryItem proves the keeper is writable and readable before init.
	canaryItem = "openbao-init-canary"
)

// Keeper is where the recovery shares and the transient root token live. The
// package keeps nothing itself: every later step reads what it needs back from
// here, and the caller owns the custody.
//
// A Keeper must not log, print or cache a secret, and must put none in an
// error. Create must not retain the slice it is given (the package zeroes it
// once the item is proven); Reveal returns a slice the package owns and
// zeroes.
type Keeper interface {
	// Titles lists the items this package writes. It reads no secret.
	Titles(ctx context.Context) (map[string]bool, error)
	// Create writes a new item holding secret, described by notes. It must
	// fail if the title exists.
	Create(ctx context.Context, title string, secret []byte, notes string) error
	// Reveal reads an item's secret back.
	Reveal(ctx context.Context, title string) ([]byte, error)
	// Archive moves an item out of Titles, still recoverable.
	Archive(ctx context.Context, title string) error
	// Delete removes an item outright; only for the preflight canary.
	Delete(ctx context.Context, title string) error
}

// RecoveryItem names the item holding recovery share n (1-based).
func RecoveryItem(n int) string {
	return fmt.Sprintf("openbao-recovery-%d", n)
}
