package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// The defaults of [Settings]: a five-share recovery key any three of which
// reconstruct it, three Raft voters, an audit device named to-stdout.
const (
	DefaultRecoveryShares    = 5
	DefaultRecoveryThreshold = 3
	DefaultVoters            = 3
	DefaultAuditDevice       = "to-stdout"
	DefaultReadyTimeout      = 5 * time.Minute
	// DefaultInitTimeout bounds the init call alone: it generates keys and
	// writes the seal config, and takes far longer than any other call. A
	// client that gives up while the server finishes loses the shares.
	DefaultInitTimeout = 5 * time.Minute
)

type (
	// Settings are the estate's facts. Every zero value is the default above.
	Settings struct {
		// RecoveryShares and RecoveryThreshold split the recovery key.
		RecoveryShares    int
		RecoveryThreshold int
		// Voters is the Raft membership a healthy install holds; Configure
		// waits for it.
		Voters int
		// AuditDevice is the declarative audit device Configure insists on.
		// It comes from the server configuration, never the API.
		AuditDevice string
		// ReadyTimeout bounds the wait for an unsealed, fully joined cluster.
		ReadyTimeout time.Duration
		// InitTimeout bounds the init call; default [DefaultInitTimeout].
		InitTimeout time.Duration
		// Description names the install in the notes of each keeper item
		// (free text: an endpoint, a cluster). Never a secret.
		Description string
		// AllowNonEmpty lets Configure run on a server that already has
		// mounts beyond the operators' door. Without it Configure refuses:
		// the bootstrap is for a fresh install, and writing the door into a
		// live one is a decision the caller states out loud.
		AllowNonEmpty bool
	}

	// Bootstrap carries what every stage needs.
	Bootstrap struct {
		API    *Client
		Keeper Keeper
		Logger *slog.Logger
		// Retry asks the operator whether to try storing an item again after
		// err. Nil means never: the step fails with the wipe advice.
		Retry func(ctx context.Context, err error) bool
		// Poll is how long to wait between readiness checks.
		Poll time.Duration
		// Now stamps the notes on each item.
		Now func() time.Time
		// Settings are the estate's facts.
		Settings Settings
		// OperatorJWT, when set, is a token the operators' issuer minted for
		// the roster audience. RevokeRoot then proves the door by logging in
		// with it and checking the operator policy arrives, instead of
		// settling for a group member on file. The caller owns the slice; it
		// is not zeroed here.
		OperatorJWT []byte

		// Founded is set by Initialize: true when this run initialized the
		// server (and so just stored its shares), false when it only verified
		// an initialized one.
		Founded bool
	}
)

func (s Settings) shares() int {
	if s.RecoveryShares == 0 {
		return DefaultRecoveryShares
	}

	return s.RecoveryShares
}

func (s Settings) threshold() int {
	if s.RecoveryThreshold == 0 {
		return DefaultRecoveryThreshold
	}

	return s.RecoveryThreshold
}

func (s Settings) voters() int {
	if s.Voters == 0 {
		return DefaultVoters
	}

	return s.Voters
}

func (s Settings) audit() string {
	if s.AuditDevice == "" {
		return DefaultAuditDevice
	}

	return s.AuditDevice
}

func (s Settings) initTimeout() time.Duration {
	if s.InitTimeout == 0 {
		return DefaultInitTimeout
	}

	return s.InitTimeout
}

func (s Settings) readyTimeout() time.Duration {
	if s.ReadyTimeout == 0 {
		return DefaultReadyTimeout
	}

	return s.ReadyTimeout
}

// validate refuses a recovery split OpenBAO would too, before anything is
// initialized.
func (s Settings) validate() error {
	shares, threshold := s.shares(), s.threshold()

	switch {
	case shares < 1 || shares > 255:
		return fmt.Errorf("recovery shares %d: want 1 to 255", shares)
	case threshold < 1 || threshold > shares:
		return fmt.Errorf("recovery threshold %d: want 1 to the %d shares", threshold, shares)
	case shares > 1 && threshold < 2:
		return fmt.Errorf("recovery threshold 1 of %d shares: any single share would reconstruct the key", shares)
	case s.voters() < 1:
		return fmt.Errorf("voters %d: want at least 1", s.voters())
	}

	return nil
}

// begin fills in what a caller may leave out (a nil Logger discards, a nil
// Now is the wall clock, a zero Poll is five seconds) and returns the cleanup
// every step defers.
func (b *Bootstrap) begin() func() {
	if b.Logger == nil {
		b.Logger = slog.New(slog.DiscardHandler)
	}

	if b.Now == nil {
		b.Now = time.Now
	}

	if b.Poll == 0 {
		b.Poll = 5 * time.Second
	}

	return b.API.redactor.wipe
}

// cleanupTimeout bounds a cleanup that must run after the caller's context
// is gone.
const cleanupTimeout = 30 * time.Second

// cleanupContext is a context for the cleanups that undo what a step started
// (cancel a root generation, revoke a token it made): it survives the
// caller's cancellation, which is exactly when those cleanups matter.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}
