package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
)

// SplitItem records the recovery split an install was initialized with
// ("shares/threshold", not a secret), so a later step that is told another
// split refuses instead of proving only some of the shares.
const SplitItem = "openbao-recovery-split"

var numberWords = map[int]string{1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven"}

// wipeAdvice is the way out when init succeeded and storing did not.
func (b *Bootstrap) wipeAdvice() string {
	count := fmt.Sprint(b.Settings.voters())
	if word, ok := numberWords[b.Settings.voters()]; ok {
		count = word
	}

	return "OpenBAO is initialized but its recovery shares are not all stored, so they are lost. " +
		"It holds no data yet: scale the openbao StatefulSet to 0, delete its " + count + " data PVCs, " +
		"let the GitOps controller recreate them, archive any openbao-* items in the keeper, and run init again"
}

type initAnswer struct {
	RecoveryKeysB64 []secret `json:"recovery_keys_base64"`
	RootToken       secret   `json:"root_token"`
}

func (a *initAnswer) wipe() {
	for _, share := range a.RecoveryKeysB64 {
		zero(share)
	}

	zero(a.RootToken)
}

// Initialize initializes OpenBAO once and keeps what that returns.
//
// Run again, it verifies instead: an initialized OpenBAO must have every
// share on file, and an uninitialized one must not have stale shares from
// an earlier install, which would read as valid until the day they are
// needed.
//
// It never initializes before the keeper has proven it can store and read
// back a secret, and never with a seal whose shares would be unseal keys.
func (b *Bootstrap) Initialize(ctx context.Context) error {
	defer b.begin()()

	b.Founded = false

	if err := b.Settings.validate(); err != nil {
		return err
	}

	var status struct {
		Initialized bool `json:"initialized"`
	}

	if err := b.API.do(ctx, http.MethodGet, "sys/init", nil, &status); err != nil {
		return err
	}

	titles, err := b.Keeper.Titles(ctx)
	if err != nil {
		return fmt.Errorf("list the break-glass items: %w", err)
	}

	if status.Initialized {
		if missing := b.recoveryItems(titles, false); len(missing) > 0 {
			if len(missing) == b.Settings.shares() && !titles[RootTokenItem] {
				// Nothing on file for a server that is initialized. There is no
				// evidence this run initialized it, and the likeliest cause by far
				// is the wrong keeper: never advise a wipe from here.
				return errors.New("OpenBAO is initialized but the keeper holds none of its recovery shares or the root token. " +
					"This is almost always the wrong keeper (directory, session, account) or lost keeper contents, not a failed init: " +
					"do NOT wipe or delete anything; check the keeper location first. " +
					"Only an install this tool initialized minutes ago, with an answer that never arrived, is a wipe candidate: " +
					"see docs/bootstrap.md, \"Recovering from a failed init\"")
			}

			return fmt.Errorf("OpenBAO is initialized but the keeper lacks %s: rekey the recovery key before anything else",
				strings.Join(missing, ", "))
		}

		if err := b.checkSplit(ctx, titles); err != nil {
			return err
		}

		if b.Settings.RecordSplit && !titles[SplitItem] {
			if err := b.recordSplit(ctx); err != nil {
				return err
			}
		}

		b.Logger.InfoContext(ctx, "openbao already initialized; every recovery share is on file")

		return nil
	}

	stale := b.recoveryItems(titles, true)
	if titles[RootTokenItem] {
		stale = append(stale, RootTokenItem)
	}

	if titles[SplitItem] {
		stale = append(stale, SplitItem)
	}

	stale = append(stale, b.extraShares(titles)...)

	if len(stale) > 0 {
		return fmt.Errorf("OpenBAO is not initialized but the keeper already holds %s from an earlier install: archive them, then run again",
			strings.Join(stale, ", "))
	}

	if err := b.requireRecoverySeal(ctx); err != nil {
		return err
	}

	if err := b.preflight(ctx, titles[canaryItem]); err != nil {
		return fmt.Errorf("keeper preflight, before anything was initialized: %w", err)
	}

	return b.initialize(ctx)
}

func (b *Bootstrap) requireRecoverySeal(ctx context.Context) error {
	var seal struct {
		Type         string `json:"type"`
		RecoverySeal bool   `json:"recovery_seal"`
	}

	if err := b.API.do(ctx, http.MethodGet, "sys/seal-status", nil, &seal); err != nil {
		return err
	}

	if !seal.RecoverySeal {
		return fmt.Errorf("seal %q is not an auto-unseal seal: recovery shares would be unseal keys, which are never handed out here", seal.Type)
	}

	return nil
}

// preflight writes, reads back and deletes a canary through the same calls
// the shares use, so a signed-out session or a missing permission fails here
// rather than after init, when the shares exist only in memory.
func (b *Bootstrap) preflight(ctx context.Context, leftover bool) error {
	// A canary an interrupted run left behind would make the read ambiguous.
	if leftover {
		if err := b.Keeper.Delete(ctx, canaryItem); err != nil {
			return b.API.redactor.scrubErr(err)
		}
	}

	canary := []byte(fmt.Sprintf("canary %d", b.Now().UnixNano()))
	defer zero(canary)

	handed := bytes.Clone(canary)
	err := b.Keeper.Create(ctx, canaryItem, handed, "Written and deleted by the bootstrap preflight.")

	zero(handed)

	if err != nil {
		return b.API.redactor.scrubErr(err)
	}

	got, err := b.Keeper.Reveal(ctx, canaryItem)
	if err != nil {
		return b.API.redactor.scrubErr(err)
	}
	defer zero(got)

	if !bytes.Equal(got, canary) {
		return errors.New("the canary read back differently from what was written")
	}

	return b.API.redactor.scrubErr(b.Keeper.Delete(ctx, canaryItem))
}

func (b *Bootstrap) initialize(ctx context.Context) error {
	shares, threshold := b.Settings.shares(), b.Settings.threshold()

	request := map[string]int{
		// Zero secret shares: with an auto-unseal seal the root key is
		// wrapped by the seal, and only the recovery key is split.
		"secret_shares":      0,
		"secret_threshold":   0,
		"recovery_shares":    shares,
		"recovery_threshold": threshold,
	}

	var answer initAnswer

	// From here the secrets exist only in this process: every path out
	// zeroes them, and the redactor knows them before anything is logged.
	defer answer.wipe()

	err := b.API.doWithin(ctx, b.Settings.initTimeout(), http.MethodPut, "sys/init", request, &answer)
	for _, share := range answer.RecoveryKeysB64 {
		b.API.redactor.add(share)
	}

	b.API.redactor.add(answer.RootToken)

	if err != nil {
		var refused *APIError
		if errors.As(err, &refused) {
			return err
		}

		// Sent, and no answer. This run saw the server uninitialized a moment
		// ago, so asking again is the evidence: only a server that now reports
		// initialized, with nothing in this run's hands, has lost its shares.
		return b.noAnswer(ctx, err)
	}

	b.Logger.InfoContext(ctx, "openbao initialized; storing the recovery shares and the root token",
		slog.Int("shares", len(answer.RecoveryKeysB64)),
	)

	if len(answer.RecoveryKeysB64) != shares || len(answer.RootToken) == 0 {
		return fmt.Errorf("init answered %d recovery shares and a root token=%t: %s",
			len(answer.RecoveryKeysB64), len(answer.RootToken) != 0, b.wipeAdvice())
	}

	stamp := b.Now().UTC().Format(time.RFC3339)

	for i, share := range answer.RecoveryKeysB64 {
		notes := fmt.Sprintf("Recovery share %d of %d for OpenBAO%s; any %d reconstruct the recovery key. "+
			"Needed for generate-root and recovery operations, never for unsealing, which the auto-unseal seal does. "+
			"Written by the bootstrap at %s.",
			i+1, shares, b.describe(), threshold, stamp)

		if err := b.store(ctx, RecoveryItem(i+1), share, notes); err != nil {
			return err
		}
	}

	rootNotes := fmt.Sprintf("Bootstrap root token of OpenBAO%s, written by the bootstrap at %s. "+
		"It lives until revoke-root has seen an operator log in through the operators' door; then it is revoked and this item archived.",
		b.describe(), stamp)

	if err := b.store(ctx, RootTokenItem, answer.RootToken, rootNotes); err != nil {
		return err
	}

	if err := b.recordSplit(ctx); err != nil {
		return err
	}

	b.Founded = true

	b.Logger.InfoContext(ctx, "recovery shares and root token stored and read back",
		slog.String("keeper_items", RecoveryItem(1)+".."+RecoveryItem(shares)+", "+RootTokenItem),
	)

	return nil
}

func (b *Bootstrap) describe() string {
	if b.Settings.Description == "" {
		return ""
	}

	return " (" + b.Settings.Description + ")"
}

// store writes one item and proves it by reading it back. A write that
// fails can be retried once the operator has fixed the session; a write
// that succeeded is never repeated, so no duplicate item appears.
func (b *Bootstrap) store(ctx context.Context, title string, value []byte, notes string) error {
	created := false

	for {
		var err error

		if !created {
			// The keeper gets its own copy: it may wipe what it is given.
			copyOf := bytes.Clone(value)
			err = b.Keeper.Create(ctx, title, copyOf, notes)
			zero(copyOf)

			created = err == nil
		}

		if created {
			var got []byte

			got, err = b.Keeper.Reveal(ctx, title)
			if err == nil {
				same := bytes.Equal(got, value)
				zero(got)

				if same {
					return nil
				}

				return fmt.Errorf("keeper item %s read back differently from what OpenBAO issued: %s", title, b.wipeAdvice())
			}
		}

		err = b.API.redactor.scrubErr(err)

		if b.Retry == nil || !b.Retry(ctx, fmt.Errorf("store %s: %w", title, err)) {
			return fmt.Errorf("store %s: %w: %s", title, err, b.wipeAdvice())
		}
	}
}

// recoveryItems lists the share items that are present (present=true) or
// missing (present=false).
func (b *Bootstrap) recoveryItems(titles map[string]bool, present bool) []string {
	var out []string

	for n := 1; n <= b.Settings.shares(); n++ {
		if titles[RecoveryItem(n)] == present {
			out = append(out, RecoveryItem(n))
		}
	}

	return out
}

// extraShares lists keeper items numbered past the configured shares: the
// remains of a larger split, whose extra shares this run would never prove.
func (b *Bootstrap) extraShares(titles map[string]bool) []string {
	var extra []string

	for title := range titles {
		var n int
		if _, err := fmt.Sscanf(title, "openbao-recovery-%d", &n); err == nil && title == RecoveryItem(n) && n > b.Settings.shares() {
			extra = append(extra, title)
		}
	}

	slices.Sort(extra)

	return extra
}

// checkSplit refuses a run told a recovery split the install was not
// initialized with: it would check, and drill, only some of the shares.
func (b *Bootstrap) checkSplit(ctx context.Context, titles map[string]bool) error {
	if extra := b.extraShares(titles); len(extra) > 0 {
		return fmt.Errorf("the keeper holds %s beyond the %d shares configured: the settings disagree with the split "+
			"the install was initialized with, and those shares would never be proven", strings.Join(extra, ", "), b.Settings.shares())
	}

	if !titles[SplitItem] {
		return nil // an install from before the split was recorded
	}

	recorded, err := b.Keeper.Reveal(ctx, SplitItem)
	if err != nil {
		return fmt.Errorf("read the recorded recovery split: %w", b.API.redactor.scrubErr(err))
	}
	defer zero(recorded)

	if want := fmt.Sprintf("%d/%d", b.Settings.shares(), b.Settings.threshold()); string(recorded) != want {
		return fmt.Errorf("the install was initialized with recovery split %s (shares/threshold) but the settings say %s: "+
			"proving only some of the shares would risk the root token for nothing", recorded, want)
	}

	return nil
}

// recordSplit writes the non-secret split item.
func (b *Bootstrap) recordSplit(ctx context.Context) error {
	split := []byte(fmt.Sprintf("%d/%d", b.Settings.shares(), b.Settings.threshold()))
	err := b.Keeper.Create(ctx, SplitItem, split, "The recovery split this install was initialized with (shares/threshold). Not a secret.")

	zero(split)

	if err != nil {
		return fmt.Errorf("recording the recovery split failed; until %s exists the later steps cannot hold to the split. "+
			"The shares and the root token are stored. Once the keeper works, run init again with the record-recovery-split "+
			"setting (--record-recovery-split), which writes it when every configured share is on file and none is beyond them: %w",
			SplitItem, b.API.redactor.scrubErr(err))
	}

	return nil
}

// noAnswer explains an init call whose answer never arrived, after asking
// the server whether it initialized anyway.
func (b *Bootstrap) noAnswer(ctx context.Context, cause error) error {
	cleanup, cancel := cleanupContext(ctx)
	defer cancel()

	var status struct {
		Initialized bool `json:"initialized"`
	}

	switch err := b.API.do(cleanup, http.MethodGet, "sys/init", nil, &status); {
	case err != nil:
		return fmt.Errorf("the init call got no answer (%w) and the server cannot be asked whether it initialized: "+
			"do not run anything else until it can. If it reports initialized and this run's keeper holds nothing, "+
			"the shares are lost; confirm with the owner that it was initialized only just now before wiping anything: %w",
			cause, b.API.redactor.scrubErr(err))
	case status.Initialized:
		return fmt.Errorf("the init call got no answer (%w) and the server now reports initialized: this run initialized it "+
			"(it was uninitialized moments ago), and its recovery shares are lost. %s", cause, b.wipeAdvice())
	default:
		return fmt.Errorf("the init call got no answer (%w) and the server still reports uninitialized: nothing was lost; run init again", cause)
	}
}
