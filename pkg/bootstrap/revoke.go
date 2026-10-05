package bootstrap

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/truvity/secrets/pkg/model"
)

type (
	generateRootStatus struct {
		Nonce        string `json:"nonce"`
		Started      bool   `json:"started"`
		Progress     int    `json:"progress"`
		Required     int    `json:"required"`
		Complete     bool   `json:"complete"`
		EncodedToken secret `json:"encoded_token"`
		OTP          secret `json:"otp"`
		OTPLength    int    `json:"otp_length"`
	}

	generateRootAnswer struct {
		Data generateRootStatus `json:"data"`
	}

	tokenLookup struct {
		Data struct {
			Accessor string   `json:"accessor"`
			Policies []string `json:"policies"`
		} `json:"data"`
	}
)

const (
	generateRootAttempt = "sys/generate-root-token/attempt"
	generateRootUpdate  = "sys/generate-root-token/update"
)

func (s *generateRootStatus) wipe() {
	zero(s.EncodedToken)
	zero(s.OTP)
}

// drillSets are the share sets the drill reconstructs the recovery key from.
// Between them every share is proven, not only the first threshold of them:
// the first set is shares 1..threshold, and each next one takes the lowest
// shares not proven yet, filled up with the highest numbers. For five shares
// and a threshold of three that is {1,2,3} and {3,4,5}.
func drillSets(shares, threshold int) [][]int {
	proven := make(map[int]bool, shares)
	sets := [][]int{}

	first := make([]int, 0, threshold)
	for n := 1; n <= threshold; n++ {
		first = append(first, n)
		proven[n] = true
	}

	sets = append(sets, first)

	for {
		set := make([]int, 0, threshold)

		for n := 1; n <= shares && len(set) < threshold; n++ {
			if !proven[n] {
				set = append(set, n)
			}
		}

		if len(set) == 0 {
			return sets
		}

		for n := shares; n >= 1 && len(set) < threshold; n-- {
			if !slices.Contains(set, n) {
				set = append(set, n)
			}
		}

		slices.Sort(set)

		for _, n := range set {
			proven[n] = true
		}

		sets = append(sets, set)
	}
}

// RevokeRoot retires the bootstrap root token, and proves the shares first.
//
// It refuses until someone has logged in through the operator group, which
// is the only evidence that revoking root does not lock every operator out;
// with [Bootstrap.OperatorJWT] set it demands more, a login through the door
// that returns the operator policy, performed here. Then it generates a root
// token from the shares, once per drill set, revoking each at once, and only
// after all succeed revokes the bootstrap token and archives its item. With
// no bootstrap token on file it has nothing left to do.
//
// Root generation is authenticated since OpenBAO v2.6 (the unauthenticated
// sys/generate-root endpoints are off by default), so the drill runs on the
// bootstrap token while it still exists; a later drill is an operator's.
func (b *Bootstrap) RevokeRoot(ctx context.Context, operatorGroup string) error {
	defer b.begin()()

	if err := b.Settings.validate(); err != nil {
		return err
	}

	titles, err := b.Keeper.Titles(ctx)
	if err != nil {
		return fmt.Errorf("list the break-glass items: %w", err)
	}

	if !titles[RootTokenItem] {
		b.Logger.InfoContext(ctx, "no bootstrap root token on file: it is already revoked")

		return nil
	}

	if missing := b.recoveryItems(titles, false); len(missing) > 0 {
		return fmt.Errorf("the keeper lacks %s: nothing is revoked while a share is missing", strings.Join(missing, ", "))
	}

	if err := b.checkSplit(ctx, titles); err != nil {
		return err
	}

	token, err := b.Keeper.Reveal(ctx, RootTokenItem)
	if err != nil {
		return fmt.Errorf("read the bootstrap root token: %w", b.API.redactor.scrubErr(err))
	}
	defer zero(token)

	root := b.API.WithToken(token)
	defer root.Wipe()

	if err := b.requireOperatorLogin(ctx, root, operatorGroup); err != nil {
		return err
	}

	for _, set := range drillSets(b.Settings.shares(), b.Settings.threshold()) {
		if err := b.drill(ctx, root, set); err != nil {
			return err
		}
	}

	if err := b.revokeSelf(ctx, root, "the bootstrap root token"); err != nil {
		return err
	}

	if err := b.Keeper.Archive(ctx, RootTokenItem); err != nil {
		return fmt.Errorf("the root token is revoked, but archiving its keeper item failed; archive %s by hand: %w",
			RootTokenItem, b.API.redactor.scrubErr(err))
	}

	b.Logger.InfoContext(ctx, "bootstrap root token revoked and its item archived; operators log in through the roster",
		slog.String("group", operatorGroup),
	)

	return nil
}

func (b *Bootstrap) requireOperatorLogin(ctx context.Context, root *Client, operatorGroup string) error {
	current, found, err := readGroup(ctx, root, operatorGroup)
	if err != nil {
		return err
	}

	if !found || current.Alias.ID == "" {
		return fmt.Errorf("identity group %s or its alias is missing: run configure first", operatorGroup)
	}

	if len(b.OperatorJWT) > 0 {
		return b.proveLogin(ctx, operatorGroup)
	}

	if len(current.MemberEntityIDs) == 0 {
		return fmt.Errorf("nobody has logged in through %s yet: log in with `bao write auth/%s/login role=%s jwt=-` "+
			"with a roster token for audience %s, then run this again",
			operatorGroup, model.RosterMount, model.RosterRole, model.RosterAudience)
	}

	return nil
}

// proveLogin logs in through the operators' door with the caller's token and
// proves what comes back is an operator: the group's policy is on the token
// and it can read that policy. The token it gets is revoked at once.
func (b *Bootstrap) proveLogin(ctx context.Context, operatorGroup string) error {
	b.API.redactor.add(b.OperatorJWT)

	var login struct {
		Auth struct {
			ClientToken      secret   `json:"client_token"`
			Policies         []string `json:"policies"`
			TokenPolicies    []string `json:"token_policies"`
			IdentityPolicies []string `json:"identity_policies"`
		} `json:"auth"`
	}

	defer func() { zero(login.Auth.ClientToken) }()

	body := map[string]any{"role": model.RosterRole, "jwt": secret(b.OperatorJWT)}

	if err := b.API.do(ctx, http.MethodPost, "auth/"+model.RosterMount+"/login", body, &login); err != nil {
		return fmt.Errorf("the operator login through %s failed, so revoking root would lock operators out: %w", model.RosterMount, err)
	}

	b.API.redactor.add(login.Auth.ClientToken)

	operator := b.API.WithToken(login.Auth.ClientToken)
	defer operator.Wipe()

	granted := slices.Concat(login.Auth.Policies, login.Auth.TokenPolicies, login.Auth.IdentityPolicies)
	if !slices.Contains(granted, operatorGroup) {
		_ = operator.do(ctx, http.MethodPost, "auth/token/revoke-self", nil, nil)

		return fmt.Errorf("the operator login worked but its token carries %v, not the %s policy: revoking root would lock operators out",
			granted, operatorGroup)
	}

	// Revoked either way: a login token is not left lying around.
	readErr := operator.do(ctx, http.MethodGet, "sys/policies/acl/"+operatorGroup, nil, nil)
	revokeErr := operator.do(ctx, http.MethodPost, "auth/token/revoke-self", nil, nil)

	if readErr != nil {
		return fmt.Errorf("the operator token cannot read its own policy: %w", readErr)
	}

	if revokeErr != nil {
		return fmt.Errorf("revoke the operator proof token: %w", revokeErr)
	}

	b.Logger.InfoContext(ctx, "operator login proven through the door; its token is revoked",
		slog.String("group", operatorGroup),
	)

	return nil
}

// drill generates a root token from the given shares and revokes it at once.
//
// It leaves nothing behind, even when the context is cancelled: an open
// generation is cancelled and a generated token is revoked on a context of
// their own (the caller's is the very thing that may be gone). A cleanup that
// fails is part of the returned error, with what to do by hand.
func (b *Bootstrap) drill(ctx context.Context, root *Client, shares []int) (err error) {
	var current generateRootAnswer

	if err := root.do(ctx, http.MethodGet, generateRootAttempt, nil, &current); err != nil {
		return err
	}

	if current.Data.Started {
		return fmt.Errorf("a root generation is already in progress (nonce %s) and it is not this step's: "+
			"find out whose, then cancel it with `bao operator generate-root -cancel`", current.Data.Nonce)
	}

	var started generateRootAnswer

	defer started.Data.wipe()

	// No OTP in the request: OpenBAO generates one and returns it.
	startErr := root.do(ctx, http.MethodPut, generateRootAttempt, map[string]string{}, &started)
	b.API.redactor.add(started.Data.OTP)

	if startErr != nil {
		if ctx.Err() != nil {
			// Cancelled mid-call: the attempt may exist on the server.
			return errors.Join(startErr, b.cancelGeneration(ctx, root))
		}

		return startErr
	}

	token, err := b.submitShares(ctx, root, started.Data, shares)
	if err != nil {
		// Leave nothing half-done behind: an open attempt blocks the next one.
		return errors.Join(err, b.cancelGeneration(ctx, root))
	}
	defer zero(token)

	b.API.redactor.add(token)

	generated := b.API.WithToken(token)
	defer generated.Wipe()

	// From here a root token exists that nobody holds but this function:
	// whatever goes wrong, it is revoked before the error leaves.
	revoked := false

	defer func() {
		if revoked {
			return
		}

		cleanup, cancel := cleanupContext(ctx)
		defer cancel()

		if revokeErr := generated.do(cleanup, http.MethodPost, "auth/token/revoke-self", nil, nil); revokeErr != nil {
			err = errors.Join(err, fmt.Errorf("the root token generated by the drill could NOT be revoked and is still valid: "+
				"list token accessors with `bao list auth/token/accessors`, find the root one this drill made and revoke it "+
				"with `bao token revoke -accessor <accessor>`: %w", revokeErr))
		}
	}()

	var lookup tokenLookup

	if err := generated.do(ctx, http.MethodGet, "auth/token/lookup-self", nil, &lookup); err != nil {
		return fmt.Errorf("the token generated from shares %v does not work: %w", shares, err)
	}

	if !slices.Contains(lookup.Data.Policies, "root") {
		return fmt.Errorf("the token generated from shares %v carries %v, not root", shares, lookup.Data.Policies)
	}

	if err := b.revokeSelf(ctx, generated, "the drill's generated root token"); err != nil {
		return err
	}

	revoked = true

	b.Logger.InfoContext(ctx, "recovery shares reconstruct the recovery key; the generated root token is revoked",
		slog.String("shares", fmt.Sprint(shares)),
	)

	return nil
}

// cancelGeneration cancels the open root generation on a context that
// survives the caller's cancellation, and says so loudly when it cannot.
func (b *Bootstrap) cancelGeneration(ctx context.Context, root *Client) error {
	cleanup, cancel := cleanupContext(ctx)
	defer cancel()

	if err := root.do(cleanup, http.MethodDelete, generateRootAttempt, nil, nil); err != nil {
		return fmt.Errorf("the pending root generation could NOT be cancelled and blocks the next attempt: "+
			"cancel it with `bao operator generate-root -cancel`: %w", err)
	}

	return nil
}

func (b *Bootstrap) submitShares(ctx context.Context, root *Client, status generateRootStatus, shares []int) ([]byte, error) {
	if status.Required != b.Settings.threshold() || len(status.OTP) == 0 || status.Nonce == "" {
		return nil, fmt.Errorf("root generation started with required=%d and otp=%t; expected %d and an OTP",
			status.Required, len(status.OTP) != 0, b.Settings.threshold())
	}

	otp, nonce := status.OTP, status.Nonce

	var progress generateRootAnswer

	defer progress.Data.wipe()

	for _, n := range shares {
		share, err := b.Keeper.Reveal(ctx, RecoveryItem(n))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", RecoveryItem(n), b.API.redactor.scrubErr(err))
		}

		b.API.redactor.add(share)

		progress.Data.wipe()

		progress = generateRootAnswer{}
		err = root.do(ctx, http.MethodPut, generateRootUpdate, map[string]any{"key": secret(share), "nonce": nonce}, &progress)

		zero(share)

		if err != nil {
			return nil, fmt.Errorf("submit %s: %w", RecoveryItem(n), err)
		}

		status = progress.Data
	}

	if !status.Complete || len(status.EncodedToken) == 0 {
		return nil, fmt.Errorf("shares %v did not complete root generation (progress %d of %d)", shares, status.Progress, status.Required)
	}

	token, err := decodeToken(status.EncodedToken, otp)
	if err != nil {
		return nil, fmt.Errorf("root generation completed but its token could not be decoded, so a root token exists that nobody holds "+
			"(list token accessors with `bao list auth/token/accessors` and revoke the root one this drill made): %w", err)
	}

	return token, nil
}

// decodeToken undoes the one-time pad OpenBAO applies to a generated root
// token (sdk/helper/roottoken.DecodeToken with a non-zero OTP length).
func decodeToken(encoded, otp []byte) ([]byte, error) {
	raw := track(make([]byte, base64.RawStdEncoding.DecodedLen(len(encoded))))
	defer zero(raw)

	n, err := base64.RawStdEncoding.Decode(raw, encoded)
	if err != nil {
		return nil, errors.New("decode the generated root token: not base64")
	}

	raw = raw[:n]
	if len(raw) != len(otp) {
		return nil, errors.New("the generated root token and its OTP differ in length")
	}

	token := track(make([]byte, len(raw)))
	for i := range raw {
		token[i] = raw[i] ^ otp[i]
	}

	return token, nil
}

// revokeSelf revokes the client's own token and proves it is gone. On
// failure the error names the accessor, which revokes it without the token.
func (b *Bootstrap) revokeSelf(ctx context.Context, api *Client, what string) error {
	var lookup tokenLookup

	if err := api.do(ctx, http.MethodGet, "auth/token/lookup-self", nil, &lookup); err != nil {
		return fmt.Errorf("look up %s: %w", what, err)
	}

	accessor := lookup.Data.Accessor

	if err := api.do(ctx, http.MethodPost, "auth/token/revoke-self", nil, nil); err != nil {
		return fmt.Errorf("revoke %s failed; revoke it by accessor with `bao token revoke -accessor %s`: %w", what, accessor, err)
	}

	err := api.do(ctx, http.MethodGet, "auth/token/lookup-self", nil, nil)

	switch {
	case hasStatus(err, http.StatusForbidden):
		return nil
	case err == nil:
		return fmt.Errorf("%s still works after revocation; revoke it with `bao token revoke -accessor %s`", what, accessor)
	default:
		return fmt.Errorf("prove %s is revoked (accessor %s): %w", what, accessor, err)
	}
}
