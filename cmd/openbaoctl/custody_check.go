package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/truvity/openbao/pkg/pki"
)

var errCustodyCheckRequired = fmt.Errorf(
	"the contract declares custody, so signing needs its cross-check: pass --%s <file> (the synced custody outputs), "+
		"or --%s <reason> to sign without it (the reason is printed and logged)", flagCustodyOutputs, flagSkipCustodyCheck)

// custodyCheck is the outcome of the pre-signing custody cross-check: the
// text the operator reviews (and that a rerun must reproduce), and, when
// the check was skipped, the flag a rerun needs.
type custodyCheck struct {
	// text is printed with the template review and with the result.
	text string
	// rerun is what a rerun must add to its flags to make the same check
	// (or the same skip); empty when nothing was checked (a hierarchy).
	rerun   string
	skipped bool
	reason  string
}

// withCustody runs the pre-signing custody cross-check for a source and
// returns the signing options to use: with --custody-outputs, the profile
// and role default to the published ones and every explicit value must
// match. artifactKeyARN is the committed root artifact's key ("" while the
// root is being created).
//
// A --contract source declares custody, so the check is required unless
// --skip-custody-check gives a reason. A --hierarchy file declares none;
// both flags are refused there rather than ignored.
func (s signingOptions) withCustody(source *pkiSource, artifactKeyARN string) (signingOptions, *custodyCheck, error) {
	if source.contract == nil {
		if s.custodyOutputs != "" || s.skipCustody != "" {
			return s, nil, fmt.Errorf("--%s and --%s need --%s: a hierarchy file declares no custody to check against",
				flagCustodyOutputs, flagSkipCustodyCheck, flagContract)
		}

		return s, &custodyCheck{}, nil
	}

	switch {
	case s.custodyOutputs != "" && s.skipCustody != "":
		return s, nil, fmt.Errorf("--%s and --%s exclude each other", flagCustodyOutputs, flagSkipCustodyCheck)
	case s.custodyOutputs == "" && s.skipCustody == "":
		return s, nil, errCustodyCheckRequired
	case s.custodyOutputs == "":
		reason := strings.TrimSpace(s.skipCustody)
		if reason == "" {
			return s, nil, errors.New("--" + flagSkipCustodyCheck + " needs a reason, not blank text")
		}

		return s, &custodyCheck{
			text: fmt.Sprintf("custody check: SKIPPED, reason: %s\n"+
				"  the key, role, region and profile were NOT cross-checked against the custody outputs\n", reason),
			rerun:   fmt.Sprintf(" --%s %q", flagSkipCustodyCheck, reason),
			skipped: true,
			reason:  reason,
		}, nil
	}

	outputs, err := pki.LoadCustodyOutputs(s.custodyOutputs)
	if err != nil {
		return s, nil, err
	}

	verdict, err := source.contract.VerifyCustody(outputs, source.generation, pki.CustodyRequest{
		KeyARN:         s.keyARNOr(artifactKeyARN),
		ArtifactKeyARN: artifactKeyARN,
		RoleARN:        s.roleARN,
		Profile:        s.awsProfile,
	})
	if err != nil {
		return s, nil, err
	}

	var text strings.Builder

	fmt.Fprintf(&text, "custody check against %s, all verified:\n", s.custodyOutputs)

	for _, statement := range verdict.Proven {
		fmt.Fprintf(&text, "  - %s\n", statement)
	}

	s.keyARN = verdict.KeyARN
	s.roleARN = verdict.RoleARN
	s.awsProfile = verdict.Profile

	return s, &custodyCheck{text: text.String(), rerun: fmt.Sprintf(" --%s %s", flagCustodyOutputs, s.custodyOutputs)}, nil
}

// log records a skipped check where the operator's terminal and any wrapper
// script's log both see it; a verified check is printed with the result.
func (c *custodyCheck) log(ctx context.Context, logger *slog.Logger) {
	if c != nil && c.skipped {
		logger.WarnContext(ctx, "signing WITHOUT the custody cross-check", slog.String("reason", c.reason))
	}
}
