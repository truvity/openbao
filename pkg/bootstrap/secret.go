package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
)

const (
	redacted = "[REDACTED]"
	// minSecret is the shortest value the redactor will hunt for: anything
	// shorter would also match ordinary words in an error message.
	minSecret = 8
)

var (
	// tokenShape is an OpenBAO token (service or batch) wherever it shows up.
	tokenShape = regexp.MustCompile(`\b[sb]\.[A-Za-z0-9_-]{16,}`)
	// shareShape is a recovery share (base64, 32 bytes or more) or an OTP.
	shareShape = regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}={0,2}`)
)

// secret is a JSON string that is decoded into, and encoded from, a byte
// slice, so it can be zeroed. Recovery shares, tokens and OTPs only ever
// travel as this type or as the []byte it wraps.
type secret []byte

// UnmarshalJSON copies the string's bytes out of the decoder's buffer. The
// strings this carries are base64 or token text and never contain an
// escape; one that does is refused rather than decoded through a string.
func (s *secret) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(raw, []byte("null")) {
		return nil
	}

	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return errors.New("a secret field is not a JSON string")
	}

	inner := raw[1 : len(raw)-1]
	if bytes.IndexByte(inner, '\\') >= 0 {
		return errors.New("a secret field holds an escape sequence")
	}

	*s = track(bytes.Clone(inner))

	return nil
}

// MarshalJSON quotes the bytes. A value that would need an escape is
// refused; the error never carries the value.
func (s secret) MarshalJSON() ([]byte, error) {
	for _, c := range s {
		if c < 0x20 || c == '"' || c == '\\' || c > 0x7e {
			return nil, errors.New("a secret field holds a character that needs escaping")
		}
	}

	out := track(make([]byte, 0, len(s)+2))
	out = append(out, '"')
	out = append(out, s...)

	return append(out, '"'), nil
}

// trackSecret, when set (tests only), sees every buffer this package
// allocates for a secret, so a test can prove each one is zeroed.
var trackSecret func([]byte)

func track(b []byte) []byte {
	if trackSecret != nil {
		trackSecret(b)
	}

	return b
}

// zero overwrites b. The compiler may not elide it: the slice is read
// afterwards by the callers' tests, and clear is a builtin the optimizer
// treats as a store.
func zero(b []byte) {
	clear(b)
}

// redactor knows the secrets of one run and scrubs them out of text.
type redactor struct {
	mu      sync.Mutex
	secrets [][]byte
}

// add remembers a copy of s.
func (r *redactor) add(s []byte) {
	if r == nil || len(s) < minSecret {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.secrets = append(r.secrets, track(bytes.Clone(s)))
}

// wipe zeroes and forgets every remembered secret.
func (r *redactor) wipe() {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, s := range r.secrets {
		zero(s)
	}

	r.secrets = nil
}

// scrub replaces every remembered secret and everything shaped like a token
// or a share in text.
func (r *redactor) scrub(text string) string {
	if r != nil {
		r.mu.Lock()

		for _, s := range r.secrets {
			text = string(bytes.ReplaceAll([]byte(text), s, []byte(redacted)))
		}

		r.mu.Unlock()
	}

	text = tokenShape.ReplaceAllString(text, redacted)

	return shareShape.ReplaceAllStringFunc(text, func(run string) string {
		if looksLikeASecret(run) {
			return redacted
		}

		return run
	})
}

// looksLikeASecret tells a share from a path or a URL of the same length.
// A share is random: base64 (mixed case and digits, or with + / = padding),
// base64url (with _), or hex (digits). A path is lowercase words and dashes.
func looksLikeASecret(run string) bool {
	hasUpper := strings.ContainsAny(run, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	hasDigit := strings.ContainsAny(run, "0123456789")

	switch {
	case strings.ContainsAny(run, "+_") || strings.HasSuffix(run, "="):
		return true
	case hasUpper && hasDigit:
		return true
	case hasDigit && !strings.ContainsAny(run, "/-"):
		// One unbroken alphanumeric run with digits: hex, or lowercase base32/36.
		return true
	default:
		return false
	}
}

// scrubbed is an error whose text has been scrubbed. It does not wrap the
// original: a chain walk (errors.Unwrap, a reporter that dumps the chain)
// must not reach the unscrubbed text. It answers errors.Is for the two
// context errors, which callers branch on, and for nothing else.
type scrubbed struct {
	text     string
	canceled bool
	deadline bool
}

func (e *scrubbed) Error() string { return e.text }

func (e *scrubbed) Is(target error) bool {
	return (e.canceled && target == context.Canceled) || (e.deadline && target == context.DeadlineExceeded)
}

// scrubErr returns err with its text scrubbed (the same error when nothing
// changed).
func (r *redactor) scrubErr(err error) error {
	if err == nil {
		return nil
	}

	text := err.Error()

	clean := r.scrub(text)
	if clean == text {
		return err
	}

	return &scrubbed{
		text:     clean,
		canceled: errors.Is(err, context.Canceled),
		deadline: errors.Is(err, context.DeadlineExceeded),
	}
}
