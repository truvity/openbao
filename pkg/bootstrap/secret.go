package bootstrap

import (
	"bytes"
	"errors"
	"regexp"
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

	*s = bytes.Clone(inner)

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

	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	out = append(out, s...)

	return append(out, '"'), nil
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

	r.secrets = append(r.secrets, bytes.Clone(s))
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

	return shareShape.ReplaceAllString(text, redacted)
}

// scrubbed is an error whose text has been scrubbed. The original stays
// reachable through errors.As and errors.Is, never through its text.
type scrubbed struct {
	text string
	err  error
}

func (e *scrubbed) Error() string { return e.text }

func (e *scrubbed) Unwrap() error { return e.err }

// scrubErr returns err with its text scrubbed (the same error when nothing
// changed).
func (r *redactor) scrubErr(err error) error {
	if err == nil {
		return nil
	}

	text := err.Error()
	if clean := r.scrub(text); clean != text {
		return &scrubbed{text: clean, err: err}
	}

	return err
}
