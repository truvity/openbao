// Package filekeeper is a [bootstrap.Keeper] for the reference CLI: every
// item is a file in one directory, encrypted with age to the recipients the
// caller names, and read back with the caller's age identity.
//
// It is a reference, not a vault. It keeps what the bootstrap hands it
// encrypted at rest and nothing else: no secret is ever logged or put in an
// error, and the plaintext buffers it owns are zeroed. Where the identity
// (the private key) lives, and who may read it, is the caller's custody
// decision; a recovery share stored beside the identity that decrypts it is
// not protected at all.
package filekeeper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"
)

const (
	suffix     = ".age"
	notesExt   = ".notes"
	archiveDir = "archive"
	// maxItem bounds what one item may hold: a share or a token is tiny.
	maxItem = 1 << 16
)

var titleShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Keeper stores items under Dir as <title>.age (the secret, age-encrypted)
// and <title>.notes (the plain description, never a secret).
type Keeper struct {
	dir        string
	recipients []age.Recipient
	identities []age.Identity
	now        func() time.Time
}

// Prepare creates the keeper directory (0700), for a caller that has just
// established the server is not initialized.
func Prepare(dir string) error {
	if dir == "" {
		return errors.New("filekeeper: a directory is required")
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("filekeeper: create %s: %w", dir, err)
	}

	return nil
}

// New returns a Keeper on dir (which must exist; see [Prepare]), encrypting to the
// age recipients (age1... strings) and decrypting with the identities in
// identityFile (an age identity file: AGE-SECRET-KEY-... lines). With no
// recipients given, the identities' own public keys are used.
func New(dir string, recipients []string, identityFile string) (*Keeper, error) {
	if dir == "" {
		return nil, errors.New("filekeeper: a directory is required")
	}

	if identityFile == "" {
		return nil, errors.New("filekeeper: an age identity file is required: items are read back to prove them")
	}

	file, err := os.Open(identityFile)
	if err != nil {
		return nil, fmt.Errorf("filekeeper: open the identity file: %w", err)
	}

	defer func() { _ = file.Close() }()

	identities, err := age.ParseIdentities(file)
	if err != nil {
		// The parser's error names a line number, never a key.
		return nil, fmt.Errorf("filekeeper: parse the identity file: %w", err)
	}

	var parsed []age.Recipient

	for _, text := range recipients {
		recipient, err := age.ParseX25519Recipient(strings.TrimSpace(text))
		if err != nil {
			return nil, fmt.Errorf("filekeeper: parse recipient %q: %w", text, err)
		}

		parsed = append(parsed, recipient)
	}

	if len(parsed) == 0 {
		for _, identity := range identities {
			x, ok := identity.(*age.X25519Identity)
			if !ok {
				return nil, errors.New("filekeeper: name recipients: an identity is not an X25519 key")
			}

			parsed = append(parsed, x.Recipient())
		}
	}

	// The directory must already exist. A typo in it would otherwise yield a
	// new, empty keeper that looks like a lost one: only [Prepare], which the
	// caller runs for an install that is not initialized yet, creates it.
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("filekeeper: the keeper directory %s does not exist: check the path "+
			"(only init on a server that is not initialized yet creates it)", dir)
	}

	if err := os.MkdirAll(filepath.Join(dir, archiveDir), 0o700); err != nil {
		return nil, fmt.Errorf("filekeeper: create %s: %w", filepath.Join(dir, archiveDir), err)
	}

	return &Keeper{dir: dir, recipients: parsed, identities: identities, now: time.Now}, nil
}

func (k *Keeper) path(title, ext string) (string, error) {
	if !titleShape.MatchString(title) {
		return "", fmt.Errorf("filekeeper: %q is not a usable item title", title)
	}

	return filepath.Join(k.dir, title+ext), nil
}

// Titles implements [bootstrap.Keeper].
func (k *Keeper) Titles(context.Context) (map[string]bool, error) {
	entries, err := os.ReadDir(k.dir)
	if err != nil {
		return nil, fmt.Errorf("filekeeper: list %s: %w", k.dir, err)
	}

	titles := map[string]bool{}

	for _, entry := range entries {
		if name := entry.Name(); !entry.IsDir() && strings.HasSuffix(name, suffix) {
			titles[strings.TrimSuffix(name, suffix)] = true
		}
	}

	return titles, nil
}

// Create implements [bootstrap.Keeper]. It refuses to overwrite an item.
func (k *Keeper) Create(_ context.Context, title string, secret []byte, notes string) error {
	path, err := k.path(title, suffix)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("filekeeper: create %s: %w", title, err)
	}

	if err := encrypt(file, secret, k.recipients); err != nil {
		_ = file.Close()
		_ = os.Remove(path)

		return fmt.Errorf("filekeeper: write %s: %w", title, err)
	}

	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)

		return fmt.Errorf("filekeeper: sync %s: %w", title, err)
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(path)

		return fmt.Errorf("filekeeper: close %s: %w", title, err)
	}

	notesPath, err := k.path(title, notesExt)
	if err != nil {
		return err
	}

	// Best effort: the notes describe the item, the item does not need them.
	_ = os.WriteFile(notesPath, []byte(notes+"\n"), 0o600)

	return nil
}

func encrypt(w io.Writer, secret []byte, recipients []age.Recipient) error {
	enc, err := age.Encrypt(w, recipients...)
	if err != nil {
		return err
	}

	if _, err := enc.Write(secret); err != nil {
		return err
	}

	return enc.Close()
}

// Reveal implements [bootstrap.Keeper].
func (k *Keeper) Reveal(_ context.Context, title string) ([]byte, error) {
	path, err := k.path(title, suffix)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("filekeeper: open %s: %w", title, err)
	}

	defer func() { _ = file.Close() }()

	dec, err := age.Decrypt(file, k.identities...)
	if err != nil {
		return nil, fmt.Errorf("filekeeper: decrypt %s: %w", title, err)
	}

	// One fixed buffer, so no earlier copy of the plaintext is left behind
	// by a growing one.
	buf := make([]byte, maxItem+1)
	defer clear(buf)

	n, err := io.ReadFull(dec, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("filekeeper: read %s: %w", title, err)
	}

	if n == 0 {
		return nil, fmt.Errorf("filekeeper: item %s is empty", title)
	}

	if n > maxItem {
		return nil, fmt.Errorf("filekeeper: item %s is larger than %d bytes", title, maxItem)
	}

	return bytes.Clone(buf[:n]), nil
}

// Archive implements [bootstrap.Keeper]: the item moves to archive/ under a
// timestamped name, still encrypted, still recoverable.
func (k *Keeper) Archive(_ context.Context, title string) error {
	path, err := k.path(title, suffix)
	if err != nil {
		return err
	}

	stamp := k.now().UTC().Format("20060102T150405Z")
	target := filepath.Join(k.dir, archiveDir, title+"."+stamp+suffix)

	if err := os.Rename(path, target); err != nil {
		return fmt.Errorf("filekeeper: archive %s: %w", title, err)
	}

	if notes, err := k.path(title, notesExt); err == nil {
		_ = os.Rename(notes, filepath.Join(k.dir, archiveDir, title+"."+stamp+notesExt))
	}

	return nil
}

// Delete implements [bootstrap.Keeper].
func (k *Keeper) Delete(_ context.Context, title string) error {
	path, err := k.path(title, suffix)
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("filekeeper: delete %s: %w", title, err)
	}

	if notes, err := k.path(title, notesExt); err == nil {
		_ = os.Remove(notes)
	}

	return nil
}
