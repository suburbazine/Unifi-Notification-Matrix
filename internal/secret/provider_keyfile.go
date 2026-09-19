//go:build !windows

package secret

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/nacl/secretbox"
)

// ageKeyProvider envelopes secrets under a key file owned by the service user,
// mode 0600 in a 0700 directory.
//
// It uses NaCl secretbox from golang.org/x/crypto, which is already an indirect
// dependency -- this tier adds ZERO new modules. filippo.io/age was considered
// and rejected on that basis alone; its file format buys nothing here, because
// nothing outside this process ever reads these blobs.
//
// IMPORTANT, and stated plainly because it is the honest weakness of this tier:
// this is NOT machine-bound. Copy the config and the key file together and the
// secrets travel with them. That is strictly weaker than DPAPI machine scope,
// systemd-creds, or TPM sealing, and it is why this tier sits third. It is
// still far better than plaintext -- the secrets are not readable from the
// config alone, and the key file is one clearly-labelled thing to protect --
// but nobody should believe it is equivalent.
type ageKeyProvider struct{}

func (ageKeyProvider) Prefix() string    { return PrefixAgeKey }
func (ageKeyProvider) Mechanism() string { return "key file + NaCl secretbox" }

// MachineBound is false. See the type comment; this is the property this tier
// does not have, and the diagnostics report says so.
func (ageKeyProvider) MachineBound() bool { return false }

var (
	keyMu      sync.RWMutex
	keyPathOvr string
)

// SetKeyFile points the key-file tier at a key beside the config it protects.
//
// Called from config.Load, config.Save and config.LoadOrCreate -- every entry
// point that touches the file -- so the key follows --data-dir wherever it
// goes. It used not to be called at ALL, and the comment here said it was.
func SetKeyFile(path string) {
	keyMu.Lock()
	defer keyMu.Unlock()
	keyPathOvr = path
}

func keyPath() string {
	keyMu.RLock()
	p := keyPathOvr
	keyMu.RUnlock()
	if p != "" {
		return p
	}
	// EVERYTHING BELOW IS A LAST RESORT, reached only when nothing has loaded
	// a config yet. Both guesses were the whole answer once, and the pair of
	// them cost a working install: $STATE_DIRECTORY is set by systemd only for
	// a unit with StateDirectory=, so a unit that cannot use that directive --
	// the UniFi gateway one, because it is always relative to /var/lib -- fell
	// through to the hardcoded path and looked for its key in a directory it
	// was not using.
	//
	// They are kept because a guess beats a crash for a caller that has not
	// named a directory, and because on the ordinary unit they are right.
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return filepath.Join(d, "secret.key")
	}
	return "/var/lib/notifymatrix/secret.key"
}

func (ageKeyProvider) Available() (bool, string) {
	dir := filepath.Dir(keyPath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Sprintf("cannot create the key directory %s: %v", dir, err)
	}
	// Prove writability rather than inferring it from the mode bits: the
	// directory may exist but be owned by another user, which mode alone does
	// not reveal.
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return false, fmt.Sprintf("the key directory %s is not writable: %v", dir, err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return true, ""
}

// loadOrCreateKey returns the 32-byte key, creating it on first use.
func loadOrCreateKey() (*[32]byte, error) {
	p := keyPath()
	if b, err := os.ReadFile(p); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("key file %s is %d bytes, expected 32; "+
				"it is truncated or is not a key file", p, len(b))
		}
		var k [32]byte
		copy(k[:], b)
		return &k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading key file %s: %w", p, err)
	}

	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	var k [32]byte
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return nil, err
	}

	// O_EXCL so that two processes starting together cannot each generate a
	// key and have the loser silently encrypt under one that is about to be
	// overwritten. On collision, re-read the winner's key.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateKey()
		}
		return nil, fmt.Errorf("creating key file %s: %w", p, err)
	}
	if _, err := f.Write(k[:]); err != nil {
		_ = f.Close()
		_ = os.Remove(p)
		return nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(p)
		return nil, err
	}
	return &k, nil
}

func (ageKeyProvider) Protect(plaintext []byte) ([]byte, error) {
	k, err := loadOrCreateKey()
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	// Nonce is prepended to the sealed box; secretbox.Seal appends onto the
	// slice it is given, so passing nonce[:] as the prefix does that in one
	// allocation.
	return secretbox.Seal(nonce[:], plaintext, &nonce, k), nil
}

func (ageKeyProvider) Unprotect(blob []byte) ([]byte, error) {
	if len(blob) < 24+secretbox.Overhead {
		return nil, errors.New("sealed value is too short to be valid")
	}
	k, err := loadOrCreateKey()
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	copy(nonce[:], blob[:24])
	out, ok := secretbox.Open(nil, blob[24:], &nonce, k)
	if !ok {
		return nil, fmt.Errorf("authentication failed; the key file %s does not "+
			"match the value in the config (wrong key, or the file was replaced)",
			keyPath())
	}
	return out, nil
}
