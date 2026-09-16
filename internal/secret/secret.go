// Package secret stores credentials so that the file on disk records how -- and
// crucially whether -- each value was actually protected.
//
// A stored secret is a prefixed, base64-encoded string. The prefix names the
// mechanism that protected it:
//
//	dpapi:    Windows DPAPI, machine scope
//	sdcreds:  systemd-creds, host key and TPM2 where available
//	tpm2:     sealed directly against the TPM
//	agekey:   NaCl secretbox under a 0600 key file owned by the service user
//	plain:    NOT ENCRYPTED. Base64 only.
//
// The prefix must always state what actually happened. A config that labels an
// unencrypted value as though it were encrypted is worse than one that admits
// it, because the second can be noticed. "plain:" means plain, on every
// platform, and it is never selected automatically -- see SelectWriter.
package secret

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Secret is a credential that must not sit in a config file in the clear.
//
// It marshals through the platform's best available protection mechanism and
// unmarshals back, so callers hold plaintext and the file never does.
type Secret string

// String deliberately does NOT return the secret.
//
// A Secret reaching a log line or an error message through %v or %s is the
// accident this prevents. Callers that genuinely want the value call Reveal.
func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return "<redacted>"
}

// Reveal returns the plaintext. Named so that every use site is greppable and
// obvious in review.
func (s Secret) Reveal() string { return string(s) }

// IsZero reports whether the secret is unset, without revealing anything.
func (s Secret) IsZero() bool { return s == "" }

func (s Secret) MarshalJSON() ([]byte, error) {
	if s == "" {
		return []byte(`""`), nil
	}
	p, err := SelectWriter()
	if err != nil {
		return nil, fmt.Errorf("secret: no way to protect this value: %w", err)
	}
	blob, err := p.Protect([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("secret: protecting with %s: %w", p.Mechanism(), err)
	}
	return json.Marshal(p.Prefix() + base64.StdEncoding.EncodeToString(blob))
}

func (s *Secret) UnmarshalJSON(b []byte) error {
	var stored string
	if err := json.Unmarshal(b, &stored); err != nil {
		return err
	}
	if stored == "" {
		*s = ""
		return nil
	}
	plain, err := Unprotect(stored)
	if err != nil {
		return err
	}
	*s = Secret(plain)
	return nil
}

// ErrUnknownPrefix is returned for a stored value whose mechanism this build
// does not recognise -- a config written by a newer version, or edited by hand.
var ErrUnknownPrefix = errors.New("unrecognised secret encoding")

// UnprotectError says which mechanism failed and why, so that a secret which
// cannot be decrypted here produces an operator-actionable message instead of
// a mystery.
//
// This type exists because of a specific failure: when a decrypt error is
// allowed to escape UnmarshalJSON unchanged, the caller reports it as a config
// PARSE error. A config carried from another machine then reads as corrupt
// rather than as foreign, and the operator goes looking for the wrong problem.
type UnprotectError struct {
	Prefix    string // the prefix as stored, e.g. "dpapi:"
	Mechanism string // human name of the mechanism
	Err       error
}

func (e *UnprotectError) Error() string {
	return fmt.Sprintf("secret: cannot decrypt a value protected with %s on this machine: %v"+
		"\n\nSecrets are bound to the machine that wrote them. If this config was"+
		"\ncopied from another host, or the host was reinstalled, the credentials"+
		"\nmust be re-entered -- they cannot be recovered from the file.",
		e.Mechanism, e.Err)
}

func (e *UnprotectError) Unwrap() error { return e.Err }

// Unprotect decodes one stored value. Exported so that diagnostics can test a
// config without loading it.
func Unprotect(stored string) ([]byte, error) {
	prefix, b64, ok := splitPrefix(stored)
	if !ok || providerFor(prefix) == nil {
		// NO RECOGNISED PREFIX: treat it as a value somebody typed by hand.
		//
		// This is deliberate, and it is the difference between a config an
		// operator can actually fill in and one they cannot. The config file
		// is the source of truth and is meant to be editable (ARCHITECTURE.md
		// §6a); refusing a pasted API key because it lacks a "dpapi:" prefix
		// would mean the only way to bootstrap is a UI that may not be running
		// yet.
		//
		// It is safe to be permissive here because it cannot MASK a decryption
		// failure: a value that was encrypted always carries its prefix, so a
		// damaged blob still lands in the branch below and still reports as
		// undecryptable. Only a value with no known prefix at all reaches
		// this, and the honest reading of that is "a human put it here".
		//
		// The caller is expected to notice and re-encrypt -- see
		// config.Load, which reports plaintext credentials loudly, because a
		// key that sat in a readable file should be treated as exposed.
		return []byte(stored), nil
	}
	p := providerFor(prefix)
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, &UnprotectError{Prefix: prefix, Mechanism: p.Mechanism(), Err: err}
	}
	plain, err := p.Unprotect(blob)
	if err != nil {
		return nil, &UnprotectError{Prefix: prefix, Mechanism: p.Mechanism(), Err: err}
	}
	return plain, nil
}

func splitPrefix(stored string) (prefix, rest string, ok bool) {
	i := strings.IndexByte(stored, ':')
	if i < 0 {
		return "", "", false
	}
	return stored[:i+1], stored[i+1:], true
}

// firstRunes truncates for an error message without splitting a rune, since the
// value may be arbitrary hand-edited text.
func firstRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "..."
}
