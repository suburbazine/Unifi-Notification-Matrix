// Package integrity notices that the running binary is not the one that was
// installed.
//
// WHAT THIS IS FOR. internal/service already warns, at install time, that a
// LocalSystem service running out of a user-writable folder "is a file anybody
// running as that user can replace, choosing what runs as the service account
// next time it starts, with no prompt and none of the updater's signature
// checking involved". That warning was true and nothing acted on it: the
// replacement started, ran with the service account's privileges, reported
// healthy, and no surface anywhere said the binary had changed.
//
// WHAT THIS IS NOT. It is a tripwire, not a defence. Anyone who can rewrite
// the binary AND the pin beside it can silence it, and on a platform where
// both live behind the same privilege there is no asymmetry to exploit. It
// earns its keep where the two differ -- most sharply on Windows, where the
// install can sit in a user-writable directory while the data directory is
// ACL'd to administrators and SYSTEM. Claiming more than that would make it
// the kind of check that is trusted and should not be.
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/fileperm"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/update"
)

// PinName is the file beside the incident store that records what the binary
// looked like last time.
//
// In the DATA directory rather than next to the binary, deliberately. The
// whole value of this check comes from the pin being harder to rewrite than
// the thing it describes, and the data directory is the one this product
// already hardens (internal/fileperm).
const PinName = "binary.pin"

// Pin is what the running binary looked like when it was last accepted.
type Pin struct {
	// Version is the product version that was running. A binary whose hash
	// changed AND whose version changed is an ordinary update; one whose hash
	// changed while the version stayed the same is not.
	Version string `json:"version"`

	// SHA256 of the binary file.
	SHA256 string `json:"sha256"`

	// Signer is the Authenticode subject, where the platform can tell. Empty
	// means either unsigned or unknowable, and Signed says which.
	Signer string `json:"signer,omitempty"`
	Signed bool   `json:"signed"`

	// Platform records whether signer identity was AVAILABLE when this pin was
	// written, so a later run can tell "was signed, now is not" from "this
	// build has never been able to look".
	IdentityAvailable bool `json:"identity_available"`

	PinnedAt time.Time `json:"pinned_at"`
	Path     string    `json:"path"`
}

// Finding is what the daemon should say about the binary it is running.
type Finding struct {
	// Changed is true when something happened that the operator should be
	// told about. False covers both "nothing changed" and "changed in a way
	// that is an ordinary update".
	Changed bool

	Title  string
	Detail string

	// Limitation is a statement about what this platform can and cannot
	// check, for surfaces that describe capabilities rather than faults. It is
	// set whatever the outcome, and it is never itself a finding.
	Limitation string
}

// Check compares the running binary against the pin, updates the pin, and
// reports anything worth telling the operator.
//
// Writing the pin on a legitimate change is what keeps this quiet. An update
// re-pins and says nothing; the alarm is reserved for a change that does not
// look like one.
func Check(exePath, dataDir, version string) (Finding, error) {
	f := Finding{Limitation: Limitation()}

	sum, err := hashFile(exePath)
	if err != nil {
		return f, fmt.Errorf("integrity: hashing the running binary: %w", err)
	}

	signer, signed, identityAvailable := signerOf(exePath)

	now := Pin{
		Version: version, SHA256: sum,
		Signer: signer, Signed: signed,
		IdentityAvailable: identityAvailable,
		PinnedAt:          time.Now().UTC(), Path: exePath,
	}

	pinPath := filepath.Join(dataDir, PinName)
	prev, found, err := loadPin(pinPath)
	if err != nil {
		// A pin that cannot be read is not evidence of anything. It is
		// replaced, and the run continues: refusing to start because a
		// tripwire file is corrupt would turn this check into an outage.
		found = false
	}

	if !found {
		return f, savePin(pinPath, now)
	}

	switch {
	// SIGNATURE FIRST, because it is the only one of these that speaks to
	// authenticity rather than to change. A validly signed binary from a
	// different publisher is the case a hash comparison would report as an
	// ordinary update if the version string were changed to match.
	case identityAvailable && prev.IdentityAvailable && prev.Signed && !signed:
		f.Changed = true
		f.Title = "The running binary is no longer signed"
		f.Detail = "This installation previously ran a binary signed by " +
			quoteOr(prev.Signer, "a publisher") + ". The binary running now carries " +
			"no valid signature. Nothing about an ordinary update does this: an " +
			"update installs a signed release, and the updater refuses one that is " +
			"not. Treat the binary at " + exePath + " as replaced until you can " +
			"account for it."

	case identityAvailable && prev.IdentityAvailable && signed && prev.Signed &&
		!strings.EqualFold(strings.TrimSpace(signer), strings.TrimSpace(prev.Signer)):
		f.Changed = true
		f.Title = "The running binary was signed by somebody else"
		f.Detail = "This installation previously ran a binary signed by " +
			quoteOr(prev.Signer, "a publisher") + ". The one running now is signed by " +
			quoteOr(signer, "a different publisher") + ". The updater pins a " +
			"replacement to the publisher already installed and would have refused " +
			"this, so it did not arrive that way."

	// A binary that changed while claiming to be the same version. An update
	// changes both; this changes one.
	case prev.SHA256 != "" && prev.SHA256 != sum && prev.Version == version:
		f.Changed = true
		f.Title = "The running binary changed without its version changing"
		f.Detail = "The file at " + exePath + " is not the one this installation " +
			"recorded, and it still reports version " + version + ". An update " +
			"changes both. This changed only the file.\n\n" +
			"previously " + shortHash(prev.SHA256) + ", recorded " +
			prev.PinnedAt.Format(time.RFC3339) + "\n" +
			"now        " + shortHash(sum)
	}

	// Re-pinned either way. After a finding the new state becomes the
	// reference, so the incident is raised ONCE for one change rather than at
	// every start until somebody fixes it -- which is how an alert becomes
	// wallpaper. The incident stays open until acknowledged; that is the
	// escalation ladder's job, not this function's.
	if err := savePin(pinPath, now); err != nil {
		return f, err
	}
	return f, nil
}

// Limitation states what this platform can actually establish, in a sentence
// meant for an operator reading a capability report.
func Limitation() string {
	if update.CanVerifyPublisher() {
		return "The running binary's Authenticode signature and its signer are " +
			"checked at every start, and compared against the publisher this " +
			"installation ran last time."
	}
	return "This platform cannot establish WHO signed the running binary: there " +
		"is no Authenticode for an ELF binary, and the sigstore bundle published " +
		"beside a release is not installed alongside it. What is checked is that " +
		"the file has not CHANGED -- which detects a replacement, and cannot tell " +
		"you that the original was authentic. It is also only as trustworthy as " +
		"the difference in privilege between the binary and the data directory, " +
		"and on a default install both are root-owned, so it catches a careless " +
		"replacement rather than a determined one."
}

// signerOf asks the platform who signed the file, distinguishing "unsigned"
// from "cannot tell".
func signerOf(path string) (signer string, signed, identityAvailable bool) {
	if !update.CanVerifyPublisher() {
		return "", false, false
	}
	name, err := update.SignerOf(path)
	if err != nil {
		if errors.Is(err, update.ErrNoPublisherIdentity) {
			return "", false, false
		}
		// The platform can look and the answer is no: unsigned, or a
		// signature that does not verify. Both are "not signed" for this
		// purpose, and both are a real state rather than a missing capability.
		return "", false, true
	}
	return name, true, true
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func loadPin(path string) (Pin, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Pin{}, false, nil
	}
	if err != nil {
		return Pin{}, false, err
	}
	var p Pin
	if err := json.Unmarshal(b, &p); err != nil {
		return Pin{}, false, err
	}
	return p, true, nil
}

// savePin writes the pin and restricts it, atomically.
//
// Written through a temporary file and renamed, like everything else here that
// matters: a pin truncated by a power cut would read as corrupt on the next
// start, and a corrupt pin is treated as absent -- which would silently
// disarm the check.
func savePin(path string, p Pin) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("integrity: encoding the pin: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("integrity: writing the pin: %w", err)
	}
	_ = fileperm.Restrict(tmp)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("integrity: replacing the pin: %w", err)
	}
	_ = fileperm.Restrict(path)
	return nil
}

func shortHash(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}

func quoteOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return `"` + s + `"`
}

// canIdentifyPublisher reports whether this platform can establish who signed
// a file. Separated from update.CanVerifyPublisher only so tests can state
// their expectation in this package's own terms.
func canIdentifyPublisher() bool { return update.CanVerifyPublisher() }
