//go:build windows

package update

import (
	"os"
	"path/filepath"
	"testing"
)

// signedFixture is a real signed release binary, when one is available. These
// tests are about whether the WinVerifyTrust and CryptMsg plumbing actually
// works against a genuine Authenticode signature, which no synthetic fixture
// can answer.
func signedFixture(t *testing.T) string {
	t.Helper()
	p := os.Getenv("NOTIFYMATRIX_SIGNED_FIXTURE")
	if p == "" {
		// Nobody asked for these to run. Skipping is right on a developer
		// machine with no signed binary to hand.
		t.Skip("set NOTIFYMATRIX_SIGNED_FIXTURE to a signed release binary")
	}
	// But once a fixture HAS been named, a missing one is a failure, not a
	// skip. The release workflow points this at the artefact it just signed,
	// and the first time it ran the path was wrong: every test skipped, the
	// step reported success, and the check that guards self-update verified
	// nothing at all while looking green. That is the exact shape of failure
	// this test exists to prevent in the product, so it does not get to
	// happen to the test.
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("NOTIFYMATRIX_SIGNED_FIXTURE is set to %s, which cannot be read: %v\n"+
			"These tests were asked for and did not run.", p, err)
	}
	return p
}

func TestARealSignedReleaseVerifies(t *testing.T) {
	exe := signedFixture(t)
	if err := verifyTrust(exe); err != nil {
		t.Fatalf("a genuinely signed release failed verification: %v", err)
	}
	name, err := signerName(exe)
	if err != nil {
		t.Fatalf("signerName: %v", err)
	}
	if name == "" {
		t.Fatal("the signer has no name, so there is nothing to pin against")
	}
	t.Logf("signer: %q", name)
}

// The check that matters. A single flipped byte invalidates the signature, and
// an updater that installs anyway has no security property at all.
func TestATamperedBinaryIsRefused(t *testing.T) {
	exe := signedFixture(t)
	raw, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the middle of the code, far from the signature blob at
	// the end -- this is the edit an attacker would make, not a corrupted
	// download.
	raw[len(raw)/2] ^= 0xff

	bad := filepath.Join(t.TempDir(), "tampered.exe")
	if err := os.WriteFile(bad, raw, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := verifyTrust(bad); err == nil {
		t.Fatal("a tampered binary passed Authenticode verification")
	}
	if err := VerifyPublisher(bad, exe); err == nil {
		t.Fatal("a tampered binary was accepted as a replacement")
	}
}

// An unsigned build must be refused rather than waved through, and the refusal
// must not depend on the file being malformed -- this one is a perfectly valid
// executable that simply nobody signed.
func TestAnUnsignedBinaryIsRefusedAsAReplacement(t *testing.T) {
	exe := signedFixture(t)
	unsigned := filepath.Join(t.TempDir(), "unsigned.exe")
	// A file with no signature at all.
	if err := os.WriteFile(unsigned, []byte("MZ not really an executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublisher(unsigned, exe); err == nil {
		t.Fatal("an unsigned file was accepted as a replacement for a signed one")
	}
}

// Pinning is to the INSTALLED binary. When that one is unsigned there is no
// publisher to compare against, and the honest answer is to refuse rather than
// to install something while calling it verified.
func TestAnUnsignedInstallHasNothingToPinAgainstAndSaysSo(t *testing.T) {
	exe := signedFixture(t)
	unsigned := filepath.Join(t.TempDir(), "installed.exe")
	if err := os.WriteFile(unsigned, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := VerifyPublisher(exe, unsigned)
	if err == nil {
		t.Fatal("accepted an update for an unsigned install without a word")
	}
	t.Logf("refused as expected: %v", err)
}
