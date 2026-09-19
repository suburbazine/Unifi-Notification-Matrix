package integrity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture writes a fake binary and returns its path plus a data directory.
func fixture(t *testing.T, content string) (exe, dataDir string) {
	t.Helper()
	dir := t.TempDir()
	exe = filepath.Join(dir, "notifymatrix-fake")
	if err := os.WriteFile(exe, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	dataDir = filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return exe, dataDir
}

func mustCheck(t *testing.T, exe, dataDir, version string) Finding {
	t.Helper()
	f, err := Check(exe, dataDir, version)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return f
}

// THE FIRST RUN ARMS THE TRIPWIRE AND SAYS NOTHING.
//
// There is nothing to compare against, and an installation that shouted on
// first start would teach its operator that the message means nothing.
func TestTheFirstRunRecordsAReferenceAndReportsNothing(t *testing.T) {
	exe, data := fixture(t, "the installed binary")

	if f := mustCheck(t, exe, data, "0.2.0"); f.Changed {
		t.Errorf("a first run reported a change: %q", f.Title)
	}
	if _, err := os.Stat(filepath.Join(data, PinName)); err != nil {
		t.Fatalf("no reference was recorded: %v", err)
	}
	// And a second, unchanged start is still quiet.
	if f := mustCheck(t, exe, data, "0.2.0"); f.Changed {
		t.Errorf("an unchanged binary reported a change: %q", f.Title)
	}
}

// THE CASE THIS WAS BUILT FOR.
//
// internal/service warns at install time that a service in a user-writable
// folder is "a file anybody running as that user can replace, choosing what
// runs as the service account next time it starts". This is what happens on
// the start after that: the file is different and it still claims to be the
// same version, because an attacker has no reason to change the version and
// every reason not to.
func TestABinaryReplacedWithoutAVersionChangeIsReported(t *testing.T) {
	exe, data := fixture(t, "the installed binary")
	mustCheck(t, exe, data, "0.2.0")

	if err := os.WriteFile(exe, []byte("something else entirely"), 0o700); err != nil {
		t.Fatal(err)
	}

	f := mustCheck(t, exe, data, "0.2.0")
	if !f.Changed {
		t.Fatal("a replaced binary reporting the same version was not reported; " +
			"this is the exact case the install-time warning describes and " +
			"nothing else in the product looks for it")
	}
	for _, want := range []string{"version", exe} {
		if !strings.Contains(f.Title+f.Detail, want) {
			t.Errorf("the report does not mention %q:\n%s\n%s", want, f.Title, f.Detail)
		}
	}
}

// AN ORDINARY UPDATE IS SILENT.
//
// The binary changes on every update, so a check that fired on a changed hash
// alone would fire on every legitimate upgrade and be switched off within a
// week. The version moving with it is what distinguishes the two.
func TestAnOrdinaryUpdateIsNotReported(t *testing.T) {
	exe, data := fixture(t, "version 0.2.0 of the binary")
	mustCheck(t, exe, data, "0.2.0")

	if err := os.WriteFile(exe, []byte("version 0.2.1 of the binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	if f := mustCheck(t, exe, data, "0.2.1"); f.Changed {
		t.Errorf("an ordinary update was reported as tampering: %q\n%s", f.Title, f.Detail)
	}
}

// ONE CHANGE, ONE REPORT.
//
// The new state becomes the reference after a finding, so an operator who
// deliberately installed something gets told once rather than at every start
// until they hunt down where to silence it. An alarm that repeats forever for
// a thing the operator has decided to live with becomes wallpaper, and takes
// the credibility of every other alarm with it.
func TestAChangeIsReportedOnceAndThenBecomesTheReference(t *testing.T) {
	exe, data := fixture(t, "original")
	mustCheck(t, exe, data, "0.2.0")

	if err := os.WriteFile(exe, []byte("replaced"), 0o700); err != nil {
		t.Fatal(err)
	}
	if f := mustCheck(t, exe, data, "0.2.0"); !f.Changed {
		t.Fatal("the change was not reported at all")
	}
	if f := mustCheck(t, exe, data, "0.2.0"); f.Changed {
		t.Errorf("the same change was reported a second time: %q", f.Title)
	}
}

// A CORRUPT REFERENCE MUST NOT STOP THE DAEMON, and must not be trusted.
//
// Treated as absent: the run continues and a fresh reference is written.
// Refusing to start because a tripwire file is unreadable would turn a
// detection aid into an outage, which for this product is the worse failure.
func TestACorruptReferenceIsReplacedRatherThanFatal(t *testing.T) {
	exe, data := fixture(t, "the binary")
	pin := filepath.Join(data, PinName)
	if err := os.WriteFile(pin, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := Check(exe, data, "0.2.0")
	if err != nil {
		t.Fatalf("a corrupt reference made the check fail: %v", err)
	}
	if f.Changed {
		t.Error("a corrupt reference was treated as evidence of tampering; it is " +
			"evidence of nothing")
	}
	var p Pin
	b, readErr := os.ReadFile(pin)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("the reference was not rewritten as valid JSON: %v", err)
	}
	if p.SHA256 == "" {
		t.Error("the rewritten reference carries no hash")
	}
}

// A MISSING BINARY IS AN ERROR, NOT A FINDING. It cannot be hashed, and
// reporting "changed" would be a claim the check cannot support.
func TestAnUnreadableBinaryIsAnErrorAndNotAFinding(t *testing.T) {
	_, data := fixture(t, "x")
	f, err := Check(filepath.Join(data, "does-not-exist"), data, "0.2.0")
	if err == nil {
		t.Fatal("hashing a binary that is not there reported success")
	}
	if f.Changed {
		t.Error("an unreadable binary was reported as a change")
	}
}

// THE LIMITATION IS STATED, AND IT IS HONEST ABOUT THIS PLATFORM.
//
// The point of the sentence is that a reader on a platform which cannot
// establish authorship finds that out here rather than inferring from a quiet
// startup that the binary has been vouched for.
func TestTheLimitationSaysWhatThisPlatformCannotDo(t *testing.T) {
	got := Limitation()
	if strings.TrimSpace(got) == "" {
		t.Fatal("no limitation is stated at all")
	}
	if !canIdentifyPublisher() {
		for _, want := range []string{"cannot", "CHANGED"} {
			if !strings.Contains(got, want) {
				t.Errorf("on a platform with no publisher identity the limitation "+
					"does not contain %q, so a reader could take silence for "+
					"a guarantee:\n%s", want, got)
			}
		}
		if strings.Contains(got, "Authenticode signature and its signer are") {
			t.Error("the limitation claims a signature check this platform cannot make")
		}
	}
}

// The reference records enough to tell the two kinds of "no signer" apart.
// Without IdentityAvailable, a pin written on Linux and later read on Windows
// would look like "was unsigned, now signed" and vice versa.
func TestTheReferenceDistinguishesUnsignedFromUnknowable(t *testing.T) {
	exe, data := fixture(t, "binary")
	mustCheck(t, exe, data, "0.2.0")

	b, err := os.ReadFile(filepath.Join(data, PinName))
	if err != nil {
		t.Fatal(err)
	}
	var p Pin
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if p.IdentityAvailable != canIdentifyPublisher() {
		t.Errorf("identity_available = %v, want %v for this platform",
			p.IdentityAvailable, canIdentifyPublisher())
	}
	if !p.IdentityAvailable && p.Signed {
		t.Error("a platform that cannot look reported the binary as signed")
	}
	if p.Path != exe {
		t.Errorf("path = %q, want %q", p.Path, exe)
	}
}
