package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
)

// writeTokenFile puts a token on disk in the real format, so these tests break
// if that format changes rather than agreeing with a copy of it.
func writeTokenFile(t *testing.T, dir, token string) {
	t.Helper()
	if err := config.WriteSetupToken(dir, token); err != nil {
		t.Fatal(err)
	}
}

const sampleToken = "0kl9NlKH7UUU_fJXcIlH0wonqn2vew823USjpdGrRoE"

// THE TOKEN IS PULLED OUT OF THE REAL FILE, decorations and all.
//
// The first version of this matched "a line with no spaces" and would have
// returned the row of equals signs under the heading. Matching the base64url
// alphabet is what distinguishes them, because "=" is exactly the character a
// token cannot contain.
func TestTheTokenIsFoundInTheRealFileFormat(t *testing.T) {
	dir := t.TempDir()
	writeTokenFile(t, dir, sampleToken)

	body, err := os.ReadFile(config.SetupTokenPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "=====") {
		t.Fatal("the file no longer has a rule of equals signs, so this test is " +
			"no longer guarding the thing it was written for")
	}
	if got := firstToken(string(body)); got != sampleToken {
		t.Errorf("firstToken = %q, want the token", got)
	}
}

func TestDecorationIsNeverMistakenForAToken(t *testing.T) {
	for _, body := range []string{
		"NotifyMatrix one-time setup token\n=================================\n\n",
		"----------------------------------------------------\n",
		"short\n",
		"",
	} {
		if got := firstToken(body); got != "" {
			t.Errorf("firstToken(%q) = %q, want nothing", body, got)
		}
	}
}

// AN UNATTENDED INSTALL MUST NOT BLOCK.
//
// A deployment hanging for ever is a far worse failure than a prompt nobody
// reads, and a scripted install has redirected stdin by definition.
func TestAnUnattendedInstallShowsTheTokenAndDoesNotWait(t *testing.T) {
	dir := t.TempDir()
	writeTokenFile(t, dir, sampleToken)

	var out strings.Builder
	done := make(chan struct{})
	go func() {
		handOverSetupToken(&out, strings.NewReader(""), dir, false, time.Second, "nm.exe")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("an unattended install blocked; a scripted deployment would hang")
	}
	if !strings.Contains(out.String(), sampleToken) {
		t.Error("the token was not shown at all")
	}
	if strings.Contains(out.String(), "Type "+confirmWord) {
		t.Error("an unattended install prompted for a confirmation nobody can give")
	}
}

// AND AN ATTENDED ONE DOES WAIT -- which is the whole request.
func TestAnAttendedInstallWaitsForTheOperatorToConfirm(t *testing.T) {
	dir := t.TempDir()
	writeTokenFile(t, dir, sampleToken)

	var out strings.Builder
	handOverSetupToken(&out, strings.NewReader("copied\n"), dir, true, time.Second, "nm.exe")

	got := out.String()
	if !strings.Contains(got, sampleToken) {
		t.Fatal("the token was not shown")
	}
	if !strings.Contains(got, "Type "+confirmWord) {
		t.Error("the operator was never asked to confirm")
	}
	if !strings.Contains(got, "Good.") {
		t.Error("a correct confirmation was not accepted")
	}
}

// PRESSING ENTER IS NOT A CONFIRMATION.
//
// Enter is what somebody presses to make a prompt go away. Accepting it would
// make this a pause dressed up as a confirmation, which is the failure it
// exists to prevent one step later.
func TestBareEnterDoesNotCountAsConfirmation(t *testing.T) {
	var out strings.Builder
	if awaitConfirmation(&out, strings.NewReader("\n\n\n")) {
		t.Error("pressing Enter was accepted as having copied the token")
	}
	if !strings.Contains(out.String(), "Type "+confirmWord) {
		t.Error("the operator was not told what to type")
	}
}

func TestConfirmationIsForgivingAboutCaseAndSpacing(t *testing.T) {
	for _, in := range []string{"copied\n", "COPIED\n", "  Copied  \n", "x\ncopied\n"} {
		var out strings.Builder
		if !awaitConfirmation(&out, strings.NewReader(in)) {
			t.Errorf("%q was not accepted", in)
		}
	}
}

// A WRONG ANSWER GIVEN FOR EVER MUST STILL END.
//
// This may be the only window the operator has. Being unable to get past a
// prompt would mean the thing meant to help them has locked them out.
func TestTheConfirmationGivesUpRatherThanTrappingAnybody(t *testing.T) {
	var out strings.Builder
	done := make(chan bool)
	go func() {
		done <- awaitConfirmation(&out, strings.NewReader(strings.Repeat("no\n", 50)))
	}()
	select {
	case ok := <-done:
		if ok {
			t.Error("a wrong answer was accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the prompt never gave up; the operator is trapped in it")
	}
}

// RE-INSTALLING OVER A WORKING CONFIGURATION WAITS FOR NOTHING.
//
// No token is minted when a password is already set, so polling for one would
// stall the install and then report a problem that does not exist.
func TestAnInstallOverAnExistingPasswordDoesNotWaitForAToken(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Web.PasswordHash = "pbkdf2-sha256$600000$c2FsdA$a2V5"
	if err := config.Save(dir, &cfg); err != nil {
		t.Skipf("cannot write a config here: %v", err)
	}

	var out strings.Builder
	start := time.Now()
	handOverSetupToken(&out, strings.NewReader(""), dir, true, 10*time.Second, "nm.exe")
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("waited %v for a token that is never minted", took)
	}
	if !strings.Contains(out.String(), "already set") {
		t.Errorf("did not say why there is no token:\n%s", out.String())
	}
}

// WHEN THE TOKEN IS SLOW, SAY SO AND SAY WHAT TO RUN.
//
// The service may not have written it yet. That is not a failure and must not
// be reported as one, because the recovery is one command.
func TestASlowTokenIsReportedAsRecoverableRatherThanBroken(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	handOverSetupToken(&out, strings.NewReader(""), dir, false, 300*time.Millisecond, "nm.exe")

	got := out.String()
	if !strings.Contains(got, "setup-token") {
		t.Errorf("did not name the command that retrieves it:\n%s", got)
	}
	for _, alarming := range []string{"error", "failed", "cannot"} {
		if strings.Contains(strings.ToLower(got), alarming) {
			t.Errorf("reported a recoverable wait as a failure (%q):\n%s", alarming, got)
		}
	}
}

// The token appearing LATE is still picked up, which is the race this exists
// to lose gracefully: the service writes the file a moment after install
// returns.
func TestATokenWrittenAfterTheWaitStartsIsStillFound(t *testing.T) {
	dir := t.TempDir()
	go func() {
		time.Sleep(400 * time.Millisecond)
		_ = config.WriteSetupToken(dir, sampleToken)
	}()

	tok, path, ok := waitForSetupToken(dir, 5*time.Second)
	if !ok {
		t.Fatal("a token written while waiting was not picked up")
	}
	if tok != sampleToken {
		t.Errorf("token = %q", tok)
	}
	if filepath.Base(path) != config.SetupTokenFile {
		t.Errorf("path = %q", path)
	}
}
