package service

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Single-instance lock
// ---------------------------------------------------------------------------

// The failure this prevents: a service AND a logon task both running, both
// ingesting the same events, both alerting. On a product whose credibility
// depends on not crying wolf, duplicate alerts are not a cosmetic problem.
func TestASecondInstanceIsRefused(t *testing.T) {
	dir := t.TempDir()

	first, err := Acquire(dir)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	t.Cleanup(func() { first.Release() })

	_, err = Acquire(dir)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Acquire = %v, want ErrAlreadyRunning", err)
	}
	// The refusal must name the holder, or the operator is left guessing which
	// of two processes to stop.
	if !strings.Contains(err.Error(), "pid") {
		t.Errorf("refusal does not identify the holder: %v", err)
	}
}

func TestTheLockIsReleasedAndReacquirable(t *testing.T) {
	dir := t.TempDir()
	first, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	second, err := Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	second.Release()

	// Release twice must not panic or error: shutdown paths run more than once
	// more often than anyone intends.
	if err := second.Release(); err != nil {
		t.Errorf("second Release: %v", err)
	}
}

// Two installations watching two different consoles from one machine are
// legitimate, which is why the lock is on the DATA DIRECTORY and not on the
// executable or a machine-wide name.
func TestSeparateDataDirectoriesLockIndependently(t *testing.T) {
	a, err := Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()

	b, err := Acquire(t.TempDir())
	if err != nil {
		t.Fatalf("a second data directory was refused: %v", err)
	}
	defer b.Release()
}

func TestHolderPIDReportsTheRunningProcess(t *testing.T) {
	dir := t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()

	if got, want := HolderPID(dir), os.Getpid(); got != want {
		t.Errorf("HolderPID() = %d, want %d", got, want)
	}
}

// ---------------------------------------------------------------------------
// Crash marker
// ---------------------------------------------------------------------------

var t0 = time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

func TestACleanShutdownLeavesNoCrashSignal(t *testing.T) {
	dir := t.TempDir()

	m, prev, err := Begin(dir, "1.0.0", t0)
	if err != nil {
		t.Fatal(err)
	}
	if prev != nil {
		t.Fatal("a first run reported a previous crash")
	}
	if err := m.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	_, prev, err = Begin(dir, "1.0.0", t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if prev != nil {
		t.Error("a clean shutdown was reported as a crash")
	}
}

// The whole point: without this, a crash loop is invisible. The service
// restarts, the UI looks healthy, and the only evidence is a gap in the
// history nobody reads.
func TestAnUncleanExitIsDetectedOnTheNextStart(t *testing.T) {
	dir := t.TempDir()

	m, _, err := Begin(dir, "1.0.0", t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Heartbeat("1.0.0", t0, t0.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// No Finish -- the process "died".

	_, prev, err := Begin(dir, "1.0.0", t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if prev == nil {
		t.Fatal("an unclean exit was not detected")
	}
	if prev.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", prev.PID, os.Getpid())
	}
	if got, want := prev.Ran(), 6*time.Minute; got != want {
		t.Errorf("Ran() = %s, want %s -- the incident should be able to say "+
			"whether it died on startup or after days of running", got, want)
	}

	detail := CrashDetail(prev)
	for _, want := range []string{"did not shut down cleanly", "6m0s", "not delivered"} {
		if !strings.Contains(detail, want) {
			t.Errorf("CrashDetail() does not mention %q:\n%s", want, detail)
		}
	}
}

// A torn marker is still evidence of an abrupt death -- the write was
// interrupted. Discarding the signal because the detail is unreadable would
// turn the worst crashes into silent ones.
func TestATornMarkerStillReportsACrash(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Begin(dir, "1.0.0", t0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, MarkerFileName), []byte(`{"pid":12`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, prev, err := Begin(dir, "1.0.0", t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("a truncated marker made Begin fail: %v", err)
	}
	if prev == nil {
		t.Fatal("a truncated marker was treated as a clean shutdown")
	}
	if !strings.Contains(CrashDetail(prev), "incomplete") {
		t.Errorf("CrashDetail should say the record was incomplete:\n%s", CrashDetail(prev))
	}
}

func TestFinishIsIdempotent(t *testing.T) {
	m, _, err := Begin(t.TempDir(), "1.0.0", t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Finish(); err != nil {
		t.Fatal(err)
	}
	if err := m.Finish(); err != nil {
		t.Errorf("second Finish: %v", err)
	}
}

// ---------------------------------------------------------------------------
// systemd unit
// ---------------------------------------------------------------------------

func testUnit(t *testing.T) string {
	t.Helper()
	u, err := RenderUnit(InstallOptions{
		ExePath: "/usr/local/bin/notifymatrix",
		DataDir: "/var/lib/notifymatrix",
		User:    "notifymatrix",
	})
	if err != nil {
		t.Fatalf("RenderUnit: %v", err)
	}
	return u
}

// The two directives that decide whether this product works at 4am.
func TestUnitNeverGivesUpRestarting(t *testing.T) {
	u := testUnit(t)

	if !strings.Contains(u, "Restart=always") {
		t.Error("unit does not set Restart=always")
	}
	// systemd's DEFAULT is to stop trying after 5 starts in 10 seconds.
	// Restart=always ALONE therefore still gives up -- which for an alarm
	// watchdog is the wrong polarity entirely.
	if !strings.Contains(u, "StartLimitIntervalSec=0") {
		t.Error("unit does not disable the start limiter, so systemd will " +
			"stop restarting after a burst -- a daemon that has crash-looped " +
			"five times still needs to be trying at 4am")
	}
}

// Without this a machine WITH a TPM silently falls to the key-file tier, which
// is not machine-bound. A silent downgrade of the secret store is exactly the
// kind of thing nobody notices.
func TestUnitGrantsTPMAccess(t *testing.T) {
	u := testUnit(t)
	if !strings.Contains(u, "SupplementaryGroups=tss") {
		t.Error("unit does not grant the tss group; systemd-creds --with-key=tpm2 " +
			"needs /dev/tpmrm0 and the daemon runs unprivileged")
	}
	// PrivateDevices=true would hide /dev/tpmrm0 and undo the line above. A
	// hardening option that quietly weakens the thing being hardened is worse
	// than not setting it.
	if strings.Contains(u, "PrivateDevices=true") {
		t.Error("PrivateDevices=true hides /dev/tpmrm0 and silently demotes " +
			"the secret store on every machine with a TPM")
	}
}

func TestUnitRunsUnprivilegedAndIsHardened(t *testing.T) {
	u := testUnit(t)
	for _, want := range []string{
		"User=notifymatrix",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"StateDirectory=notifymatrix",
		"WantedBy=multi-user.target", // comes back after a reboot
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit is missing %q", want)
		}
	}
}

// ProtectSystem=strict makes everything read-only except what StateDirectory
// grants, and StateDirectory is relative to /var/lib. A data directory outside
// it produces a unit that starts fine and cannot write its incident store --
// failing at the first alarm rather than at install.
func TestUnitRefusesADataDirItCannotWrite(t *testing.T) {
	_, err := RenderUnit(InstallOptions{
		ExePath: "/usr/local/bin/notifymatrix",
		DataDir: "/opt/notifymatrix/data",
		User:    "notifymatrix",
	})
	if err == nil {
		t.Fatal("a data directory outside /var/lib was accepted")
	}
	if !strings.Contains(err.Error(), "/var/lib") {
		t.Errorf("the error does not explain the constraint: %v", err)
	}
}

func TestUnitRefusesIncompleteOptions(t *testing.T) {
	if _, err := RenderUnit(InstallOptions{DataDir: "/var/lib/notifymatrix"}); err == nil {
		t.Error("rendered a unit with no ExecStart path")
	}
	if _, err := RenderUnit(InstallOptions{ExePath: "/usr/local/bin/notifymatrix"}); err == nil {
		t.Error("rendered a unit with no data directory")
	}
}

// ---------------------------------------------------------------------------
// Status rendering
// ---------------------------------------------------------------------------

// An installed, automatic, running service with no crash recovery looks
// perfectly healthy. The status line must say otherwise, loudly, because that
// is the configuration prior in-house work shipped.
func TestStatusSaysWhenItWillNotSurviveACrash(t *testing.T) {
	s := Status{State: StateRunning, PID: 42, StartType: "automatic", RecoversFromCrash: false}
	if !strings.Contains(s.String(), "WILL NOT restart after a crash") {
		t.Errorf("status hides the missing recovery configuration: %s", s)
	}

	ok := Status{State: StateRunning, PID: 42, StartType: "automatic", RecoversFromCrash: true}
	if !strings.Contains(ok.String(), "restarts after a crash") {
		t.Errorf("status does not confirm crash recovery: %s", ok)
	}
}

func TestNotInstalledStatusIsQuiet(t *testing.T) {
	s := Status{State: StateNotInstalled}
	if strings.Contains(s.String(), "crash") {
		t.Errorf("an uninstalled service should not report recovery state: %s", s)
	}
}

func TestRestartLadderIsConfigured(t *testing.T) {
	if len(RestartDelays) == 0 {
		t.Fatal("no restart delays configured")
	}
	last := time.Duration(-1)
	for i, d := range RestartDelays {
		if d <= 0 {
			t.Errorf("delay %d is not positive: %s", i, d)
		}
		if d < last {
			t.Errorf("delay %d (%s) is shorter than the one before (%s); the "+
				"ladder should back off, not tighten", i, d, last)
		}
		last = d
	}
	// A short reset period means a daemon crashing once an hour looks healthy
	// forever, because every failure is counted as if it were the first.
	if FailureResetPeriod < time.Hour {
		t.Errorf("FailureResetPeriod %s is too short to recognise a slow crash loop",
			FailureResetPeriod)
	}
}

// The lock file's contents outlive the process that wrote them, so reading
// them is not a liveness check. Diagnostics that confuse the two send an
// operator hunting for a process that exited hours ago.
func TestIsHeldTestsTheLockRatherThanReadingTheFile(t *testing.T) {
	dir := t.TempDir()

	if IsHeld(dir) {
		t.Error("an untouched directory reported as locked")
	}

	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !IsHeld(dir) {
		t.Error("a held directory reported as unlocked")
	}

	l.Release()

	// The file -- and the pid inside it -- still exist. IsHeld must not be
	// fooled by that.
	if HolderPID(dir) == 0 {
		t.Fatal("test precondition: expected a stale pid to remain on disk")
	}
	if IsHeld(dir) {
		t.Error("a released lock still reports as held; IsHeld is reading the " +
			"file instead of testing the lock")
	}
}

// An install that cannot write to Program Files must be reported as something
// ELEVATION fixes, not as a flat failure.
//
// PlaceBinary runs before the service is created, so it is the first thing to
// hit the permission wall -- and only ErrNeedsPrivilege makes the caller
// re-run the command elevated. Without the sentinel here, an unelevated
// install printed "access denied", suggested --portable, and exited: the UAC
// prompt the double-click path promises was unreachable, and the only route
// offered was a LocalSystem service running from a user-writable folder.
func TestAPermissionFailureWhilePlacingTheBinaryAsksForElevation(t *testing.T) {
	err := placeError(`C:\Program Files\NotifyMatrix`, fs.ErrPermission)
	if !errors.Is(err, ErrNeedsPrivilege) {
		t.Errorf("a permission failure did not ask for elevation: %v", err)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("the cause was lost: %v", err)
	}
}

// Anything else stays an ordinary failure: a full disk is not fixed by a UAC
// prompt, and looping the operator through one would waste their time.
func TestOtherFailuresWhilePlacingTheBinaryDoNotAskForElevation(t *testing.T) {
	err := placeError(`C:\Program Files\NotifyMatrix`, errors.New("no space left on device"))
	if errors.Is(err, ErrNeedsPrivilege) {
		t.Errorf("a non-permission failure asked for elevation: %v", err)
	}
}
