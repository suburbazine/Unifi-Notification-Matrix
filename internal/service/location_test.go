package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The service runs as LocalSystem on Windows. Its binary therefore has to sit
// where an UNelevated process cannot write, because whoever can replace that
// file chooses what runs as the service account next time it starts.
//
// The natural thing to do with a downloaded program is run it from Downloads,
// and install records whatever path it was run from for ever. Observed in the
// field: a service running as LocalSystem from a Downloads folder its own
// non-elevated user had FullControl over.
func TestInstallingFromAUserProfileIsWarnedAbout(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory on this machine")
	}
	exe := filepath.Join(home, "Downloads", "notifymatrix.exe")

	w := LocationWarning(exe)
	if w == "" {
		t.Fatalf("installing from %s drew no warning", exe)
	}
	// The warning has to say what to do, not only that something is wrong.
	if !strings.Contains(w, "administrators") {
		t.Errorf("the warning does not say where it should go instead:\n%s", w)
	}
}

func TestInstallingFromATempDirectoryIsWarnedAbout(t *testing.T) {
	exe := filepath.Join(os.TempDir(), "notifymatrix.exe")
	if LocationWarning(exe) == "" {
		t.Fatalf("installing from %s drew no warning", exe)
	}
}

// A sensible location must be silent, or the warning is noise and gets
// ignored on the day it matters.
func TestAProperInstallLocationIsNotWarnedAbout(t *testing.T) {
	for _, exe := range []string{
		`C:\Program Files\NotifyMatrix\notifymatrix.exe`,
		"/usr/local/bin/notifymatrix",
		"/opt/notifymatrix/notifymatrix",
	} {
		if w := LocationWarning(exe); w != "" {
			t.Errorf("%s was warned about:\n%s", exe, w)
		}
	}
}

// An empty path must not produce a warning about nothing.
func TestNoPathIsNotWarnedAbout(t *testing.T) {
	if w := LocationWarning(""); w != "" {
		t.Errorf("an empty path produced: %s", w)
	}
}
