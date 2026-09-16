package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyReplacesInPlaceAndKeepsTheOldOne(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "notifymatrix")
	newFile := filepath.Join(dir, ".notifymatrix-update-123")
	mustWrite(t, target, "old")
	mustWrite(t, newFile, "new")

	if err := Apply(newFile, target); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := mustRead(t, target); got != "new" {
		t.Errorf("target = %q, want new", got)
	}
	if got := mustRead(t, target+backupSuffix); got != "old" {
		t.Errorf("backup = %q, want old -- without it there is no rollback", got)
	}
}

// The rollback path is the one that decides whether a bad update is an
// inconvenience or a machine with no daemon on it.
func TestRollbackPutsThePreviousBinaryBack(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "notifymatrix")
	newFile := filepath.Join(dir, ".notifymatrix-update-123")
	mustWrite(t, target, "old")
	mustWrite(t, newFile, "new")
	if err := Apply(newFile, target); err != nil {
		t.Fatal(err)
	}

	if err := Rollback(target); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := mustRead(t, target); got != "old" {
		t.Errorf("after rollback target = %q, want old", got)
	}
	if _, err := os.Stat(target + backupSuffix); !os.IsNotExist(err) {
		t.Error("the backup is still there after being rolled back into place")
	}
}

// Installing from another directory would make the rename a cross-filesystem
// copy, which is not atomic -- and a half-copied binary at the service's path
// is a machine that comes up with no daemon.
func TestApplyRefusesToInstallFromAnotherDirectory(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	target := filepath.Join(dir, "notifymatrix")
	newFile := filepath.Join(other, "downloaded")
	mustWrite(t, target, "old")
	mustWrite(t, newFile, "new")

	if err := Apply(newFile, target); err == nil {
		t.Fatal("accepted a replacement from another directory")
	}
	if got := mustRead(t, target); got != "old" {
		t.Errorf("the installed binary was touched: %q", got)
	}
}

// A failed install must leave the old binary at the path the service points
// at. Simulated by handing Apply a source that does not exist, so the second
// rename fails after the first has already moved the original aside.
func TestAFailedInstallPutsTheOriginalBack(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "notifymatrix")
	mustWrite(t, target, "old")

	err := Apply(filepath.Join(dir, "does-not-exist"), target)
	if err == nil {
		t.Fatal("Apply succeeded with no source file")
	}
	if got := mustRead(t, target); got != "old" {
		t.Fatalf("after a failed install the target is %q -- the service now points "+
			"at something that is not the daemon", got)
	}
}

func TestCleanBackupsRemovesTheLeftover(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "notifymatrix")
	mustWrite(t, target+backupSuffix, "old")
	CleanBackups(target)
	if _, err := os.Stat(target + backupSuffix); !os.IsNotExist(err) {
		t.Error("the leftover survived CleanBackups")
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
