package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// placedBackupSuffix marks the binary a re-install replaced.
//
// Kept rather than deleted, because on Windows the file being replaced may be
// the one currently running and a running executable cannot be deleted. It can
// be renamed, which is what makes replacing it possible at all.
const placedBackupSuffix = ".previous"

// PlaceBinary copies this program to where a service binary belongs, and
// returns the path it put it at.
//
// This exists because of what `install` used to do, which was to register
// whatever path it happened to be run from -- for ever. The natural thing to
// do with a downloaded program is run it where it landed, so the natural
// outcome was a service running as LocalSystem out of a Downloads folder that
// its own unelevated user could write to. Anybody able to replace that file
// chooses what runs as the service account next time it starts, and none of
// the updater's signature checking applies to a file somebody simply
// overwrites.
//
// Copy, verify, then rename into place. The verification is not ceremony: a
// truncated copy is a service that will not start, discovered at the moment
// something needed watching.
// placeError reports a failure to write into the install directory, and marks
// the permission case as one elevation would fix.
//
// Wrapping ErrNeedsPrivilege is what makes install actually prompt. Without
// it, an unelevated install failed HERE -- before m.Install, which was the only
// thing that returned the sentinel -- so the caller printed "access denied",
// suggested --portable, and exited. The UAC prompt the double-click path and
// SETUP.md both promise was unreachable, and the only route offered was the
// insecure one: a LocalSystem service running out of a user-writable folder.
func placeError(dir string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("service: writing to %s: %w: %w", dir, ErrNeedsPrivilege, err)
	}
	return fmt.Errorf("service: writing to %s: %w", dir, err)
}

func PlaceBinary(src string) (string, error) {
	dest := DefaultInstallPath()

	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return "", fmt.Errorf("service: %w", err)
	}
	if sameFile(srcAbs, dest) {
		return dest, nil // already where it belongs
	}

	want, err := hashFile(srcAbs)
	if err != nil {
		return "", fmt.Errorf("service: reading %s: %w", srcAbs, err)
	}

	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", placeError(dir, err)
	}

	// Staged in the destination directory, so the final step is a rename
	// within one filesystem and therefore atomic. A copy straight onto the
	// destination can fail halfway and leave the service pointing at a
	// half-written binary.
	tmp, err := os.CreateTemp(dir, ".notifymatrix-install-*")
	if err != nil {
		return "", placeError(dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	var in *os.File
	if in, err = os.Open(srcAbs); err != nil {
		return "", fmt.Errorf("service: %w", err)
	}
	defer in.Close()

	if _, err = io.Copy(tmp, in); err != nil {
		return "", fmt.Errorf("service: copying to %s: %w", dir, err)
	}
	// Flushed before it is checked, or the check reads a buffer rather than
	// the file the service manager will launch.
	if err = tmp.Sync(); err != nil {
		return "", fmt.Errorf("service: flushing %s: %w", tmpName, err)
	}
	if err = tmp.Close(); err != nil {
		return "", fmt.Errorf("service: %w", err)
	}

	var got string
	if got, err = hashFile(tmpName); err != nil {
		return "", fmt.Errorf("service: re-reading the copy: %w", err)
	}
	if got != want {
		err = fmt.Errorf("service: the copy of this program at %s does not match "+
			"the original (%s vs %s); it was discarded and nothing was installed",
			tmpName, got, want)
		return "", err
	}

	if err = os.Chmod(tmpName, 0o755); err != nil {
		return "", fmt.Errorf("service: %w", err)
	}

	// An existing binary is moved aside rather than overwritten, because it may
	// be the running service and Windows will not let that be deleted. It will
	// let it be renamed.
	if _, statErr := os.Stat(dest); statErr == nil {
		_ = os.Remove(dest + placedBackupSuffix)
		if err = os.Rename(dest, dest+placedBackupSuffix); err != nil {
			return "", fmt.Errorf("service: moving the installed binary aside "+
				"(stop the service first): %w", err)
		}
	}
	if err = os.Rename(tmpName, dest); err != nil {
		// Put the old one back rather than leave the path empty.
		if _, statErr := os.Stat(dest + placedBackupSuffix); statErr == nil {
			_ = os.Rename(dest+placedBackupSuffix, dest)
		}
		return "", fmt.Errorf("service: installing to %s: %w", dest, err)
	}
	return dest, nil
}

// CleanPlacedBackup removes what a re-install moved aside. Called at start,
// because at install time the old binary may still be the running process.
func CleanPlacedBackup() {
	_ = os.Remove(DefaultInstallPath() + placedBackupSuffix)
}

// sameFile reports whether two paths are the same file on disk, following the
// spelling differences -- case, separators, a trailing dot -- that would
// otherwise make a program copy itself over itself.
func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
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

// ErrNoInstallDir means this platform has nowhere obvious to put a service
// binary, which is a thing to say rather than a thing to guess about.
var ErrNoInstallDir = errors.New("service: no standard install directory on this platform")
