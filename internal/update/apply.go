package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// backupSuffix marks the binary an update replaced.
//
// Kept rather than deleted. On Windows the old file cannot be removed while it
// is still running -- which it is, since the process doing the update is the
// one being replaced -- and having it there is also the whole of the rollback.
const backupSuffix = ".previous"

// Apply puts the verified file in place of the installed one.
//
// Two renames, in the only order that is safe. A rename is atomic within a
// filesystem, so at no point is there no binary at the target path: it is
// either the old one or the new one. The alternative -- delete then copy --
// has a window in which the service points at nothing, and a machine that
// reboots inside that window comes up with no daemon and raises no alarms,
// which is this product failing in the exact way it exists to prevent.
//
// Windows will not let a running executable be deleted, but it WILL let it be
// renamed. That is what makes replacing a running service possible at all.
func Apply(verified, target string) error {
	if verified == "" || target == "" {
		return errors.New("update: nothing to install")
	}
	if filepath.Dir(verified) != filepath.Dir(target) {
		// The rename below would cross filesystems and silently become a copy,
		// which is not atomic and can fail halfway.
		return fmt.Errorf("update: %s is not beside %s", verified, target)
	}

	backup := target + backupSuffix
	// A backup left by a previous update is in the way. It is safe to drop:
	// whatever was running then is not running now.
	_ = os.Remove(backup)

	if err := os.Rename(target, backup); err != nil {
		return fmt.Errorf("update: could not move the installed binary aside "+
			"(%w) -- nothing was changed", err)
	}
	if err := os.Rename(verified, target); err != nil {
		// Put it back. Failing here without a rollback leaves the service
		// pointing at a path with nothing at it.
		if back := os.Rename(backup, target); back != nil {
			return fmt.Errorf("update: could not install the new binary (%w), AND "+
				"could not restore the old one (%v). The previous version is at %s "+
				"and must be moved back to %s by hand", err, back, backup, target)
		}
		return fmt.Errorf("update: could not install the new binary (%w) -- the "+
			"previous one was put back and nothing has changed", err)
	}
	return nil
}

// Rollback undoes Apply, for when the replacement will not start.
func Rollback(target string) error {
	backup := target + backupSuffix
	if _, err := os.Stat(backup); err != nil {
		return fmt.Errorf("update: there is no %s to roll back to", backup)
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("update: could not remove the failed binary: %w", err)
	}
	return os.Rename(backup, target)
}

// CleanBackups removes the file a previous update left behind.
//
// Called at start, not at the end of an update: at the end of an update the
// old binary is still the running process and Windows will not delete it.
func CleanBackups(target string) {
	_ = os.Remove(target + backupSuffix)
}

// IsBackup reports whether a path is one of this package's leftovers, so the
// daemon does not mistake it for something it should be running.
func IsBackup(path string) bool { return strings.HasSuffix(path, backupSuffix) }
