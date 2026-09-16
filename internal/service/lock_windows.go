//go:build windows

package service

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// acquirePlatform opens the lock file with NO sharing, so a second opener is
// refused by the kernel.
//
// os.OpenFile cannot express this: it opens with FILE_SHARE_READ|WRITE, which
// lets any number of processes hold the same file happily. A named mutex would
// also work, but it would be scoped to the machine rather than to the DATA
// DIRECTORY -- and two installations watching two different consoles from one
// machine are legitimate.
//
// The handle is released by the kernel when the process exits, crash included,
// so there is no stale lock to reason about.
func acquirePlatform(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("service: lock path: %w", err)
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		// FILE_SHARE_READ, not 0.
		//
		// Windows sharing is symmetric: an open succeeds only if the requested
		// ACCESS is permitted by every existing handle's share mode, AND the
		// requested SHARE mode permits every existing handle's access. So
		// permitting readers still refuses a second writer -- its GENERIC_WRITE
		// is not allowed by FILE_SHARE_READ -- while letting anything open the
		// file for reading.
		//
		// dwShareMode 0 looked stricter and was strictly worse: it locked out
		// our OWN holder-identification read, so a refusal could not say which
		// process held the directory. A lock that cannot name its holder
		// leaves the operator guessing which of two processes to stop.
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
			errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
			errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("service: claiming %s: %w", path, err)
	}
	return os.NewFile(uintptr(h), path), nil
}

// releasePlatform closes the handle. The file is deliberately left on disk:
// deleting it races a second process that has just opened it, and an empty
// lock file costs nothing.
func releasePlatform(f *os.File, _ string) error {
	return f.Close()
}
