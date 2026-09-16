//go:build !windows

package service

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// acquirePlatform takes a non-blocking exclusive flock.
//
// flock rather than a PID file: the kernel drops it when the process exits,
// crash included, so there is no stale lock to reason about and no PID-reuse
// race. That matters most after a power cut, which is exactly when this
// product is needed and exactly when a PID file is least trustworthy.
//
// Non-blocking on purpose. A second instance must fail loudly and immediately;
// blocking would leave a silent process waiting for a lock it will never get,
// which looks identical to a service that started successfully and is doing
// nothing.
func acquirePlatform(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("service: opening %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("service: locking %s: %w", path, err)
	}
	return f, nil
}

func releasePlatform(f *os.File, _ string) error {
	// Closing the descriptor releases the flock. Unlocking explicitly first
	// makes the intent legible and is harmless.
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return f.Close()
}
