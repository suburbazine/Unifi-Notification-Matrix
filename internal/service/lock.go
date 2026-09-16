package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrAlreadyRunning means another process holds this data directory.
var ErrAlreadyRunning = errors.New("another instance is already running")

// LockFileName lives inside the data directory, not beside the executable.
//
// The lock is on the DATA DIRECTORY on purpose: two installations with
// separate configs watching separate consoles are legitimate and must both be
// able to run. What must never happen is two processes sharing one data
// directory.
const LockFileName = "notifymatrix.lock"

// Lock is an exclusive claim on a data directory, held for the life of the
// process and released when it exits -- including when it crashes.
//
// The classic way this product breaks is a service AND a logon task both
// running: two processes ingesting the same events and sending duplicate
// alerts, on a product whose credibility depends on not crying wolf. Prior
// in-house work removed the logon task when installing the service, which is
// right but relies on knowing every way the app could have been started. A
// lock does not need to know.
//
// Stale locks after a crash are handled by the platform, not by us: both
// implementations use an OS-level claim the kernel drops when the process
// dies. A PID file compared against a running-process check has a race and a
// PID-reuse problem, and gets it wrong exactly when a machine has just come
// back from a power cut -- which is when this product is most needed.
type Lock struct {
	path string
	f    *os.File
}

// Acquire claims dir, creating it if needed.
func Acquire(dir string) (*Lock, error) {
	if dir == "" {
		return nil, errors.New("service: no data directory given to lock")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("service: creating data directory: %w", err)
	}
	path := filepath.Join(dir, LockFileName)

	f, err := acquirePlatform(path)
	if err != nil {
		if errors.Is(err, ErrAlreadyRunning) {
			// Name the holder if it wrote its identity. Best-effort: the file
			// may be mid-write, and a lock that cannot say who holds it is
			// still a lock.
			if who := readHolder(path); who != "" {
				return nil, fmt.Errorf("%w (%s)", ErrAlreadyRunning, who)
			}
		}
		return nil, err
	}

	l := &Lock{path: path, f: f}
	l.writeHolder()
	return l, nil
}

// writeHolder records who holds the lock, so a refusal can say so. Advisory
// only -- correctness comes from the OS-level claim, never from this content.
func (l *Lock) writeHolder() {
	exe, _ := os.Executable()
	body := fmt.Sprintf("pid=%d\nexe=%s\n", os.Getpid(), exe)
	// Truncate first: a previous holder's longer record would otherwise leave
	// a tail behind and make the file say two contradictory things.
	if err := l.f.Truncate(0); err != nil {
		return
	}
	if _, err := l.f.Seek(0, 0); err != nil {
		return
	}
	_, _ = l.f.WriteString(body)
	_ = l.f.Sync()
}

func readHolder(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var pid, exe string
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "pid":
			pid = v
		case "exe":
			exe = v
		}
	}
	switch {
	case pid != "" && exe != "":
		return fmt.Sprintf("held by pid %s: %s", pid, exe)
	case pid != "":
		return "held by pid " + pid
	}
	return ""
}

// IsHeld reports whether some process currently holds dir.
//
// It TESTS the lock rather than reading the file, because the file's contents
// outlive the process that wrote them. Reading alone reports a long-dead pid
// as the current holder -- which in diagnostics is worse than saying nothing,
// since it sends the operator looking for a process that does not exist.
//
// Implemented by trying to acquire and immediately releasing. That is safe
// here: this is a diagnostic path, and a caller that then starts the daemon
// takes its own lock and would be refused if someone else won the race.
func IsHeld(dir string) bool {
	l, err := Acquire(dir)
	if err != nil {
		return errors.Is(err, ErrAlreadyRunning)
	}
	_ = l.Release()
	return false
}

// HolderPID returns the recorded pid from the lock file, or 0.
//
// Advisory: the file outlives its writer, so a non-zero result means "the last
// process to hold this wrote that pid", NOT "that process is running now".
// Pair it with IsHeld before telling an operator anything.
func HolderPID(dir string) int {
	b, err := os.ReadFile(filepath.Join(dir, LockFileName))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "pid="); ok {
			n, _ := strconv.Atoi(v)
			return n
		}
	}
	return 0
}

// Release drops the claim. Safe to call twice.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	return releasePlatform(f, l.path)
}

// Path is the lock file, for diagnostics.
func (l *Lock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}
