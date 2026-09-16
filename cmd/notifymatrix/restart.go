package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/service"
)

// restartServiceVerb is the hidden command the restart helper runs as.
//
// Not in `usage`, because it is not a thing to type: it exists so a daemon can
// be restarted by something that is not itself.
const restartServiceVerb = "restart-service"

// restartSelf restarts the service this process IS.
//
// The obvious implementation -- stop, then start -- cannot work from inside
// the thing being stopped: the stop succeeds, this process dies, and nothing
// is left running to do the start. The result is a daemon that is not running
// and raises no alarms, which is the worst state this product has.
//
// So the work is handed to a detached child that outlives us: it stops the
// service, waits for the service manager to say it really has stopped, and
// starts it again. A service's children are not killed with it on Windows, and
// the child inherits LocalSystem, so it has the rights to do both halves.
func restartSelf(m service.Manager) error {
	st, err := m.Status()
	if err != nil {
		return fmt.Errorf("could not read the service state: %w", err)
	}
	if st.State == service.StateNotInstalled {
		// Running in a terminal rather than as a service. Restarting is
		// something the operator does by closing the window, and pretending
		// otherwise would leave them with nothing running.
		return errors.New("this daemon is not running as a service, so it cannot " +
			"restart itself -- stop it and start it again")
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not locate this executable: %w", err)
	}
	cmd := exec.Command(exe, restartServiceVerb)
	detachChild(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start the restart helper: %w", err)
	}
	// Deliberately not waited for. It is about to stop this process, and a
	// Wait would be waiting for something that kills the waiter.
	go func() { _ = cmd.Process.Release() }()
	return nil
}

// restartServiceHelper is the detached child: stop, wait, start.
//
// Its whole job is to be a process that is not the one being restarted.
func restartServiceHelper() int {
	m := service.New()

	if err := m.Stop(); err != nil && !errors.Is(err, service.ErrNotInstalled) {
		fmt.Fprintln(os.Stderr, "restart: stopping:", err)
		// Carry on to the start regardless. A stop that failed because the
		// service was already down must still be followed by a start, or the
		// helper leaves it off -- and a daemon that is off raises nothing.
	}

	// Wait for the service manager to agree it has stopped. Starting a service
	// that is still stopping fails, and it fails in a way that leaves it
	// stopped, so this is the difference between a restart and an outage.
	deadline := time.Now().Add(restartStopTimeout)
	for time.Now().Before(deadline) {
		st, err := m.Status()
		if err == nil && st.State != service.StateRunning {
			break
		}
		time.Sleep(restartPollInterval)
	}

	if err := m.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "restart: starting:", err)
		return 1
	}
	return 0
}

const (
	// restartStopTimeout bounds the wait for a stop. Generous, because the
	// daemon closes a SQLite store and drains delivery queues on the way down,
	// and cutting that short to start sooner is how a restart becomes a
	// corrupted store.
	restartStopTimeout = 60 * time.Second

	restartPollInterval = 250 * time.Millisecond
)
