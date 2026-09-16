package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
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
//
// The data directory goes with it so the child can RECORD a failure. Without
// that, a restart that stops and does not start leaves no trace anywhere and
// the only symptom is a daemon that is not running -- which is exactly the
// thing this product exists to notice about everything except itself.
func restartSelf(m service.Manager, dataDir string) error {
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
	args := []string{restartServiceVerb}
	if dataDir != "" {
		args = append(args, "--data-dir", dataDir)
	}
	cmd := exec.Command(exe, args...)
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
func restartServiceHelper(dataDir string) int {
	m := service.New()

	if err := m.Stop(); err != nil && !errors.Is(err, service.ErrNotInstalled) {
		// Carry on to the start regardless. A stop that failed because the
		// service was already down must still be followed by a start, or the
		// helper leaves it off -- and a daemon that is off raises nothing.
		recordRestartTrouble(dataDir, "stopping the service reported an error", err)
	}

	// Wait for STOPPED specifically.
	//
	// This is where the first version got it wrong, and the bug took a live
	// installation down and left it down. Stop() only SENDS the control and
	// returns; the service then sits in STOP_PENDING while it closes its store
	// and drains its queues. The wait was written as "not running", and
	// STOP_PENDING is not running -- so it fell through immediately and called
	// Start() into a service that was still stopping, which Windows refuses.
	// The helper then exited quietly and the machine was left with no daemon.
	stopped := false
	deadline := time.Now().Add(restartStopTimeout)
	for time.Now().Before(deadline) {
		if st, err := m.Status(); err == nil && st.State == service.StateStopped {
			stopped = true
			break
		}
		time.Sleep(restartPollInterval)
	}
	if !stopped {
		recordRestartTrouble(dataDir,
			"the service did not reach a stopped state within "+restartStopTimeout.String()+
				"; starting anyway", nil)
	}

	// And retry the start, because the window between "stopped" and "startable"
	// is not always zero. Failing here is the failure that matters: everything
	// above has already taken the daemon down.
	var err error
	for attempt := 1; attempt <= restartStartAttempts; attempt++ {
		if err = m.Start(); err == nil {
			return 0
		}
		time.Sleep(restartStartBackoff)
	}

	recordRestartTrouble(dataDir,
		"THE SERVICE IS STOPPED AND COULD NOT BE STARTED. Nothing is being "+
			"watched until it is started by hand", err)
	fmt.Fprintln(os.Stderr, "restart: starting:", err)
	return 1
}

// recordRestartTrouble writes to the audit record, which is the only place a
// detached child with no console can say anything at all.
//
// Best effort by necessity -- if this fails there is genuinely nowhere left to
// report -- but it is the difference between a stopped daemon with a reason
// and a stopped daemon that simply stopped.
func recordRestartTrouble(dataDir, summary string, cause error) {
	if dataDir == "" {
		return
	}
	log, err := audit.Open(filepath.Dir(filepath.Join(dataDir, "audit.jsonl")))
	if err != nil {
		return
	}
	defer log.Close()

	fields := map[string]string{"stage": "restart"}
	if cause != nil {
		fields["error"] = cause.Error()
	}
	_ = log.Append(context.Background(), audit.Entry{
		Kind: audit.KindService, Actor: "system",
		Summary: "restart: " + summary,
		Fields:  fields,
	})
}

const (
	// restartStopTimeout bounds the wait for a stop. Generous, because the
	// daemon closes a SQLite store and drains delivery queues on the way down,
	// and cutting that short to start sooner is how a restart becomes a
	// corrupted store.
	restartStopTimeout = 60 * time.Second

	restartPollInterval = 250 * time.Millisecond

	// restartStartAttempts covers the gap between the service manager
	// reporting STOPPED and being willing to start it again.
	restartStartAttempts = 10
	restartStartBackoff  = 1 * time.Second
)
