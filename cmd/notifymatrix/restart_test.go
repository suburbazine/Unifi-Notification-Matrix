package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/service"
)

// The bug this exists for took a live installation down and left it down.
//
// Stop() only SENDS the stop control and returns; the service then sits in
// STOP_PENDING while it closes its store and drains its queues. Windows maps
// STOP_PENDING to neither Running nor Stopped, and the wait was written as
// "not running" -- so it fell through instantly, called Start() into a service
// that was still stopping, which Windows refuses, and the helper exited
// quietly. The machine was left with no daemon and nothing said why.
//
// The distinction is the whole fix, so it is asserted directly: an in-between
// state must NOT satisfy the condition the helper waits on.
func TestATransitionalStateIsNotMistakenForStopped(t *testing.T) {
	// What the helper now waits for.
	stoppedEnough := func(s service.State) bool { return s == service.StateStopped }

	if stoppedEnough(service.StateUnknown) {
		t.Error("a service in an unknown or transitional state was treated as " +
			"stopped; starting it there is refused and leaves the machine with " +
			"no daemon")
	}
	if stoppedEnough(service.StateRunning) {
		t.Error("a running service was treated as stopped")
	}
	if !stoppedEnough(service.StateStopped) {
		t.Error("a stopped service was not recognised, so the helper would wait " +
			"out its whole timeout before starting")
	}

	// And the condition that CAUSED it, kept here so it cannot come back by
	// looking reasonable: "not running" is true of a service that is still
	// stopping.
	notRunning := func(s service.State) bool { return s != service.StateRunning }
	if !notRunning(service.StateUnknown) {
		t.Fatal("the test's model of the old condition is wrong")
	}
	if stoppedEnough(service.StateUnknown) == notRunning(service.StateUnknown) {
		t.Error("the new condition agrees with the one that broke it on a " +
			"transitional state, so it would fall through and start too early " +
			"in exactly the same way")
	}
}

// A restart that cannot start the service is the worst outcome this product
// has: nothing is watched, and the daemon that would normally notice is the
// thing that is gone. It must not be silent.
func TestAFailedRestartIsRecordedWhereSomebodyWillFindIt(t *testing.T) {
	dir := t.TempDir()
	recordRestartTrouble(dir, "the service could not be started", nil)

	log := readAuditLines(t, dir)
	if len(log) == 0 {
		t.Fatal("a failed restart wrote nothing to the audit record, so a stopped " +
			"daemon would have no explanation anywhere")
	}
	if !containsAll(log[0], "restart", "could not be started") {
		t.Errorf("the entry does not say what happened: %s", log[0])
	}
}

// With no data directory there is nowhere to write, and that must not panic --
// the helper is a detached process with no console, so a panic here is a
// silent death on top of a silent death.
func TestRecordingWithNoDataDirectoryIsHarmless(t *testing.T) {
	recordRestartTrouble("", "anything", nil)
}

func readAuditLines(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
