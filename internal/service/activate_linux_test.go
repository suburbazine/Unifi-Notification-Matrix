//go:build linux

package service

import (
	"errors"
	"strings"
	"testing"
)

// INSTALL HAS TO LEAVE THE SERVICE RUNNING THE BINARY THAT IS THERE NOW.
//
// Install is idempotent on Linux on purpose -- re-running it is how an upgrade
// is applied -- and `systemctl start` on an already-running unit is a no-op.
// That left the new binary on disk, the old one executing, and every version
// reading except the interface's claiming success.
//
// Asserted on the VERB, because nothing else can see it. There is no
// observable difference between the two until somebody notices the daemon is
// serving a version it should not be.
func TestActivateRestartsRatherThanStarting(t *testing.T) {
	real := systemctl
	t.Cleanup(func() { systemctl = real })

	var got []string
	systemctl = func(args ...string) (string, error) {
		got = append(got, strings.Join(args, " "))
		return "", nil
	}

	if err := activate(); err != nil {
		t.Fatalf("activate: %v", err)
	}

	want := []string{"daemon-reload", "enable " + Name, "restart " + Name}
	if len(got) != len(want) {
		t.Fatalf("systemctl calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, got[i], want[i])
		}
	}
	for _, c := range got {
		if c == "start "+Name {
			t.Error("Install uses `systemctl start`, which is a no-op on a " +
				"running unit -- an upgrade would leave the old binary serving")
		}
	}
}

// A FAILURE AT ANY STEP STOPS THE REST.
//
// Reporting success after a failed daemon-reload would mean an install that
// says it worked and left systemd reading a stale unit.
func TestActivateStopsAtTheFirstFailure(t *testing.T) {
	real := systemctl
	t.Cleanup(func() { systemctl = real })

	for _, failAt := range []string{"daemon-reload", "enable", "restart"} {
		var got []string
		systemctl = func(args ...string) (string, error) {
			got = append(got, args[0])
			if args[0] == failAt {
				return "", errors.New("boom")
			}
			return "", nil
		}
		err := activate()
		if err == nil {
			t.Errorf("a failure at %q was reported as success", failAt)
			continue
		}
		if last := got[len(got)-1]; last != failAt {
			t.Errorf("failing at %q, the last call was %q -- it kept going", failAt, last)
		}
	}
}
