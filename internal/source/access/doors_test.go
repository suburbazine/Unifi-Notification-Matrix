package access

import (
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
)

var t0 = time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

func newTestDoors() *doors { return newDoors(60*time.Second, 45*time.Second) }

func conditions(ts []transition) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		s := t.condition
		if t.clears {
			s += "(clear)"
		}
		out = append(out, s)
	}
	return out
}

func has(ts []transition, condition string, clears bool) bool {
	for _, t := range ts {
		if t.condition == condition && t.clears == clears {
			return true
		}
	}
	return false
}

// THE FALSE POSITIVE THIS WHOLE DESIGN EXISTS TO AVOID.
//
// A normal entry through a door whose lock relocks quickly ends in exactly the
// state a forced entry ends in -- locked, and open. A rule that looks at the
// current pair raises a critical alarm every single time somebody walks in.
func TestANormalEntryOnAQuickRelockingLockIsNotForced(t *testing.T) {
	d := newTestDoors()

	// The door starts shut and locked. This is what makes later reasoning safe.
	d.observePosition("d1", "Front Door", LockLocked, PositionClosed, t0)

	// Somebody badges in. The socket sees the unlock immediately.
	d.observeLock("d1", "Front Door", LockUnlocked, false, t0.Add(1*time.Second))

	// The lock relocks behind them while the door is still swinging, so by the
	// time the position poll runs the pair reads "locked and open".
	got := d.observePosition("d1", "Front Door", LockLocked, PositionOpen, t0.Add(8*time.Second))

	if has(got, event.ConditionDoorForced, false) {
		t.Fatalf("an ordinary entry was reported as a forced door: %v", conditions(got))
	}
}

// And the thing it must still catch.
func TestADoorThatOpensWhileLockedIsForced(t *testing.T) {
	d := newTestDoors()
	d.observePosition("d1", "Front Door", LockLocked, PositionClosed, t0)

	// No unlock, ever. The door simply opens.
	got := d.observePosition("d1", "Front Door", LockLocked, PositionOpen, t0.Add(time.Minute))

	if !has(got, event.ConditionDoorForced, false) {
		t.Fatalf("a door opened while locked and was not reported: %v", conditions(got))
	}
}

// The grace window is a window, not a latch: an unlock long ago does not
// authorise an opening now.
func TestAnOldUnlockDoesNotAuthoriseALaterOpening(t *testing.T) {
	d := newTestDoors()
	d.observePosition("d1", "Front Door", LockLocked, PositionClosed, t0)
	d.observeLock("d1", "Front Door", LockUnlocked, false, t0)

	// Two minutes later -- well past the 45s grace -- the door opens while
	// locked. Somebody badged in earlier and left; this is a different event.
	got := d.observePosition("d1", "Front Door", LockLocked, PositionOpen, t0.Add(2*time.Minute))

	if !has(got, event.ConditionDoorForced, false) {
		t.Fatalf("an opening two minutes after the last unlock was treated as "+
			"authorised: %v", conditions(got))
	}
}

// Forced is decided at the TRANSITION. A door that was already open when this
// source first looked at it cannot be classified, because the ordering that
// separates forced from normal is not knowable.
func TestAColdStartDoesNotInventAForcedEntry(t *testing.T) {
	d := newTestDoors()

	// First ever observation: locked and open.
	got := d.observePosition("d1", "Front Door", LockLocked, PositionOpen, t0)
	if has(got, event.ConditionDoorForced, false) {
		t.Fatalf("a forced entry was inferred from a cold start, where the "+
			"open-versus-lock ordering is unknowable: %v", conditions(got))
	}

	// But it is still reported for what it observably is.
	got = d.tick(t0.Add(2 * time.Minute))
	if !has(got, event.ConditionDoorHeld, false) {
		t.Errorf("a door standing open across a restart was not reported at all: %v",
			conditions(got))
	}
}

func TestHeldOpenRaisesAfterTheThresholdAndClearsWhenShut(t *testing.T) {
	d := newTestDoors()
	d.observePosition("d1", "Front Door", LockUnlocked, PositionClosed, t0)
	d.observeLock("d1", "Front Door", LockUnlocked, false, t0)

	got := d.observePosition("d1", "Front Door", LockUnlocked, PositionOpen, t0.Add(time.Second))
	if has(got, event.ConditionDoorHeld, false) {
		t.Fatalf("held-open raised immediately; the threshold is what makes it "+
			"distinguishable from somebody walking through: %v", conditions(got))
	}

	// Still open 30s later: not yet.
	if got := d.tick(t0.Add(31 * time.Second)); len(got) != 0 {
		t.Errorf("raised before the threshold: %v", conditions(got))
	}

	// Past 60s: now.
	got = d.tick(t0.Add(70 * time.Second))
	if !has(got, event.ConditionDoorHeld, false) {
		t.Fatalf("held-open never raised: %v", conditions(got))
	}

	// Raised once, not once per tick.
	if got := d.tick(t0.Add(80 * time.Second)); len(got) != 0 {
		t.Errorf("held-open raised again on the next tick: %v", conditions(got))
	}

	// Shutting the door clears it.
	got = d.observePosition("d1", "Front Door", LockLocked, PositionClosed, t0.Add(90*time.Second))
	if !has(got, event.ConditionDoorHeld, true) {
		t.Errorf("a door that was shut again did not clear: %v", conditions(got))
	}
}

// A forced-open incident clears when the door SHUTS, never because somebody
// unlocked it afterwards -- which is what a person dealing with the alarm
// would do, and would erase the alarm they were dealing with.
func TestForcedOpenDoesNotClearMerelyBecauseTheLockWasOpened(t *testing.T) {
	d := newTestDoors()
	d.observePosition("d1", "Front Door", LockLocked, PositionClosed, t0)
	got := d.observePosition("d1", "Front Door", LockLocked, PositionOpen, t0.Add(time.Minute))
	if !has(got, event.ConditionDoorForced, false) {
		t.Fatalf("setup did not raise forced: %v", conditions(got))
	}

	// Somebody unlocks the door to deal with it. Still open.
	d.observeLock("d1", "Front Door", LockUnlocked, false, t0.Add(70*time.Second))
	got = d.observePosition("d1", "Front Door", LockUnlocked, PositionOpen, t0.Add(75*time.Second))
	if has(got, event.ConditionDoorForced, true) {
		t.Errorf("unlocking a forced door cleared its incident: %v", conditions(got))
	}

	// Shutting it does clear.
	got = d.observePosition("d1", "Front Door", LockLocked, PositionClosed, t0.Add(2*time.Minute))
	if !has(got, event.ConditionDoorForced, true) {
		t.Errorf("a forced door that was shut again never cleared: %v", conditions(got))
	}
}

// Most doors have no position sensor. "none" is the console saying so, and it
// is NOT "the door is shut".
func TestADoorWithNoPositionSensorDerivesNothing(t *testing.T) {
	d := newTestDoors()
	for _, p := range []PositionState{PositionNone, PositionUnknown} {
		got := d.observePosition("d"+string(p), "Side Door", LockLocked, p, t0)
		if len(got) != 0 {
			t.Errorf("position %q produced %v; nothing is derivable without a sensor",
				p, conditions(got))
		}
		if got := d.tick(t0.Add(time.Hour)); len(got) != 0 {
			t.Errorf("position %q produced %v after an hour", p, conditions(got))
		}
	}
}

// The socket pushes full state syncs on a timer, so an arriving frame is not a
// change. A source that emitted on arrival would raise the same incident every
// few seconds forever.
func TestRepeatedRemainUnlockedFramesRaiseOnce(t *testing.T) {
	d := newTestDoors()

	got := d.observeLock("d1", "Front Door", LockUnlocked, true, t0)
	if !has(got, event.ConditionDoorUnlocked, false) {
		t.Fatalf("remain-unlocked never raised: %v", conditions(got))
	}
	for i := 0; i < 20; i++ {
		if got := d.observeLock("d1", "Front Door", LockUnlocked, true, t0.Add(time.Duration(i)*time.Second)); len(got) != 0 {
			t.Fatalf("a repeated state sync re-raised the incident: %v", conditions(got))
		}
	}
	got = d.observeLock("d1", "Front Door", LockLocked, false, t0.Add(time.Minute))
	if !has(got, event.ConditionDoorUnlocked, true) {
		t.Errorf("leaving remain-unlocked never cleared: %v", conditions(got))
	}
}

// An incident belongs to the operator, not to the console's current inventory.
func TestADoorWithAnOpenIncidentIsNotForgotten(t *testing.T) {
	d := newTestDoors()
	d.observePosition("d1", "Front Door", LockLocked, PositionClosed, t0)
	d.observePosition("d1", "Front Door", LockLocked, PositionOpen, t0.Add(time.Minute))
	d.observePosition("d2", "Back Door", LockLocked, PositionClosed, t0)

	// The console stops listing both doors.
	d.forget(map[string]bool{})

	if d.count() != 1 {
		t.Errorf("doors known = %d, want 1: the door with the open forced "+
			"incident must survive, the quiet one need not", d.count())
	}
}

// A door arriving from the socket has an id and often no name at all. The name
// comes from the door list, and must not be erased when the socket mentions
// the door again.
func TestANamelessSocketFrameDoesNotEraseAKnownName(t *testing.T) {
	d := newTestDoors()
	d.observePosition("d1", "UDM-Pro-Max - 1F - DOOR8", LockLocked, PositionClosed, t0)
	d.observeLock("d1", "", LockUnlocked, false, t0.Add(time.Second))

	if got := d.nameOf("d1", "fallback"); !strings.Contains(got, "DOOR8") {
		t.Errorf("name = %q, want the one from the door list", got)
	}
}

// THE FALSE POSITIVE THAT SURVIVED THE FIRST ROUND OF TESTS.
//
// Somebody badges in and then holds the door -- a delivery, a conversation, a
// wheelchair. The lock relocks behind them, and the unlock eventually ages out
// of the grace window. Every poll after that sees "locked and open" with no
// recent unlock, which is the exact signature of a forced entry.
//
// Deciding on the TRANSITION rather than on the state is what separates them,
// and nothing else does. Found by mutation testing: replacing the transition
// check with an unconditional one passed every test in this file.
func TestADoorHeldOpenAfterALegitimateEntryIsNeverReportedAsForced(t *testing.T) {
	d := newTestDoors()

	d.observePosition("d1", "Front Door", LockLocked, PositionClosed, t0)
	d.observeLock("d1", "Front Door", LockUnlocked, false, t0.Add(time.Second))
	got := d.observePosition("d1", "Front Door", LockUnlocked, PositionOpen, t0.Add(2*time.Second))
	if has(got, event.ConditionDoorForced, false) {
		t.Fatalf("setup already wrong: %v", conditions(got))
	}

	// The lock relocks while the door is still open, and time passes well
	// beyond the 45-second grace.
	var seen []transition
	for _, at := range []time.Duration{10 * time.Second, time.Minute, 5 * time.Minute, time.Hour} {
		got = d.observePosition("d1", "Front Door", LockLocked, PositionOpen, t0.Add(at))
		if has(got, event.ConditionDoorForced, false) {
			t.Fatalf("a door held open %s after a legitimate entry was reported as "+
				"FORCED: %v", at, conditions(got))
		}
		seen = append(seen, got...)
	}

	// It is still reported -- as held open, which is what it actually is, and
	// exactly once rather than on every poll.
	held := 0
	for _, tr := range seen {
		if tr.condition == event.ConditionDoorHeld && !tr.clears {
			held++
		}
	}
	if held != 1 {
		t.Errorf("held-open raised %d time(s) across the poll sequence, want 1: %v",
			held, conditions(seen))
	}
}

// And the transition rule must not go the other way either: once the door
// shuts, the next opening is judged afresh.
func TestASecondOpeningAfterTheDoorShutsIsJudgedAgain(t *testing.T) {
	d := newTestDoors()
	d.observePosition("d1", "Front Door", LockLocked, PositionClosed, t0)
	d.observeLock("d1", "Front Door", LockUnlocked, false, t0.Add(time.Second))
	d.observePosition("d1", "Front Door", LockUnlocked, PositionOpen, t0.Add(2*time.Second))
	d.observePosition("d1", "Front Door", LockLocked, PositionClosed, t0.Add(10*time.Second))

	// Hours later, with no unlock at all, it opens again.
	got := d.observePosition("d1", "Front Door", LockLocked, PositionOpen, t0.Add(3*time.Hour))
	if !has(got, event.ConditionDoorForced, false) {
		t.Errorf("a later opening with no unlock was not reported as forced: %v",
			conditions(got))
	}
}
