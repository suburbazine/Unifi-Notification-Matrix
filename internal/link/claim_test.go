package link

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 18, 3, 0, 0, 0, time.UTC)

const silentAfter = 15 * time.Minute

func heldClaim(t *testing.T) *Claim {
	t.Helper()
	c := NewClaim("access", time.Minute)
	c.Heartbeat(t0)
	if held, why := c.Held(t0.Add(time.Minute+time.Second), silentAfter); !held {
		t.Fatalf("a freshly heartbeating peer does not hold its claim: %s", why)
	}
	return c
}

// A peer holds nothing until it has been heard from. Suppressing our own
// source on the strength of a configuration entry alone would mean an install
// that pairs and never connects watches nothing.
func TestAClaimIsNotHeldBeforeTheFirstHeartbeat(t *testing.T) {
	c := NewClaim("access", time.Minute)
	if held, why := c.Held(t0, silentAfter); held || why == "" {
		t.Errorf("held=%v why=%q, want not held with a reason", held, why)
	}
}

// The case we already had: the peer goes quiet.
func TestASilentPeerLosesItsClaim(t *testing.T) {
	c := heldClaim(t)
	if held, _ := c.Held(t0.Add(silentAfter+time.Minute), silentAfter); held {
		t.Error("a peer silent past its threshold still held its claim")
	}
}

// THE CASE THAT WAS MISSING. The peer is alive and heartbeating perfectly --
// the link runs over loopback, not through the console -- and cannot see a
// single door. Keying suppression on liveness alone leaves this product silent
// through exactly that, with every surface reading healthy.
func TestAnAliveButBlindPeerLosesItsClaim(t *testing.T) {
	c := heldClaim(t)

	at := t0.Add(2 * time.Minute)
	c.Heartbeat(at)
	c.Observe("sentry-blocked-locally", true, false, at)

	held, why := c.Held(at, silentAfter)
	if held {
		t.Fatal("a peer that cannot reach the console still held its claim")
	}
	// The REASON has to be the demotion, not something adjacent. Asserting
	// only "not held" passes even with the demotion check removed, because
	// raising a demoting condition also resets the recovery clock and the
	// claim then reads as merely recovering. Naming the condition is what
	// makes this test about the thing it says it is about.
	if !strings.Contains(why, "sentry-blocked-locally") {
		t.Errorf("reason %q does not name what is wrong; the operator needs to know "+
			"which product is authoritative and why", why)
	}

	// Still demoted while it keeps heartbeating, which is the whole point.
	for i := 1; i <= 5; i++ {
		beat := at.Add(time.Duration(i) * time.Minute)
		c.Heartbeat(beat)
		if held, _ := c.Held(beat, silentAfter); held {
			t.Fatalf("heartbeat %d restored a claim the peer cannot serve", i)
		}
	}
}

// A condition that is not claim-demoting is an ordinary incident and moves
// nothing. Otherwise every alarm the peer sent would hand authority back and
// forth.
func TestAnOrdinaryConditionDoesNotMoveTheClaim(t *testing.T) {
	c := heldClaim(t)
	at := t0.Add(2 * time.Minute)
	c.Heartbeat(at)
	c.Observe("sentry-access-denied", false, false, at)

	if held, why := c.Held(at, silentAfter); !held {
		t.Errorf("an ordinary alarm demoted the claim: %s", why)
	}
}

// Hysteresis on the resume side. Handing authority back the instant a flapping
// console recovers would flip which product is watching on every poll.
func TestTheClaimResumesOnlyAfterTheHysteresis(t *testing.T) {
	c := NewClaim("access", 2*time.Minute)
	c.Heartbeat(t0)
	c.Observe("sentry-watchdog-unhealthy", true, false, t0)

	cleared := t0.Add(time.Minute)
	c.Observe("sentry-watchdog-unhealthy", true, true, cleared)

	if held, _ := c.Held(cleared.Add(time.Minute), silentAfter); held {
		t.Error("the claim resumed before the hysteresis had passed")
	}
	if held, why := c.Held(cleared.Add(2*time.Minute+time.Second), silentAfter); !held {
		t.Errorf("the claim never resumed: %s", why)
	}
}

// Two problems at once, and the claim recovers only when the LAST clears --
// otherwise clearing one of two would hand back authority the peer still
// cannot exercise.
func TestTheClaimRecoversOnlyWhenTheLastProblemClears(t *testing.T) {
	c := NewClaim("access", time.Minute)
	c.Heartbeat(t0)
	c.Observe("sentry-blocked-locally", true, false, t0)
	c.Observe("sentry-controller-cert-changed", true, false, t0)

	_, why := c.Held(t0, silentAfter)
	if why == "" {
		t.Error("no reason given for a doubly-demoted claim")
	}

	first := t0.Add(time.Minute)
	c.Observe("sentry-blocked-locally", true, true, first)
	if held, _ := c.Held(first.Add(2*time.Minute), silentAfter); held {
		t.Error("clearing one of two problems restored the claim")
	}

	second := first.Add(time.Minute)
	c.Observe("sentry-controller-cert-changed", true, true, second)
	if held, why := c.Held(second.Add(time.Minute+time.Second), silentAfter); !held {
		t.Errorf("the claim did not recover after the last problem cleared: %s", why)
	}
}

// A problem raised during recovery restarts the clock rather than letting the
// earlier healthy period count toward it.
func TestAProblemDuringRecoveryRestartsTheClock(t *testing.T) {
	c := NewClaim("access", 2*time.Minute)
	c.Heartbeat(t0)
	c.Observe("sentry-blocked-locally", true, false, t0)
	c.Observe("sentry-blocked-locally", true, true, t0.Add(time.Minute))

	// Half way through recovery, it breaks again.
	again := t0.Add(2 * time.Minute)
	c.Observe("sentry-blocked-locally", true, false, again)
	c.Observe("sentry-blocked-locally", true, true, again.Add(time.Second))

	if held, _ := c.Held(again.Add(time.Minute), silentAfter); held {
		t.Error("recovery credited time from before the second failure")
	}
	if held, why := c.Held(again.Add(2*time.Minute+2*time.Second), silentAfter); !held {
		t.Errorf("the claim never recovered: %s", why)
	}
}

// The reason names the conditions, because "monitoring authority changed
// hands at 03:12" is a fact an operator needs while reconstructing an incident
// afterwards, and it is invisible at the time by definition.
func TestTheReasonNamesWhatIsWrong(t *testing.T) {
	c := heldClaim(t)
	at := t0.Add(2 * time.Minute)
	c.Heartbeat(at)
	c.Observe("sentry-blocked-locally", true, false, at)

	_, why := c.Held(at, silentAfter)
	if want := "sentry-blocked-locally"; !strings.Contains(why, want) {
		t.Errorf("reason %q does not name %q", why, want)
	}
}
