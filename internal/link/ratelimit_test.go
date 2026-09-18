package link

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

// A PAIRED PEER IS BOUNDED, because source-available means the connector's
// shape is public and "it is a first-party product" is not an access control.
func TestAPeerSendingTooFastIsRefused(t *testing.T) {
	l := newLimiter()
	for i := 0; i < 5; i++ {
		if !l.allow("lnk", now, 5, time.Minute) {
			t.Fatalf("refused request %d of an allowance of 5", i+1)
		}
	}
	if l.allow("lnk", now, 5, time.Minute) {
		t.Error("the sixth request of an allowance of 5 was accepted")
	}

	// The window turns over and the allowance returns. A limiter that latched
	// would take a peer off the air until a restart, which is a worse failure
	// than the one it prevents.
	if !l.allow("lnk", now.Add(time.Minute), 5, time.Minute) {
		t.Error("the allowance did not return when the window turned over")
	}
}

// ONE PEER'S FLOOD MUST NOT SILENCE ANOTHER. The limit is per credential, not
// per listener: two paired products share nothing, and a loop in one of them
// taking the other off the air would make pairing a second product a risk.
func TestOnePeerCannotSpendAnotherPeersAllowance(t *testing.T) {
	l := newLimiter()
	for i := 0; i < 5; i++ {
		l.allow("lnk_noisy", now, 5, time.Minute)
	}
	if l.allow("lnk_noisy", now, 5, time.Minute) {
		t.Fatal("the noisy peer was not limited, so this test proves nothing")
	}
	if !l.allow("lnk_quiet", now, 5, time.Minute) {
		t.Error("a quiet peer was refused because a different peer was noisy")
	}
}

// THE LIMIT IS COUNTED AFTER AUTHENTICATION, and that is the whole design.
//
// Keyed on the link id in the HEADER, anybody who can reach the port could
// name a real peer and spend its allowance -- turning a protection into a way
// to silence the doors from outside. This is the same reasoning the replay
// cache uses for consuming a nonce last, and it is the kind of thing that
// looks like an optimisation to move earlier.
func TestAStrangerCannotSpendAPairedPeersAllowanceByNamingIt(t *testing.T) {
	h := newHarness(t)
	stamp := strconv.FormatInt(now.Unix(), 10)

	// Far more than the allowance, all claiming to be the paired peer and none
	// of them signed with its key.
	for i := 0; i < PerPeerRate+50; i++ {
		h.raw(RouteEvents, h.cred.LinkID, stamp, "junk-"+strconv.Itoa(i),
			Scheme+" "+Sign([]byte("not the key"), "nonsense"), []byte("{}"))
	}

	// The real peer is still heard.
	w := h.post(RoutePing, nil, "after-the-flood")
	if w.Code != http.StatusOK {
		t.Fatalf("a paired peer was refused with %d after a stranger sent %d "+
			"requests in its name; the doors can be silenced from outside",
			w.Code, PerPeerRate+50)
	}
}

// And the refusal is labelled, so an operator can tell a peer that is looping
// from a peer that cannot authenticate.
func TestGoingOverTheRateIsLabelled(t *testing.T) {
	h := newHarness(t)
	for i := 0; i <= PerPeerRate; i++ {
		h.post(RoutePing, nil, "n"+strconv.Itoa(i))
	}
	if got := h.lastCause(t); got != CauseRateLimited {
		t.Errorf("cause = %q, want %q", got, CauseRateLimited)
	}
}

// The agreed figure sits far above anything a working peer produces. Pinned
// because a limit tuned close to real load throttles the operator's own
// product during the one hour it matters: an alarm storm at three in the
// morning is exactly when a peer legitimately sends more than usual.
func TestTheRateSitsWellAboveMeasuredPeerLoad(t *testing.T) {
	// Measured on a busy site: about 11 observations an hour across all
	// sources, plus a heartbeat every five minutes.
	const busiestMeasuredPerMinute = 1
	if PerPeerRate < busiestMeasuredPerMinute*50 {
		t.Errorf("PerPeerRate is %d, which is within striking distance of real "+
			"load (%d/min); a limiter that can trip during an alarm storm has "+
			"taken the side of the attacker", PerPeerRate, busiestMeasuredPerMinute)
	}
}
