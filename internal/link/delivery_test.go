package link

import (
	"testing"
	"time"
)

func TestHealthyChannelsReportOK(t *testing.T) {
	got := DeliveryStatus([]ChannelState{
		{Name: "email", Enabled: true},
		{Name: "ntfy", Enabled: false, ConsecutiveFails: 9}, // disabled: not our problem
	}, t0)
	if got != DeliveryOK {
		t.Errorf("DeliveryStatus() = %q, want %q", got, DeliveryOK)
	}
}

func TestAFailingChannelIsDegraded(t *testing.T) {
	if got := DeliveryStatus([]ChannelState{{Name: "email", Enabled: true, ConsecutiveFails: 1}}, t0); got != DeliveryDegraded {
		t.Errorf("a failing channel reported %q", got)
	}
}

// A channel being held back after repeated failures is not being attempted,
// and a channel that is not being attempted must not read as healthy.
func TestABackingOffChannelIsDegraded(t *testing.T) {
	ch := []ChannelState{{Name: "ntfy", Enabled: true, BackingOffUntil: t0.Add(5 * time.Minute)}}
	if got := DeliveryStatus(ch, t0); got != DeliveryDegraded {
		t.Errorf("a channel being held back reported %q", got)
	}
	// Once the hold has passed it is healthy again.
	if got := DeliveryStatus(ch, t0.Add(6*time.Minute)); got != DeliveryOK {
		t.Errorf("a recovered channel still reported %q", got)
	}
}

// Nothing configured means nothing can be delivered. Reported as degraded on
// purpose, including for a freshly paired install: pairing early must not
// create a silent gap. The operator sees doubled notifications until setup is
// finished, which the checklist should say rather than leave looking like a bug.
func TestNoEnabledChannelsIsDegraded(t *testing.T) {
	for _, chans := range [][]ChannelState{
		nil,
		{{Name: "email", Enabled: false}},
	} {
		if got := DeliveryStatus(chans, t0); got != DeliveryDegraded {
			t.Errorf("with %d channels configured, got %q, want degraded", len(chans), got)
		}
	}
}

// THE CONSTRAINT THAT MATTERS MOST. Degraded means BROKEN, never "chose not to
// send". Quiet hours, a ladder that gave up, an acknowledged incident, a rule
// that silenced something -- all of those are the operator's policy working
// exactly as configured, and none of them is visible to this function at all.
//
// Reporting any of them as degraded would have a peer second-guessing the
// operator's own quiet hours with duplicate alerts at 3am: the same inversion
// as importing a watch window as quiet hours.
//
// This is enforced structurally rather than by a check: DeliveryStatus is given
// channel health and nothing else, so there is no policy state in scope for it
// to accidentally consult. This test exists to say so, and to fail loudly if
// somebody later widens the signature.
func TestDeliveryStatusSeesOnlyChannelHealth(t *testing.T) {
	healthy := []ChannelState{{Name: "email", Enabled: true}}
	if got := DeliveryStatus(healthy, t0); got != DeliveryOK {
		t.Fatalf("a healthy channel reported %q", got)
	}
	// Whatever the operator's policy is doing -- holding for quiet hours,
	// giving up, honouring an ack -- it cannot reach this function, so the
	// answer for healthy channels is the same at every hour of the day.
	for h := 0; h < 24; h++ {
		at := t0.Add(time.Duration(h) * time.Hour)
		if got := DeliveryStatus(healthy, at); got != DeliveryOK {
			t.Errorf("at %s the same healthy channels reported %q", at.Format("15:04"), got)
		}
	}
}
