package incident

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 15, 3, 0, 0, 0, time.UTC)

func newTestIncident() *Incident {
	return Open("i1", Key("access", "front-door", "forced-open"),
		SeverityCritical, "access", "Door forced open", "Front door", t0)
}

// The central invariant: Acknowledged and Resolved are orthogonal, and neither
// alone closes the incident. If this test is ever "simplified" by adding a
// state field, the product has lost the distinction it exists for.
func TestAckAndResolveAreOrthogonal(t *testing.T) {
	t.Run("acked but not resolved is an open obligation", func(t *testing.T) {
		i := newTestIncident()
		_ = i.RecordAlert(t0, 0)
		_ = i.Acknowledge(t0.Add(time.Minute), "ntfy")

		if got := i.State(); got != StateAcknowledged {
			t.Fatalf("State() = %q, want %q", got, StateAcknowledged)
		}
		if i.Terminal() {
			t.Error("an acked-but-unresolved incident must not be terminal; " +
				"the door is still open and that obligation must stay visible")
		}
		if i.ShouldReAlert() {
			t.Error("an acknowledged incident must stop nagging")
		}
	})

	t.Run("resolved but never acked stays visible", func(t *testing.T) {
		i := newTestIncident()
		_ = i.RecordAlert(t0, 0)
		_ = i.Resolve(t0.Add(time.Minute))

		if got := i.State(); got != StateResolved {
			t.Fatalf("State() = %q, want %q", got, StateResolved)
		}
		if i.Terminal() {
			t.Error("a self-clearing condition nobody acknowledged must not be " +
				"erased; the morning shift needs to see it")
		}
	})

	t.Run("both facts true closes it, in either order", func(t *testing.T) {
		for _, order := range []string{"ack-then-resolve", "resolve-then-ack"} {
			i := newTestIncident()
			_ = i.RecordAlert(t0, 0)
			if order == "ack-then-resolve" {
				_ = i.Acknowledge(t0.Add(time.Minute), "ntfy")
				_ = i.Resolve(t0.Add(2 * time.Minute))
			} else {
				_ = i.Resolve(t0.Add(time.Minute))
				_ = i.Acknowledge(t0.Add(2*time.Minute), "email")
			}
			if got := i.State(); got != StateClosed {
				t.Errorf("%s: State() = %q, want %q", order, got, StateClosed)
			}
		}
	})
}

func TestAcknowledgeIsIdempotent(t *testing.T) {
	i := newTestIncident()
	_ = i.RecordAlert(t0, 0)

	first := t0.Add(time.Minute)
	_ = i.Acknowledge(first, "ntfy")
	// Two taps on the same push notification is not an error.
	_ = i.Acknowledge(t0.Add(5*time.Minute), "email")

	if !i.AckedAt.Equal(first) {
		t.Errorf("AckedAt = %v, want the FIRST ack at %v", i.AckedAt, first)
	}
	if i.AckVia != "ntfy" {
		t.Errorf("AckVia = %q, want the channel of the first ack", i.AckVia)
	}
}

func TestResolveIsIdempotent(t *testing.T) {
	// The same clear can arrive over both a push channel and a reconciliation
	// sweep, so this must not be an error or move the timestamp.
	i := newTestIncident()
	first := t0.Add(time.Minute)
	_ = i.Resolve(first)
	_ = i.Resolve(t0.Add(9 * time.Minute))

	if !i.ResolvedAt.Equal(first) {
		t.Errorf("ResolvedAt = %v, want %v", i.ResolvedAt, first)
	}
}

func TestClosedIsTerminal(t *testing.T) {
	i := newTestIncident()
	i.Close(t0.Add(time.Minute), "dismissed by operator")

	if err := i.Acknowledge(t0.Add(2*time.Minute), "ntfy"); err != ErrClosed {
		t.Errorf("Acknowledge on closed = %v, want ErrClosed", err)
	}
	if err := i.Resolve(t0.Add(2 * time.Minute)); err != ErrClosed {
		t.Errorf("Resolve on closed = %v, want ErrClosed", err)
	}
	if err := i.RecordAlert(t0.Add(2*time.Minute), 0); err != ErrClosed {
		t.Errorf("RecordAlert on closed = %v, want ErrClosed", err)
	}
}

// A condition that clears and returns must not inherit the old acknowledgement
// -- that would make an ack apply to an event the acknowledger never saw.
func TestRecurDoesNotInheritAcknowledgement(t *testing.T) {
	first := newTestIncident()
	_ = first.RecordAlert(t0, 0)
	_ = first.Acknowledge(t0.Add(time.Minute), "ntfy")
	_ = first.Resolve(t0.Add(2 * time.Minute))

	later := t0.Add(time.Hour)
	next := first.Recur("i2", later)

	if next.Acknowledged() {
		t.Fatal("a recurrence must not carry the predecessor's acknowledgement")
	}
	if next.State() != StateOpen {
		t.Errorf("State() = %q, want %q", next.State(), StateOpen)
	}
	if next.PredecessorID != "i1" {
		t.Errorf("PredecessorID = %q, want %q", next.PredecessorID, "i1")
	}
	if next.DedupKey != first.DedupKey {
		t.Error("a recurrence keeps the dedup key; it is the same condition")
	}
}

// If every channel failed, the incident has not been alerted. Advancing
// LastAlertAt here would let a total delivery outage look like a completed nag.
func TestFailedDeliveryIsNotAnAlert(t *testing.T) {
	i := newTestIncident()
	i.RecordDeliveryFailure(t0.Add(time.Second), "smtp: connection refused")

	if i.LastAlertAt != nil {
		t.Error("a failed delivery must not set LastAlertAt")
	}
	if i.AlertCount != 0 {
		t.Errorf("AlertCount = %d, want 0", i.AlertCount)
	}
	if i.State() != StateOpen {
		t.Errorf("State() = %q, want %q -- nothing was delivered", i.State(), StateOpen)
	}
}

func TestRecordAlertClearsPriorError(t *testing.T) {
	i := newTestIncident()
	i.RecordDeliveryFailure(t0, "smtp: connection refused")
	_ = i.RecordAlert(t0.Add(time.Minute), 1)

	if i.LastDeliveryError != "" {
		t.Errorf("LastDeliveryError = %q, want empty after a success", i.LastDeliveryError)
	}
	if i.Stage != 1 {
		t.Errorf("Stage = %d, want 1", i.Stage)
	}
}

// The same logical condition arriving by two routes must collapse to one
// incident, so the key must not encode how it arrived.
func TestKeyIsRouteIndependent(t *testing.T) {
	viaSocket := Key("protect", "Camera-ABC", "offline")
	viaWebhook := Key("Protect", "camera-abc", "Offline")

	if viaSocket != viaWebhook {
		t.Errorf("keys differ by route/case: %q vs %q", viaSocket, viaWebhook)
	}
	if got, want := viaSocket, "protect/camera-abc/offline"; got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}
}

func TestKeyHandlesEmptyParts(t *testing.T) {
	// A source that supplies no entity must not produce a key that collides
	// with a different condition on the same source.
	a := Key("network", "", "wan-down")
	b := Key("network", "", "device-offline")
	if a == b {
		t.Fatalf("distinct conditions collided: %q", a)
	}
}

// Condition() reads the condition back out of the dedup key, which is only
// safe because Key cleans each part and replaces any "/" inside it. This pins
// that: the day it stops holding, Condition returns something plausible and
// wrong, and the momentary/state decision silently stops applying.
func TestConditionRoundTripsThroughTheDedupKey(t *testing.T) {
	for _, tc := range []struct{ source, entity, condition string }{
		{"access", "door-1", "door-forced-open"},
		{"protect", "Front Door/Camera", "motion"}, // a "/" inside a part
		{"network", "", "offline"},                 // an empty part becomes "unknown"
		{"internal", "notifymatrix", "unclean-shutdown"},
	} {
		key := Key(tc.source, tc.entity, tc.condition)
		inc := &Incident{DedupKey: key}
		if got := inc.Condition(); got != tc.condition {
			t.Errorf("Key(%q,%q,%q) = %q; Condition() = %q, want %q",
				tc.source, tc.entity, tc.condition, key, got, tc.condition)
		}
	}
	// A key that is not three segments has no condition to report, and must
	// say so rather than guess.
	if got := (&Incident{DedupKey: "nonsense"}).Condition(); got != "" {
		t.Errorf("Condition() on a malformed key = %q, want empty", got)
	}
}

// Entity() reads the middle segment back, in the CLEANED form Key wrote:
// lower-cased, "/" replaced, "unknown" for an empty id. Pinned as the cleaned
// form on purpose -- a rule generated from it has to match the way Key
// normalised, not the way the source spelled it.
func TestEntityRoundTripsThroughTheDedupKey(t *testing.T) {
	for _, tc := range []struct{ source, entity, condition, want string }{
		{"access", "door-1", "door-forced-open", "door-1"},
		{"protect", "Front Door Cam", "motion", "front door cam"},
		{"protect", "Front Door/Camera", "motion", "front door_camera"},
		{"network", "", "offline", "unknown"},
	} {
		inc := &Incident{DedupKey: Key(tc.source, tc.entity, tc.condition)}
		if got := inc.Entity(); got != tc.want {
			t.Errorf("Key(%q,%q,%q): Entity() = %q, want %q",
				tc.source, tc.entity, tc.condition, got, tc.want)
		}
	}
	if got := (&Incident{DedupKey: "nonsense"}).Entity(); got != "" {
		t.Errorf("Entity() on a malformed key = %q, want empty", got)
	}
}
