package escalate

import (
	"context"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// justDoorForced classifies one condition as momentary, so these tests describe
// a vocabulary instead of depending on the real catalogue.
func justDoorForced(condition string) bool { return condition == "door-forced-open" }

func resolvedUndelivered(t *testing.T, id, key string, opened, cleared time.Time) *incident.Incident {
	t.Helper()
	inc := incident.Open(id, key, incident.SeverityHigh, "access", "Door forced", "", opened)
	if err := inc.Resolve(cleared); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if inc.FirstAlertAt != nil {
		t.Fatal("fixture was already delivered")
	}
	return inc
}

func momentaryScheduler(t *testing.T, st incident.Store, r *recorder, c *clock) *Scheduler {
	t.Helper()
	s, err := NewScheduler(st, repeatingPolicy(), r.deliver,
		WithClock(c.now), WithInterval(time.Hour), WithMomentary(justDoorForced))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	return s
}

// THE BUG. A door forced open that swung shut before the scheduler's next tick
// told nobody at all, and the incident sat closed on the board looking handled.
// NextDue refuses any resolved incident, the tick is 5s, and every default
// policy's first rung fires at offset 0.
func TestAMomentaryConditionClearedBeforeItsFirstRungIsStillDelivered(t *testing.T) {
	ctx := context.Background()
	inc := resolvedUndelivered(t, "inc-1", "access/door-1/door-forced-open",
		sched0.Add(-10*time.Second), sched0.Add(-5*time.Second))

	st := newFakeStore(inc)
	r := &recorder{}
	c := &clock{t: sched0}
	s := momentaryScheduler(t, st, r, c)

	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got := r.count(); got != 1 {
		t.Fatalf("deliveries = %d, want 1 -- a forced door that shut again is still news", got)
	}

	// ...and exactly once. It is resolved, so it must not become a nag.
	c.advance(time.Hour)
	if err := s.Tick(ctx); err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if got := r.count(); got != 1 {
		t.Errorf("deliveries = %d after an hour, want 1 -- a cleared incident must not repeat", got)
	}
}

// THE PROPERTY THAT MUST NOT REGRESS, and the reason this is a per-condition
// flag rather than "always deliver at least once".
//
// motion is the noisiest condition on any site and carries an end timestamp
// that clears it within seconds. Delivering those would flood every install
// that has cameras -- so for STATE conditions, suppressing a fast self-clear is
// correct rather than a missed alarm.
func TestAStateConditionClearedBeforeItsFirstRungStaysSilent(t *testing.T) {
	ctx := context.Background()
	inc := resolvedUndelivered(t, "inc-2", "protect/cam-1/motion",
		sched0.Add(-10*time.Second), sched0.Add(-9*time.Second))

	st := newFakeStore(inc)
	r := &recorder{}
	c := &clock{t: sched0}
	s := momentaryScheduler(t, st, r, c)

	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got := r.count(); got != 0 {
		t.Errorf("deliveries = %d, want 0 -- fast-clearing motion is noise, not an alarm", got)
	}
}

// A human already responded. Nothing is owed, whatever the condition.
func TestAnAcknowledgedClearedIncidentIsOwedNothing(t *testing.T) {
	ctx := context.Background()
	inc := resolvedUndelivered(t, "inc-3", "access/door-1/door-forced-open",
		sched0.Add(-10*time.Second), sched0.Add(-5*time.Second))
	if err := inc.Acknowledge(sched0.Add(-4*time.Second), "web"); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}

	st := newFakeStore(inc)
	r := &recorder{}
	c := &clock{t: sched0}
	s := momentaryScheduler(t, st, r, c)

	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got := r.count(); got != 0 {
		t.Errorf("deliveries = %d, want 0 -- somebody had already seen it", got)
	}
}

// An incident that was delivered and THEN cleared is owed nothing further: the
// debt is one delivery, not one delivery per clear.
func TestAnAlreadyDeliveredIncidentIsOwedNothingWhenItClears(t *testing.T) {
	inc := incident.Open("inc-4", "access/door-1/door-forced-open",
		incident.SeverityHigh, "access", "Door forced", "", sched0.Add(-time.Minute))
	if err := inc.RecordAlert(sched0.Add(-50*time.Second), 0); err != nil {
		t.Fatalf("RecordAlert: %v", err)
	}
	if err := inc.Resolve(sched0.Add(-40 * time.Second)); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	pol := repeatingPolicy()[incident.SeverityHigh]
	if _, _, ok := pol.OwedFinalDelivery(inc); ok {
		t.Error("an incident that was already delivered is owed another")
	}
}
