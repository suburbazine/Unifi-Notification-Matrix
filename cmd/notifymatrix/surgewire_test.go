package main

import (
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/surge"
)

type countingStore struct{ put []surge.Bucket }

func (c *countingStore) PutBucket(b surge.Bucket) error { c.put = append(c.put, b); return nil }
func (c *countingStore) Buckets(time.Time, time.Time) ([]surge.Bucket, error) {
	return append([]surge.Bucket(nil), c.put...), nil
}

func activity(t *testing.T, now *time.Time) (*siteActivity, *countingStore) {
	t.Helper()
	s := &countingStore{}
	clock := func() time.Time { return *now }
	rec := surge.NewRecorder(s, clock, nil)
	rep := surge.NewReporter(s, time.UTC, clock, nil)
	return newSiteActivity(rec, rep, nil), s
}

var w0 = time.Date(2026, 9, 22, 3, 0, 0, 0, time.UTC)

// A SILENCED EVENT IS STILL SITE ACTIVITY, and it is exactly what a jammer
// removes. Counting after the rule engine would make the busiest camera on
// site invisible to the one measurement that cares how busy it is.
func TestASilencedEventStillCounts(t *testing.T) {
	now := w0
	a, _ := activity(t, &now)

	// The shape a rule-silenced motion event has at the ingest boundary: it
	// reached the engine, and the engine will drop it.
	a.observe(event.Event{
		Source: "protect", Condition: "motion",
		Entity: event.Entity{ID: "cam-1"}, At: w0,
	})

	if ev, dev := a.rep.Window(); ev != 1 || dev != 1 {
		t.Errorf("window = %d across %d, want the event counted", ev, dev)
	}
}

// This product talking about itself is not the site being busy. Left in, a
// daemon restarting during an outage looks like activity.
func TestInternalEventsAreNotSiteActivity(t *testing.T) {
	now := w0
	a, _ := activity(t, &now)

	a.observe(event.Event{
		Source: "internal", Condition: "unclean-exit",
		Entity: event.Entity{ID: "service"}, At: w0,
	})

	if ev, _ := a.rep.Window(); ev != 0 {
		t.Errorf("window = %d, want this product's own news excluded", ev)
	}
}

// A CLEAR IS THE END OF SOMETHING ALREADY COUNTED. Counting both ends doubles
// every transient, while a genuine drop-off burst -- which produces offline
// events and no clears at all -- looks comparatively smaller.
func TestAClearIsNotASecondThingHappening(t *testing.T) {
	now := w0
	a, _ := activity(t, &now)

	a.observe(event.Event{Source: "protect", Condition: "motion",
		Entity: event.Entity{ID: "cam-1"}, At: w0})
	a.observe(event.Event{Source: "protect", Condition: "motion", Clears: true,
		Entity: event.Entity{ID: "cam-1"}, At: w0.Add(time.Second)})

	if ev, _ := a.rep.Window(); ev != 1 {
		t.Errorf("window = %d, want the clear not counted", ev)
	}
}

// Nine devices are nine devices whatever their sources, because the key is
// the identity the dedup key already uses.
func TestDevicesAreCountedAcrossSources(t *testing.T) {
	now := w0
	a, _ := activity(t, &now)

	for _, e := range []event.Event{
		{Source: "protect", Entity: event.Entity{ID: "cam-1"}, At: w0},
		{Source: "access", Entity: event.Entity{ID: "cam-1"}, At: w0},
		{Source: "network", Entity: event.Entity{ID: "sw-1"}, At: w0},
	} {
		a.observe(e)
	}
	if ev, dev := a.rep.Window(); ev != 3 || dev != 3 {
		t.Errorf("window = %d across %d, want 3 across 3", ev, dev)
	}
}

// An event with no time of its own is still an event that just arrived.
func TestAnEventWithNoTimeUsesItsArrival(t *testing.T) {
	now := w0
	a, _ := activity(t, &now)

	a.observe(event.Event{Source: "protect", Entity: event.Entity{ID: "cam-1"},
		ReceivedAt: w0})

	if ev, _ := a.rep.Window(); ev != 1 {
		t.Errorf("window = %d, want the event counted at its arrival", ev)
	}
}

// A build with no measurement wired must behave exactly as it did before.
func TestANilActivityIsSafe(t *testing.T) {
	var a *siteActivity
	a.observe(event.Event{Source: "protect", At: w0})
	if got := a.note(w0); got != "" {
		t.Errorf("note = %q, want empty", got)
	}
}
