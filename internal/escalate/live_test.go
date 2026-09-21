package escalate

import (
	"context"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// A SETTING CHANGED IS A SETTING IN FORCE, WITHOUT A RESTART.
//
// The escalation ladders were built once at start and never rebuilt, so an
// operator who widened a ladder, saved it, and watched the interface agree
// that it was saved still had the old one deciding whether their phone rang.
// The file, the screen and the running process disagreed, and nothing said so.
//
// A restart is not a neutral remedy here either: it drops every console
// connection, re-polls everything and re-reads every open incident. An
// operator who must do that to change one interval does it rarely, which means
// the intervals stay wrong.
func TestNewLaddersTakeEffectOnTheNextPassWithNoRestart(t *testing.T) {
	ctx := context.Background()
	inc := incident.Open("inc-1", "protect/cam-1/offline", incident.SeverityHigh,
		"protect", "Camera offline", "", sched0)

	st := newFakeStore(inc)
	r := &recorder{}
	c := &clock{t: sched0}
	s := newTestScheduler(t, st, repeatingPolicy(), r, c)

	// The ladder in force sends to ntfy at stage 0.
	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got := r.all()[0].channels; len(got) != 1 || got[0] != "ntfy" {
		t.Fatalf("first alert went to %v, want [ntfy]", got)
	}

	// The operator adds a second channel to the rung and saves. No restart.
	if err := s.SetPolicies(map[incident.Severity]Policy{
		incident.SeverityHigh: {
			Name:        "test-high",
			Stages:      []Stage{{After: 0, Channels: []string{"ntfy", "email"}}},
			RepeatEvery: 5 * time.Minute,
		},
	}); err != nil {
		t.Fatalf("SetPolicies: %v", err)
	}

	c.advance(6 * time.Minute)
	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick after the change: %v", err)
	}
	if r.count() < 2 {
		t.Fatalf("alerts = %d after the change, want 2", r.count())
	}
	got := r.all()[1].channels
	if len(got) != 2 || got[0] != "ntfy" || got[1] != "email" {
		t.Errorf("the second alert went to %v, want [ntfy email] -- the ladder was "+
			"changed and saved, and the running scheduler is still using the old one", got)
	}
}

// AND A LADDER THAT CANNOT EXPRESS ITSELF IS REFUSED, NOT SWAPPED IN.
//
// Same reason NewScheduler validates: the failure mode of a bad ladder is an
// alert that never fires, which is invisible until the night it matters. A
// refusal leaves the running scheduler exactly as it was -- half-applied is
// the one state that must not be reachable.
func TestARefusedLadderLeavesTheRunningOneAlone(t *testing.T) {
	ctx := context.Background()
	inc := incident.Open("inc-1", "protect/cam-1/offline", incident.SeverityHigh,
		"protect", "Camera offline", "", sched0)
	st := newFakeStore(inc)
	r := &recorder{}
	c := &clock{t: sched0}
	s := newTestScheduler(t, st, repeatingPolicy(), r, c)

	// A critical policy that gives up is the case Policy.Validate exists for.
	err := s.SetPolicies(map[incident.Severity]Policy{
		incident.SeverityCritical: {
			Name:        "give-up-on-critical",
			Stages:      []Stage{{After: 0, Channels: []string{"ntfy"}}},
			RepeatEvery: time.Minute,
			GiveUpAfter: time.Hour,
		},
	})
	if err == nil {
		t.Fatal("SetPolicies accepted a policy NewScheduler would have refused")
	}
	if err := s.SetPolicies(nil); err == nil {
		t.Error("SetPolicies accepted an empty set; a scheduler with no ladders " +
			"cannot alert on anything")
	}

	// The original is still deciding.
	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got := r.all()[0].channels; len(got) != 1 || got[0] != "ntfy" {
		t.Errorf("after a refused change the alert went to %v, want [ntfy] -- the "+
			"refusal was not clean and the scheduler is holding part of a set it "+
			"said it would not take", got)
	}
}

// Quiet hours the same way: set them, and the next alert is held.
func TestANewQuietWindowHoldsTheNextAlertWithNoRestart(t *testing.T) {
	ctx := context.Background()
	inc := incident.Open("inc-1", "protect/cam-1/offline", incident.SeverityHigh,
		"protect", "Camera offline", "", sched0)
	st := newFakeStore(inc)
	r := &recorder{}
	c := &clock{t: sched0}

	pols := map[incident.Severity]Policy{
		incident.SeverityHigh: {
			Name:              "test-high",
			Stages:            []Stage{{After: 0, Channels: []string{"ntfy"}}},
			RepeatEvery:       5 * time.Minute,
			RespectQuietHours: true,
		},
	}
	s := newTestScheduler(t, st, pols, r, c)

	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if r.count() != 1 {
		t.Fatalf("alerts = %d before quiet hours, want 1", r.count())
	}

	// A window covering the whole day, in the clock's own zone.
	q := QuietHours{Enabled: true, Start: "00:00", End: "23:59", Zone: c.now().Location().String()}
	if err := s.SetQuietHours(q); err != nil {
		t.Fatalf("SetQuietHours: %v", err)
	}
	c.advance(6 * time.Minute)
	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick inside the new window: %v", err)
	}
	if r.count() != 1 {
		t.Errorf("alerts = %d; the quiet window was saved and the running scheduler "+
			"is still alerting through it", r.count())
	}
	if s.Stats().Held == 0 {
		t.Error("nothing was counted as held, so the operator asking \"why was I " +
			"not paged\" has no answer on the screen")
	}

	// And a malformed window is refused rather than silencing the product at
	// hours nobody chose.
	if err := s.SetQuietHours(QuietHours{Enabled: true, Start: "22:00", End: "22:00"}); err == nil {
		t.Error("SetQuietHours accepted a window with no length, which is ambiguous " +
			"between \"never\" and \"always\" and must be refused")
	}
}
