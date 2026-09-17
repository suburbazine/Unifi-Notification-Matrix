package inbound

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TEST MODE: the console can prove it reaches us WITHOUT waking anybody.
//
// Pressing "Test" in Alarm Manager was otherwise indistinguishable from a real
// alarm: it raised an incident, escalated, and had to be acknowledged. An
// operator who wants to check the rule they just wrote should not have to
// choose between not checking and paging themselves.
func TestAnArrivalInTestModeIsAcceptedAndRaisesNothing(t *testing.T) {
	r, s := newTestReceiver(t)

	until, err := r.ArmTest("wan", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !until.Equal(t0.Add(15 * time.Minute)) {
		t.Errorf("armed until %v, want %v", until, t0.Add(15*time.Minute))
	}

	resp := post(t, r, "/hook/tok-wan-1234567890", `{"alarm":{"name":"WAN down"}}`)
	// The console must still be told it worked. That is the thing being tested.
	if resp.Code != 204 {
		t.Errorf("status = %d, want 204: the rule has to see success", resp.Code)
	}
	if n := len(s.all()); n != 0 {
		t.Errorf("%d event(s) raised while in test mode", n)
	}

	rec := receiptFor(t, r, "wan")
	if rec.TestCount != 1 {
		t.Errorf("TestCount = %d, want 1", rec.TestCount)
	}
	// Counted separately, so "nothing real has ever arrived" survives testing.
	if rec.Count != 0 {
		t.Errorf("Count = %d; a test arrival was counted as a real one", rec.Count)
	}
	if rec.LastAt.Equal(t0) {
		t.Error("a test arrival moved LastAt, which is the real-arrival evidence")
	}
}

// And once it lapses, an alarm is an alarm again. This is the property that
// makes test mode safe to hand to somebody: forgetting cannot silently swallow
// real alarms for ever.
func TestTestModeLapsesOnItsOwn(t *testing.T) {
	s := &sink{}
	now := t0
	r := New(testHooks(), Options{Emit: s.emit, Now: func() time.Time { return now }})

	if _, err := r.ArmTest("wan", time.Minute); err != nil {
		t.Fatal(err)
	}
	now = t0.Add(30 * time.Second)
	post(t, r, "/hook/tok-wan-1234567890", `{}`)
	if n := len(s.all()); n != 0 {
		t.Fatalf("%d event(s) raised while still armed", n)
	}

	now = t0.Add(2 * time.Minute)
	post(t, r, "/hook/tok-wan-1234567890", `{}`)
	if n := len(s.all()); n != 1 {
		t.Errorf("%d event(s) after test mode lapsed, want 1", n)
	}
	if !r.TestArmedUntil("wan").IsZero() {
		t.Error("a lapsed test mode still reports itself armed")
	}
}

func TestTestModeIsBoundedAndCanBeDisarmed(t *testing.T) {
	r, _ := newTestReceiver(t)

	until, err := r.ArmTest("wan", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if want := t0.Add(MaxTestWindow); !until.Equal(want) {
		t.Errorf("a day of test mode was granted as %v, want it capped at %v", until, want)
	}

	if err := r.DisarmTest("wan"); err != nil {
		t.Fatal(err)
	}
	if !r.TestArmedUntil("wan").IsZero() {
		t.Error("disarming left test mode armed")
	}
}

// Arming affects ONE hook. A site with a hook per alarm type must be able to
// test one without deafening itself to the others.
func TestArmingOneHookLeavesTheOthersLive(t *testing.T) {
	r, s := newTestReceiver(t)
	if _, err := r.ArmTest("wan", time.Minute); err != nil {
		t.Fatal(err)
	}
	post(t, r, "/hook/tok-threat-098765", `{}`)
	if n := len(s.all()); n != 1 {
		t.Errorf("%d event(s) from the hook that was NOT in test mode, want 1", n)
	}
}

func TestArmingAnUnknownHookIsRefused(t *testing.T) {
	r, _ := newTestReceiver(t)
	if _, err := r.ArmTest("no-such-hook", time.Minute); !errors.Is(err, ErrNoSuchHook) {
		t.Errorf("err = %v, want ErrNoSuchHook", err)
	}
	if err := r.DisarmTest("no-such-hook"); !errors.Is(err, ErrNoSuchHook) {
		t.Errorf("err = %v, want ErrNoSuchHook", err)
	}
}

// FIRE A TEST ALARM: the other half, and a different question.
//
// Test mode asks "can UniFi reach us". This asks "and when it does, does
// anybody's phone ring" -- which depends on the rules, the severity, the
// ladder and every channel, none of which an arriving alarm exercises until
// the night it matters.
func TestFiringATestAlarmGoesThroughTheRealPath(t *testing.T) {
	r, s := newTestReceiver(t)

	ev, err := r.FireTest("wan")
	if err != nil {
		t.Fatal(err)
	}
	got := s.all()
	if len(got) != 1 {
		t.Fatalf("%d event(s) emitted, want 1", len(got))
	}
	if got[0].Condition != ev.Condition || got[0].Severity != ev.Severity {
		t.Error("the fired event is not the one the hook would produce")
	}
	// Unmistakable at 3am.
	if !strings.HasPrefix(got[0].Title, "TEST") {
		t.Errorf("title = %q, want it to announce itself as a test", got[0].Title)
	}
	// Severity is the REAL one on purpose: a test that quietly downgrades to
	// info proves the ladder works for info and nothing about critical.
	if got[0].Severity != testHooks()[0].Severity {
		t.Errorf("severity = %v, want the hook's real %v",
			got[0].Severity, testHooks()[0].Severity)
	}
}

// A test alarm must not merge into a real one already open on the same hook,
// or acknowledging the test would silence the genuine alarm underneath it.
func TestATestAlarmDoesNotMergeIntoARealOne(t *testing.T) {
	r, s := newTestReceiver(t)

	post(t, r, "/hook/tok-wan-1234567890", `{"alarm":{"name":"WAN down"}}`)
	if _, err := r.FireTest("wan"); err != nil {
		t.Fatal(err)
	}
	got := s.all()
	if len(got) != 2 {
		t.Fatalf("%d event(s), want 2", len(got))
	}
	if got[0].DedupKey() == got[1].DedupKey() {
		t.Errorf("the test shares a dedup key with the real alarm (%s); "+
			"acknowledging one would silence the other", got[0].DedupKey())
	}
}

// Firing a test must NOT be counted as a real arrival, or the evidence that a
// hook has never actually fired is destroyed by checking it.
func TestFiringATestDoesNotClaimTheHookHasReceivedAnything(t *testing.T) {
	r, _ := newTestReceiver(t)
	if _, err := r.FireTest("wan"); err != nil {
		t.Fatal(err)
	}
	if rec := receiptFor(t, r, "wan"); rec.Count != 0 {
		t.Errorf("Count = %d after firing a test; the hook has still received nothing", rec.Count)
	}
}

func receiptFor(t *testing.T, r *Receiver, name string) Receipt {
	t.Helper()
	for _, rec := range r.Receipts() {
		if rec.Name == name {
			return rec
		}
	}
	t.Fatalf("no receipt for %q", name)
	return Receipt{}
}
