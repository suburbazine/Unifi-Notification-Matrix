package channel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// countingChannel fails on demand and counts how often it was actually asked.
type countingChannel struct {
	name  string
	fail  atomic.Bool
	calls atomic.Int64
}

func (c *countingChannel) Name() string { return c.name }
func (c *countingChannel) Send(context.Context, Alert) error {
	c.calls.Add(1)
	if c.fail.Load() {
		return errors.New("the service refused")
	}
	return nil
}
func (c *countingChannel) Test(context.Context) error { return nil }

// A broken channel republished every twenty seconds for hours and got the
// installation BANNED by the service -- which turned a misconfigured channel
// into no channel at all, including for the alarms that would have gone
// through once it was fixed.
//
// So repeated failure has to widen the gap between attempts, and the proof is
// that the SERVICE stops being called, not merely that an error is returned.
func TestRepeatedFailureStopsHammeringTheService(t *testing.T) {
	ch := &countingChannel{name: "test"}
	ch.fail.Store(true)
	q := NewQueue(ch, 8, nil)
	defer q.Close()

	now := time.Now()
	// Enough failures to climb past the first rung, which is deliberately free.
	for i := 0; i < 3; i++ {
		_ = q.SendAndWait(context.Background(), Alert{IncidentID: "i"}, now)
	}
	reached := ch.calls.Load()
	if reached == 0 {
		t.Fatal("the channel was never attempted at all")
	}

	// Now hammer it at the cadence an escalation ladder would.
	for i := 0; i < 20; i++ {
		_ = q.SendAndWait(context.Background(), Alert{IncidentID: "i"}, now)
	}
	if got := ch.calls.Load(); got != reached {
		t.Errorf("the service was called %d more times while backing off; that "+
			"is the behaviour that got a real installation banned", got-reached)
	}
}

// Held back is NOT delivered. The escalation scheduler only advances an
// incident on a successful delivery, so reporting a skip as success would mark
// an alarm delivered that nobody received.
func TestBeingHeldBackIsReportedAsAFailureNotASuccess(t *testing.T) {
	ch := &countingChannel{name: "test"}
	ch.fail.Store(true)
	q := NewQueue(ch, 8, nil)
	defer q.Close()

	now := time.Now()
	for i := 0; i < 3; i++ {
		_ = q.SendAndWait(context.Background(), Alert{IncidentID: "i"}, now)
	}

	err := q.SendAndWait(context.Background(), Alert{IncidentID: "i"}, now)
	if err == nil {
		t.Fatal("a held-back delivery was reported as success, so the incident " +
			"would be marked delivered with nobody told")
	}
	var backing *ErrBackingOff
	if !errors.As(err, &backing) {
		t.Fatalf("the error does not identify itself as a backoff: %v", err)
	}
	if backing.Until.IsZero() {
		t.Error("the error does not say when it will try again")
	}
}

// One success clears the ladder. A channel that just worked is working, and
// making it climb back down would keep punishing it for an outage that is
// over.
func TestOneSuccessClearsTheBackoff(t *testing.T) {
	ch := &countingChannel{name: "test"}
	ch.fail.Store(true)
	q := NewQueue(ch, 8, nil)
	defer q.Close()

	now := time.Now()
	for i := 0; i < 3; i++ {
		_ = q.SendAndWait(context.Background(), Alert{IncidentID: "i"}, now)
	}
	if q.Stats().ConsecutiveFails == 0 {
		t.Fatal("failures were not counted")
	}

	// Well past the backoff, and now healthy.
	ch.fail.Store(false)
	later := now.Add(time.Hour)
	if err := q.SendAndWait(context.Background(), Alert{IncidentID: "i"}, later); err != nil {
		t.Fatalf("a healthy channel was still refused: %v", err)
	}
	st := q.Stats()
	if st.ConsecutiveFails != 0 || !st.BackingOffUntil.IsZero() {
		t.Errorf("the backoff survived a success: %+v", st)
	}
}

// The first failure costs nothing. Most failures are transient, and making the
// next alarm wait fifteen seconds for the previous one's blip is a worse trade
// than one extra attempt.
func TestTheFirstFailureDoesNotDelayTheNextAttempt(t *testing.T) {
	if backoffFor(1) != 0 {
		t.Errorf("a single failure imposes %s of delay", backoffFor(1))
	}
	if backoffFor(2) == 0 {
		t.Error("a second consecutive failure imposes no delay at all")
	}
}

// And it is bounded, because a channel that has failed two hundred times must
// still recover within a few minutes of being fixed.
func TestTheBackoffIsCapped(t *testing.T) {
	if got := backoffFor(200); got != 5*time.Minute {
		t.Errorf("backoffFor(200) = %s, want the 5m cap", got)
	}
}

// FIXING A CHANNEL AND PROVING IT WORKS HAS TO END THE HOLD.
//
// The way out of the backoff is to fix the channel, and the way an operator
// confirms they have is the test button. But Test bypassed the hold without
// clearing it, so the sequence that actually happens -- fix the topic, press
// Test, watch it pass -- left real alerts held for up to another five minutes
// behind a green tick saying everything was fine.
func TestAPassingTestClearsTheBackoff(t *testing.T) {
	ch := &countingChannel{name: "test"}
	ch.fail.Store(true)
	q := NewQueue(ch, 8, nil)
	defer q.Close()

	now := time.Now()
	for i := 0; i < 3; i++ {
		_ = q.SendAndWait(context.Background(), Alert{IncidentID: "i"}, now)
	}
	if q.Stats().BackingOffUntil.IsZero() {
		t.Fatal("precondition: the channel should be backing off by now")
	}

	// The operator fixes it and presses Test.
	ch.fail.Store(false)
	if err := q.Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}

	if st := q.Stats(); !st.BackingOffUntil.IsZero() || st.ConsecutiveFails != 0 {
		t.Errorf("a passing test left the channel held until %v after %d failures",
			st.BackingOffUntil, st.ConsecutiveFails)
	}

	// And the next real alert is actually attempted.
	before := ch.calls.Load()
	if err := q.SendAndWait(context.Background(), Alert{IncidentID: "i"}, now); err != nil {
		t.Errorf("the first alert after a passing test was refused: %v", err)
	}
	if ch.calls.Load() == before {
		t.Error("the channel was not attempted after a passing test")
	}
}

// A FAILING test must not push the channel further down the ladder. Pressing a
// diagnostic button is not another delivery failure, and an operator should not
// be able to make their own outage worse by investigating it.
func TestAFailingTestDoesNotDeepenTheBackoff(t *testing.T) {
	ch := &failingTestChannel{}
	q := NewQueue(ch, 8, nil)
	defer q.Close()

	for i := 0; i < 3; i++ {
		_ = q.Test(context.Background())
	}
	if st := q.Stats(); st.ConsecutiveFails != 0 || !st.BackingOffUntil.IsZero() {
		t.Errorf("failed tests counted as delivery failures: %d fails, held until %v",
			st.ConsecutiveFails, st.BackingOffUntil)
	}
}

type failingTestChannel struct{}

func (failingTestChannel) Name() string                      { return "test" }
func (failingTestChannel) Send(context.Context, Alert) error { return nil }
func (failingTestChannel) Test(context.Context) error        { return errors.New("still broken") }
