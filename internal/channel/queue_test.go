package channel

import (
	"errors"
	"testing"
	"time"
)

// The health view's two dead fields.
//
// last_sent and last_error were declared on the health struct and neither was
// ever populated, so a channel that had just delivered read as "last delivery:
// never" beside a green tick -- on the one surface an operator uses to answer
// "is this working?". Found against a live install whose audit record showed
// deliveries the same page claimed had never happened.
func TestTheQueueReportsItsLastDeliveryAndLastError(t *testing.T) {
	at := time.Date(2026, 9, 18, 4, 30, 0, 0, time.UTC)

	q := NewQueue(&countingChannel{name: "email"}, 4, nil)
	defer q.Close()

	if got := q.Stats(); !got.LastSent.IsZero() || got.LastError != "" {
		t.Fatalf("a queue that has done nothing claims history: %+v", got)
	}

	q.recordOutcome(nil, at)
	if got := q.Stats(); !got.LastSent.Equal(at) {
		t.Errorf("LastSent = %v, want %v", got.LastSent, at)
	}

	q.recordOutcome(errors.New("smtp: connection refused"), at.Add(time.Minute))
	got := q.Stats()
	if got.LastError != "smtp: connection refused" {
		t.Errorf("LastError = %q", got.LastError)
	}
	// A failure must not move LastSent. "When did this last work" and "what is
	// wrong now" are different questions and an operator needs both at once.
	if !got.LastSent.Equal(at) {
		t.Errorf("a failure moved LastSent to %v; it must still be the last SUCCESS", got.LastSent)
	}

	q.recordOutcome(nil, at.Add(2*time.Minute))
	if got := q.Stats(); got.LastError != "" {
		t.Errorf("a success did not clear LastError: %q", got.LastError)
	}
}

// A TEST IS NOT A DELIVERY.
//
// The Test button clears the failure backoff through recordOutcome with a zero
// time. That must not move "last sent": this product's standing rule is that
// nothing may claim a delivery that did not happen, and a health view saying a
// channel delivered just now is exactly such a claim.
func TestPressingTestDoesNotClaimADelivery(t *testing.T) {
	at := time.Date(2026, 9, 18, 4, 30, 0, 0, time.UTC)
	q := NewQueue(&countingChannel{name: "email"}, 4, nil)
	defer q.Close()

	q.recordOutcome(errors.New("nope"), at)
	q.recordOutcome(nil, time.Time{}) // the Test path

	got := q.Stats()
	if !got.LastSent.IsZero() {
		t.Errorf("a passing test claimed a delivery at %v", got.LastSent)
	}
	if got.ConsecutiveFails != 0 {
		t.Errorf("a passing test did not clear the backoff: %d fails", got.ConsecutiveFails)
	}
	if got.LastError != "" {
		t.Errorf("a passing test left the old error standing: %q", got.LastError)
	}
}
