package network

import (
	"errors"
	"testing"
	"time"
)

// The same lie, in the source that had it worst. Network declares no deadman,
// so a poll that never succeeds sits on the board as REPORTING forever -- and
// on the console that prompted this, every poll was a 401 because the key
// belonged to a different appliance.
//
// The doc comment on LastContact already said "the last poll that ACTUALLY
// reached the console". The code stamped every attempt.
func TestAPollThatFailedIsNotContact(t *testing.T) {
	s := &Source{}
	s.health.UnknownStates = map[string]int64{}

	s.notePoll(time.Now(), errors.New("network: HTTP 401 on /sites"))

	if got := s.LastContact(); !got.IsZero() {
		t.Errorf("LastContact = %v after a poll that was refused", got)
	}
	if s.LastError() == "" {
		t.Error("the refusal was not reported as the reason")
	}
}

func TestAPollThatWorkedIsContact(t *testing.T) {
	s := &Source{}
	s.health.UnknownStates = map[string]int64{}

	now := time.Now()
	s.notePoll(now, nil)

	if !s.LastContact().Equal(now) {
		t.Errorf("LastContact = %v, want %v", s.LastContact(), now)
	}
	if s.LastError() != "" {
		t.Errorf("a successful poll left an error: %q", s.LastError())
	}
}
