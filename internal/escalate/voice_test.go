package escalate

import (
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Voice is implemented, so an operator may put it on a rung and validation has
// to accept it. Being implemented is the whole of what this list means.
func TestAnOperatorMayPutVoiceOnARung(t *testing.T) {
	var implemented bool
	for _, n := range ImplementedChannels() {
		if n == "voice" {
			implemented = true
		}
	}
	if !implemented {
		t.Fatalf("voice is built and is not in ImplementedChannels: %v -- "+
			"a rung naming it would be refused as a channel that does not exist",
			ImplementedChannels())
	}

	p := DefaultPolicies()
	crit := p[incident.SeverityCritical]
	crit.Stages = append(crit.Stages, Stage{
		After: 0, Channels: []string{"voice"},
	})
	p[incident.SeverityCritical] = crit
	if err := ValidateAgainstChannels(p, ImplementedChannels()); err != nil {
		t.Fatalf("an operator's ladder naming voice was refused: %v", err)
	}
}

// AND NOTHING PUTS IT THERE FOR THEM. A shipped default that places billed
// phone calls the first time an alarm fires at 3am is not a decision this
// package gets to make on an operator's behalf, so voice appears on no default
// ladder at any severity. TestChannelsUsed guards the same thing from the
// other side; this one says voice by name, so the failure explains itself.
func TestVoiceIsOnNoDefaultLadder(t *testing.T) {
	for sev, p := range DefaultPolicies() {
		for i, st := range p.Stages {
			for _, ch := range st.Channels {
				if ch == "voice" {
					t.Errorf("the shipped %s ladder calls somebody's phone at "+
						"stage %d: voice is opt-in, never a default", sev, i)
				}
			}
		}
	}
}
