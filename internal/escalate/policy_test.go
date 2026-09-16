package escalate

import (
	"errors"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

var t0 = time.Date(2026, 9, 15, 3, 0, 0, 0, time.UTC)

func critical() Policy { return DefaultPolicies()[incident.SeverityCritical] }

func newInc() *incident.Incident {
	return incident.Open("i1", "access/front-door/forced-open",
		incident.SeverityCritical, "access", "Door forced open", "", t0)
}

// THE restart test.
//
// The daemon goes down during a power event -- which is exactly when it is most
// likely to go down, and exactly when alarms are firing -- and comes back an
// hour later with an incident still unacknowledged. It must nag once, not
// deliver the twelve alerts it "owed" while it was gone. An operator who gets
// a burst learns to mute the product, which is a worse outcome than the
// missed hour.
func TestRestartFiresOnceNotOncePerMissedInterval(t *testing.T) {
	p := critical()
	inc := newInc()

	// Alerted through the whole ladder, last alert at +10m.
	_ = inc.RecordAlert(t0, 0)
	_ = inc.RecordAlert(t0.Add(2*time.Minute), 1)
	_ = inc.RecordAlert(t0.Add(10*time.Minute), 2)

	// Down for an hour. RepeatEvery is 5m, so twelve repeats were "missed".
	back := t0.Add(70 * time.Minute)

	due, stage, channels := p.DueNow(inc, back)
	if !due {
		t.Fatal("an unacknowledged critical incident must be due after downtime")
	}
	if stage != len(p.Stages)-1 {
		t.Errorf("stage = %d, want the final stage %d", stage, len(p.Stages)-1)
	}
	if len(channels) == 0 {
		t.Error("the final stage must name channels")
	}

	// Deliver once, as the scheduler would.
	_ = inc.RecordAlert(back, stage)

	// It must now be quiet until one interval has passed -- not immediately
	// due again for each interval it missed.
	if due, _, _ := p.DueNow(inc, back); due {
		t.Fatal("still due immediately after delivering: the scheduler would " +
			"emit one alert per missed interval, which is the burst this " +
			"design exists to prevent")
	}
	if due, _, _ := p.DueNow(inc, back.Add(p.RepeatEvery-time.Second)); due {
		t.Error("due before RepeatEvery elapsed")
	}
	if due, _, _ := p.DueNow(inc, back.Add(p.RepeatEvery)); !due {
		t.Error("not due after RepeatEvery elapsed")
	}
}

func TestLadderProgressesThroughStages(t *testing.T) {
	p := critical()
	inc := newInc()

	for i, s := range p.Stages {
		at, stage, ok := p.NextDue(inc)
		if !ok {
			t.Fatalf("stage %d: NextDue not ok", i)
		}
		if stage != i {
			t.Errorf("stage = %d, want %d", stage, i)
		}
		if want := t0.Add(s.After); !at.Equal(want) {
			t.Errorf("stage %d due at %v, want %v", i, at, want)
		}
		_ = inc.RecordAlert(at, stage)
	}

	// Past the ladder: repeats from the last alert.
	at, _, ok := p.NextDue(inc)
	if !ok {
		t.Fatal("critical must keep repeating past the last stage")
	}
	if want := inc.LastAlertAt.Add(p.RepeatEvery); !at.Equal(want) {
		t.Errorf("repeat due at %v, want %v", at, want)
	}
}

func TestAcknowledgementStopsTheLadder(t *testing.T) {
	p := critical()
	inc := newInc()
	_ = inc.RecordAlert(t0, 0)
	_ = inc.Acknowledge(t0.Add(30*time.Second), "ntfy")

	if _, _, ok := p.NextDue(inc); ok {
		t.Error("an acknowledged incident must not be scheduled again")
	}
}

func TestResolutionStopsTheLadder(t *testing.T) {
	p := critical()
	inc := newInc()
	_ = inc.RecordAlert(t0, 0)
	_ = inc.Resolve(t0.Add(30 * time.Second))

	if _, _, ok := p.NextDue(inc); ok {
		t.Error("a resolved incident must not be scheduled again")
	}
}

func TestFirstAlertIsDueImmediately(t *testing.T) {
	p := critical()
	inc := newInc()

	due, stage, _ := p.DueNow(inc, t0)
	if !due || stage != 0 {
		t.Errorf("DueNow at open = (%v, %d), want (true, 0)", due, stage)
	}
}

// A total delivery failure must leave the incident due, so the next tick tries
// again rather than treating the failure as a completed nag.
func TestDeliveryFailureLeavesIncidentDue(t *testing.T) {
	p := critical()
	inc := newInc()

	inc.RecordDeliveryFailure(t0, "every channel failed")

	if due, _, _ := p.DueNow(inc, t0.Add(time.Second)); !due {
		t.Error("an incident whose delivery failed must still be due")
	}
}

// Critical must not be configurable into silence. These are not style checks:
// the config simply cannot express the hazard.
func TestCriticalCannotBeMutedOrAbandoned(t *testing.T) {
	t.Run("quiet hours", func(t *testing.T) {
		p := critical()
		p.RespectQuietHours = true
		err := p.Validate(incident.SeverityCritical)
		if !errors.Is(err, ErrCriticalQuietHours) {
			t.Errorf("Validate = %v, want ErrCriticalQuietHours", err)
		}
	})

	t.Run("giving up", func(t *testing.T) {
		p := critical()
		p.GiveUpAfter = time.Hour
		err := p.Validate(incident.SeverityCritical)
		if !errors.Is(err, ErrCriticalGivesUp) {
			t.Errorf("Validate = %v, want ErrCriticalGivesUp", err)
		}
	})

	t.Run("lower severities may do both", func(t *testing.T) {
		p := DefaultPolicies()[incident.SeverityLow]
		if err := p.Validate(incident.SeverityLow); err != nil {
			t.Errorf("low policy rejected: %v", err)
		}
	})
}

func TestDefaultPoliciesAreValid(t *testing.T) {
	for sev, p := range DefaultPolicies() {
		if err := p.Validate(sev); err != nil {
			t.Errorf("default policy %q is invalid: %v", sev, err)
		}
	}
}

func TestCriticalNeverGivesUp(t *testing.T) {
	p := critical()
	inc := newInc()
	_ = inc.RecordAlert(t0, 0)

	// A week later, still unacknowledged.
	if p.ShouldGiveUp(inc, t0.Add(7*24*time.Hour)) {
		t.Error("critical must never give up; a top severity that goes quiet " +
			"has a silent failure mode exactly when nobody is around")
	}
}

func TestLowerSeverityGivesUp(t *testing.T) {
	p := DefaultPolicies()[incident.SeverityHigh]
	inc := incident.Open("i2", "k", incident.SeverityHigh, "network", "WAN down", "", t0)
	_ = inc.RecordAlert(t0, 0)

	if p.ShouldGiveUp(inc, t0.Add(time.Hour)) {
		t.Error("gave up before GiveUpAfter elapsed")
	}
	if !p.ShouldGiveUp(inc, t0.Add(5*time.Hour)) {
		t.Error("did not give up after GiveUpAfter elapsed")
	}
	// An acknowledged incident is someone's problem now; do not close it out
	// from under them.
	_ = inc.Acknowledge(t0.Add(time.Minute), "web")
	if p.ShouldGiveUp(inc, t0.Add(5*time.Hour)) {
		t.Error("must not give up on an acknowledged incident")
	}
}

func TestValidateRejectsUnorderedStages(t *testing.T) {
	p := Policy{Name: "bad", Stages: []Stage{
		{After: 5 * time.Minute, Channels: []string{"ntfy"}},
		{After: time.Minute, Channels: []string{"ntfy"}},
	}}
	if err := p.Validate(incident.SeverityHigh); !errors.Is(err, ErrStagesUnordered) {
		t.Errorf("Validate = %v, want ErrStagesUnordered", err)
	}
}

func TestValidateRejectsStageWithNoChannels(t *testing.T) {
	p := Policy{Name: "bad", Stages: []Stage{{After: 0}}}
	if err := p.Validate(incident.SeverityHigh); !errors.Is(err, ErrNoChannels) {
		t.Errorf("Validate = %v, want ErrNoChannels", err)
	}
}

func TestNoRepeatEndsTheLadder(t *testing.T) {
	p := Policy{Name: "once", Stages: []Stage{{After: 0, Channels: []string{"ntfy"}}}}
	inc := newInc()
	_ = inc.RecordAlert(t0, 0)

	if _, _, ok := p.NextDue(inc); ok {
		t.Error("a policy with no RepeatEvery must stop after its last stage")
	}
}

// THE LADDER MUST CLIMB EVEN WHEN ITS FIRST RUNG NEVER WORKS.
//
// Observed: an ntfy server the site could not reach at all. The default
// critical ladder pushes ntfy at once and adds email at +2m, but the stage was
// taken from the last SUCCESSFUL alert -- and there had not been one -- so
// every critical incident sat on rung 0 retrying ntfy, and email was never
// attempted. A configured, working channel named on the ladder delivered
// nothing while the alarm went unheard.
func TestTheLadderClimbsWhileNothingHasBeenDelivered(t *testing.T) {
	p := Policy{
		Name: "critical",
		Stages: []Stage{
			{After: 0, Channels: []string{"ntfy"}},
			{After: 2 * time.Minute, Channels: []string{"ntfy", "email"}},
		},
		RepeatEvery: 5 * time.Minute,
	}
	inc := newInc()
	// Nothing has ever been delivered: every attempt so far has failed.
	inc.RecordDeliveryFailure(t0, "ntfy: could not connect at all")

	due, stage, channels := p.DueNow(inc, t0.Add(10*time.Minute))
	if !due {
		t.Fatal("an incident nobody has been told about must stay due")
	}
	if stage == 0 {
		t.Errorf("still on rung 0 ten minutes in; the ladder never climbs")
	}
	var sawEmail bool
	for _, c := range channels {
		if c == "email" {
			sawEmail = true
		}
	}
	if !sawEmail {
		t.Errorf("email is on the ladder and was never attempted: channels=%v", channels)
	}
}

// ...and the rung must still be paced by the ladder, not jumped to the top the
// instant an incident opens. Escalation that arrives all at once is just a
// louder first alert.
func TestTheLadderDoesNotSkipAheadBeforeItsTime(t *testing.T) {
	p := Policy{
		Name: "critical",
		Stages: []Stage{
			{After: 0, Channels: []string{"ntfy"}},
			{After: 2 * time.Minute, Channels: []string{"email"}},
		},
		RepeatEvery: 5 * time.Minute,
	}
	inc := newInc()

	_, stage, channels := p.DueNow(inc, t0.Add(30*time.Second))
	if stage != 0 {
		t.Errorf("thirty seconds in the rung is %d, want 0", stage)
	}
	if len(channels) != 1 || channels[0] != "ntfy" {
		t.Errorf("thirty seconds in the channels are %v, want [ntfy]", channels)
	}
}
