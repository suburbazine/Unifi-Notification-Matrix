// Package escalate decides when an incident should be alerted again, and
// through which channels.
//
// The scheduler owns no timers of record. Every decision here is a pure
// function of the incident's persisted timestamps and the policy, so that a
// restart reconstructs the schedule exactly rather than losing it -- which for
// a product whose job is nagging until acknowledged is the difference between
// working and not.
package escalate

import (
	"errors"
	"fmt"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Stage is one rung of the ladder: at this age, alert through these channels.
//
// Each stage names its channels in full rather than adding to the previous
// stage, so a stage can be read on its own and a config cannot accidentally
// drop a channel by omission.
type Stage struct {
	After    time.Duration
	Channels []string
}

// Policy is the escalation behaviour for one severity.
type Policy struct {
	Name   string
	Stages []Stage

	// RepeatEvery is the interval after the final stage. Zero means the ladder
	// ends and the incident stops nagging once the last stage has fired.
	RepeatEvery time.Duration

	// GiveUpAfter closes an unacknowledged incident after this long. Zero
	// means never, which is the correct default for critical: a product whose
	// top severity eventually gives up has a silent failure mode precisely
	// when nobody is around, which is when it matters.
	GiveUpAfter time.Duration

	// RespectQuietHours must be false for critical -- enforced by Validate.
	RespectQuietHours bool
}

var (
	ErrNoStages           = errors.New("policy has no stages")
	ErrStagesUnordered    = errors.New("policy stages must be in increasing order of After")
	ErrNoChannels         = errors.New("policy stage has no channels")
	ErrCriticalQuietHours = errors.New("critical policies cannot respect quiet hours")
	ErrCriticalGivesUp    = errors.New("critical policies cannot give up")
)

// Validate refuses configurations that would produce silence during an alarm.
//
// Two of these are not style rules. A critical policy that can be muted by
// quiet hours, or that gives up on its own, is one support call away from a
// very bad outcome -- so rather than documenting the hazard, the config simply
// cannot express it.
func (p Policy) Validate(sev incident.Severity) error {
	if len(p.Stages) == 0 {
		return fmt.Errorf("%s: %w", p.Name, ErrNoStages)
	}
	last := time.Duration(-1)
	for i, s := range p.Stages {
		if s.After <= last {
			return fmt.Errorf("%s: stage %d: %w", p.Name, i, ErrStagesUnordered)
		}
		last = s.After
		if len(s.Channels) == 0 {
			return fmt.Errorf("%s: stage %d: %w", p.Name, i, ErrNoChannels)
		}
	}
	if sev == incident.SeverityCritical {
		if p.RespectQuietHours {
			return fmt.Errorf("%s: %w", p.Name, ErrCriticalQuietHours)
		}
		if p.GiveUpAfter != 0 {
			return fmt.Errorf("%s: %w", p.Name, ErrCriticalGivesUp)
		}
	}
	return nil
}

// NextDue returns when the incident should next be alerted and which stage
// that is. ok is false when it should never alert again.
//
// The schedule is computed from OpenedAt and LastAlertAt rather than
// accumulated, which is what gives the restart behaviour for free: an incident
// whose next alert fell due during downtime returns a due time in the past and
// therefore fires ONCE on the next tick, not once per missed interval. A
// restart must never produce a burst -- a burst during a power event, when
// restarts are most likely, is exactly how an operator learns to mute the
// product.
func (p Policy) NextDue(inc *incident.Incident) (at time.Time, stage int, ok bool) {
	if inc.Terminal() || inc.Acknowledged() || inc.Resolved() {
		return time.Time{}, 0, false
	}

	// Never delivered: the first stage is due at its offset from open.
	if inc.LastAlertAt == nil {
		if len(p.Stages) == 0 {
			return time.Time{}, 0, false
		}
		return inc.OpenedAt.Add(p.Stages[0].After), 0, true
	}

	// Find the first stage whose scheduled time is strictly after the last
	// successful alert.
	for i, s := range p.Stages {
		t := inc.OpenedAt.Add(s.After)
		if t.After(*inc.LastAlertAt) {
			return t, i, true
		}
	}

	// Past the last stage: repeat, if the policy repeats.
	if p.RepeatEvery <= 0 {
		return time.Time{}, 0, false
	}
	return inc.LastAlertAt.Add(p.RepeatEvery), len(p.Stages) - 1, true
}

// DueNow reports whether the incident should be alerted at now, and how.
//
// When NOTHING has ever been delivered, the rung is decided by how long the
// incident has been open -- not by which rung was last attempted, and not by
// the last SUCCESS, because there has not been one.
//
// NextDue answers "when is the next obligation" and, with LastAlertAt still
// nil, that answer is always stage 0. Taking the stage from it too meant a
// ladder could never climb while its first rung was failing: the default
// critical ladder pushes ntfy at once and adds email at +2m, so an unreachable
// ntfy server pinned every critical incident to ntfy forever and email -- named
// on the ladder, configured, and working -- was never once attempted. That is
// the failure the ladder exists to prevent, so it cannot be gated on the ladder
// already having worked.
//
// The channels are the UNION of every rung whose time has passed, rather than
// just the highest. A rung that drops a channel an earlier rung named is
// expressing an order to try things in, not a decision to stop trying them,
// and while nobody has been reached at all the widest net is the right one.
func (p Policy) DueNow(inc *incident.Incident, now time.Time) (due bool, stage int, channels []string) {
	at, st, ok := p.NextDue(inc)
	if !ok || at.After(now) {
		return false, 0, nil
	}
	if inc.LastAlertAt == nil {
		st = p.highestRungDue(inc.OpenedAt, now)
		return true, st, p.channelsUpTo(st)
	}
	return true, st, p.Stages[st].Channels
}

// highestRungDue is the last stage whose scheduled time has arrived.
func (p Policy) highestRungDue(openedAt, now time.Time) int {
	st := 0
	for i, s := range p.Stages {
		if !openedAt.Add(s.After).After(now) {
			st = i
		}
	}
	return st
}

// channelsUpTo collects the channels of every stage through st, in ladder
// order and without repeating one that appears on more than one rung.
func (p Policy) channelsUpTo(st int) []string {
	seen := map[string]bool{}
	var out []string
	for i := 0; i <= st && i < len(p.Stages); i++ {
		for _, c := range p.Stages[i].Channels {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// ShouldGiveUp reports whether an unacknowledged incident has outlived the
// policy. Always false when GiveUpAfter is zero.
func (p Policy) ShouldGiveUp(inc *incident.Incident, now time.Time) bool {
	if p.GiveUpAfter <= 0 || inc.Terminal() || inc.Acknowledged() {
		return false
	}
	return now.Sub(inc.OpenedAt) > p.GiveUpAfter
}

// DefaultPolicies is the shipped starting point. Critical never gives up and
// ignores quiet hours; the operator can change the intervals but the default
// will not choose silence for them.
//
// EVERY CHANNEL NAMED HERE MUST EXIST. The ladders are deliberately shorter
// than the eventual design because only ntfy and email are implemented, and a
// default that named "voice" or "pushover" today would ship a stage that
// silently delivers nothing — which ValidateAgainstChannels now refuses to
// start with, and rightly. The rungs go back in when the channels land:
//
//	critical  +10m → add voice, once internal/channel/voice exists
//	critical  +2m  → add pushover
//	info           → webhook, once internal/channel/webhook exists
//
// TestDefaultPoliciesNameOnlyImplementedChannels fails if this drifts.
func DefaultPolicies() map[incident.Severity]Policy {
	return map[incident.Severity]Policy{
		incident.SeverityCritical: {
			Name: "critical",
			Stages: []Stage{
				{After: 0, Channels: []string{"ntfy"}},
				{After: 2 * time.Minute, Channels: []string{"ntfy", "email"}},
			},
			RepeatEvery: 5 * time.Minute,
			GiveUpAfter: 0, // never
		},
		incident.SeverityHigh: {
			Name: "high",
			Stages: []Stage{
				{After: 0, Channels: []string{"ntfy"}},
				{After: 15 * time.Minute, Channels: []string{"ntfy", "email"}},
			},
			RepeatEvery: 30 * time.Minute,
			GiveUpAfter: 4 * time.Hour,
		},
		incident.SeverityMedium: {
			Name:        "medium",
			Stages:      []Stage{{After: 0, Channels: []string{"ntfy"}}},
			RepeatEvery: 2 * time.Hour,
			GiveUpAfter: 12 * time.Hour,
		},
		incident.SeverityLow: {
			Name:              "low",
			Stages:            []Stage{{After: 0, Channels: []string{"ntfy"}}},
			RespectQuietHours: true,
			GiveUpAfter:       24 * time.Hour,
		},
		incident.SeverityInfo: {
			Name:              "info",
			Stages:            []Stage{{After: 0, Channels: []string{"ntfy"}}},
			RespectQuietHours: true,
			GiveUpAfter:       time.Hour,
		},
	}
}

// ImplementedChannels is the set of channels this build can actually deliver
// through. Kept next to DefaultPolicies so the two cannot drift apart
// unnoticed; the real startup path passes the channels it actually
// constructed, not this list.
func ImplementedChannels() []string { return []string{"email", "ntfy"} }
