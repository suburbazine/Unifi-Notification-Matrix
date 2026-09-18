package rule

import (
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

func at(hh, mm int) time.Time {
	return time.Date(2026, 9, 18, hh, mm, 0, 0, time.UTC)
}

// A window that wraps midnight is the ordinary case for "out of hours" and the
// one easiest to get wrong.
func TestAWindowWrapsMidnight(t *testing.T) {
	w := Window{Start: "21:30", End: "06:00"}
	for _, tc := range []struct {
		t    time.Time
		want bool
	}{
		{at(21, 29), false},
		{at(21, 30), true}, // the start minute is inside
		{at(23, 59), true},
		{at(0, 0), true},
		{at(5, 59), true},
		{at(6, 0), false}, // the end minute is not
		{at(12, 0), false},
	} {
		if got := w.Contains(tc.t); got != tc.want {
			t.Errorf("Contains(%s) = %v, want %v", tc.t.Format("15:04"), got, tc.want)
		}
	}
}

func TestAWindowWithinOneDay(t *testing.T) {
	w := Window{Start: "08:00", End: "18:00"}
	for _, tc := range []struct {
		t    time.Time
		want bool
	}{
		{at(7, 59), false},
		{at(8, 0), true},
		{at(17, 59), true},
		{at(18, 0), false},
		{at(3, 0), false},
	} {
		if got := w.Contains(tc.t); got != tc.want {
			t.Errorf("Contains(%s) = %v, want %v", tc.t.Format("15:04"), got, tc.want)
		}
	}
}

// A malformed window must be refused at startup rather than treated as
// "matches nothing", which would silently disable the rule built on it.
func TestAMalformedWindowIsRefused(t *testing.T) {
	for _, w := range []Window{
		{Start: "25:00", End: "06:00"},
		{Start: "21:30", End: "6"},
		{Start: "", End: "06:00"},
		{Start: "09:61", End: "10:00"},
		{Start: "09:00", End: "09:00"}, // matches nothing
	} {
		if err := w.Validate(); err == nil {
			t.Errorf("window %+v was accepted", w)
		}
	}
	if err := (Window{Start: "21:30", End: "06:00"}).Validate(); err != nil {
		t.Errorf("a wrapping window was refused: %v", err)
	}
}

func denial(when time.Time) event.Event {
	return event.Event{
		Source: "access", Condition: "access-denied", At: when,
		Severity: incident.SeverityMedium,
		Entity:   event.Entity{ID: "door-1", Name: "Chapel Entrance", Kind: "door"},
	}
}

// THE POINT OF THE WHOLE FEATURE. A rule could say WHAT to escalate and never
// WHEN, so "a denial at 3am is worse than one at 2pm" could only be expressed
// by whatever sent the event deciding severity for us -- which puts a judgement
// about the building inside a product that cannot see the building.
func TestAWindowedRuleElevatesOnlyInsideItsHours(t *testing.T) {
	set := Set{{
		Name:       "out of hours",
		Conditions: []string{"access-denied"},
		Elevate:    2,
		Window:     &Window{Start: "21:30", End: "06:00"},
	}}
	if err := set.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if got := set.DecideIn(denial(at(3, 0)), time.UTC); got.Severity != incident.SeverityCritical {
		t.Errorf("at 03:00 severity = %q, want critical (medium shifted two tiers)", got.Severity)
	}
	d := set.DecideIn(denial(at(14, 0)), time.UTC)
	if d.Severity != incident.SeverityMedium {
		t.Errorf("at 14:00 severity = %q, want medium (unchanged)", d.Severity)
	}
	// A rule that did not apply is not an answer to "why did this alert
	// happen", so it must not appear in the audit record either.
	if len(d.MatchedBy) != 0 {
		t.Errorf("a rule outside its window was recorded as having matched: %v", d.MatchedBy)
	}
}

// The window is evaluated at the SITE, not on this machine. A daemon on a UTC
// server watching a building in New York must use the building's clock.
func TestAWindowIsEvaluatedInTheSiteZone(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("no tzdata: %v", err)
	}
	set := Set{{
		Name: "out of hours", Conditions: []string{"access-denied"},
		Elevate: 1, Window: &Window{Start: "21:30", End: "06:00"},
	}}

	// 08:00 UTC is 04:00 in New York: inside 21:30-06:00 for the site, and
	// outside it for the server. (02:00 UTC would not do -- a window that
	// wraps midnight contains it in BOTH zones, which is the sort of example
	// that proves nothing.)
	ev := denial(at(8, 0))
	if got := set.DecideIn(ev, ny); got.Severity != incident.SeverityHigh {
		t.Errorf("in the site zone severity = %q, want high", got.Severity)
	}
	if got := set.DecideIn(ev, time.UTC); got.Severity != incident.SeverityMedium {
		t.Errorf("in UTC severity = %q, want medium -- 02:00 UTC is outside 21:30-06:00", got.Severity)
	}
}

// The window gates the WHOLE rule, so it works for an ignore as readily as an
// elevation: "ignore motion during opening hours" is one rule.
func TestAWindowedIgnoreOnlySilencesInsideItsHours(t *testing.T) {
	set := Set{{
		Name: "daytime motion is traffic", Conditions: []string{"motion"},
		Ignore: true, Window: &Window{Start: "08:00", End: "18:00"},
	}}
	if err := set.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	motion := func(when time.Time) event.Event {
		e := denial(when)
		e.Condition = "motion"
		return e
	}
	if !set.DecideIn(motion(at(12, 0)), time.UTC).Ignore {
		t.Error("motion at noon was not ignored")
	}
	if set.DecideIn(motion(at(3, 0)), time.UTC).Ignore {
		t.Error("motion at 03:00 was ignored; the rule's window is daytime only")
	}
}

// Shifting clamps at both ends rather than wrapping, and never invents a tier.
func TestSeverityShiftClamps(t *testing.T) {
	for _, tc := range []struct {
		from incident.Severity
		by   int
		want incident.Severity
	}{
		{incident.SeverityCritical, 2, incident.SeverityCritical},
		{incident.SeverityInfo, -3, incident.SeverityInfo},
		{incident.SeverityMedium, 1, incident.SeverityHigh},
		{incident.SeverityHigh, -2, incident.SeverityLow},
		{incident.Severity("nonsense"), 1, incident.Severity("nonsense")},
	} {
		if got := shiftSeverity(tc.from, tc.by); got != tc.want {
			t.Errorf("shiftSeverity(%q, %d) = %q, want %q", tc.from, tc.by, got, tc.want)
		}
	}
}

// Two answers to one question, where which wins would depend on field order.
func TestARuleCannotBothSetAndShiftSeverity(t *testing.T) {
	r := Rule{Name: "both", Conditions: []string{"motion"},
		Severity: incident.SeverityHigh, Elevate: 1}
	if err := r.Validate(); err == nil {
		t.Error("a rule setting and shifting severity was accepted")
	}
	if err := (Rule{Name: "far", Elevate: 9}).Validate(); err == nil {
		t.Error("a shift beyond the ladder was accepted; a silent clamp hides a typo")
	}
}
