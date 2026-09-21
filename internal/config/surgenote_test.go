package config

import (
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

func alertBody(t *testing.T, note func(time.Time) string, detail string) string {
	t.Helper()
	d := &Delivery{SurgeNote: note}
	inc := incident.Open("i1", "k", incident.SeverityHigh, "protect", "Door forced", detail, time.Now())
	return d.alertFor(inc, 0).Body
}

// The note reaches every channel because alertFor is the only place an Alert
// is built. Asserted here so a second construction site would fail rather than
// quietly deliver alerts without it.
func TestTheSurgeNoteReachesTheAlert(t *testing.T) {
	body := alertBody(t, func(time.Time) string {
		return "14 events across 9 devices in the last 10 minutes."
	}, "Front door held open for 2 minutes.")

	if !strings.Contains(body, "Front door held open") {
		t.Error("the incident's own detail was lost")
	}
	if !strings.Contains(body, "9 devices") {
		t.Error("the note did not reach the alert")
	}
	// The incident first. Context that pushes the alarm off the top of a
	// phone notification is context that cost somebody the alarm.
	if strings.Index(body, "Front door") > strings.Index(body, "9 devices") {
		t.Error("the note was put above what the alert is about")
	}
}

// Nothing to say is the common case, and it must leave the body untouched.
func TestNoNoteLeavesTheBodyAlone(t *testing.T) {
	const detail = "Front door held open for 2 minutes."
	if got := alertBody(t, func(time.Time) string { return "   " }, detail); got != detail {
		t.Errorf("body = %q, want it unchanged", got)
	}
	if got := alertBody(t, nil, detail); got != detail {
		t.Errorf("body with no reporter = %q, want it unchanged", got)
	}
}

// DECORATION ONLY. A statistical signal must not move a real alarm up a tier:
// that is how a firmware rollout becomes a phone call at 3am.
func TestTheNoteDoesNotTouchSeverity(t *testing.T) {
	d := &Delivery{SurgeNote: func(time.Time) string { return "busy" }}
	inc := incident.Open("i1", "k", incident.SeverityLow, "network", "Switch offline", "", time.Now())
	if got := d.alertFor(inc, 0).Severity; got != incident.SeverityLow {
		t.Errorf("severity = %q, want it untouched at low", got)
	}
}
