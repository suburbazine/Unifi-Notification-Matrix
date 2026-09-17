package config

import (
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/escalate"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// A TIME SHOWN TO A PERSON IS THE SITE'S WALL CLOCK.
//
// Times are stored in UTC -- right for storage, right for sorting -- and they
// come back out of the store carrying UTC as their location. Every channel
// formatted them without converting, so they announced UTC.
//
// The voice channel made it worst, because it speaks a bare "At 3:14 PM" with
// no zone in it: reported from a real installation as a call announcing an
// alarm four hours in the future, with nothing to say which clock it meant.
func TestAlertTimesAreInTheSiteZone(t *testing.T) {
	newYork, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tzdata on this machine:", err)
	}

	d := &Delivery{site: newYork}

	// 03:14 UTC on a September night is 23:14 the PREVIOUS DAY in New York --
	// so this catches a conversion that only fixes the hour and not the date.
	stored := time.Date(2026, 9, 17, 3, 14, 7, 0, time.UTC)
	inc := &incident.Incident{
		ID: "inc-1", Severity: incident.SeverityCritical,
		Title: "Door forced open", OpenedAt: stored,
	}

	a := d.alertFor(inc, 0)

	if got := a.At.Format("15:04"); got != "23:14" {
		t.Errorf("At = %s, want 23:14 in New York (stored %s UTC)", got, stored.Format("15:04"))
	}
	if got := a.At.Format("2006-01-02"); got != "2026-09-16" {
		t.Errorf("date = %s, want the 16th: converting the hour and not the date "+
			"is how an alarm gets reported on the wrong night", got)
	}
	if zone, _ := a.At.Zone(); zone != "EDT" {
		t.Errorf("zone = %s, want EDT -- the channels that print a zone would print the server's", zone)
	}
	if got := a.OpenedAt.Format("15:04"); got != "23:14" {
		t.Errorf("OpenedAt = %s, want 23:14: email prints it as \"Open since\"", got)
	}
}

// The last alert time goes the same way. It is the one the repeat count is
// about, and the one ntfy and Pushover stamp onto a re-alert.
func TestTheLastAlertTimeIsAlsoConverted(t *testing.T) {
	newYork, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tzdata:", err)
	}
	last := time.Date(2026, 9, 17, 3, 44, 0, 0, time.UTC)
	inc := &incident.Incident{
		ID: "inc-1", Severity: incident.SeverityHigh,
		OpenedAt: last.Add(-time.Hour), LastAlertAt: &last,
	}
	a := (&Delivery{site: newYork}).alertFor(inc, 1)
	if got := a.At.Format("15:04"); got != "23:44" {
		t.Errorf("At = %s, want 23:44 in New York", got)
	}
}

// No zone configured is the ordinary case -- a machine sitting at the site it
// watches -- and must still not leave times in UTC.
func TestWithNoConfiguredZoneTimesAreTheHostsLocal(t *testing.T) {
	d := &Delivery{site: escalate.QuietHours{}.SiteLocation()}
	stored := time.Date(2026, 9, 17, 3, 14, 7, 0, time.UTC)
	inc := &incident.Incident{ID: "inc-1", OpenedAt: stored}

	a := d.alertFor(inc, 0)
	want := stored.In(time.Local)
	if !a.At.Equal(want) || a.At.Location().String() != time.Local.String() {
		t.Errorf("At location = %s, want the host's local zone", a.At.Location())
	}
}

// A zone that does not exist must never stop an alarm going out. Quiet hours
// validates the same string at startup, which is where a typo gets reported.
func TestAnUnknownZoneFallsBackInsteadOfFailing(t *testing.T) {
	loc := escalate.QuietHours{Zone: "Mars/Olympus_Mons"}.SiteLocation()
	if loc == nil {
		t.Fatal("an unknown zone produced no location at all")
	}
	if loc.String() != time.Local.String() {
		t.Errorf("fell back to %s, want the host's local zone", loc)
	}
}

// A zone this machine cannot resolve is worth saying out loud, and quiet
// hours will not say it: with the window switched off, QuietHours.Validate
// returns before it looks at the zone. The zone still decides what clock
// every alert is announced in.
func TestABadZoneIsWarnedAboutEvenWithQuietHoursOff(t *testing.T) {
	c := Config{QuietHours: escalate.QuietHours{Zone: "Mars/Olympus_Mons"}}

	var found bool
	for _, w := range c.Warnings() {
		if strings.Contains(w, "Mars/Olympus_Mons") {
			found = true
			if !strings.Contains(w, "own clock") {
				t.Errorf("the warning does not say what happens instead: %q", w)
			}
		}
	}
	if !found {
		t.Errorf("a bad zone produced no warning: %v", c.Warnings())
	}

	// ...and it must not fire on a good one, or on the ordinary blank case.
	for _, z := range []string{"", "America/New_York", "UTC"} {
		c := Config{QuietHours: escalate.QuietHours{Zone: z}}
		for _, w := range c.Warnings() {
			if strings.Contains(w, "is not a time zone") {
				t.Errorf("zone %q was warned about: %q", z, w)
			}
		}
	}
}

// With quiet hours ENABLED a bad zone is already a startup refusal, which is a
// better answer than a warning. Saying it twice, in two registers, is worse.
func TestTheZoneWarningDefersToTheStartupRefusal(t *testing.T) {
	c := Config{QuietHours: escalate.QuietHours{
		Enabled: true, Start: "22:00", End: "07:00", Zone: "Mars/Olympus_Mons",
	}}
	for _, w := range c.Warnings() {
		if strings.Contains(w, "is not a time zone") {
			t.Errorf("warned about a zone that already refuses at startup: %q", w)
		}
	}
	if err := c.QuietHours.Validate(); err == nil {
		t.Error("an enabled window with a bad zone was accepted")
	}
}
