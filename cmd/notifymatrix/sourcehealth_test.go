package main

import (
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/ingest"
)

var hNow = time.Date(2026, 9, 21, 3, 0, 0, 0, time.UTC)

// The bug this whole chain exists to kill: a console with no Protect
// installed, so every read fails, rendered on the board as a working source.
func TestASourceThatNeverReachedItsConsoleIsNotReporting(t *testing.T) {
	sh := sourceHealthFrom(ingest.Status{
		Name: "protect", Expected: 30 * time.Minute,
		// The supervisor starts this at launch so the deadman has a grace
		// window. It is not a sighting.
		LastEventAt: hNow,
		LastError:   "protect sweep: response was not JSON",
	})

	if !sh.NeverConnected {
		t.Error("a source with no contact was not marked never-connected")
	}
	if !sh.Silent {
		t.Error("it was left looking like a reporting source")
	}
	if !sh.LastSeen.IsZero() {
		t.Errorf("last seen = %v; the column would say it was seen just now, "+
			"beside a badge saying there has been no contact", sh.LastSeen)
	}
	if sh.Detail == "" || sh.Detail == "0 event(s)" {
		t.Errorf("detail = %q, want the reason the daemon already has", sh.Detail)
	}
}

// The reason it is worth carrying the error at all.
func TestTheReasonReachesTheBoard(t *testing.T) {
	sh := sourceHealthFrom(ingest.Status{
		Name: "network", LastEventAt: hNow,
		LastError: "network: HTTP 401 on /sites",
	})
	if want := "401"; !contains(sh.Detail, want) {
		t.Errorf("detail = %q, want it to carry %q", sh.Detail, want)
	}
}

// A failing sweep reports every path it could not read. The column gets one
// line of it, not three URLs.
func TestTheReasonIsTrimmedToOneLine(t *testing.T) {
	sh := sourceHealthFrom(ingest.Status{
		Name: "protect", LastEventAt: hNow,
		LastError: "first line\nsecond line\nthird line",
	})
	if contains(sh.Detail, "second line") {
		t.Errorf("detail = %q, want only the first line", sh.Detail)
	}
}

// A source in contact with nothing to say is the normal state of a quiet
// site, and must keep saying so.
func TestAQuietButConnectedSourceStillReadsAsHealthy(t *testing.T) {
	sh := sourceHealthFrom(ingest.Status{
		Name: "protect", Expected: 30 * time.Minute,
		LastEventAt: hNow, LastContactAt: hNow,
	})
	if sh.NeverConnected {
		t.Error("a source in contact was marked never-connected")
	}
	if sh.Silent {
		t.Error("a source in contact was marked silent")
	}
	if sh.Detail != "in contact; nothing to report yet" {
		t.Errorf("detail = %q", sh.Detail)
	}
	if !sh.LastSeen.Equal(hNow) {
		t.Errorf("last seen = %v, want the contact time", sh.LastSeen)
	}
}

// A source that ran and stopped is SILENT, which is a different fact from
// never having connected and must not be relabelled.
func TestASourceThatWentQuietIsStillSilentNotNeverConnected(t *testing.T) {
	sh := sourceHealthFrom(ingest.Status{
		Name: "protect", Expected: 30 * time.Minute, Silent: true,
		Events: 12, LastEventAt: hNow.Add(-2 * time.Hour),
		LastContactAt: hNow.Add(-2 * time.Hour),
	})
	if sh.NeverConnected {
		t.Error("a source that used to work was reported as never connected")
	}
	if !sh.Silent {
		t.Error("it stopped being silent")
	}
}

// A source that cannot start at all has its own message, and keeps it.
func TestASourceThatCannotRunKeepsItsOwnReason(t *testing.T) {
	sh := sourceHealthFrom(ingest.Status{
		Name: "access", Fatal: "no API key", LastEventAt: hNow,
	})
	if sh.NeverConnected {
		t.Error("a source that cannot run was relabelled never-connected")
	}
	if !contains(sh.Detail, "no API key") {
		t.Errorf("detail = %q, want the fatal reason", sh.Detail)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
