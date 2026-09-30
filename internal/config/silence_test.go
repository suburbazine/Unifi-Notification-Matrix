package config

import (
	"strings"
	"testing"
	"time"
)

// A BAD WINDOW WARNS AND IS CLAMPED; IT NEVER STOPS THE DAEMON.
//
// Refusing would mean a typo in one peer's window keeps the whole daemon from
// starting, and a monitoring daemon that is not running watches nothing --
// worse than any window.
func TestAPeerWindowIsClampedAndWarnedNeverRefused(t *testing.T) {
	for _, tc := range []struct {
		in    string
		want  time.Duration
		warns bool
	}{
		{"", DefaultPeerSilentAfter, false},
		{"2m", 2 * time.Minute, false},
		{"10s", MinPeerSilentAfter, true},
		{"48h", MaxPeerSilentAfter, true},
		{"two minutes", DefaultPeerSilentAfter, true},
	} {
		got, warn := Link{Slug: "sentry", SilentAfter: tc.in}.Silence()
		if got != tc.want || (warn != "") != tc.warns {
			t.Errorf("silent_after %q = %s (warning %q), want %s (warns %v)",
				tc.in, got, warn, tc.want, tc.warns)
		}
	}

	c := Config{Links: []Link{{Slug: "sentry", SilentAfter: "10s"}}}
	found := false
	for _, w := range c.Warnings() {
		if strings.Contains(w, "silent_after") {
			found = true
		}
	}
	if !found {
		t.Error("an unusable silent_after produced no startup warning, so the operator " +
			"never learns their 10s became a minute")
	}
}
