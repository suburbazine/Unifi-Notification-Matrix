package web

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/escalate"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// THE INTERFACE AND THE DAEMON MUST AGREE ABOUT THE DEFAULTS.
//
// app.js carries its own copy of the shipped ladders so that a severity the
// config does not override can still be SHOWN -- materialising every default
// the first time somebody opens the page would freeze today's defaults into
// the installation for ever.
//
// Two copies of the same table drift. This one did: info omitted
// give_up_after, so the card promised "keep going" for a default that gives up
// after an hour, and the moment anybody edited that card it wrote a policy
// that really did keep going. A behaviour change from opening a page.
func TestTheInterfaceDefaultLaddersMatchTheDaemons(t *testing.T) {
	type jsStage struct {
		After    string   `json:"after"`
		Channels []string `json:"channels"`
	}
	type jsPolicy struct {
		Stages            []jsStage `json:"stages"`
		RepeatEvery       string    `json:"repeat_every"`
		GiveUpAfter       string    `json:"give_up_after"`
		RespectQuietHours bool      `json:"respect_quiet_hours"`
	}

	var shown map[string]jsPolicy
	if err := json.Unmarshal([]byte(defaultLaddersLiteral(t)), &shown); err != nil {
		t.Fatalf("DEFAULT_LADDERS in app.js is not parseable: %v", err)
	}

	want := escalate.DefaultPolicies()
	if len(shown) != len(want) {
		t.Errorf("the interface shows %d ladders, the daemon has %d", len(shown), len(want))
	}

	for sev, pol := range want {
		got, ok := shown[string(sev)]
		if !ok {
			t.Errorf("%s has no ladder in the interface", sev)
			continue
		}
		if d := mustDuration(t, sev, "repeat_every", got.RepeatEvery); d != pol.RepeatEvery {
			t.Errorf("%s repeat_every: interface %v, daemon %v", sev, d, pol.RepeatEvery)
		}
		if d := mustDuration(t, sev, "give_up_after", got.GiveUpAfter); d != pol.GiveUpAfter {
			t.Errorf("%s give_up_after: interface %v, daemon %v", sev, d, pol.GiveUpAfter)
		}
		if got.RespectQuietHours != pol.RespectQuietHours {
			t.Errorf("%s respect_quiet_hours: interface %v, daemon %v",
				sev, got.RespectQuietHours, pol.RespectQuietHours)
		}
		if len(got.Stages) != len(pol.Stages) {
			t.Errorf("%s has %d rungs in the interface, %d in the daemon",
				sev, len(got.Stages), len(pol.Stages))
			continue
		}
		for i, st := range got.Stages {
			if d := mustDuration(t, sev, "stage after", st.After); d != pol.Stages[i].After {
				t.Errorf("%s rung %d after: interface %v, daemon %v",
					sev, i, d, pol.Stages[i].After)
			}
			if strings.Join(st.Channels, ",") != strings.Join(pol.Stages[i].Channels, ",") {
				t.Errorf("%s rung %d channels: interface %v, daemon %v",
					sev, i, st.Channels, pol.Stages[i].Channels)
			}
		}
	}
}

// mustDuration reads the interface's spelling. "" and "never" both mean the
// zero value, which is what the daemon uses for "no horizon".
func mustDuration(t *testing.T, sev incident.Severity, field, s string) time.Duration {
	t.Helper()
	if s == "" || s == "never" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatalf("%s %s: the interface says %q, which is not a duration", sev, field, s)
	}
	return d
}

// defaultLaddersLiteral pulls the object out of app.js. If it ever fails to
// find it, that is a failure and not a skip: a checker that quietly matches
// nothing passes for ever while checking nothing.
func defaultLaddersLiteral(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	const marker = "var DEFAULT_LADDERS = "
	i := strings.Index(string(b), marker)
	if i < 0 {
		t.Fatal("DEFAULT_LADDERS is no longer declared in app.js; this test is checking nothing")
	}
	rest := string(b)[i+len(marker):]
	end := strings.Index(rest, "\n};")
	if end < 0 {
		t.Fatal("could not find the end of DEFAULT_LADDERS in app.js")
	}
	return rest[:end+2]
}
