package demo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Demo mode fabricates security alarms. Mixing those into a real store is how
// real alarms stop being believed -- so it refuses, rather than warning.
func TestADemoRefusesToRunAgainstARealInstallation(t *testing.T) {
	for _, name := range []string{"config.yaml", "incidents.db", "audit.jsonl"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := Refuse(dir)
		if err == nil {
			t.Fatalf("a directory containing %s was accepted for a demo", name)
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal does not name what it found: %v", err)
		}
	}
}

func TestAnEmptyDirectoryIsFineForADemo(t *testing.T) {
	if err := Refuse(t.TempDir()); err != nil {
		t.Fatalf("an empty directory was refused: %v", err)
	}
}

// Nothing is delivered. A fabricated "door forced open" arriving on somebody's
// phone is indistinguishable from a real one, and the second time it happens
// they stop believing the first.
func TestDeliveryIsRefusedRatherThanSilentlyDropped(t *testing.T) {
	err := RefuseDelivery(context.Background(), nil, 0, []string{"ntfy"})
	if err == nil {
		t.Fatal("demo delivery reported success, which is what a real delivery " +
			"looks like to everything upstream")
	}
}

// Every fabricated incident has to be identifiable as one from its own
// contents, not only from the banner on the page it happens to be rendered on.
// A screenshot, an export or a row read straight out of the store all outlive
// the banner.
func TestEveryDemoIncidentSaysSoInItsOwnTitle(t *testing.T) {
	for _, inc := range script(time.Now()) {
		if !strings.Contains(inc.Title, "[DEMO]") {
			t.Errorf("incident %q is not marked as fabricated", inc.Title)
		}
	}
}

// The board is chosen to show the states a notification list cannot represent.
// If the seed drifts into a row of identical open alarms it stops making the
// argument it exists to make.
func TestTheSeededBoardShowsTheStatesThatJustifyIncidents(t *testing.T) {
	now := time.Now()
	all := script(now)

	var unacked, ackedNotResolved, failing, closed int
	for _, inc := range all {
		switch {
		case inc.State() == "closed":
			closed++
		case inc.Acknowledged() && !inc.Resolved():
			ackedNotResolved++
		case !inc.Acknowledged():
			unacked++
		}
		if inc.LastDeliveryError != "" {
			failing++
		}
	}

	if unacked == 0 {
		t.Error("nothing is still unacknowledged, which is the state the whole " +
			"product exists for")
	}
	if ackedNotResolved == 0 {
		t.Error("nothing is acknowledged-but-not-resolved -- the open obligation " +
			"a notification cannot express")
	}
	if failing == 0 {
		t.Error("no delivery is failing, so the most useful line on the screen " +
			"is never shown")
	}
	if closed == 0 {
		t.Error("nothing is closed, so the board cannot show what resolution " +
			"looks like")
	}
}

// The seed must not fabricate anything that looks like a live credential. A
// screenshot of a demo is going in a README.
func TestTheDemoCarriesNothingThatLooksLikeACredential(t *testing.T) {
	for _, inc := range script(time.Now()) {
		body := inc.Title + " " + inc.Detail
		for _, bad := range []string{"Bearer ", "/hook/", "api_key", "token="} {
			if strings.Contains(body, bad) {
				t.Errorf("incident %q contains %q, which reads as a real credential",
					inc.Title, bad)
			}
		}
	}
}
