package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func activityFromStatus(t *testing.T, h *harness) *SiteActivity {
	t.Helper()
	resp, body := h.do("GET", "/api/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
	var got struct {
		Health struct {
			Activity *SiteActivity `json:"activity"`
		} `json:"health"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	return got.Health.Activity
}

// The panel carries the count, the comparison and the verdict.
func TestTheActivityPanelReachesTheScreen(t *testing.T) {
	h := newHarness(t)
	h.mu.Lock()
	h.activity = SiteActivity{
		Available: true, Saying: true, Verdict: "busy",
		Events: 14, Devices: 9, Slot: "a weekday at this hour",
		Earned: true, TypicalEvents: 3, TypicalDevices: 2, SlotSamples: 240,
		Sentence: "Site unusually busy: 14 events across 9 devices…",
		Recent:   []ActivityBucket{{Events: 3, Devices: 2}, {Events: 14, Devices: 9}},
	}
	h.mu.Unlock()

	a := activityFromStatus(t, h)
	if a == nil {
		t.Fatal("no activity in the health payload")
	}
	if a.Events != 14 || a.Devices != 9 || a.Verdict != "busy" {
		t.Errorf("panel = %+v", a)
	}
	if len(a.Recent) != 2 {
		t.Errorf("recent = %d stretches, want the shape as well as the claim", len(a.Recent))
	}
}

// THE ABSENCE NEEDS A REASON. "Nothing unusual" and "we are not currently
// watching all of it" look identical on a screen and are opposite facts --
// which is the confusion this whole product exists to remove.
func TestASilentPanelSaysWhy(t *testing.T) {
	h := newHarness(t)
	h.mu.Lock()
	h.activity = SiteActivity{
		Available: true, Saying: false,
		Silent: "a source is not reporting, so this would measure what still reaches us",
	}
	h.mu.Unlock()

	a := activityFromStatus(t, h)
	if a == nil || a.Saying {
		t.Fatalf("panel = %+v, want it not saying anything", a)
	}
	if !strings.Contains(a.Silent, "not reporting") {
		t.Errorf("silent = %q, want the reason", a.Silent)
	}
}

// A build with no measurement has no panel, rather than an empty one that
// reads as a quiet site.
func TestNoMeasurementMeansNoPanel(t *testing.T) {
	h := newHarness(t)
	h.mu.Lock()
	h.activityOff = true
	h.mu.Unlock()

	if a := activityFromStatus(t, h); a != nil && a.Available {
		t.Errorf("panel = %+v, want none", a)
	}
}

// And the screen renders the three states rather than only the happy one.
func TestTheBoardRendersActivity(t *testing.T) {
	b, err := assetFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, want := range []string{
		"renderActivity",
		"Not saying anything yet",
		"days learned",
		"The last hour, ten minutes at a time",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("the board does not render %q", want)
		}
	}
	html, err := assetFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), `id="health-activity"`) {
		t.Error("the Health tab has nowhere to put it")
	}
}
