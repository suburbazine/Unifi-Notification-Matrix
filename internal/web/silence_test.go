package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/rule"
)

// noisyCamera is the alarm this feature exists for: a camera on a bad PoE
// port, offline again, at a severity nobody is going to lose sleep over.
func noisyCamera(sev incident.Severity) *incident.Incident {
	return incident.Open("i1", incident.Key("protect", "Cam-7", "offline"), sev,
		"protect", "Car park camera offline", "detail", time.Now().Add(-time.Hour))
}

func silence(t *testing.T, h *harness, id string) (*http.Response, map[string]any) {
	t.Helper()
	resp, body := h.do("POST", "/api/incidents/"+id+"/silence", map[string]any{})
	var out map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decoding %s: %v", body, err)
		}
	}
	return resp, out
}

func rulesOf(h *harness) rule.Set {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg.Rules
}

func protectEvent(entity, condition string) event.Event {
	return event.Event{
		Source: "protect", Condition: condition,
		Entity:   event.Entity{ID: entity, Name: "some camera"},
		Severity: incident.SeverityMedium,
	}
}

// SILENCING WRITES A RULE, so it sits behind a session like the form that
// would otherwise write it.
func TestSilencingIsGated(t *testing.T) {
	h := newHarness(t, noisyCamera(incident.SeverityMedium))
	h.setPassword(testPassword)

	resp, _ := silence(t, h, "i1")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("signed out = %d, want 401", resp.StatusCode)
	}
	if len(rulesOf(h)) != 0 {
		t.Errorf("a rule was written anyway: %+v", rulesOf(h))
	}
}

// The whole feature: the rule that lands matches THIS alarm and nothing near
// it, and the incident stops alerting.
func TestSilencingWritesARuleMatchingOnlyThisAlarm(t *testing.T) {
	h := newHarness(t, noisyCamera(incident.SeverityMedium))
	h.setPassword(testPassword)
	h.signIn()

	resp, out := silence(t, h, "i1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("silence: %d %v", resp.StatusCode, out)
	}
	if out["closed"] != true || out["already"] != false {
		t.Errorf("response = %v, want closed and not already", out)
	}

	rules := rulesOf(h)
	if len(rules) != 1 {
		t.Fatalf("rules = %+v, want exactly one", rules)
	}
	r := rules[0]
	if r.Name != "silence protect/cam-7/offline" || out["rule"] != r.Name {
		t.Errorf("name = %q (response said %v)", r.Name, out["rule"])
	}
	if !r.Ignore || r.Severity != "" || r.Elevate != 0 || r.Window != nil {
		t.Errorf("rule does something other than ignore: %+v", r)
	}
	if err := rules.Validate(); err != nil {
		t.Errorf("the written rule set does not validate: %v", err)
	}

	// Test the DECISION the rule makes, not the fields it holds: the engine
	// must drop the alarm on the card and nothing beside it.
	for _, tc := range []struct {
		name string
		ev   event.Event
		want bool
	}{
		{"this camera, this condition", protectEvent("cam-7", "offline"), true},
		{"this camera, as the source spells it", protectEvent("Cam-7", "offline"), true},
		{"another camera, same condition", protectEvent("cam-8", "offline"), false},
		{"this camera, another condition", protectEvent("cam-7", "motion"), false},
		{"another camera, another condition", protectEvent("cam-8", "smoke"), false},
	} {
		if got := rules.Decide(tc.ev).Ignore; got != tc.want {
			t.Errorf("%s: ignored = %v, want %v", tc.name, got, tc.want)
		}
	}
	other := protectEvent("cam-7", "offline")
	other.Source = "access"
	if rules.Decide(other).Ignore {
		t.Errorf("the same entity and condition on another source was silenced")
	}

	// And the alarm on the card is no longer alerting, with a reason that
	// says where it went.
	inc, err := h.store.Get(t.Context(), "i1")
	if err != nil {
		t.Fatal(err)
	}
	if !inc.Terminal() {
		t.Errorf("incident state = %s, want closed", inc.State())
	}
	if !strings.Contains(inc.CloseReason, r.Name) {
		t.Errorf("close reason = %q, does not name the rule", inc.CloseReason)
	}
}

// A CRITICAL ALARM CANNOT BE SILENCED FROM THE BOARD, and the API is what
// says so -- the page not offering the button is a courtesy, not the rule.
func TestACriticalAlarmCannotBeSilencedFromTheBoard(t *testing.T) {
	h := newHarness(t, noisyCamera(incident.SeverityCritical))
	h.setPassword(testPassword)
	h.signIn()

	resp, out := silence(t, h, "i1")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("silence critical = %d %v, want 403", resp.StatusCode, out)
	}
	if len(rulesOf(h)) != 0 {
		t.Errorf("a rule was written: %+v", rulesOf(h))
	}
	h.mu.Lock()
	saved := h.saved
	h.mu.Unlock()
	if saved != 0 {
		t.Errorf("the configuration was saved %d times", saved)
	}
	inc, _ := h.store.Get(t.Context(), "i1")
	if inc.Terminal() {
		t.Errorf("the critical incident was closed anyway")
	}
}

// SILENCING THE SAME ALARM TWICE ADDS NOTHING. The second click finds the
// rule it would have written, writes nothing, and still closes the card.
func TestSilencingTheSameAlarmTwiceAddsNothing(t *testing.T) {
	h := newHarness(t, noisyCamera(incident.SeverityMedium))
	h.setPassword(testPassword)
	h.signIn()

	if resp, out := silence(t, h, "i1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("first silence: %d %v", resp.StatusCode, out)
	}
	// The condition came back as a new incident before the operator noticed
	// the rule had not been saved -- or they clicked twice. Either way.
	h.store.Put(t.Context(), incident.Open("i2", incident.Key("protect", "Cam-7", "offline"),
		incident.SeverityMedium, "protect", "Car park camera offline", "detail", time.Now()))

	resp, out := silence(t, h, "i2")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second silence: %d %v", resp.StatusCode, out)
	}
	if out["already"] != true || out["closed"] != true {
		t.Errorf("response = %v, want already and closed", out)
	}
	rules := rulesOf(h)
	if len(rules) != 1 {
		t.Fatalf("rules = %+v, want still exactly one", rules)
	}
	if err := rules.Validate(); err != nil {
		t.Errorf("rule set no longer validates: %v", err)
	}
	h.mu.Lock()
	saved := h.saved
	h.mu.Unlock()
	if saved != 1 {
		t.Errorf("configuration saved %d times, want once", saved)
	}
	inc, _ := h.store.Get(t.Context(), "i2")
	if !inc.Terminal() {
		t.Errorf("the second incident was left %s", inc.State())
	}
}

// A GENERATED RULE THE OPERATOR HAS EDITED IS THEIRS NOW. The name matches
// but the content does not, so the click neither overwrites it nor stacks a
// duplicate name the validator would refuse.
func TestASilenceRuleEditedByHandIsLeftAlone(t *testing.T) {
	h := newHarness(t, noisyCamera(incident.SeverityMedium))
	h.setPassword(testPassword)
	h.signIn()
	h.mu.Lock()
	h.cfg.Rules = rule.Set{{
		Name: "silence protect/cam-7/offline", Sources: []string{"protect"},
		Conditions: []string{"offline"}, Entities: []string{"cam-7"},
		Window: &rule.Window{Start: "09:00", End: "17:00"}, Ignore: true,
	}}
	h.mu.Unlock()

	resp, out := silence(t, h, "i1")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("silence over an edited rule = %d %v, want 409", resp.StatusCode, out)
	}
	rules := rulesOf(h)
	if len(rules) != 1 || rules[0].Window == nil {
		t.Errorf("the edited rule was changed or joined: %+v", rules)
	}
	inc, _ := h.store.Get(t.Context(), "i1")
	if inc.Terminal() {
		t.Errorf("the incident was closed although nothing was silenced")
	}
}

// AN ALARM WITHOUT A DEVICE HAS NOTHING FOR A RULE TO MATCH. Key writes
// "unknown" for an empty entity, and a rule for the word "unknown" matches
// nothing -- it would be shown, audited and silence nothing.
func TestAnAlarmWithNoEntityCannotBeSilenced(t *testing.T) {
	h := newHarness(t, incident.Open("i1", incident.Key("network", "", "wan-down"),
		incident.SeverityMedium, "network", "WAN down", "detail", time.Now()))
	h.setPassword(testPassword)
	h.signIn()

	resp, out := silence(t, h, "i1")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("silence with no entity = %d %v, want 400", resp.StatusCode, out)
	}
	if len(rulesOf(h)) != 0 {
		t.Errorf("a rule was written: %+v", rulesOf(h))
	}
}

// A SILENCE IS RECORDED with what it silenced, against the incident it came
// from -- and the close is recorded as a close, with the rule in its reason.
func TestASilenceIsRecorded(t *testing.T) {
	h := newHarness(t, noisyCamera(incident.SeverityMedium))
	h.setPassword(testPassword)
	h.signIn()

	if resp, out := silence(t, h, "i1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("silence: %d %v", resp.StatusCode, out)
	}

	var change, closed *audit.Entry
	h.log.mu.Lock()
	for i := range h.log.entries {
		e := &h.log.entries[i]
		switch {
		case e.Kind == audit.KindConfigChanged && strings.Contains(e.Summary, "silenced an alarm"):
			change = e
		case e.Kind == audit.KindClosed:
			closed = e
		}
	}
	h.log.mu.Unlock()

	if change == nil {
		t.Fatalf("no config change recorded; the summaries were %v", h.log.summaries())
	}
	if change.IncidentID != "i1" || change.DedupKey != "protect/cam-7/offline" {
		t.Errorf("change is not tied to the incident: %+v", change)
	}
	for k, want := range map[string]string{
		"rule": "silence protect/cam-7/offline", "source": "protect",
		"condition": "offline", "entity": "cam-7",
	} {
		if change.Fields[k] != want {
			t.Errorf("field %s = %q, want %q", k, change.Fields[k], want)
		}
	}
	if closed == nil {
		t.Fatalf("no close recorded; the summaries were %v", h.log.summaries())
	}
	if !strings.Contains(closed.Fields["reason"], "silence protect/cam-7/offline") {
		t.Errorf("close reason = %q, does not name the rule", closed.Fields["reason"])
	}
}

// A SILENCE FROM THE HISTORY LIST STILL WRITES THE RULE. The incident is
// already closed, so there is nothing to close -- and the response says so
// rather than claiming it did.
func TestSilencingAClosedIncidentStillWritesTheRule(t *testing.T) {
	inc := noisyCamera(incident.SeverityMedium)
	inc.Close(time.Now(), "camera replaced")
	h := newHarness(t, inc)
	h.setPassword(testPassword)
	h.signIn()

	resp, out := silence(t, h, "i1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("silence: %d %v", resp.StatusCode, out)
	}
	if out["closed"] != false {
		t.Errorf("claimed to close an incident that was already closed: %v", out)
	}
	if len(rulesOf(h)) != 1 {
		t.Errorf("rules = %+v, want one", rulesOf(h))
	}
	got, _ := h.store.Get(t.Context(), "i1")
	if got.CloseReason != "camera replaced" {
		t.Errorf("the original close reason was overwritten: %q", got.CloseReason)
	}
}
