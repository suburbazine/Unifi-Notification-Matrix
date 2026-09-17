package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE RULES EDITOR HAS TO BE TOLD THE VOCABULARY.
//
// Source and Severity were dropdowns; Condition -- the one field with a fixed,
// finite vocabulary -- was a free-text box with the placeholder "any". A typo
// there does not fail: the rule silently never matches, so a rule written to
// silence a noisy camera goes on not silencing it.
func TestTheSettingsAPISendsTheConditionVocabulary(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	_, body := h.do("GET", "/api/settings", nil)
	var v struct {
		Conditions []struct {
			Name    string   `json:"name"`
			Group   string   `json:"group"`
			Meaning string   `json:"meaning"`
			Sources []string `json:"sources"`
		} `json:"conditions"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Conditions) < 30 {
		t.Fatalf("the interface was sent %d conditions; the vocabulary is larger than that",
			len(v.Conditions))
	}
	for _, c := range v.Conditions {
		if c.Name == "" || c.Group == "" || len(strings.TrimSpace(c.Meaning)) < 20 {
			t.Errorf("a condition arrived unusable: %+v", c)
		}
	}
	// Spot-check ones an operator will actually reach for, and which appeared
	// in no documentation at all before this existed.
	for _, want := range []string{"motion", "door-forced-open", "water-leak", "smart-detect"} {
		var found bool
		for _, c := range v.Conditions {
			if c.Name == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not offered to the Rules editor", want)
		}
	}
}

// Entity suggestions come from what the daemon has SEEN. They are observation,
// not configuration, which is why they are added by the handler and not by
// viewSettings -- a save round-trips the view, and suggestions written back
// into the config file would be observation masquerading as settings.
func TestTheSettingsAPIOffersTheEntitiesItHasSeen(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	h.mu.Lock()
	h.entities = []EntitySeen{
		{Source: "protect", ID: "cam-1", Name: "Front Door Cam", Kind: "camera", LastAt: time.Now()},
	}
	h.mu.Unlock()

	_, body := h.do("GET", "/api/settings", nil)
	var v struct {
		Entities []EntitySeen `json:"entities"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Entities) != 1 || v.Entities[0].Name != "Front Door Cam" {
		t.Fatalf("entities = %+v, want the one that was seen", v.Entities)
	}
	// A rule matches an entity by id OR name, so both have to reach the editor.
	if v.Entities[0].ID != "cam-1" {
		t.Error("the id was not offered; a rule that must survive a rename needs it")
	}
}

// A save must not write the suggestions into the configuration. They are
// observation, and a config file that accumulates every camera ever seen is a
// config file that lies about what the operator asked for.
func TestEntitySuggestionsAreNeverSavedIntoTheConfig(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	h.mu.Lock()
	h.entities = []EntitySeen{{Source: "protect", ID: "cam-1", Name: "Front Door Cam"}}
	h.mu.Unlock()

	resp, body := h.do("POST", "/api/settings", validUpdate())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}
	h.mu.Lock()
	saved := h.cfg
	h.mu.Unlock()
	for _, r := range saved.Rules {
		if len(r.Entities) > 0 && r.Entities[0] == "Front Door Cam" {
			t.Error("a suggestion was written into the saved configuration")
		}
	}
}

// The browser must actually use what it is sent. The server sending a field
// the interface drops is a failure both halves pass -- it has already happened
// once here, with the hook URLs.
func TestTheInterfaceUsesTheVocabularyItIsSent(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"conditionPicker",    // the dropdown replacing the free-text box
		"conditionReference", // the full list in the advanced editor
		"entityDatalist",     // suggestions for the site-specific field
		"s.conditions",       // it reads the vocabulary off the payload
		"s.entities",         // ...and the observed entities
	} {
		if !strings.Contains(string(js), want) {
			t.Errorf("app.js does not reference %q, so the Rules editor is not "+
				"using what the server sends it", want)
		}
	}
}
