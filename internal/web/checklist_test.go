package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A hook URL carries its token, and anyone holding it can raise an alarm on
// this system. The checklist is public -- so that somebody at a wall display
// can see the thing is not configured -- which makes this the one field on it
// that must not be public.
func TestHookURLsAreNotShownToASignedOutViewer(t *testing.T) {
	h := newHarness(t)

	resp, body := h.do(http.MethodGet, "/api/checklist", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: the checklist is public on purpose", resp.StatusCode)
	}
	if strings.Contains(string(body), canary) {
		t.Fatalf("a hook URL reached a signed-out caller:\n%s", body)
	}

	var d struct {
		Authenticated bool `json:"authenticated"`
		Hooks         []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Hooks) != 1 {
		t.Fatalf("hooks = %d, want the hook to be listed -- knowing one EXISTS "+
			"is the useful half and discloses nothing", len(d.Hooks))
	}
	if d.Hooks[0].Name != "wan" {
		t.Errorf("hook name = %q", d.Hooks[0].Name)
	}
	if d.Hooks[0].URL != "" {
		t.Errorf("hook URL = %q, want empty when signed out", d.Hooks[0].URL)
	}
}

// And the operator who signs in does get them, or they cannot finish setup.
func TestHookURLsAreShownToASignedInOperator(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	_, body := h.do(http.MethodGet, "/api/checklist", nil)
	if !strings.Contains(string(body), canary) {
		t.Fatalf("a signed-in operator was not given the hook URL, so there is "+
			"nothing for them to paste into Alarm Manager:\n%s", body)
	}
}

// The checklist says what has never been DONE, which is a different question
// from what is currently WRONG.
func TestTheChecklistReportsRemainingSteps(t *testing.T) {
	h := newHarness(t)
	_, body := h.do(http.MethodGet, "/api/checklist", nil)

	var d struct {
		Available bool `json:"available"`
		Ready     bool `json:"ready"`
		Steps     []struct {
			Title  string   `json:"title"`
			Status string   `json:"status"`
			Why    string   `json:"why"`
			How    []string `json:"how"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatal(err)
	}
	if !d.Available {
		t.Fatal("the checklist reported itself unavailable")
	}
	if !d.Ready {
		t.Error("a console, a source and a channel are configured; that IS ready")
	}
	if len(d.Steps) < 5 {
		t.Fatalf("steps = %d, want the whole checklist", len(d.Steps))
	}
	for _, s := range d.Steps {
		if s.Why == "" {
			t.Errorf("step %q has no reason; an instruction without a consequence "+
				"is one people postpone", s.Title)
		}
		if s.Status != "done" && len(s.How) == 0 {
			t.Errorf("step %q is not done and says nothing about how to do it", s.Title)
		}
	}
}

// A build that supplies no checklist must not break the page.
func TestAMissingChecklistIsReportedNotFatal(t *testing.T) {
	h := newHarness(t)
	h.srv.deps.Checklist = nil

	resp, body := h.do(http.MethodGet, "/api/checklist", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"available":false`) {
		t.Errorf("body = %s", body)
	}
}

// A SIGNED-IN READER MUST ACTUALLY BE SHOWN THE HOOK CREDENTIALS.
//
// The negative is tested above: a signed-out reader never sees them. The
// positive was not, and it failed in the place nobody looks -- the server sent
// url, header_name and header_value, and app.js rendered neither the Setup
// tab's hook list nor anything on the Webhooks card. So an operator who had
// just created a hook in the interface was told by that same interface to
// paste a URL it would not show them, and the only way to get it was
// `notifymatrix setup` in a terminal, on the screen built so nobody has to
// open one.
func TestASignedInReaderIsGivenTheHookURLAndHeader(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	_, body := h.do(http.MethodGet, "/api/checklist", nil)
	var d struct {
		Authenticated bool `json:"authenticated"`
		Hooks         []struct {
			Name        string `json:"name"`
			URL         string `json:"url"`
			HeaderName  string `json:"header_name"`
			HeaderValue string `json:"header_value"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatal(err)
	}
	if !d.Authenticated {
		t.Fatal("the harness did not sign in")
	}
	if len(d.Hooks) == 0 {
		t.Fatal("no hooks in the checklist; this test is checking nothing")
	}
	for _, hk := range d.Hooks {
		if hk.URL == "" {
			t.Errorf("hook %q has no URL for a signed-in reader", hk.Name)
		}
		if hk.HeaderName == "" || hk.HeaderValue == "" {
			t.Errorf("hook %q has no header for a signed-in reader", hk.Name)
		}
	}
}

// ...AND THE INTERFACE HAS TO RENDER WHAT THE SERVER SENDS.
//
// Every field below was served correctly and dropped on the floor by the
// browser, which is a failure no API test can see: both halves passed while
// the operator got nothing. This asserts the interface at least references
// each field, so adding one to the response without rendering it fails here.
func TestTheInterfaceRendersEveryHookFieldTheServerSends(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"url", "header_name", "header_value", "last_reject"} {
		if !bytes.Contains(js, []byte(field)) {
			t.Errorf("the checklist sends hook.%s and app.js never mentions it, "+
				"so a signed-in operator is never shown it", field)
		}
	}
}
