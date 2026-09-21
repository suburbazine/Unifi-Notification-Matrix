package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

func consoleFromSettings(t *testing.T, h *harness) map[string]any {
	t.Helper()
	resp, body := h.do("GET", "/api/settings", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("settings: %d %s", resp.StatusCode, body)
	}
	var got struct {
		Consoles []map[string]any `json:"consoles"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Consoles) == 0 {
		t.Fatal("no consoles in the settings payload")
	}
	return got.Consoles[0]
}

// Whether a per-application key exists, and never the key itself -- the same
// rule the console key has always had.
func TestTheInterfaceSaysWhichApplicationKeysExist(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.cfg.Consoles[0].ProtectKey = secret.Secret("protect-only")
	h.mu.Unlock()

	c := consoleFromSettings(t, h)
	if c["protect_key_set"] != true {
		t.Errorf("protect_key_set = %v, want true", c["protect_key_set"])
	}
	if c["access_key_set"] == true {
		t.Error("access_key_set is true with no Access key stored")
	}
	for k, v := range c {
		if s, ok := v.(string); ok && s == "protect-only" {
			t.Errorf("the key itself reached the page in %q", k)
		}
	}
}

// Setting one, which is the whole point: a console serving Protect and Access
// needs two keys and had one field.
func TestAnApplicationKeyCanBeSaved(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	name := h.cfg.Consoles[0].Name
	host := h.cfg.Consoles[0].Host
	h.mu.Unlock()

	resp, body := h.do("POST", "/api/settings", map[string]any{
		"consoles": []map[string]any{{
			"name": name, "host": host, "sources": []string{"protect", "access"},
			"access_key_new": "access-only",
		}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if got := h.cfg.Consoles[0].AccessKey.Reveal(); got != "access-only" {
		t.Errorf("access key = %q, want it stored", got)
	}
	if h.cfg.Consoles[0].APIKey.IsZero() {
		t.Error("saving an application key wiped the console key")
	}
}

// A save that does not mention it keeps it, for the same reason every other
// credential works that way: the form cannot echo a secret back.
func TestASaveWithoutAKeyKeepsTheStoredOne(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.cfg.Consoles[0].ProtectKey = secret.Secret("protect-only")
	name := h.cfg.Consoles[0].Name
	host := h.cfg.Consoles[0].Host
	h.mu.Unlock()

	resp, _ := h.do("POST", "/api/settings", map[string]any{
		"consoles": []map[string]any{{"name": name, "host": host, "sources": []string{"protect"}}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save: %d", resp.StatusCode)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if got := h.cfg.Consoles[0].ProtectKey.Reveal(); got != "protect-only" {
		t.Errorf("protect key = %q after a save that never mentioned it", got)
	}
}

// And removing one has to be possible, or an operator who pastes a key into
// the wrong application can never take it back.
func TestAnApplicationKeyCanBeRemoved(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.cfg.Consoles[0].ProtectKey = secret.Secret("wrong-one")
	name := h.cfg.Consoles[0].Name
	host := h.cfg.Consoles[0].Host
	h.mu.Unlock()

	resp, body := h.do("POST", "/api/settings", map[string]any{
		"consoles": []map[string]any{{
			"name": name, "host": host, "sources": []string{"protect"},
			"clear_keys": []string{"protect"},
		}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.cfg.Consoles[0].ProtectKey.IsZero() {
		t.Error("the application key survived being cleared")
	}
	if h.cfg.Consoles[0].APIKey.IsZero() {
		t.Error("clearing an application key took the console key with it")
	}
}
