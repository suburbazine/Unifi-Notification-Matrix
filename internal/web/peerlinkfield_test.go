package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The Peer link section tells an operator to "set a link address in Web below
// and restart". There was no such field: Web offers listen, the ack link
// address and the ack-only listener, and the only thing on it with "link
// address" in the label is the ACK one. So the instruction sent people to set
// the wrong field, restart, and find the section unchanged -- which is
// exactly what happened.
func TestTheWebSectionCarriesThePeerLinkAddress(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.cfg.Web.LinkListen = "0.0.0.0:8444"
	h.mu.Unlock()

	resp, body := h.do("GET", "/api/settings", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("settings: %d %s", resp.StatusCode, body)
	}
	var got struct {
		Web struct {
			LinkListen string `json:"link_listen"`
		} `json:"web"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Web.LinkListen != "0.0.0.0:8444" {
		t.Errorf("link_listen = %q; the page cannot show a field it is never sent", got.Web.LinkListen)
	}
}

// And it has to be settable, or the instruction is still a lie.
func TestThePeerLinkAddressCanBeSetFromTheInterface(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	resp, body := h.do("POST", "/api/settings", map[string]any{
		"web": map[string]any{"listen": "127.0.0.1:8322", "link_listen": "auto"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg.Web.LinkListen != "auto" {
		t.Errorf("saved link_listen = %q, want auto", h.cfg.Web.LinkListen)
	}
}

// A partial save must not cut off a paired peer. Every other field in this
// section is a pointer for this reason; this one carries a listener that
// peers hold an address for, so omitting it has to mean "leave it alone".
func TestASaveThatDoesNotMentionThePeerLinkLeavesItAlone(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.cfg.Web.LinkListen = "0.0.0.0:8444"
	h.mu.Unlock()

	resp, body := h.do("POST", "/api/settings", map[string]any{
		"web": map[string]any{"listen": "127.0.0.1:8322"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg.Web.LinkListen != "0.0.0.0:8444" {
		t.Errorf("a save that never mentioned the peer link set it to %q; "+
			"every paired peer holds that address", h.cfg.Web.LinkListen)
	}
}

// Clearing it deliberately still has to work, or an operator cannot withdraw
// the listener without editing YAML.
func TestThePeerLinkAddressCanBeClearedDeliberately(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.cfg.Web.LinkListen = "0.0.0.0:8444"
	h.mu.Unlock()

	resp, body := h.do("POST", "/api/settings", map[string]any{
		"web": map[string]any{"listen": "127.0.0.1:8322", "link_listen": ""},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg.Web.LinkListen != "" {
		t.Errorf("link_listen = %q after being cleared", h.cfg.Web.LinkListen)
	}
}

// The instruction on the Peer link section names a field. If the label on
// that field ever moves, this is the test that says so.
func TestThePeerLinkInstructionNamesAFieldThatExists(t *testing.T) {
	b, err := assetFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if !strings.Contains(js, "Peer link address") {
		t.Error("the Web section has no field labelled \"Peer link address\"")
	}
	if !strings.Contains(js, "Set the peer link address in Web") {
		t.Error("the Peer link section does not point at that field by name")
	}
}
