package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// Reading a console's certificate is the daemon dialling an address somebody
// typed into a form, so it is behind a session like every other write.
func TestFetchingAFingerprintIsGated(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)

	resp, _ := h.do("POST", "/api/consoles/fingerprint", map[string]any{"host": "192.168.1.1"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("signed out = %d, want 401", resp.StatusCode)
	}
}

// What the startup warning has always promised: show me the fingerprint.
func TestAFingerprintIsShownForPinning(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.fingerprint = "AA:BB:CC"
	h.mu.Unlock()

	resp, body := h.do("POST", "/api/consoles/fingerprint", map[string]any{"host": "192.168.1.1"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch = %d %s", resp.StatusCode, body)
	}
	var got struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != "AA:BB:CC" {
		t.Errorf("fingerprint = %q", got.Fingerprint)
	}
}

// IT SHOWS; IT DOES NOT PIN. A path that stored the value it just read would
// be trust-on-first-use performed by the machine, which has no protection on
// the one connection an attacker would target.
func TestFetchingAFingerprintDoesNotSaveIt(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.fingerprint = "AA:BB:CC"
	before := h.cfg.Consoles[0].Fingerprint
	saves := h.saved
	h.mu.Unlock()

	if resp, _ := h.do("POST", "/api/consoles/fingerprint", map[string]any{"host": "192.168.1.1"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch = %d", resp.StatusCode)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg.Consoles[0].Fingerprint != before {
		t.Errorf("the console was pinned by reading it: %q", h.cfg.Consoles[0].Fingerprint)
	}
	if h.saved != saves {
		t.Error("reading a certificate saved the configuration")
	}
}

// The refusal an operator most needs to see, verbatim: the address they typed
// is not one this daemon will dial.
func TestARefusedHostSaysWhy(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.fingerprintErr = errors.New("8.8.8.8 is not a local address")
	h.mu.Unlock()

	resp, body := h.do("POST", "/api/consoles/fingerprint", map[string]any{"host": "8.8.8.8"})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a refused host returned a fingerprint")
	}
	if !strings.Contains(string(body), "not a local address") {
		t.Errorf("the reason did not reach the operator: %s", body)
	}
}

func TestAnEmptyHostIsRejectedBeforeDialling(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	resp, _ := h.do("POST", "/api/consoles/fingerprint", map[string]any{"host": "  "})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty host = %d, want 400", resp.StatusCode)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fingerprintCalls != 0 {
		t.Error("an empty address was dialled anyway")
	}
}

var _ = context.Background
