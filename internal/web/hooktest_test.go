package web

import (
	"net/http"
	"strings"
	"testing"
)

// Both endpoints are GATED, and for different reasons. Arming makes this
// installation deliberately deaf to one hook for a quarter of an hour; firing
// pages whoever the ladder pages, and with voice on a rung it places a billed
// phone call. Neither is something a passing LAN device gets to do.
func TestTheHookTestEndpointsNeedASession(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)

	for _, path := range []string{
		"/api/hooks/wan/test-mode",
		"/api/hooks/wan/fire",
	} {
		resp, _ := h.do("POST", path, map[string]any{"minutes": 15})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s from a signed-out caller = %d, want 401", path, resp.StatusCode)
		}
	}
	if len(h.hookArmed) != 0 || len(h.hookFired) != 0 {
		t.Errorf("a signed-out caller reached the hook: armed=%v fired=%v",
			h.hookArmed, h.hookFired)
	}
}

// Arming and disarming both have to be in the audit record. For the fifteen
// minutes it is armed this installation throws away real alarms at that hook,
// and "why did nothing happen at 22:14" must be answerable afterwards.
func TestArmingAndDisarmingTestModeAreRecorded(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	resp, body := h.do("POST", "/api/hooks/wan/test-mode", map[string]any{"minutes": 15})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("arm: %d %s", resp.StatusCode, body)
	}
	resp, body = h.do("POST", "/api/hooks/wan/test-mode", map[string]any{"minutes": 0})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disarm: %d %s", resp.StatusCode, body)
	}

	if got := strings.Join(h.hookArmed, ","); got != "wan:15,wan:0" {
		t.Errorf("the daemon was asked for %q, want \"wan:15,wan:0\"", got)
	}

	h.log.mu.Lock()
	defer h.log.mu.Unlock()
	var armed, disarmed bool
	for _, e := range h.log.entries {
		if strings.Contains(e.Summary, "into test mode") {
			armed = true
			if !strings.Contains(e.Summary, "raising no alarm") {
				t.Errorf("the record does not say alarms are discarded: %q", e.Summary)
			}
		}
		if strings.Contains(e.Summary, "out of test mode") {
			disarmed = true
		}
	}
	if !armed || !disarmed {
		t.Errorf("arming recorded=%v, disarming recorded=%v; both must be", armed, disarmed)
	}
}

// Firing opens a REAL incident that escalates, so the record has to show it was
// deliberate -- otherwise the history of a site contains an alarm nobody can
// account for, which is the question the audit record exists to answer.
func TestFiringATestAlarmIsRecordedAsDeliberate(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	resp, body := h.do("POST", "/api/hooks/wan/fire", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fire: %d %s", resp.StatusCode, body)
	}
	if len(h.hookFired) != 1 || h.hookFired[0] != "wan" {
		t.Fatalf("fired = %v, want [wan]", h.hookFired)
	}
	// The reply must warn that this behaves like a real alarm, or somebody
	// presses it expecting a no-op and then wonders why their phone is ringing.
	if !strings.Contains(string(body), "escalates") {
		t.Errorf("the reply does not say it escalates like a real alarm: %s", body)
	}

	h.log.mu.Lock()
	defer h.log.mu.Unlock()
	var found bool
	for _, e := range h.log.entries {
		if strings.Contains(e.Summary, "test alarm fired") {
			found = true
			if !strings.Contains(e.Summary, "acknowledged") {
				t.Errorf("the record does not say it must be acknowledged: %q", e.Summary)
			}
		}
	}
	if !found {
		t.Error("firing a test alarm was not recorded")
	}
}
