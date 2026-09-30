package web

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/firewall"
)

func blockedReport() firewall.Report {
	return firewall.Report{Supported: true, FirewallOn: true, NeedsFix: true,
		Command: "New-NetFirewallRule -Name 'NotifyMatrix-ack' ...",
		Rules: []firewall.Rule{{Want: firewall.Want{Name: "NotifyMatrix-ack",
			Purpose: "acknowledgements", Setting: "web.ack_listen", Port: 50001},
			Status: "missing"}}}
}

// Which ports are open to whom is not for the wall display.
func TestTheFirewallIsBehindASession(t *testing.T) {
	h := newHarness(t)
	h.firewall = func(context.Context, bool) (firewall.Report, error) { return blockedReport(), nil }
	for _, m := range []string{"GET", "POST"} {
		if resp, _ := h.do(m, "/api/firewall", map[string]any{}); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s /api/firewall signed out: %d, want 401", m, resp.StatusCode)
		}
	}
}

// The report reaches the page with its command, and applying is recorded
// with the ports it opened.
func TestApplyingTheFirewallRulesIsRecorded(t *testing.T) {
	h := newHarness(t)
	var applied bool
	h.firewall = func(_ context.Context, apply bool) (firewall.Report, error) {
		if !apply {
			return blockedReport(), nil
		}
		applied = true
		rep := blockedReport()
		rep.NeedsFix = false
		rep.Rules[0].Status = "allowed"
		return rep, nil
	}
	h.setPassword(testPassword)
	h.signIn()

	_, raw := h.do("GET", "/api/firewall", nil)
	var got firewall.Report
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !got.NeedsFix || got.Command == "" {
		t.Errorf("report %s: the page needs to know it is blocked, and the command", raw)
	}
	if applied {
		t.Fatal("reading the rules changed them")
	}

	resp, raw := h.do("POST", "/api/firewall", map[string]any{})
	if resp.StatusCode != http.StatusOK || !applied {
		t.Fatalf("apply: %d %s (applied %v)", resp.StatusCode, raw, applied)
	}
	if !h.log.has(audit.KindConfigChanged, "allowed in acknowledgements on TCP 50001") {
		t.Errorf("opening a port was not recorded, or not with the port: %v", h.log.summaries())
	}
}

// Without the rights, the operator is told to use the command, and the
// attempt is recorded as NOT having changed anything.
func TestApplyingWithoutRightsSaysSo(t *testing.T) {
	h := newHarness(t)
	h.firewall = func(_ context.Context, apply bool) (firewall.Report, error) {
		if apply {
			return firewall.Report{}, firewall.ErrNeedsAdmin
		}
		return blockedReport(), nil
	}
	h.setPassword(testPassword)
	h.signIn()

	resp, raw := h.do("POST", "/api/firewall", map[string]any{})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "administrator") {
		t.Errorf("apply without rights: %d %s", resp.StatusCode, raw)
	}
	if !h.log.has(audit.KindConfigChanged, "NOT changed") {
		t.Errorf("a failed attempt to open ports was not recorded: %v", h.log.summaries())
	}
}

// THE CARD. Text assertions, as with the other page tests; the proof was a
// browser, against the real daemon and this machine's real firewall.
func TestTheWebSettingsOfferTheFirewallRule(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)

	if !strings.Contains(fnBody(src, "function renderWebSection("), "loadFirewall(") {
		t.Error("the Web settings no longer draw the firewall card -- the page where the " +
			"port is chosen is the one place the rule can be offered in time")
	}
	fw := fnBody(src, "function loadFirewall(")
	if fw == "" {
		t.Fatal("loadFirewall() is gone")
	}
	if !regexp.MustCompile(`if \(!d\.supported\) return;`).MatchString(fw) {
		t.Error("the card is drawn where there is no Windows Firewall")
	}
	if !strings.Contains(fw, `api("POST", "/api/firewall"`) {
		t.Error("the card has no button that applies the rules")
	}
	// The command, at minimum: always there, copyable, for an administrator
	// terminal -- the fallback when the service cannot or should not.
	if !regexp.MustCompile(`if \(d\.command\) \{`).MatchString(fw) ||
		!strings.Contains(fw, "credRow(d.command.trim(), true)") {
		t.Error("the card does not always show the command to run, with a copy button")
	}
	if !regexp.MustCompile(`if \(d\.needs_fix\) \{`).MatchString(fw) {
		t.Error("the button is offered when nothing needs fixing")
	}
}
