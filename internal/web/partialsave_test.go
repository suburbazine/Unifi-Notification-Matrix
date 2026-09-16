package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
)

// Reported from the field: adding email was refused because ntfy was not
// finished. The only way out of a broken configuration was to fix every part
// of it in one edit, which is the opposite of what a settings page is for.
//
// You may not make it worse. You are not held hostage by damage already there.
func TestAPreExistingProblemDoesNotBlockAnUnrelatedFix(t *testing.T) {
	// Already broken: email is enabled with an unusable From.
	cur := testConfig()
	cur.Channels.Email = &config.Email{
		Enabled: true, Host: "smtp.example.com", Port: 587,
		From: "Notify Matrix", Recipients: []string{"oncall@example.com"},
	}
	if cur.Validate() == nil {
		t.Fatal("the fixture is not actually broken, so this proves nothing")
	}

	// A save that touches something else entirely and leaves the break alone.
	next := *cur
	next.Web.AckBaseURL = "http://192.168.1.50:8322"

	if err := refusedBy(cur, &next); err != nil {
		t.Fatalf("an unrelated fix was refused because of a pre-existing "+
			"problem:\n%v", err)
	}
}

// Making it worse is still refused, and the message names only what this edit
// broke -- not a wall of problems that were already there.
func TestASaveThatAddsAProblemIsStillRefused(t *testing.T) {
	cur := testConfig()
	cur.Channels.Email = &config.Email{
		Enabled: true, Host: "smtp.example.com", Port: 587,
		From: "Notify Matrix", Recipients: []string{"oncall@example.com"},
	}

	next := *cur
	// A NEW break, in a different section.
	next.Web.AckBaseURL = "not-a-url-at-all"

	err := refusedBy(cur, &next)
	if err == nil {
		t.Fatal("a save that introduced a new problem was accepted")
	}
	if !strings.Contains(err.Error(), "ack_base_url") {
		t.Errorf("the refusal does not name what this edit broke: %v", err)
	}
	if strings.Contains(err.Error(), "from") {
		t.Errorf("the refusal repeats a problem that was already there:\n%v", err)
	}
}

// Fixing the pre-existing problem must obviously work too.
func TestFixingTheBrokenFieldIsAccepted(t *testing.T) {
	cur := testConfig()
	cur.Channels.Email = &config.Email{
		Enabled: true, Host: "smtp.example.com", Port: 587,
		From: "Notify Matrix", Recipients: []string{"oncall@example.com"},
	}
	next := *cur
	email := *cur.Channels.Email
	email.From = "Notify Matrix <alerts@example.com>"
	next.Channels.Email = &email

	if err := refusedBy(cur, &next); err != nil {
		t.Fatalf("repairing the broken field was refused: %v", err)
	}
}

// End to end through the endpoint, since the rule only matters where the
// browser meets it.
func TestTheEndpointAcceptsAnUnrelatedFixOnABrokenConfig(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.cfg.Channels.Email = &config.Email{
		Enabled: true, Host: "smtp.example.com", Port: 587,
		From: "Notify Matrix", Recipients: []string{"oncall@example.com"},
	}
	cur := h.cfg
	h.mu.Unlock()

	upd := map[string]any{
		"consoles":    consolesAsUpdate(cur),
		"channels":    channelsAsUpdate(cur),
		"rules":       cur.Rules,
		"quiet_hours": cur.QuietHours,
		"web": map[string]any{
			"listen":       cur.Web.Listen,
			"ack_base_url": "http://192.168.1.50:8322",
		},
	}
	res, body := h.do("POST", "/api/settings", upd)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an unrelated fix was refused with %d: %s", res.StatusCode, body)
	}
}
