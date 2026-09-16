package web

import (
	"encoding/json"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/escalate"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/rule"
)

// A tab that edits PART of the configuration must leave the rest alone.
//
// The Webhooks tab posts only the two sections it owns. Everything nested
// inside `channels` was being cleared first and refilled from the update, so
// that save deleted ntfy, email and Pushover -- and Rules, QuietHours and
// AckBaseURL went the same way for being plain values rather than pointers.
// The save was accepted, "Saved." was printed, and the site stopped delivering
// anything at all until somebody worked out why.
//
// The payload below is what app.js actually sends, byte for byte, so this test
// fails if the interface and this function ever disagree again.
func TestSavingOneTabLeavesEveryOtherSectionAlone(t *testing.T) {
	cur := testConfig()
	cur.Rules = rule.Set{{Name: "quiet-lobby-cam", Ignore: true}}
	cur.QuietHours = escalate.QuietHours{Enabled: true, Start: "22:00", End: "07:00"}

	const webhooksTabPayload = `{"hooks":[],"channels":{"webhooks":[` +
		`{"name":"homeassistant","enabled":true,"url":"http://10.0.0.5/hook"}]}}`

	var upd settingsUpdate
	if err := json.Unmarshal([]byte(webhooksTabPayload), &upd); err != nil {
		t.Fatal(err)
	}
	next, _ := applyUpdate(cur, upd)

	if next.Channels.Ntfy == nil {
		t.Error("ntfy was deleted by a save that never mentioned it")
	}
	if next.Channels.Email == nil {
		t.Error("email was deleted by a save that never mentioned it")
	}
	if len(next.Rules) != len(cur.Rules) {
		t.Errorf("rules were deleted by a save that never mentioned them: %d left, want %d",
			len(next.Rules), len(cur.Rules))
	}
	if next.QuietHours != cur.QuietHours {
		t.Errorf("quiet hours were changed by a save that never mentioned them: %+v", next.QuietHours)
	}
	if next.Web.AckBaseURL != cur.Web.AckBaseURL {
		t.Errorf("ack_base_url was changed by a save that never mentioned it: %q", next.Web.AckBaseURL)
	}
	// And the thing it DID mention actually landed.
	if len(next.Channels.Webhooks) != 1 || next.Channels.Webhooks[0].Name != "homeassistant" {
		t.Errorf("the endpoint the tab was editing did not survive: %+v", next.Channels.Webhooks)
	}
}

// The mirror image: a save that DOES mention a section must still be able to
// change and to empty it, or "leave absent alone" would have made the settings
// page read-only for anything list-shaped.
func TestASaveThatMentionsASectionCanStillEmptyIt(t *testing.T) {
	cur := testConfig()
	cur.Rules = rule.Set{{Name: "quiet-lobby-cam", Ignore: true}}

	empty := rule.Set{}
	next, _ := applyUpdate(cur, settingsUpdate{Rules: &empty})
	if len(next.Rules) != 0 {
		t.Errorf("an explicit empty rule set was ignored: %+v", next.Rules)
	}

	cleared := ""
	next, _ = applyUpdate(cur, settingsUpdate{Web: webUpdate{AckBaseURL: &cleared}})
	if next.Web.AckBaseURL != "" {
		t.Errorf("an explicitly cleared ack_base_url was ignored: %q", next.Web.AckBaseURL)
	}
}

// "LEAVE IT BLANK FOR THE DEFAULT" HAS TO MEAN THAT IN THE INTERFACE TOO.
//
// The defaults only ran on the load path, so a field left blank in the file
// was filled in and the identical field left blank in the form was refused. A
// brand-new email channel posted tls:"" and came back with `tls "" is not
// auto, starttls, implicit or none`, which reads as a typo rather than as a
// field the form never asked about -- and a blank port saved as 0.
func TestANewEmailChannelSavesWithoutTypingTheDefaults(t *testing.T) {
	cur := testConfig()
	cur.Channels.Email = nil

	const payload = `{"channels":{"email":{"enabled":true,"host":"smtp.example.com",` +
		`"from":"alerts@example.com","recipients":["operator@example.com"]}}}`
	var upd settingsUpdate
	if err := json.Unmarshal([]byte(payload), &upd); err != nil {
		t.Fatal(err)
	}
	next, _ := applyUpdate(cur, upd)

	if next.Channels.Email == nil {
		t.Fatal("the email channel did not survive the save")
	}
	if got := next.Channels.Email.TLS; got != "auto" {
		t.Errorf("tls = %q, want the default %q", got, "auto")
	}
	if got := next.Channels.Email.Port; got != 587 {
		t.Errorf("port = %d, want the default 587", got)
	}
	if err := next.Validate(); err != nil {
		t.Errorf("a complete email channel with the defaults left blank was refused: %v", err)
	}
}
