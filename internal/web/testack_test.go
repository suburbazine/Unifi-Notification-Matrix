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
)

// A TEST THAT SENT A REAL ALERT TELLS THE PAGE WHICH INCIDENT TO WATCH.
//
// Without the id the page can only say "sent", which is what the old test
// said while the Acknowledge button on every ntfy alert did nothing. With it,
// the page waits for the acknowledgement to come back and says which channel
// it came through.
func TestATestAlertHandsThePageTheIncidentToWatch(t *testing.T) {
	h := newHarness(t)
	h.testChannelResult = func(context.Context, string) (ChannelTest, error) {
		return ChannelTest{IncidentID: "t1", AckLink: true}, nil
	}
	h.setPassword(testPassword)
	h.signIn()

	resp, raw := h.do("POST", "/api/channels/ntfy/test", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test: %d %s", resp.StatusCode, raw)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["incident_id"] != "t1" || body["ack_link"] != true {
		t.Errorf("reply %s: the page is not told which incident to watch", raw)
	}
	if d, _ := body["detail"].(string); !strings.Contains(d, "Press Acknowledge") {
		t.Errorf("detail %q does not tell the operator the test is not finished until "+
			"they press Acknowledge", d)
	}
}

// A link the server knows will not reach it is said with the test, not
// fifteen minutes later as a timeout.
func TestATestAlertPassesOnTheLinkWarning(t *testing.T) {
	h := newHarness(t)
	h.testChannelResult = func(context.Context, string) (ChannelTest, error) {
		return ChannelTest{IncidentID: "t3", AckLink: true, AckWarning: "names no port"}, nil
	}
	h.setPassword(testPassword)
	h.signIn()

	_, raw := h.do("POST", "/api/channels/ntfy/test", nil)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["ack_warning"] != "names no port" {
		t.Errorf("reply %s: the warning about the link did not reach the page", raw)
	}
}

// And with no button on it, the page is told why, in the server's words.
func TestATestAlertWithNoButtonSaysWhy(t *testing.T) {
	h := newHarness(t)
	h.testChannelResult = func(context.Context, string) (ChannelTest, error) {
		return ChannelTest{IncidentID: "t2", AckReason: "web.ack_base_url is not set"}, nil
	}
	h.setPassword(testPassword)
	h.signIn()

	_, raw := h.do("POST", "/api/channels/ntfy/test", nil)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["ack_link"] != false || body["ack_reason"] != "web.ack_base_url is not set" {
		t.Errorf("reply %s: a test alert with no acknowledgement on it must say so, and why", raw)
	}
	if d, _ := body["detail"].(string); strings.Contains(d, "Press Acknowledge") {
		t.Errorf("detail %q tells the operator to press a button the alert does not have", d)
	}
}

// THE PAGE WAITS FOR THE BUTTON.
//
// Text assertions, as with occurrencelog_test.go; the proof was a browser,
// where pressing the test with an ack listener running showed the waiting
// sentence, then "Acknowledged via ntfy -- acknowledgement works from ntfy"
// once the button's POST landed. What this pins is what a regression would
// silently remove.
func TestTheSettingsPageWaitsForTheTestToBeAcknowledged(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)

	row := fnBody(src, "function testRow(")
	if row == "" {
		t.Fatal("testRow() is gone; this test no longer describes the channel test")
	}
	if !strings.Contains(row, "watchTestAck(r.data.incident_id") {
		t.Error("testRow() no longer watches the test incident. The test reports \"sent\" " +
			"and proves nothing about the button -- the old test, which passed while " +
			"ntfy's Acknowledge acknowledged nothing.")
	}
	if !strings.Contains(row, "r.data.ack_link") || !strings.Contains(row, "r.data.ack_reason") {
		t.Error("testRow() does not tell the operator when the alert carried no " +
			"acknowledgement at all, and would wait for ever for a button that is not there.")
	}

	if !regexp.MustCompile(`if \(r\.data\.ack_warning\)`).MatchString(row) {
		t.Error("testRow() drops the server's warning about the link, and the operator " +
			"finds out from a phone that cannot connect")
	}

	watch := fnBody(src, "function watchTestAck(")
	if !strings.Contains(watch, `"/api/incidents"`) || !strings.Contains(watch, "setTimeout(tick") {
		t.Error("watchTestAck() no longer polls the incident list")
	}
	// It stops when a newer test replaces this one, or two watchers write
	// into one line and the older one's "closed as superseded" wins. Checked
	// twice: before polling, and again when the reply lands, because the
	// replacement can happen while a request is in flight.
	if n := len(regexp.MustCompile(`out\.dataset\.watching\s*!==\s*id`).FindAllString(watch, -1)); n < 2 {
		t.Errorf("watchTestAck() checks it is still the current test %d time(s), want 2: "+
			"before polling and when the reply lands", n)
	}
	if !strings.Contains(watch, "TEST_ACK_WINDOW_MS") {
		t.Error("watchTestAck() never gives up")
	}

	verdict := fnBody(src, "function testAckVerdict(")
	if !strings.Contains(verdict, "inc.acknowledged") || !strings.Contains(verdict, "inc.ack_via") {
		t.Error("testAckVerdict() does not report the acknowledgement and where it came from")
	}
	// Acknowledging the test from the board is not the channel working.
	if !regexp.MustCompile(`via\s*===\s*"web"`).MatchString(verdict) {
		t.Error("testAckVerdict() reports an acknowledgement pressed on this page as the " +
			"channel working")
	}
	if !strings.Contains(verdict, `inc.state === "closed"`) {
		t.Error("testAckVerdict() does not notice a test closed without acknowledgement, " +
			"and waits fifteen minutes to say what the server already knows")
	}

	// And on the board: seen, not counted. In the browser a waiting test made
	// the lede read "3 alerting" beside a header that said 2.
	board := fnBody(src, "function refreshIncidents(")
	if !regexp.MustCompile(`inc\.condition\s*!==\s*"channel-test"\)\s*nAlert\+\+`).MatchString(board) {
		t.Error("refreshIncidents() counts a channel test waiting for its button as an " +
			"alarm, and a test from the settings page turns the wall board red")
	}
}
