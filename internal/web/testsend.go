package web

import (
	"context"
	"net/http"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
)

// testSendTimeout bounds a test. Long enough for a slow SMTP handshake, short
// enough that an operator gets an answer rather than a spinner.
const testSendTimeout = 45 * time.Second

// handleTestChannel sends one channel's own proof-of-configuration message.
//
// GATED, and it is worth saying why given the status page is not: this sends a
// real notification to the operator's real phone. An open endpoint that makes
// somebody's alarm app buzz is a nuisance at best and a way to train them to
// ignore it at worst.
//
// It reports the REAL outcome of this attempt, not "accepted". The whole
// purpose is to answer "did I type the token correctly", and a queued answer
// that succeeds and then fails silently is worse than no button.
func (s *Server) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	if s.deps.TestChannel == nil {
		writeJSON(w, http.StatusNotImplemented,
			errorBody("this build cannot send test messages"))
		return
	}
	name := r.PathValue("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("no channel named"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), testSendTimeout)
	defer cancel()

	res, err := s.deps.TestChannel(ctx, name)
	summary := res.Summary
	if err != nil {
		s.record(r, audit.Entry{
			Kind: audit.KindAlertFailed, Actor: "web",
			Summary: "test message to " + name + " failed",
			Fields:  map[string]string{"channel": name, "error": err.Error()},
		})
		// The channel's own error is passed through rather than generalised.
		// "535 5.7.8 authentication failed" tells an operator exactly what to
		// change; "could not send" tells them to open a support ticket.
		writeJSON(w, http.StatusBadGateway, errorBody(err.Error()))
		return
	}
	// A channel whose test does something other than deliver a message says
	// so, and BOTH the record and the reply use its words.
	//
	// The generic wording was written when every channel delivered something.
	// Voice does not -- its test checks credentials and deliberately places no
	// call -- so the audit record said "test message sent to voice" and the
	// API replied "Sent.", which is the product's own append-only record
	// asserting a delivery that never happened. Painting over it in the
	// browser would have left the record still lying.
	detail := "Sent. If it does not arrive, the problem is between " +
		name + " and the device, not in this configuration."
	recorded := "test message sent to " + name
	if summary != "" {
		detail = summary
		recorded = "test of " + name + ": " + summary
	}
	// A REAL ALERT WAS SENT, with the real acknowledgement on it. The page is
	// told which incident to watch, so it can say "acknowledged via ntfy"
	// when the button is pressed -- the part of the channel the old test
	// never touched, and the part that was broken.
	body := map[string]any{"ok": true, "detail": detail}
	if res.IncidentID != "" {
		body["incident_id"] = res.IncidentID
		body["ack_link"] = res.AckLink
		if res.AckWarning != "" {
			body["ack_warning"] = res.AckWarning
		}
		if res.AckLink {
			body["detail"] = "Sent a test alert. Press Acknowledge on it, on the " +
				"device, to prove acknowledgement works from " + name +
				" -- this page will say when it arrives."
		} else {
			body["ack_reason"] = res.AckReason
		}
		recorded = "test alert sent to " + name + " (incident " + res.IncidentID + ")"
	}
	s.record(r, audit.Entry{
		Kind: audit.KindAlertSent, Actor: "web",
		Summary: recorded,
		Fields:  map[string]string{"channel": name},
	})
	writeJSON(w, http.StatusOK, body)
}

// ChannelTest is what a channel's test did.
type ChannelTest struct {
	// Summary is what the channel says its test did, when that is not
	// "delivered a message" -- voice checks credentials and places no call.
	Summary string

	// IncidentID is the test incident a real alert was sent about, for a
	// channel a person acknowledges from. Empty for any other.
	IncidentID string

	// AckLink says the alert carried an acknowledgement, and AckReason why
	// it could not when it did not.
	AckLink   bool
	AckReason string
	// AckWarning is set when the alert carries a link that will not reach
	// this program -- today, one with no port going to 80. The test is still
	// sent: pressing the button on the phone is what proves it either way.
	AckWarning string
}
