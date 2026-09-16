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

	if err := s.deps.TestChannel(ctx, name); err != nil {
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
	s.record(r, audit.Entry{
		Kind: audit.KindAlertSent, Actor: "web",
		Summary: "test message sent to " + name,
		Fields:  map[string]string{"channel": name},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"detail": "Sent. If it does not arrive, the problem is between " +
			name + " and the device, not in this configuration.",
	})
}
