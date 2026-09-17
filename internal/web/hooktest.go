package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
)

// A hook has two separate questions, and one button could never answer both.
//
//	CAN UNIFI REACH US?   Arm test mode, press Test in Alarm Manager, watch the
//	                      count rise. Nothing is raised and nobody is woken.
//	AND THEN WHAT?        Fire a test alarm. It goes through the real rules,
//	                      the real ladder and the real channels, so a phone
//	                      actually rings -- which is the half that an arriving
//	                      alarm does not prove until the night it matters.
//
// Both are gated. Arming makes this installation deaf to one hook for a while,
// and firing costs real notifications, possibly a real phone call.

// handleHookTestMode arms or disarms a hook's test mode.
func (s *Server) handleHookTestMode(w http.ResponseWriter, r *http.Request) {
	if s.deps.HookTestMode == nil {
		writeJSON(w, http.StatusNotImplemented,
			errorBody("this build cannot put a hook into test mode"))
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("no hook named"))
		return
	}

	var in struct {
		Minutes int `json:"minutes"`
	}
	if r.ContentLength > 0 {
		if err := readJSON(r, &in); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody("that request could not be read"))
			return
		}
	}

	until, err := s.deps.HookTestMode(name, in.Minutes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}

	if in.Minutes <= 0 {
		s.record(r, audit.Entry{
			Kind: audit.KindConfigChanged, Actor: "web",
			Summary: "hook " + name + " taken out of test mode; its alarms are real again",
			Fields:  map[string]string{"hook": name},
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "armed": false,
			"detail": "Back to normal. Alarms arriving at this hook raise incidents again.",
		})
		return
	}

	// Recorded as a configuration change, because that is what it is: for the
	// next few minutes this installation is deliberately deaf to one hook, and
	// "why did nothing happen at 22:14" has to be answerable afterwards.
	s.record(r, audit.Entry{
		Kind: audit.KindConfigChanged, Actor: "web",
		Summary: "hook " + name + " put into test mode until " + until.Format(time.RFC3339) +
			"; arrivals will be accepted and discarded, raising no alarm",
		Fields: map[string]string{"hook": name, "until": until.Format(time.RFC3339)},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "armed": true, "until": until,
		"detail": "Press Test on the Alarm Manager rule now. Arrivals will be " +
			"counted and discarded, and no alarm is raised. This ends by itself.",
	})
}

// handleFireHookTest raises the alarm this hook would raise.
func (s *Server) handleFireHookTest(w http.ResponseWriter, r *http.Request) {
	if s.deps.FireHookTest == nil {
		writeJSON(w, http.StatusNotImplemented,
			errorBody("this build cannot fire a test alarm"))
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("no hook named"))
		return
	}

	title, err := s.deps.FireHookTest(name)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}

	// A REAL incident is now open and escalating. Recorded as deliberate so
	// that nobody reading the history later mistakes it for a genuine alarm,
	// and so the one thing that could look like crying wolf is accounted for.
	s.record(r, audit.Entry{
		Kind: audit.KindIncidentOpened, Actor: "web",
		Summary: "test alarm fired from the interface for hook " + name +
			"; it escalates like a real one and must be acknowledged",
		Fields: map[string]string{"hook": name},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "title": title,
		"detail": "Raised. It escalates exactly like a real alarm, so it will " +
			"keep going until you acknowledge or close it.",
	})
}
