package web

import (
	"net/http"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
)

// ServiceAction is what the operator asked the service manager to do.
type ServiceAction string

const (
	// ServiceStart and ServiceStop are the two the daemon can be asked for.
	ServiceStart ServiceAction = "start"
	ServiceStop  ServiceAction = "stop"

	// ServiceRestart is start and stop together, and is the one that matters:
	// channels, policies and rules are all built once at start, so every
	// configuration change needs it and there was nothing in this interface
	// that could do it. The instruction was "open a terminal", to somebody
	// whose whole reason for being on this page is that they would rather not.
	ServiceRestart ServiceAction = "restart"
)

// handleServiceAction runs one service-manager action on behalf of the
// operator.
//
// Restarting is the interesting one, and it is deliberately not hidden behind
// a confirmation: a daemon that is not running raises no alarms, so the risk
// of the button is real and the risk of NOT having it is a configuration that
// silently never takes effect. The audit record carries who asked and what
// happened either way.
func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	if s.deps.ControlService == nil {
		writeJSON(w, http.StatusNotImplemented,
			errorBody("this build cannot control the service"))
		return
	}

	var body struct {
		Action string `json:"action"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("that request could not be read"))
		return
	}

	action := ServiceAction(body.Action)
	switch action {
	case ServiceStart, ServiceStop, ServiceRestart:
	default:
		writeJSON(w, http.StatusBadRequest,
			errorBody(`action must be "start", "stop" or "restart"`))
		return
	}

	// Recorded BEFORE it runs. A restart that succeeds takes this process down
	// with it, so an entry written afterwards is an entry that never gets
	// written -- and "the daemon stopped and nothing says why" is precisely
	// the gap the audit record exists to close.
	s.record(r, audit.Entry{
		Kind: audit.KindService, Actor: "web",
		Summary: "service " + string(action) + " requested from the web UI",
		Fields:  map[string]string{"action": string(action)},
	})

	if err := s.deps.ControlService(action); err != nil {
		s.record(r, audit.Entry{
			Kind: audit.KindService, Actor: "web",
			Summary: "service " + string(action) + " failed",
			Fields:  map[string]string{"action": string(action), "error": err.Error()},
		})
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"action": string(action),
	})
}
