package web

import (
	"net/http"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
)

// UpdateState is what the interface shows about upgrading.
type UpdateState struct {
	// Current is the version running now.
	Current string `json:"current"`

	// Available is the newer version, empty when there is none. Checked is
	// when the last check ran, and Error is why the last one failed --
	// reported, because a check that quietly failed looks exactly like being
	// up to date, which is how a machine sits on a known-bad build.
	Available   string    `json:"available,omitempty"`
	ReleaseURL  string    `json:"release_url,omitempty"`
	PublishedAt time.Time `json:"published_at,omitempty"`
	Checked     time.Time `json:"checked,omitempty"`
	Error       string    `json:"error,omitempty"`

	// CanApply says whether this installation can replace itself. False on a
	// platform that cannot check who signed the replacement, and false when
	// the binary is somewhere this process cannot write.
	CanApply bool   `json:"can_apply"`
	Why      string `json:"why,omitempty"`
}

// handleUpdateState reports what is known without going to the network.
func (s *Server) handleUpdateState(w http.ResponseWriter, r *http.Request) {
	if s.deps.UpdateState == nil {
		writeJSON(w, http.StatusNotImplemented,
			errorBody("this build cannot check for updates"))
		return
	}
	writeJSON(w, http.StatusOK, s.deps.UpdateState())
}

// handleUpdateCheck asks the release feed.
//
// A POST, not a GET: it reaches out to the internet from a machine whose
// outbound connections an operator may well be watching, and that is an action
// rather than a read.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if s.deps.CheckUpdate == nil {
		writeJSON(w, http.StatusNotImplemented,
			errorBody("this build cannot check for updates"))
		return
	}
	st, err := s.deps.CheckUpdate(r.Context())
	if err != nil {
		s.record(r, audit.Entry{
			Kind: audit.KindService, Actor: "web",
			Summary: "update check failed",
			Fields:  map[string]string{"error": err.Error()},
		})
		writeJSON(w, http.StatusBadGateway, errorBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// handleUpdateApply downloads, verifies and installs.
//
// Every refusal from the verifier is returned verbatim. They are the most
// important sentences this endpoint can produce -- "signed by a different
// publisher" is not a transient error to retry past, it is the thing the whole
// mechanism exists to catch -- and summarising them into "update failed" would
// throw away the only signal that matters.
func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if s.deps.ApplyUpdate == nil {
		writeJSON(w, http.StatusNotImplemented,
			errorBody("this build cannot install updates"))
		return
	}

	var body struct {
		Version string `json:"version"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("that request could not be read"))
		return
	}

	// Recorded before, for the same reason the service actions are: a
	// successful update restarts this process, so anything written afterwards
	// is never written.
	s.record(r, audit.Entry{
		Kind: audit.KindService, Actor: "web",
		Summary: "update to " + body.Version + " requested from the web UI",
		Fields:  map[string]string{"version": body.Version},
	})

	if err := s.deps.ApplyUpdate(r.Context(), body.Version); err != nil {
		s.record(r, audit.Entry{
			Kind: audit.KindService, Actor: "web",
			Summary: "update to " + body.Version + " was refused or failed",
			Fields:  map[string]string{"version": body.Version, "error": err.Error()},
		})
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": body.Version})
}
