package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
)

// Showing an operator a certificate so they can pin it.
//
// THE WARNING HAS ALWAYS PROMISED THIS. "pin a certificate (notifymatrix will
// show you its fingerprint)" has been printed at startup and shown in the
// interface since pinning existed, and nothing behind it was ever wired:
// unifi.FetchCertFingerprint was written, tested, documented as the thing a
// setup screen would call, and called by nothing. An operator following the
// advice had to go and find openssl.
//
// TRUST-ON-FIRST-USE IS AN OPERATOR ACTION, so this fetches and SHOWS. It
// never writes the pin: the value is returned for a human to look at and
// accept, and accepting it is an ordinary save of the console. A path that
// learned a pin on its own would have no protection on the one connection an
// attacker would target.
type fingerprintRequest struct {
	Host string `json:"host"`
}

func (s *Server) handleFetchFingerprint(w http.ResponseWriter, r *http.Request) {
	if s.deps.FetchFingerprint == nil {
		writeJSON(w, http.StatusNotFound, errorBody("this build cannot read a certificate"))
		return
	}
	var req fingerprintRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("could not read that request"))
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("give the console's address first"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	fp, err := s.deps.FetchFingerprint(ctx, host)
	if err != nil {
		// Shown rather than generic. Everything this can refuse is about the
		// address the operator just typed -- not local, nothing listening,
		// no TLS there -- and a generic failure would leave a button that
		// does nothing for a reason nobody can see.
		writeJSON(w, http.StatusBadGateway, errorBody(err.Error()))
		return
	}

	s.record(r, audit.Entry{
		Kind:    audit.KindService,
		Summary: "read a console certificate to offer its fingerprint",
		Fields:  map[string]string{"host": host, "fingerprint": fp},
	})
	writeJSON(w, http.StatusOK, map[string]any{"fingerprint": fp})
}
