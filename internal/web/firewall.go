package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/firewall"
)

// firewallTimeout bounds one PowerShell run. The first use on a machine
// loads the NetSecurity module, which takes a few seconds.
const firewallTimeout = 60 * time.Second

// handleFirewall reports the Windows Firewall rules for the listeners meant
// to be reached from elsewhere, against the SAVED addresses, with the exact
// command that fixes them. See internal/firewall.
//
// Behind a session, like the settings it sits beside: which ports are open to
// whom is not for the wall display.
func (s *Server) handleFirewall(w http.ResponseWriter, r *http.Request) {
	if s.deps.Firewall == nil {
		writeJSON(w, http.StatusOK, firewall.Report{})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), firewallTimeout)
	defer cancel()
	rep, err := s.deps.Firewall(ctx, false)
	if err != nil {
		// The command is still worth having when the firewall could not be
		// read: it is what the operator runs either way.
		writeJSON(w, http.StatusOK, map[string]any{"supported": rep.Supported,
			"command": rep.Command, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleFirewallApply creates or corrects the rules. It opens ports, so it
// is recorded whether it worked or not, with the ports it was asked for.
func (s *Server) handleFirewallApply(w http.ResponseWriter, r *http.Request) {
	if s.deps.Firewall == nil {
		writeJSON(w, http.StatusNotImplemented, errorBody("this build cannot change the firewall"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), firewallTimeout)
	defer cancel()
	rep, err := s.deps.Firewall(ctx, true)
	if err != nil {
		s.record(r, audit.Entry{Kind: audit.KindConfigChanged, Actor: "web",
			Summary: "Windows Firewall rules NOT changed: " + err.Error()})
		status := http.StatusBadGateway
		if errors.Is(err, firewall.ErrNeedsAdmin) {
			status = http.StatusForbidden
		}
		writeJSON(w, status, errorBody(err.Error()))
		return
	}
	var allowed []string
	for _, rule := range rep.Rules {
		if rule.Status == "allowed" {
			allowed = append(allowed, rule.Purpose+" on TCP "+strconv.Itoa(rule.Port))
		}
	}
	summary := "Windows Firewall rules set: nothing allowed in"
	if len(allowed) > 0 {
		summary = "Windows Firewall rules set: allowed in " + strings.Join(allowed, ", ")
	}
	s.record(r, audit.Entry{Kind: audit.KindConfigChanged, Actor: "web", Summary: summary})
	writeJSON(w, http.StatusOK, rep)
}
