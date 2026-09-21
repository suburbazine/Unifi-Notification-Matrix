package web

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
)

// The capability probe, on the screen instead of in a terminal.
//
// TWO THINGS A PAGE CAN DO THAT A COMMAND CANNOT.
//
// It can refuse BEFORE the window. A console with no API key issued answers
// every request with its login page, and a run against one spends ninety
// seconds capturing nothing while the operator walks past cameras on purpose.
// The daemon already knows which consoles have keys; saying so before the
// button is pressed is the whole of the first half.
//
// And it can hold the instruction up while it is true. "Trigger the thing you
// want captured NOW" is a line somebody scrolls past in a terminal and a
// countdown on a page.
//
// What it must NOT do is make contributing easier than reading. The command
// prints the entire file before offering to contribute it, precisely so the
// bytes pass in front of a person first; a button that skipped that would be
// a downgrade wearing a nicer coat. So the page downloads a file and says
// plainly that submitting it is a separate, manual act.

// ErrProbeBusy is a run asked for while one is already listening.
var ErrProbeBusy = errors.New("a probe is already running")

// ProbeStatus is everything the Probe section shows.
type ProbeStatus struct {
	// Available is false where this build cannot run a probe at all. Distinct
	// from "not ready": one is a missing feature, the other a missing key.
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`

	Consoles []ProbeConsole `json:"consoles"`

	// Ready is whether pressing the button could produce anything. Blocked
	// says why not, in a sentence meant to be read by somebody who has not
	// been told what an integration key is.
	Ready   bool   `json:"ready"`
	Blocked string `json:"blocked,omitempty"`

	Running   bool      `json:"running"`
	Lines     []string  `json:"lines,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	EndedAt   time.Time `json:"ended_at,omitempty"`

	// Error is a run that could not happen. A console that refused every
	// request is NOT this: that run happened and found something out.
	Error string `json:"error,omitempty"`

	LastReport        string `json:"last_report,omitempty"`
	LastAuthenticated bool   `json:"last_authenticated,omitempty"`

	Reports []ProbeReportInfo `json:"reports"`
}

// ProbeConsole is one configured console and whether it can be probed.
type ProbeConsole struct {
	Name    string   `json:"name"`
	Host    string   `json:"host"`
	HasKey  bool     `json:"has_key"`
	Sources []string `json:"sources,omitempty"`
}

// ProbeReportInfo is one report on disk.
type ProbeReportInfo struct {
	Name string    `json:"name"`
	At   time.Time `json:"at"`
	Size int64     `json:"size"`

	// Authenticated decides whether this file is worth contributing, and it
	// is read back from the file rather than remembered from the run.
	Authenticated bool   `json:"authenticated"`
	Findings      int    `json:"findings"`
	Unreadable    string `json:"unreadable,omitempty"`
}

// ProbeRunRequest is what the page asks for.
type ProbeRunRequest struct {
	Console  string   `json:"console"`
	Seconds  int      `json:"seconds"`
	Products []string `json:"products,omitempty"`
}

// The capture window the page may ask for.
//
// Floored because a window shorter than the walk to the door captures nothing
// and looks like a firmware that sends nothing. Capped because this holds
// sockets open inside a daemon whose actual job is to be watching, and a page
// should not be able to ask it to stop doing that for an hour.
const (
	ProbeMinSeconds     = 10
	ProbeMaxSeconds     = 180
	ProbeDefaultSeconds = 30
)

// probeReportName is the only shape a report file has. Names arrive in a URL
// from a page that lists them, which is exactly the path by which somebody
// would try to read something else.
var probeReportName = regexp.MustCompile(`^probe-[0-9A-Za-z_\-]+\.jsonl$`)

func validProbeReportName(name string) bool {
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return false
	}
	return probeReportName.MatchString(name)
}

func (s *Server) handleProbeStatus(w http.ResponseWriter, r *http.Request) {
	if s.deps.ProbeStatus == nil {
		writeJSON(w, http.StatusOK, ProbeStatus{
			Detail:  "this build cannot run a probe",
			Reports: []ProbeReportInfo{},
		})
		return
	}
	st := s.deps.ProbeStatus()
	if st.Reports == nil {
		st.Reports = []ProbeReportInfo{}
	}
	if st.Consoles == nil {
		st.Consoles = []ProbeConsole{}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleProbeRun(w http.ResponseWriter, r *http.Request) {
	if s.deps.ProbeStart == nil {
		writeJSON(w, http.StatusNotFound, errorBody("this build cannot run a probe"))
		return
	}
	var req ProbeRunRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("could not read that request"))
		return
	}
	secs := req.Seconds
	if secs == 0 {
		secs = ProbeDefaultSeconds
	}
	if secs < ProbeMinSeconds || secs > ProbeMaxSeconds {
		writeJSON(w, http.StatusBadRequest, errorBody("the capture window must be between "+
			strconv.Itoa(ProbeMinSeconds)+" and "+strconv.Itoa(ProbeMaxSeconds)+" seconds"))
		return
	}

	err := s.deps.ProbeStart(req.Console, time.Duration(secs)*time.Second, req.Products)
	switch {
	case errors.Is(err, ErrProbeBusy):
		writeJSON(w, http.StatusConflict, errorBody("a probe is already running"))
		return
	case err != nil:
		// Shown rather than generic: everything this can refuse is something
		// the operator chose -- a console with no key, a host that is not
		// local -- and hiding it would leave the button doing nothing for a
		// reason nobody can see.
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}

	s.record(r, audit.Entry{
		Kind:    audit.KindService,
		Summary: "capability probe started from the web UI",
		Fields:  map[string]string{"console": req.Console, "seconds": strconv.Itoa(secs)},
	})
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Server) handleProbeStop(w http.ResponseWriter, r *http.Request) {
	if s.deps.ProbeStop == nil {
		writeJSON(w, http.StatusNotFound, errorBody("this build cannot run a probe"))
		return
	}
	s.deps.ProbeStop()
	s.record(r, audit.Entry{
		Kind:    audit.KindService,
		Summary: "capability probe stopped from the web UI",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleProbeReport serves a report for READING, in the page.
//
// text/plain, so a browser renders it as the bytes it is rather than trying to
// be helpful with it, and nosniff is already set on every response.
func (s *Server) handleProbeReport(w http.ResponseWriter, r *http.Request) {
	body, name, ok := s.probeReportBody(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Report-Name", name)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleProbeDownload serves the same bytes as a file to keep.
//
// The end of the road here, deliberately. Nothing uploads: the operator gets
// a file, reads it, and attaches it to an issue themselves if they decide to.
func (s *Server) handleProbeDownload(w http.ResponseWriter, r *http.Request) {
	body, name, ok := s.probeReportBody(w, r)
	if !ok {
		return
	}
	s.record(r, audit.Entry{
		Kind:    audit.KindService,
		Summary: "capability probe report downloaded from the web UI",
		Fields:  map[string]string{"report": name},
	})
	w.Header().Set("Content-Type", "application/jsonl")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) probeReportBody(w http.ResponseWriter, r *http.Request) (body []byte, name string, ok bool) {
	if s.deps.ProbeRead == nil {
		writeJSON(w, http.StatusNotFound, errorBody("this build cannot run a probe"))
		return nil, "", false
	}
	name = r.PathValue("name")
	if !validProbeReportName(name) {
		writeJSON(w, http.StatusBadRequest, errorBody("that is not a report name"))
		return nil, "", false
	}
	body, err := s.deps.ProbeRead(name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorBody("no such report"))
		return nil, "", false
	}
	return body, name, true
}
