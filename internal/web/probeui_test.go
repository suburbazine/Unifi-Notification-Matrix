package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
)

// Running a probe is an action against the console, and a report describes the
// site even after redaction. Both sit behind a session, like every other
// surface that names what the operator has.
func TestTheProbeSectionIsGated(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)

	for _, c := range []struct{ method, path string }{
		{"GET", "/api/probe"},
		{"POST", "/api/probe/run"},
		{"POST", "/api/probe/stop"},
		{"GET", "/api/probe/reports/probe-20260921T015822Z.jsonl"},
		{"GET", "/api/probe/reports/probe-20260921T015822Z.jsonl/download"},
	} {
		resp, _ := h.do(c.method, c.path, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("signed out %s %s = %d, want 401", c.method, c.path, resp.StatusCode)
		}
	}
}

func probeStatus(t *testing.T, h *harness) ProbeStatus {
	t.Helper()
	resp, body := h.do("GET", "/api/probe", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
	var out ProbeStatus
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	return out
}

// THE SENTENCE THIS FEATURE EXISTS FOR. A console with no key reaches the
// login page and nothing else, and the page has to say so before somebody
// spends the capture window finding out.
func TestAConsoleWithNoKeyBlocksTheRunAndSaysWhy(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.probeStatus = ProbeStatus{
		Available: true,
		Consoles:  []ProbeConsole{{Name: "home", Host: "192.168.1.1", HasKey: false}},
		Blocked:   "No console here has an API key.",
	}
	h.mu.Unlock()

	st := probeStatus(t, h)
	if st.Ready {
		t.Error("a console with no key was reported as ready to probe")
	}
	if st.Blocked == "" {
		t.Error("nothing said why it cannot run")
	}
}

// And the refusal survives somebody pressing the button anyway -- the status
// is a courtesy, the check is at the start.
func TestARefusedRunShowsTheReasonRatherThanAGenericError(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.probeStartErr = &probeRefusal{"home has no API key, so a probe would only reach its login page"}
	h.mu.Unlock()

	resp, body := h.do("POST", "/api/probe/run", map[string]any{"console": "home"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("run = %d %s, want 400", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "no API key") {
		t.Errorf("the reason did not reach the operator: %s", body)
	}
}

// A second run while one is listening is a conflict, not a failure, because
// somebody is standing in front of a door for the first one.
func TestASecondRunIsAConflict(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	h.mu.Lock()
	h.probeStartErr = ErrProbeBusy
	h.mu.Unlock()

	resp, body := h.do("POST", "/api/probe/run", map[string]any{"console": "home"})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("second run = %d %s, want 409", resp.StatusCode, body)
	}
}

// The window is bounded in both directions: too short captures nothing and
// looks like silence, too long holds sockets open inside a daemon whose job
// is to be watching something else.
func TestTheCaptureWindowIsBounded(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	for _, secs := range []int{1, ProbeMaxSeconds + 1, -5} {
		resp, body := h.do("POST", "/api/probe/run", map[string]any{"seconds": secs})
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("seconds=%d = %d %s, want 400", secs, resp.StatusCode, body)
		}
	}

	// Zero means "the default", not "no window".
	resp, body := h.do("POST", "/api/probe/run", map[string]any{"seconds": 0})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("seconds=0 = %d %s, want 202", resp.StatusCode, body)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.probeStarts) != 1 || !strings.Contains(h.probeStarts[0], "30s") {
		t.Errorf("started %q, want the default window", h.probeStarts)
	}
}

// A report name arrives in a URL from a list the page rendered, which is
// exactly the path by which somebody would ask for something else.
func TestAReportNameCannotLeaveTheReportDirectory(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	for _, name := range []string{
		"..%2Fconfig.yaml",
		"config.yaml",
		"probe-..%2F..%2Fsecret.key.jsonl",
		"probe-x.jsonl.yaml",
	} {
		// 400 specifically: refused by the handler BEFORE anything looks at
		// the disk. A 404 would pass this test for the wrong reason -- the
		// file simply not existing -- and would still be a handler that
		// builds paths out of whatever arrives.
		resp, body := h.do("GET", "/api/probe/reports/"+name, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q = %d %s, want 400 from the name check", name, resp.StatusCode, body)
		}
	}
}

// Reading and downloading are the same bytes. The download is the end of the
// road: it is a file the operator then attaches to an issue themselves, and
// nothing here uploads anything.
func TestAReportIsReadableAndDownloadableAsAFile(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	const name = "probe-20260921T015822Z.jsonl"
	body := []byte(`{"record":"meta","schema_version":1}` + "\n")
	h.mu.Lock()
	h.probeBodies = map[string][]byte{name: body}
	h.mu.Unlock()

	resp, got := h.do("GET", "/api/probe/reports/"+name, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read = %d %s", resp.StatusCode, got)
	}
	if string(got) != string(body) {
		t.Errorf("read returned %q, want the file", got)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("read content type = %q, want text/plain", ct)
	}

	resp, got = h.do("GET", "/api/probe/reports/"+name+"/download", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download = %d %s", resp.StatusCode, got)
	}
	if string(got) != string(body) {
		t.Errorf("download returned %q, want the file", got)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") ||
		!strings.Contains(cd, name) {
		t.Errorf("download disposition = %q, want an attachment named %s", cd, name)
	}
}

// A download is a copy of site detail leaving the machine, so it is written
// down. The audit log is how an operator finds out one happened.
func TestADownloadIsRecorded(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	const name = "probe-20260921T015822Z.jsonl"
	h.mu.Lock()
	h.probeBodies = map[string][]byte{name: []byte("{}\n")}
	h.mu.Unlock()

	if resp, body := h.do("GET", "/api/probe/reports/"+name+"/download", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("download = %d %s", resp.StatusCode, body)
	}

	h.log.mu.Lock()
	entries := append([]audit.Entry(nil), h.log.entries...)
	h.log.mu.Unlock()

	var found bool
	for _, e := range entries {
		if strings.Contains(e.Summary, "probe") && strings.Contains(e.Summary, "downloaded") {
			found = true
		}
	}
	if !found {
		t.Error("a report left the machine and nothing was written down")
	}
}

// probeRefusal is an ordinary error the start seam can return, standing in for
// everything main.go refuses before a run: no such console, no key, not local.
type probeRefusal struct{ msg string }

func (e *probeRefusal) Error() string { return e.msg }
