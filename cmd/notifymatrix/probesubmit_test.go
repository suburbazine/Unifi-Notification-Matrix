package main

import (
	"path/filepath"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/probe"
)

// save writes a report the way a run would, so the test exercises the file
// rather than the struct. submit only ever sees a file.
func save(t *testing.T, r *probe.Report) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "probe-20260921T015822Z.jsonl")
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

// The report an operator with no API key gets: every request refused, no
// versions, and -- before this -- an invitation to contribute it.
func TestSubmitRefusesAReportNothingAuthenticated(t *testing.T) {
	_, path := save(t, &probe.Report{
		Meta: probe.Meta{
			Record: "meta", SchemaVersion: probe.SchemaVersion,
			Versions: map[string]string{},
		},
		Endpoints: []probe.EndpointResult{{
			Record: "endpoint", Product: "protect", Method: "GET",
			Path: "/proxy/protect/integration/v1/cameras", Known: true,
			Status: 401, ContentType: "application/json",
		}},
	})

	if code := probeSubmit(filepath.Dir(path), path); code != 1 {
		t.Errorf("submit accepted a report from a run that was refused: exit %d", code)
	}
}

// The control. Without it the guard above could reject everything and the
// suite would still be green.
func TestSubmitAcceptsAReportThatGotIn(t *testing.T) {
	_, path := save(t, &probe.Report{
		Meta: probe.Meta{
			Record: "meta", SchemaVersion: probe.SchemaVersion,
			Versions: map[string]string{"protect": "7.3.53"},
		},
		Endpoints: []probe.EndpointResult{{
			Record: "endpoint", Product: "protect", Method: "GET",
			Path: "/proxy/protect/integration/v1/cameras", Known: true,
			Status: 200, ContentType: "application/json",
		}},
	})

	if code := probeSubmit(filepath.Dir(path), path); code != 0 {
		t.Errorf("submit refused a report with a real survey in it: exit %d", code)
	}
}
