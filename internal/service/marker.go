package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MarkerFileName records that a run is in progress. Present at start means the
// previous run did not exit cleanly.
const MarkerFileName = "running.json"

// RunMarker detects that the previous run ended badly.
//
// Without this a crash loop is INVISIBLE. The service manager restarts the
// process, the web UI looks healthy, the incident store is intact, and the
// only evidence is a gap in the event history that nobody reads. The §9
// deadman catches a SOURCE going quiet; this catches the product itself going
// quiet, which is the failure an operator has no other way to see.
//
// Written at start, removed on a clean stop. Finding one at start therefore
// means the last process died without running its shutdown path: a panic, a
// SIGKILL, a power cut, or the Windows SCM terminating a service that did not
// stop in time.
type RunMarker struct {
	path string
}

// PreviousRun is what was found on disk from the last start.
type PreviousRun struct {
	PID       int       `json:"pid"`
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`

	// Heartbeat is refreshed while running, so the incident can say roughly
	// WHEN it died rather than only that it did. A crash three seconds after
	// start is a configuration problem; one after six days is something else,
	// and an operator should not have to guess which they have.
	Heartbeat time.Time `json:"heartbeat"`
}

// Unclean reports how long the previous run lasted before dying. Zero when the
// timestamps are unusable.
func (p PreviousRun) Ran() time.Duration {
	if p.StartedAt.IsZero() || p.Heartbeat.Before(p.StartedAt) {
		return 0
	}
	return p.Heartbeat.Sub(p.StartedAt)
}

// Begin claims the marker for this run.
//
// The returned PreviousRun is non-nil exactly when the previous run ended
// uncleanly, and is what the caller turns into an incident.
func Begin(dir, version string, now time.Time) (*RunMarker, *PreviousRun, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("service: creating data directory: %w", err)
	}
	path := filepath.Join(dir, MarkerFileName)

	var prev *PreviousRun
	if b, err := os.ReadFile(path); err == nil {
		var p PreviousRun
		if json.Unmarshal(b, &p) == nil && p.PID != 0 {
			prev = &p
		} else {
			// Unparseable, but PRESENT -- which is the fact that matters. A
			// truncated marker is itself evidence of an abrupt death (the
			// write was interrupted), so report the crash with what little is
			// known rather than discarding the signal because the detail is
			// missing.
			prev = &PreviousRun{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("service: reading %s: %w", path, err)
	}

	m := &RunMarker{path: path}
	if err := m.write(PreviousRun{
		PID:       os.Getpid(),
		Version:   version,
		StartedAt: now,
		Heartbeat: now,
	}); err != nil {
		return nil, nil, err
	}
	return m, prev, nil
}

func (m *RunMarker) write(p PreviousRun) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	// Written in place rather than through a temp-file rename. A torn write
	// here is not a problem to be prevented -- it is the same signal as a
	// present marker, and Begin already treats an unparseable one as a crash.
	if err := os.WriteFile(m.path, b, 0o600); err != nil {
		return fmt.Errorf("service: writing %s: %w", m.path, err)
	}
	return nil
}

// Heartbeat refreshes the marker so a later crash report can say how long the
// process had been up.
func (m *RunMarker) Heartbeat(version string, startedAt, now time.Time) error {
	if m == nil {
		return nil
	}
	return m.write(PreviousRun{
		PID:       os.Getpid(),
		Version:   version,
		StartedAt: startedAt,
		Heartbeat: now,
	})
}

// Finish removes the marker, declaring this run to have ended cleanly.
//
// Call it ONLY on a genuinely orderly shutdown. Calling it from a deferred
// cleanup that also runs on a panic would turn every crash into a clean exit
// and silently delete the signal this type exists to provide.
func (m *RunMarker) Finish() error {
	if m == nil {
		return nil
	}
	err := os.Remove(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Path is the marker file, for diagnostics.
func (m *RunMarker) Path() string {
	if m == nil {
		return ""
	}
	return m.path
}

// CrashDetail renders a previous unclean run for an incident body.
func CrashDetail(p *PreviousRun) string {
	if p == nil {
		return ""
	}
	if p.PID == 0 {
		return "The previous run did not shut down cleanly. Its record was " +
			"incomplete, which usually means the process died mid-write."
	}
	s := fmt.Sprintf("The previous run (pid %d", p.PID)
	if p.Version != "" {
		s += ", version " + p.Version
	}
	s += ") did not shut down cleanly."
	if d := p.Ran(); d > 0 {
		s += fmt.Sprintf(" It had been running for %s.", d.Round(time.Second))
	}
	if !p.Heartbeat.IsZero() {
		s += fmt.Sprintf(" Last seen alive at %s.", p.Heartbeat.UTC().Format(time.RFC3339))
	}
	s += "\n\nAlarms raised while it was down were not delivered. " +
		"Check the console's own event history for the gap."
	return s
}
