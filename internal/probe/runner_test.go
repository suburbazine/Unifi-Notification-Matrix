package probe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestRunner returns a runner whose "console" is a function, so a test can
// finish a run without a capture window.
func newTestRunner(t *testing.T, run func(context.Context, Options) (*Report, error)) *Runner {
	t.Helper()
	r := NewRunner(t.TempDir())
	r.run = run
	return r
}

func waitDone(t *testing.T, r *Runner) Progress {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p := r.Snapshot(); !p.Running {
			return p
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the run never finished")
	return Progress{}
}

func authenticatedReport() *Report {
	return &Report{
		Meta: Meta{Record: "meta", SchemaVersion: SchemaVersion, Versions: map[string]string{"protect": "7.3.53"}},
		Endpoints: []EndpointResult{{
			Record: "endpoint", Product: "protect", Path: "/a", Known: true,
			Status: 200, ContentType: "application/json",
		}},
	}
}

func refusedReport() *Report {
	return &Report{
		Meta: Meta{Record: "meta", SchemaVersion: SchemaVersion, Versions: map[string]string{}},
		Endpoints: []EndpointResult{{
			Record: "endpoint", Product: "protect", Path: "/a", Known: true,
			Status: 401, ContentType: "application/json",
		}},
	}
}

// The window is the point. A second run started while somebody is standing in
// front of a door would capture an empty one, so it is refused rather than
// queued.
func TestASecondRunIsRefusedWhileOneIsListening(t *testing.T) {
	release := make(chan struct{})
	r := newTestRunner(t, func(ctx context.Context, o Options) (*Report, error) {
		<-release
		return authenticatedReport(), nil
	})

	if err := r.Start(Options{Host: "192.168.1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(Options{Host: "192.168.1.1"}); !errors.Is(err, ErrBusy) {
		t.Errorf("second Start = %v, want ErrBusy", err)
	}
	close(release)
	waitDone(t, r)

	// And the next one is allowed, or a single run would wedge the feature
	// for the life of the process.
	if err := r.Start(Options{Host: "192.168.1.1"}); err != nil {
		t.Errorf("Start after a finished run = %v, want nil", err)
	}
	waitDone(t, r)
}

// What the page needs off the back of a run: the file, and whether anything
// in it got past the front door.
func TestAFinishedRunReportsItsFileAndWhetherItGotIn(t *testing.T) {
	r := newTestRunner(t, func(ctx context.Context, o Options) (*Report, error) {
		o.Progress("GET /proxy/protect/integration/v1/cameras")
		return authenticatedReport(), nil
	})
	if err := r.Start(Options{Host: "192.168.1.1"}); err != nil {
		t.Fatal(err)
	}
	p := waitDone(t, r)

	if p.Report == "" {
		t.Fatal("a finished run named no report file")
	}
	if !p.Authenticated {
		t.Error("a run that reached the console was reported as unauthenticated")
	}
	if p.Error != "" {
		t.Errorf("unexpected error: %s", p.Error)
	}
	if len(p.Lines) != 1 || p.Lines[0] != "GET /proxy/protect/integration/v1/cameras" {
		t.Errorf("progress lines = %q, want the one the run emitted", p.Lines)
	}
	if _, err := os.Stat(filepath.Join(r.dir, p.Report)); err != nil {
		t.Errorf("the named report is not on disk: %v", err)
	}
}

// A console that refused everything is a RESULT, not a failure: the file is
// still written, because what it records is what the console refused.
func TestARefusedRunStillWritesTheFileAndSaysItGotNowhere(t *testing.T) {
	r := newTestRunner(t, func(ctx context.Context, o Options) (*Report, error) {
		return refusedReport(), nil
	})
	if err := r.Start(Options{Host: "192.168.1.1"}); err != nil {
		t.Fatal(err)
	}
	p := waitDone(t, r)

	if p.Report == "" {
		t.Error("the file a refused run produced was not kept")
	}
	if p.Authenticated {
		t.Error("a run that was refused everywhere claimed to be authenticated")
	}
	if p.Error != "" {
		t.Errorf("being refused was reported as a failed run: %s", p.Error)
	}
}

// A run that could not happen at all is the other thing, and must not be
// confused with the above.
func TestARunThatCouldNotHappenReportsTheError(t *testing.T) {
	r := newTestRunner(t, func(ctx context.Context, o Options) (*Report, error) {
		return nil, errors.New("host is not on a local network")
	})
	if err := r.Start(Options{Host: "8.8.8.8"}); err != nil {
		t.Fatal(err)
	}
	p := waitDone(t, r)

	if p.Error == "" {
		t.Error("a run that never happened reported no error")
	}
	if p.Report != "" {
		t.Errorf("a failed run named a report file: %q", p.Report)
	}
}

// A daemon expected to sit still for months does not accumulate a run's
// chatter without limit.
func TestProgressIsBounded(t *testing.T) {
	r := newTestRunner(t, func(ctx context.Context, o Options) (*Report, error) {
		for i := 0; i < maxProgressLines*3; i++ {
			o.Progress("line")
		}
		return authenticatedReport(), nil
	})
	if err := r.Start(Options{Host: "192.168.1.1"}); err != nil {
		t.Fatal(err)
	}
	p := waitDone(t, r)
	if len(p.Lines) > maxProgressLines {
		t.Errorf("kept %d progress lines, want at most %d", len(p.Lines), maxProgressLines)
	}
}

// The list is what somebody picks from when deciding what to contribute, so
// it carries the same verdict the file does, read from the file.
func TestListReportsIsNewestFirstAndSaysWhichGotIn(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, r *Report) {
		t.Helper()
		if err := r.Save(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	write("probe-20260101T000000Z.jsonl", refusedReport())
	write("probe-20260102T000000Z.jsonl", authenticatedReport())

	list, err := ListReports(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("listed %d reports, want 2", len(list))
	}
	if list[0].Name != "probe-20260102T000000Z.jsonl" {
		t.Errorf("first listed is %q, want the newest", list[0].Name)
	}
	if !list[0].Authenticated || list[1].Authenticated {
		t.Errorf("verdicts are wrong: %+v", list)
	}
	if list[0].Size == 0 {
		t.Error("no size was reported")
	}
}
