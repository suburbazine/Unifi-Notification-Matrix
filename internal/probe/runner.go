package probe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// A probe run from the interface rather than from a terminal.
//
// WHY THE DAEMON RUNS IT. The capture window is the whole difficulty: several
// event classes do not exist unless somebody walks past a camera or opens a
// door, so the operator has to be standing somewhere else while it listens.
// A terminal gives them a prompt they have already scrolled past; a page can
// hold the instruction on screen for the ninety seconds it is true.
//
// The other half is the precondition. A console with no API key issued serves
// its login page to every request, and a run against one produces a file that
// describes this build's catalogue and nothing about the site -- which is
// exactly what happened to the author. The daemon knows which consoles have
// keys BEFORE anything runs, and can refuse instead of wasting the window.

// ErrBusy is a second run asked for while one is still listening.
//
// Refused rather than queued: the point of a run is that somebody is standing
// in front of a door while it happens, and a run that starts when they have
// walked away captures an empty window.
var ErrBusy = errors.New("a probe is already running")

// maxProgressLines bounds what a run accumulates for the page. A run walks
// about thirty paths and three sockets, so this is far above any real run and
// exists only so a pathological one cannot grow without limit in a daemon that
// is otherwise expected to sit still for months.
const maxProgressLines = 400

// Progress is one run, as the interface sees it.
type Progress struct {
	Running   bool      `json:"running"`
	Lines     []string  `json:"lines"`
	StartedAt time.Time `json:"started_at,omitempty"`
	EndedAt   time.Time `json:"ended_at,omitempty"`

	// Error is a run that could not happen at all -- a refused host, a dial
	// failure. NOT a console that refused every request: that is a finished
	// run with a result, and the result is that nothing was authenticated.
	Error string `json:"error,omitempty"`

	// Report is the file the run wrote, empty until it has written one.
	Report string `json:"report,omitempty"`

	// Authenticated carries the one fact that decides whether the file is
	// worth anything, so the page can say so without reading it back.
	Authenticated bool `json:"authenticated,omitempty"`
}

// Runner holds the single run this daemon will do at a time.
type Runner struct {
	dir string

	mu       sync.Mutex
	progress Progress
	cancel   context.CancelFunc

	// Seams. Tests drive a run without a console, and without waiting out a
	// capture window.
	run func(context.Context, Options) (*Report, error)
	now func() time.Time
}

// NewRunner returns a Runner writing reports into dir.
func NewRunner(dir string) *Runner {
	return &Runner{dir: dir, run: Run, now: time.Now}
}

// Start begins a run and returns immediately.
//
// The error is only ever "already running" -- everything else is a result,
// reported through Snapshot, because a probe that cannot reach a console has
// found something out and the operator should see it on the page rather than
// as a failed button.
func (r *Runner) Start(opts Options) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.progress.Running {
		return ErrBusy
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.progress = Progress{Running: true, StartedAt: r.now(), Lines: []string{}}
	opts.Progress = r.append

	go func() {
		defer cancel()
		rep, err := r.run(ctx, opts)

		r.mu.Lock()
		defer r.mu.Unlock()
		r.progress.Running = false
		r.progress.EndedAt = r.now()
		if err != nil {
			r.progress.Error = err.Error()
			return
		}
		r.progress.Authenticated = rep.Authenticated()

		// Written even when nothing authenticated. The file records what the
		// console refused, which is worth having in front of somebody; what
		// it is not is a contribution, and every surface that offers one
		// checks before offering.
		path := DefaultPath(r.dir)
		if err := rep.Save(path); err != nil {
			r.progress.Error = err.Error()
			return
		}
		r.progress.Report = filepath.Base(path)
	}()
	return nil
}

// Stop cancels a run in progress. Safe to call when nothing is running.
func (r *Runner) Stop() {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Snapshot is the run as it stands, safe to hand to a response.
func (r *Runner) Snapshot() Progress {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.progress
	p.Lines = append([]string(nil), r.progress.Lines...)
	return p
}

func (r *Runner) append(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.progress.Lines) >= maxProgressLines {
		return
	}
	r.progress.Lines = append(r.progress.Lines, line)
}

// ReportInfo is one report on disk, as the list on the page shows it.
type ReportInfo struct {
	Name string    `json:"name"`
	At   time.Time `json:"at"`
	Size int64     `json:"size"`

	// Authenticated is read back from the file rather than remembered from
	// the run, because the list outlives the process that wrote it.
	Authenticated bool `json:"authenticated"`
	Findings      int  `json:"findings"`

	// Unreadable is a file that could not be parsed. Listed rather than
	// hidden: a report that will not load is something to tell somebody
	// about, not something to quietly omit from a list they are using to
	// decide what to contribute.
	Unreadable string `json:"unreadable,omitempty"`
}

// ListReports returns the reports in dir, newest first, at most limit of them.
func ListReports(dir string, limit int) ([]ReportInfo, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "probe-*.jsonl"))
	if err != nil {
		return nil, err
	}
	// Timestamped names sort chronologically, which is the whole reason they
	// are timestamped. Reversed: the newest is the one somebody just made.
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	if limit > 0 && len(matches) > limit {
		matches = matches[:limit]
	}

	out := make([]ReportInfo, 0, len(matches))
	for _, m := range matches {
		info := ReportInfo{Name: filepath.Base(m)}
		if st, err := os.Stat(m); err == nil {
			info.At = st.ModTime().UTC()
			info.Size = st.Size()
		}
		f, err := os.Open(m)
		if err != nil {
			info.Unreadable = "could not be opened"
			out = append(out, info)
			continue
		}
		sum, err := ScanFile(f)
		f.Close()
		if err != nil {
			info.Unreadable = "could not be read to the end"
		}
		info.Authenticated = sum.Authenticated
		info.Findings = sum.Findings
		out = append(out, info)
	}
	return out, nil
}
