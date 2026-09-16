package ingest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

var t0 = time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

// fakeSource is a source whose behaviour a test dictates.
type fakeSource struct {
	name     string
	liveness time.Duration

	mu    sync.Mutex
	runs  int
	emit  []event.Event
	err   error
	block bool
}

func (f *fakeSource) Name() string            { return f.name }
func (f *fakeSource) Liveness() time.Duration { return f.liveness }

func (f *fakeSource) Run(ctx context.Context, out event.Sink) error {
	f.mu.Lock()
	f.runs++
	evs, err, block := f.emit, f.err, f.block
	f.mu.Unlock()

	for _, e := range evs {
		out.Emit(e)
	}
	if block {
		<-ctx.Done()
		return nil
	}
	return err
}

func (f *fakeSource) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs
}

type raised struct {
	entity    string
	condition string
}

type recorder struct {
	mu       sync.Mutex
	events   []event.Event
	raises   []raised
	resolves []raised
	logs     []string
}

func (r *recorder) deps(now func() time.Time) Deps {
	return Deps{
		Handle: func(_ context.Context, ev event.Event) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.events = append(r.events, ev)
			return nil
		},
		Raise: func(_ context.Context, ent event.Entity, condition string,
			_ incident.Severity, _, _ string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.raises = append(r.raises, raised{ent.ID, condition})
			return nil
		},
		Resolve: func(_ context.Context, ent event.Entity, condition string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.resolves = append(r.resolves, raised{ent.ID, condition})
			return nil
		},
		Logf: func(format string, args ...any) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.logs = append(r.logs, format)
		},
		Now: now,
	}
}

func (r *recorder) counts() (events, raises, resolves int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events), len(r.raises), len(r.resolves)
}

// THE POINT OF THE PACKAGE. A source that is constructed and never run is a
// product that looks entirely healthy while being blind -- which is exactly
// what this daemon did before this package existed.
func TestEventsFromASourceReachTheHandler(t *testing.T) {
	src := &fakeSource{name: "protect", emit: []event.Event{
		{Source: "protect", Condition: "offline"},
		{Source: "protect", Condition: "smoke"},
	}}
	r := &recorder{}
	s, err := New([]event.Source{src}, r.deps(func() time.Time { return t0 }))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()

	waitFor(t, func() bool { n, _, _ := r.counts(); return n == 2 })
	cancel()
	<-done
}

// A source returns non-nil only for something reconnecting cannot fix. Looping
// on it would spin against a configuration that cannot work, so it stops --
// and because a stopped source is invisible, it raises an incident first.
func TestASourceThatCannotRunStopsAndIsReported(t *testing.T) {
	src := &fakeSource{name: "access", err: errors.New("no API key configured")}
	r := &recorder{}
	s, _ := New([]event.Source{src}, r.deps(func() time.Time { return t0 }))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()

	waitFor(t, func() bool { _, n, _ := r.counts(); return n == 1 })

	r.mu.Lock()
	got := r.raises[0]
	r.mu.Unlock()
	if got.condition != event.ConditionSourceSilent {
		t.Errorf("raised %q, want the deadman condition", got.condition)
	}
	if got.entity != "source/access" {
		t.Errorf("entity = %q, want one per source -- a shared entity would "+
			"collapse two dead sources into one incident", got.entity)
	}

	// And it is not restarted in a loop.
	time.Sleep(50 * time.Millisecond)
	if n := src.runCount(); n != 1 {
		t.Errorf("ran %d times against a configuration that cannot work", n)
	}
	cancel()
	<-done
}

// One misconfigured source must not remove coverage that works. A site whose
// Access key is wrong still wants its cameras watched.
func TestOneBrokenSourceDoesNotStopTheOthers(t *testing.T) {
	bad := &fakeSource{name: "access", err: errors.New("bad key")}
	good := &fakeSource{name: "protect", block: true, emit: []event.Event{
		{Source: "protect", Condition: "offline"},
	}}
	r := &recorder{}
	s, _ := New([]event.Source{bad, good}, r.deps(func() time.Time { return t0 }))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()

	waitFor(t, func() bool {
		ev, ra, _ := r.counts()
		return ev == 1 && ra == 1
	})
	cancel()
	<-done
}

// THE DEADMAN. A source that dies quietly is indistinguishable from a quiet
// site, and on an alarm product those are opposite situations.
func TestSilenceBeyondTheDeclaredWindowIsRaisedAndThenResolved(t *testing.T) {
	now := t0
	src := &fakeSource{name: "protect", liveness: 30 * time.Minute, block: true}
	r := &recorder{}
	s, _ := New([]event.Source{src}, r.deps(func() time.Time { return now }))

	// Inside the window: nothing.
	now = t0.Add(20 * time.Minute)
	s.checkLiveness(context.Background())
	if _, n, _ := r.counts(); n != 0 {
		t.Fatalf("raised %d incident(s) while the source was within its window", n)
	}

	// Past it: raised.
	now = t0.Add(31 * time.Minute)
	s.checkLiveness(context.Background())
	if _, n, _ := r.counts(); n != 1 {
		t.Fatalf("raises = %d, want 1", n)
	}

	// Still silent: raised ONCE, not once per check.
	now = t0.Add(45 * time.Minute)
	s.checkLiveness(context.Background())
	if _, n, _ := r.counts(); n != 1 {
		t.Errorf("raises = %d; the deadman re-raised on every check", n)
	}

	// It speaks again, and the incident is resolved -- a deadman that can
	// raise but never resolve teaches the operator to ignore the one message
	// that means the product itself is broken.
	s.note("protect")
	s.checkLiveness(context.Background())
	if _, _, n := r.counts(); n != 1 {
		t.Errorf("resolves = %d, want 1 after the source recovered", n)
	}
}

// A zero window is an explicit statement by that source that silence means
// nothing for it.
func TestASourceWithNoLivenessWindowIsNeverDeadmanned(t *testing.T) {
	now := t0
	src := &fakeSource{name: "quiet", liveness: 0, block: true}
	r := &recorder{}
	s, _ := New([]event.Source{src}, r.deps(func() time.Time { return now }))

	now = t0.Add(72 * time.Hour)
	s.checkLiveness(context.Background())
	if _, n, _ := r.counts(); n != 0 {
		t.Errorf("raised %d incident(s) for a source that declared no window", n)
	}
}

// A source already reported as unable to run must not also be reported as
// quiet: two incidents for one fault split the operator's attention.
func TestAFailedSourceIsNotAlsoDeadmanned(t *testing.T) {
	now := t0
	src := &fakeSource{name: "access", liveness: time.Minute, err: errors.New("bad key")}
	r := &recorder{}
	s, _ := New([]event.Source{src}, r.deps(func() time.Time { return now }))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	waitFor(t, func() bool { _, n, _ := r.counts(); return n == 1 })

	now = t0.Add(time.Hour)
	s.checkLiveness(context.Background())
	if _, n, _ := r.counts(); n != 1 {
		t.Errorf("raises = %d, want 1: the same fault was reported twice", n)
	}
	cancel()
	<-done
}

// A source is given its full window from launch. Starting the clock at zero
// would raise a fault for every source on every start.
func TestASourceIsGivenItsWindowFromStartup(t *testing.T) {
	now := t0
	src := &fakeSource{name: "protect", liveness: 30 * time.Minute, block: true}
	r := &recorder{}
	s, _ := New([]event.Source{src}, r.deps(func() time.Time { return now }))

	s.checkLiveness(context.Background())
	if _, n, _ := r.counts(); n != 0 {
		t.Errorf("a source that had just started was reported as silent")
	}
}

func TestStatusesReportWhatTheInterfaceNeeds(t *testing.T) {
	src := &fakeSource{name: "protect", liveness: 30 * time.Minute, block: true,
		emit: []event.Event{{Source: "protect", Condition: "offline"}}}
	r := &recorder{}
	s, _ := New([]event.Source{src}, r.deps(func() time.Time { return t0 }))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	waitFor(t, func() bool { n, _, _ := r.counts(); return n == 1 })

	got := s.Statuses()
	if len(got) != 1 {
		t.Fatalf("statuses = %+v, want one", got)
	}
	if got[0].Events != 1 {
		t.Errorf("events = %d, want 1", got[0].Events)
	}
	if got[0].Expected != 30*time.Minute {
		t.Errorf("expected window = %v, want the source's own declaration -- "+
			"without it the page cannot say whether quiet is bad", got[0].Expected)
	}
	cancel()
	<-done
}

// A daemon with no sources will never raise anything from a console, which is
// the single most important thing an operator could be told about it.
func TestNoSourcesIsSaidOutLoud(t *testing.T) {
	r := &recorder{}
	s, _ := New(nil, r.deps(func() time.Time { return t0 }))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()

	waitFor(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.logs) > 0
	})
	cancel()
	<-done
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition never became true")
}

// A source that cannot run must not be restarted in a loop against a
// configuration that cannot work.
//
// Asserted with a tiny restart delay rather than by waiting out the real one:
// the first version of this test slept fifty milliseconds against a
// thirty-second delay, so it passed whether or not the source stopped. That is
// a test certifying a property it never checked, and mutation testing is the
// only thing that finds it.
func TestASourceThatCannotRunIsNotRestarted(t *testing.T) {
	src := &fakeSource{name: "access", err: errors.New("bad key")}
	r := &recorder{}
	deps := r.deps(func() time.Time { return t0 })
	deps.RestartDelay = time.Millisecond
	s, _ := New([]event.Source{src}, deps)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	waitFor(t, func() bool { _, n, _ := r.counts(); return n == 1 })

	// Long enough for hundreds of restarts at this delay.
	time.Sleep(100 * time.Millisecond)
	if n := src.runCount(); n != 1 {
		t.Errorf("ran %d times against a configuration that cannot work", n)
	}
	cancel()
	<-done
}

// A source that returns nil without cancellation IS restarted: sources
// reconnect internally, so returning at all is unexpected, and leaving it
// stopped would be a source that silently never comes back.
func TestASourceThatStopsOnItsOwnIsRestarted(t *testing.T) {
	src := &fakeSource{name: "protect"} // returns nil immediately
	r := &recorder{}
	deps := r.deps(func() time.Time { return t0 })
	deps.RestartDelay = time.Millisecond
	s, _ := New([]event.Source{src}, deps)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()

	waitFor(t, func() bool { return src.runCount() > 3 })
	cancel()
	<-done

	if got := s.Statuses(); len(got) == 0 || got[0].Restarts == 0 {
		t.Errorf("restarts were not counted, so a source that keeps dying looks "+
			"healthy in the interface: %+v", got)
	}
}
