package ingest

import (
	"context"
	"errors"
	"fmt"
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

// contactableSource reports contact independently of emitting events, the way
// a real socket-backed source does.
type contactableSource struct {
	fakeSource
	mu      sync.Mutex
	contact time.Time
}

func (c *contactableSource) LastContact() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.contact
}

func (c *contactableSource) sawFrame(at time.Time) {
	c.mu.Lock()
	c.contact = at
	c.mu.Unlock()
}

// A QUIET SITE IS NOT A DEAD SOURCE.
//
// The deadman measured EMITTED EVENTS, so a Protect source holding two healthy
// websockets over a still evening -- no motion, no detections, nothing
// changing state -- looked exactly like one whose socket had died. After
// thirty minutes it was reported as silent at HIGH, and repeated every half
// hour until somebody closed it by hand. Observed on a real installation, all
// day, while Protect was working perfectly.
//
// Protect's own health had carried the distinction all along: LastMessageAt is
// any frame at all, LastEmitAt is what reached the sink, and "the gap between
// them is what tells a mute socket from a quiet site". The deadman was reading
// the wrong one.
func TestASourceInContactIsNotSilentEvenWithNothingToReport(t *testing.T) {
	now := t0
	src := &contactableSource{fakeSource: fakeSource{
		name: "protect", liveness: 30 * time.Minute, block: true,
	}}
	src.sawFrame(t0)
	r := &recorder{}
	s, _ := New([]event.Source{&src.fakeSource}, r.deps(func() time.Time { return now }))
	// Register the contactable wrapper as the source the supervisor sees.
	s.sources = []event.Source{src}

	// Four hours of a perfectly healthy, entirely uneventful night. The socket
	// keeps receiving; nothing is worth emitting.
	for i := 1; i <= 8; i++ {
		now = t0.Add(time.Duration(i) * 30 * time.Minute)
		src.sawFrame(now.Add(-time.Minute))
		s.checkLiveness(context.Background())
	}
	if _, raised, _ := r.counts(); raised != 0 {
		t.Fatalf("a source in contact was reported silent %d time(s) over a quiet night", raised)
	}

	// Now contact actually stops -- the socket is dead, not the site quiet.
	for i := 9; i <= 11; i++ {
		now = t0.Add(time.Duration(i) * 30 * time.Minute)
		s.checkLiveness(context.Background())
	}
	if _, raised, _ := r.counts(); raised != 1 {
		t.Errorf("a source that genuinely stopped being in contact raised %d incident(s), want 1", raised)
	}
}

// THE RECORD IS READ BACK BEFORE ANY SOURCE SPEAKS.
//
// Without this the rules editor is empty until each device says something --
// indefinitely for a camera that has been quiet since before the restart, and
// for ever for one destroyed in the event that caused the restart. The record
// answers "what did this site have", and consulting it only for things that
// have already spoken again would make it answer "what still works".
func TestPriorEntitiesAreLoadedBeforeSourcesRun(t *testing.T) {
	prior := []EntitySeen{
		{Source: "protect", ID: "cam-gone", Name: "Destroyed Camera",
			Kind: "camera", MAC: "aa:bb:cc:dd:ee:01"},
	}
	var asked bool
	s, err := New(nil, Deps{
		Handle:    func(context.Context, event.Event) error { return nil },
		Logf:      func(string, ...any) {},
		KnownFrom: func(context.Context) []EntitySeen { asked = true; return prior },
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Run returns at once with no sources; the load happens first.
	_ = s.Run(ctx)

	if !asked {
		t.Fatal("the durable record was never read")
	}
	known := s.KnownEntities()
	if len(known) != 1 || known[0].ID != "cam-gone" {
		t.Fatalf("known entities after start = %+v, want the recorded one", known)
	}
	if known[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("the MAC did not survive the load: %+v", known[0])
	}
}

// EVERY OBSERVED ENTITY REACHES THE RECORD, including its MAC -- which is the
// only identifier that survives both a rename and a re-adoption.
func TestObservedEntitiesArePersisted(t *testing.T) {
	var written []EntitySeen
	s, err := New(nil, Deps{
		Handle:     func(context.Context, event.Event) error { return nil },
		Logf:       func(string, ...any) {},
		NoteEntity: func(_ context.Context, e EntitySeen) { written = append(written, e) },
	})
	if err != nil {
		t.Fatal(err)
	}
	s.noteEntity("protect", event.Entity{
		ID: "cam-1", Name: "Front Gate", Kind: "camera", MAC: "aa:bb:cc:dd:ee:01",
	})
	if len(written) != 1 {
		t.Fatalf("wrote %d entities, want 1", len(written))
	}
	if written[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("the MAC was not recorded: %+v; nothing else survives a "+
			"re-adoption AND a rename", written[0])
	}
}

// EVICTION IS OFF WHEN THERE IS A RECORD, and that is the point.
//
// Dropping the least recently seen discards the camera that stopped reporting
// first -- which after a power cut or a lightning strike is precisely the row
// somebody needs. A cache that forgets the losses and keeps the survivors
// answers the opposite of the question being asked.
func TestWithADurableRecordNothingIsEvictedByRecency(t *testing.T) {
	s, err := New(nil, Deps{
		Handle:     func(context.Context, event.Event) error { return nil },
		Logf:       func(string, ...any) {},
		NoteEntity: func(context.Context, EntitySeen) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxKnownEntities+25; i++ {
		s.noteEntity("network", event.Entity{ID: fmt.Sprintf("dev-%d", i), Kind: "device"})
	}
	if got := len(s.KnownEntities()); got != maxKnownEntities+25 {
		t.Errorf("held %d entities, want all %d: the earliest -- the ones that "+
			"stopped reporting first -- were evicted", got, maxKnownEntities+25)
	}
}

// ...AND STAYS ON WITHOUT ONE. An unbounded map fed by arriving events, with
// nothing writing them down, is a memory leak dressed up as a convenience.
func TestWithNoRecordTheBoundStillApplies(t *testing.T) {
	s, err := New(nil, Deps{
		Handle: func(context.Context, event.Event) error { return nil },
		Logf:   func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxKnownEntities+25; i++ {
		s.noteEntity("network", event.Entity{ID: fmt.Sprintf("dev-%d", i), Kind: "device"})
	}
	if got := len(s.KnownEntities()); got > maxKnownEntities {
		t.Errorf("held %d entities with no durable record, want at most %d",
			got, maxKnownEntities)
	}
}
