package ingest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
)

// started runs s on its own goroutine and returns what stops it.
func started(t *testing.T, s *Supervisor) (cancel func(), done chan struct{}) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	return stop, done
}

func statusOf(t *testing.T, s *Supervisor, name string) Status {
	t.Helper()
	for _, st := range s.Statuses() {
		if st.Name == name {
			return st
		}
	}
	t.Fatalf("no status for %q in %+v", name, s.Statuses())
	return Status{}
}

// AN UNCHANGED SOURCE IS NOT TOUCHED.
//
// A Protect source holds the websocket, the backoff ladder and the table that
// turns an `update` frame into a clear. An operator who edits an unrelated
// field -- a quiet-hours window, a channel's address -- must not pay for that
// with a reconnect, and must not have the board forget what that source has
// reported.
func TestAReplaceLeavesAnUnchangedSourceRunning(t *testing.T) {
	now := t0
	protect := &fakeSource{name: "protect", block: true, emit: []event.Event{
		{Source: "protect", Condition: "offline"},
	}}
	access := &fakeSource{name: "access", block: true}
	r := &recorder{}
	s, _ := New([]event.Source{protect, access}, r.deps(func() time.Time { return now }))
	cancel, done := started(t, s)
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { n, _, _ := r.counts(); return n == 1 })

	// The console gains Network; nothing about Protect changed, so the SAME
	// value comes back.
	now = t0.Add(time.Hour)
	network := &fakeSource{name: "network", block: true}
	change, err := s.Replace([]event.Source{protect, network})
	if err != nil {
		t.Fatal(err)
	}

	if n := protect.runCount(); n != 1 {
		t.Errorf("the unchanged source was run %d times; a reconnect was paid "+
			"for an edit that did not concern it", n)
	}
	if n := protect.exitCount(); n != 0 {
		t.Errorf("the unchanged source was stopped (%d exits)", n)
	}
	got := statusOf(t, s, "protect")
	if got.Events != 1 || !got.LastEventAt.Equal(t0) || !got.Since.Equal(t0) {
		t.Errorf("the unchanged source's record was reset: %+v", got)
	}
	if len(change.Kept) != 1 || change.Kept[0] != "protect" {
		t.Errorf("change.Kept = %v, want [protect]", change.Kept)
	}
}

// A REMOVED SOURCE IS GONE, and the deadman stops looking for it.
//
// Gone means its goroutine has returned by the time Replace does, not merely
// that it was told to stop -- a source still winding down would still be
// counting events into a record nobody is showing. And a source nobody
// configured any more must not be reported as silent, because it will be
// silent for ever.
func TestARemovedSourceIsStoppedAndNoLongerDeadmanned(t *testing.T) {
	now := t0
	protect := &fakeSource{name: "protect", block: true}
	access := &fakeSource{name: "access", liveness: time.Minute, block: true,
		teardown: 30 * time.Millisecond}
	r := &recorder{}
	s, _ := New([]event.Source{protect, access}, r.deps(func() time.Time { return now }))
	cancel, done := started(t, s)
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { return access.runCount() == 1 })

	change, err := s.Replace([]event.Source{protect})
	if err != nil {
		t.Fatal(err)
	}
	if n := access.exitCount(); n != 1 {
		t.Errorf("Replace returned with the removed source's Run still going "+
			"(exits = %d); it was told to go, not waited for", n)
	}
	if len(change.Stopped) != 1 || change.Stopped[0] != "access" {
		t.Errorf("change.Stopped = %v, want [access]", change.Stopped)
	}
	if got := s.Statuses(); len(got) != 1 || got[0].Name != "protect" {
		t.Errorf("statuses after removal = %+v, want protect alone", got)
	}

	// Long past the removed source's window. Nothing is raised, because
	// nothing is configured to be heard from.
	now = t0.Add(2 * time.Hour)
	s.checkLiveness(context.Background())
	if _, n, _ := r.counts(); n != 0 {
		t.Errorf("the deadman raised %d incident(s) for a source that is no "+
			"longer configured", n)
	}
}

// A removed source's open incident is closed with it. It was about a
// configuration that no longer exists, and left open it escalates until
// somebody acknowledges a fault in a thing that is not there.
func TestRemovingASilentSourceResolvesItsIncident(t *testing.T) {
	now := t0
	access := &fakeSource{name: "access", liveness: time.Minute, block: true}
	r := &recorder{}
	s, _ := New([]event.Source{access}, r.deps(func() time.Time { return now }))
	cancel, done := started(t, s)
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { return access.runCount() == 1 })

	now = t0.Add(time.Hour)
	s.checkLiveness(context.Background())
	if _, n, _ := r.counts(); n != 1 {
		t.Fatalf("raises = %d, want the removed source to have been silent first", n)
	}

	if _, err := s.Replace(nil); err != nil {
		t.Fatal(err)
	}
	_, _, resolves := r.counts()
	if resolves != 1 {
		t.Errorf("resolves = %d; the incident about a source that no longer "+
			"exists was left open", resolves)
	}
	r.mu.Lock()
	got := r.resolves
	r.mu.Unlock()
	if len(got) == 1 && got[0].entity != "source/access" {
		t.Errorf("resolved %q, want source/access", got[0].entity)
	}
}

// A NEW SOURCE STARTS and is counted, and what it sees reaches the record.
func TestAReplaceStartsANewSourceAndCountsIt(t *testing.T) {
	now := t0
	protect := &fakeSource{name: "protect", block: true}
	r := &recorder{}
	s, _ := New([]event.Source{protect}, r.deps(func() time.Time { return now }))
	cancel, done := started(t, s)
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { return protect.runCount() == 1 })

	now = t0.Add(time.Hour)
	network := &fakeSource{name: "network", liveness: 30 * time.Minute, block: true,
		emit: []event.Event{{Source: "network", Condition: "wan-down",
			Entity: event.Entity{ID: "gw-1", Name: "Gateway"}}}}
	change, err := s.Replace([]event.Source{protect, network})
	if err != nil {
		t.Fatal(err)
	}
	if len(change.Started) != 1 || change.Started[0] != "network" {
		t.Errorf("change.Started = %v, want [network]", change.Started)
	}

	waitFor(t, func() bool { n, _, _ := r.counts(); return n == 1 })
	got := statusOf(t, s, "network")
	if got.Events != 1 || !got.Since.Equal(t0.Add(time.Hour)) {
		t.Errorf("new source's status = %+v, want 1 event since it was added", got)
	}
	if known := s.KnownEntities(); len(known) != 1 || known[0].ID != "gw-1" {
		t.Errorf("the new source's entity did not reach the record: %+v", known)
	}
}

// A SOURCE ADDED BY REPLACE IS GIVEN ITS WINDOW FROM WHEN IT WAS ADDED -- the
// same grace a source gets at launch, and for the same reason: a clock at
// zero raises a fault for every source the moment it is configured.
//
// The source here emits NOTHING, on purpose. One that spoke on start would
// set its own clock and hide a supervisor that had never set it.
func TestASourceAddedByReplaceIsGivenItsWindowFromThen(t *testing.T) {
	now := t0
	protect := &fakeSource{name: "protect", block: true}
	r := &recorder{}
	s, _ := New([]event.Source{protect}, r.deps(func() time.Time { return now }))
	cancel, done := started(t, s)
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { return protect.runCount() == 1 })

	t1 := t0.Add(time.Hour)
	now = t1
	network := &fakeSource{name: "network", liveness: 30 * time.Minute, block: true}
	if _, err := s.Replace([]event.Source{protect, network}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return network.runCount() == 1 })

	// Ten minutes in, twenty short of its window: nothing.
	now = t1.Add(10 * time.Minute)
	s.checkLiveness(context.Background())
	if _, n, _ := r.counts(); n != 0 {
		t.Fatalf("a source added ten minutes ago was reported silent: its clock " +
			"was not started when it was")
	}
	// Past the window with nothing heard: it IS silent, so the clock was set
	// when it was added and not, say, never checked at all.
	now = t1.Add(31 * time.Minute)
	s.checkLiveness(context.Background())
	if _, n, _ := r.counts(); n != 1 {
		t.Errorf("raises = %d, want 1 once the added source was quiet past its window", n)
	}
}

// STATUSES TELL THE TRUTH ABOUT ALL THREE CASES AT ONCE.
//
// The board distinguishes reporting, silent and never-connected, and it has
// lied before: it said three sources were reporting on a console running one.
// After a swap, a retained source keeps what it has reported, a replaced one
// -- same name, corrected key -- starts from nothing, and an added one starts
// from nothing. The name is not the identity; the source is.
func TestStatusesAfterAReplaceDoNotInheritOrForget(t *testing.T) {
	now := t0
	protect := &fakeSource{name: "protect", block: true, emit: []event.Event{
		{Source: "protect", Condition: "offline", Entity: event.Entity{ID: "cam-1", Name: "Gate"}},
	}}
	oldAccess := &fakeSource{name: "access", block: true, emit: []event.Event{
		{Source: "access", Condition: "forced-open", Entity: event.Entity{ID: "door-1", Name: "Server Room"}},
	}}
	r := &recorder{}
	s, _ := New([]event.Source{protect, oldAccess}, r.deps(func() time.Time { return now }))
	cancel, done := started(t, s)
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { n, _, _ := r.counts(); return n == 2 })

	// The Access key is corrected: a NEW access source with the SAME name.
	// Network is ticked for the first time.
	t1 := t0.Add(time.Hour)
	now = t1
	newAccess := &fakeSource{name: "access", block: true}
	network := &fakeSource{name: "network", block: true}
	if _, err := s.Replace([]event.Source{protect, newAccess, network}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return newAccess.runCount() == 1 && network.runCount() == 1 })

	got := s.Statuses()
	if len(got) != 3 {
		t.Fatalf("statuses = %+v, want three", got)
	}
	if p := statusOf(t, s, "protect"); p.Events != 1 || !p.LastEventAt.Equal(t0) || !p.Since.Equal(t0) {
		t.Errorf("retained protect forgot what it reported: %+v", p)
	}
	if a := statusOf(t, s, "access"); a.Events != 0 || !a.LastEventAt.Equal(t1) || !a.Since.Equal(t1) {
		t.Errorf("replaced access inherited the old one's record: %+v -- the "+
			"board would say a source that has never connected has been heard from", a)
	}
	if n := statusOf(t, s, "network"); n.Events != 0 || !n.Since.Equal(t1) {
		t.Errorf("added network = %+v, want nothing reported since %s", n, t1)
	}
	if n := oldAccess.exitCount(); n != 1 {
		t.Errorf("the replaced access source is still running (exits = %d)", n)
	}

	// The entity record belongs to the site, not to the sources. The door the
	// old access source saw is still known after that source is gone.
	known := s.KnownEntities()
	if len(known) != 2 {
		t.Fatalf("known entities after the swap = %+v, want both", known)
	}
	var sawDoor bool
	for _, e := range known {
		sawDoor = sawDoor || e.ID == "door-1"
	}
	if !sawDoor {
		t.Errorf("the replaced source's entities were forgotten: %+v", known)
	}
}

// REPLACE UNDER LOAD. A busy site keeps emitting through every Replace, and
// the race detector is the assertion here: each Replace swaps the set while
// the sink is writing to it.
func TestReplaceIsSafeWhileEventsAreArriving(t *testing.T) {
	protect := &fakeSource{name: "protect", chatty: true}
	r := &recorder{}
	s, _ := New([]event.Source{protect}, r.deps(time.Now))
	cancel, done := started(t, s)
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { n, _, _ := r.counts(); return n > 10 })

	for i := 0; i < 20; i++ {
		access := &fakeSource{name: "access", chatty: true}
		if _, err := s.Replace([]event.Source{protect, access}); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool { return access.runCount() == 1 })
		if _, err := s.Replace([]event.Source{protect}); err != nil {
			t.Fatal(err)
		}
		if n := access.exitCount(); n != 1 {
			t.Fatalf("round %d: the removed source did not exit (exits = %d)", i, n)
		}
		_ = s.Statuses()
		_ = s.KnownEntities()
	}
	if n := protect.runCount(); n != 1 {
		t.Errorf("the source that was never changed was run %d times", n)
	}
	before, _, _ := r.counts()
	waitFor(t, func() bool { n, _, _ := r.counts(); return n > before })
}

// A Replace before Run sets what Run will start. The daemon builds the
// supervisor before it starts it, and a configuration saved in that window
// must not be lost.
func TestAReplaceBeforeRunIsWhatRunStarts(t *testing.T) {
	r := &recorder{}
	s, _ := New(nil, r.deps(func() time.Time { return t0 }))
	protect := &fakeSource{name: "protect", block: true, emit: []event.Event{
		{Source: "protect", Condition: "offline"},
	}}
	if _, err := s.Replace([]event.Source{protect}); err != nil {
		t.Fatal(err)
	}
	cancel, done := started(t, s)
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { n, _, _ := r.counts(); return n == 1 })
}

// After Run has returned nothing can be started, and Replace says so rather
// than reporting a source as running that never will.
func TestAReplaceAfterRunHasReturnedIsRefused(t *testing.T) {
	r := &recorder{}
	s, _ := New(nil, r.deps(func() time.Time { return t0 }))
	cancel, done := started(t, s)
	cancel()
	<-done

	protect := &fakeSource{name: "protect", block: true}
	_, err := s.Replace([]event.Source{protect})
	if !errors.Is(err, ErrStopped) {
		t.Errorf("Replace after Run returned = %v, want ErrStopped", err)
	}
	if n := protect.runCount(); n != 0 {
		t.Errorf("a source was run under a supervisor that had stopped")
	}
}

// Every source is waited for at shutdown, including one a Replace removed a
// moment earlier that is still closing what it holds. Run returning with a
// source goroutine still alive is a goroutine that outlives the daemon's
// own idea of itself.
func TestShutdownWaitsForEverySource(t *testing.T) {
	protect := &fakeSource{name: "protect", block: true, teardown: 30 * time.Millisecond}
	access := &fakeSource{name: "access", block: true, teardown: 30 * time.Millisecond}
	r := &recorder{}
	s, _ := New([]event.Source{protect, access}, r.deps(func() time.Time { return t0 }))
	cancel, done := started(t, s)
	waitFor(t, func() bool { return protect.runCount() == 1 && access.runCount() == 1 })

	cancel()
	<-done
	if protect.exitCount() != 1 || access.exitCount() != 1 {
		t.Errorf("Run returned with sources still running: protect exits = %d, "+
			"access exits = %d", protect.exitCount(), access.exitCount())
	}
}
