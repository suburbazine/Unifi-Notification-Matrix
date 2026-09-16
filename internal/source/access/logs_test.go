package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"
)

// fakeLog is a console's system log, queryable the way the real one is.
type fakeLog struct {
	rows map[string][]logHit // by topic

	// failTopics makes those topics return an error, so the watermark
	// behaviour on partial failure is testable.
	failTopics map[string]bool

	windows []string // every (topic, since, until) asked for
	pages   int
}

func (f *fakeLog) fetch(_ context.Context, topic string, since, until time.Time, page int) ([]logHit, error) {
	f.pages++
	f.windows = append(f.windows, fmt.Sprintf("%s %d-%d", topic, since.Unix(), until.Unix()))
	if f.failTopics[topic] {
		return nil, errors.New("console said no")
	}
	if page > 1 {
		return nil, nil
	}
	var out []logHit
	for _, h := range f.rows[topic] {
		at, _ := h.at()
		if at.Before(since) || at.After(until) {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

func row(id string, at time.Time, key string) logHit {
	h := logHit{ID: id}
	h.Source.Event.LogKey = key
	h.Source.Event.Published = json.Number(strconv.FormatInt(at.UnixMilli(), 10))
	return h
}

func ids(rows []logRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.hit.ID)
	}
	return out
}

// THE CORRECTNESS RULE OF THIS WHOLE FILE.
//
// A partial window looks exactly like a complete one to everything
// downstream. Advancing past a failed query silently drops whatever was in it,
// and on a log with no cursor there is nothing to rewind to -- the denial is
// simply never seen by anybody, ever.
func TestTheWatermarkDoesNotAdvanceWhenATopicFails(t *testing.T) {
	now := t0
	f := &fakeLog{
		rows:       map[string][]logHit{topicDoorOpenings: {row("a", t0.Add(-time.Minute), "access.door.denied")}},
		failTopics: map[string]bool{topicCritical: true},
	}
	p := newPoller(f.fetch, time.Minute, 10*time.Minute, func() time.Time { return now })

	if _, err := p.poll(context.Background()); err == nil {
		t.Fatal("a failing topic was reported as success")
	}
	p.mu.Lock()
	wm := p.watermark
	p.mu.Unlock()
	if !wm.IsZero() {
		t.Fatalf("watermark advanced to %v after a failed poll; the next window "+
			"would start after rows nobody has read", wm)
	}

	// The topic recovers. The window must still reach back over the failure.
	f.failTopics = nil
	f.windows = nil
	now = t0.Add(5 * time.Minute)
	if _, err := p.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	wm = p.watermark
	p.mu.Unlock()
	if wm.IsZero() {
		t.Error("watermark never advanced even after a clean poll")
	}
}

// Rows that arrive in two overlapping windows must be emitted once. The row id
// is the only trustworthy de-duplicator: the query takes SECONDS while the
// rows carry MILLISECONDS, and the boundary semantics are undocumented.
func TestAnOverlappingWindowDoesNotReemitRows(t *testing.T) {
	now := t0
	f := &fakeLog{rows: map[string][]logHit{
		topicDoorOpenings: {
			row("a", t0.Add(-2*time.Minute), "access.door.denied"),
			row("b", t0.Add(-1*time.Minute), "access.door.denied"),
		},
	}}
	p := newPoller(f.fetch, time.Minute, 10*time.Minute, func() time.Time { return now })

	first, err := p.poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 {
		t.Fatalf("first poll returned %v, want both rows", ids(first))
	}

	// The next window overlaps by ten minutes, so the console returns the same
	// two rows again.
	now = t0.Add(time.Minute)
	second, err := p.poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Errorf("second poll re-emitted %v; every denial would be alerted twice", ids(second))
	}
}

// A fresh install must not replay yesterday's denials as though they were
// happening now. Somebody already dealt with those.
func TestAColdStartDoesNotReplayHistory(t *testing.T) {
	now := t0
	f := &fakeLog{rows: map[string][]logHit{
		topicDoorOpenings: {
			row("old", t0.Add(-48*time.Hour), "access.door.denied"),
			row("new", t0.Add(-time.Minute), "access.door.denied"),
		},
	}}
	p := newPoller(f.fetch, time.Minute, 10*time.Minute, func() time.Time { return now })

	got, err := p.poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].hit.ID != "new" {
		t.Errorf("cold start returned %v, want only the recent row", ids(got))
	}
}

// Rows reach the rule engine oldest-first, so a burst of denials is processed
// in the order it happened rather than in whatever order the console paged it.
func TestRowsAreOrderedOldestFirst(t *testing.T) {
	now := t0
	f := &fakeLog{rows: map[string][]logHit{
		topicDoorOpenings: {
			row("third", t0.Add(-time.Minute), "denied"),
			row("first", t0.Add(-5*time.Minute), "denied"),
			row("second", t0.Add(-3*time.Minute), "denied"),
		},
	}}
	p := newPoller(f.fetch, time.Minute, 10*time.Minute, func() time.Time { return now })
	got, err := p.poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"first", "second", "third"}
	for i, id := range ids(got) {
		if i >= len(want) || id != want[i] {
			t.Fatalf("order = %v, want %v", ids(got), want)
		}
	}
}

// A row with no id cannot be de-duplicated, so emitting it would re-emit it on
// every overlapping window until it aged out.
func TestARowWithNoIDIsCountedNotEmitted(t *testing.T) {
	now := t0
	f := &fakeLog{rows: map[string][]logHit{
		topicDoorOpenings: {row("", t0.Add(-time.Minute), "denied")},
	}}
	p := newPoller(f.fetch, time.Minute, 10*time.Minute, func() time.Time { return now })
	got, err := p.poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("an id-less row was emitted: %v", ids(got))
	}
	_, _, _, unknown := p.stats()
	if unknown["<row-with-no-id>"] == 0 {
		t.Error("an id-less row was dropped without being counted anywhere")
	}
}

// The response carries no pagination fields at all -- no total, no cursor, no
// next -- so a short page is the only end-of-data signal there is.
func TestPagingStopsOnAShortPage(t *testing.T) {
	now := t0
	f := &fakeLog{rows: map[string][]logHit{
		topicDoorOpenings: {row("a", t0.Add(-time.Minute), "denied")},
	}}
	p := newPoller(f.fetch, time.Minute, 10*time.Minute, func() time.Time { return now })
	if _, err := p.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	// One page per topic, and no more: two topics are polled.
	if f.pages != len(topicsPolled) {
		t.Errorf("fetched %d pages for %d topics; paging did not stop on a short page",
			f.pages, len(topicsPolled))
	}
}

// The de-duplication set cannot grow without bound on a busy site.
func TestSeenRowsAreEvicted(t *testing.T) {
	now := t0
	f := &fakeLog{rows: map[string][]logHit{}}
	p := newPoller(f.fetch, time.Minute, time.Minute, func() time.Time { return now })

	p.mu.Lock()
	for i := 0; i < 100; i++ {
		p.seen[fmt.Sprintf("old%d", i)] = t0.Add(-time.Hour)
	}
	p.mu.Unlock()

	if _, err := p.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	n := len(p.seen)
	p.mu.Unlock()
	if n != 0 {
		t.Errorf("%d stale row ids survived eviction", n)
	}
}

func TestDenialsAreRecognisedAndOrdinaryOpeningsAreNot(t *testing.T) {
	denials := []string{
		"access.door.denied", "ACCESS_DENIED", "door.open.fail",
		"credential.invalid", "access.unauthorized", "policy.reject",
	}
	for _, k := range denials {
		if !isDenial(row("x", t0, k)) {
			t.Errorf("log key %q was not recognised as a denial", k)
		}
	}
	for _, k := range []string{"access.door.unlock", "door.opened", "access.remote_unlock"} {
		if isDenial(row("x", t0, k)) {
			t.Errorf("log key %q was treated as a denial; an ordinary entry is not "+
				"an incident and would bury the real ones", k)
		}
	}
}
