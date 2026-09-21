package surge

import (
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 21, 3, 0, 0, 0, time.UTC)

type fakeStore struct {
	put []Bucket
	err error
}

func (f *fakeStore) PutBucket(b Bucket) error { f.put = append(f.put, b); return f.err }
func (f *fakeStore) Buckets(from, to time.Time) ([]Bucket, error) {
	return nil, nil
}

func recorder(t *testing.T, now *time.Time) (*Recorder, *fakeStore) {
	t.Helper()
	s := &fakeStore{}
	return NewRecorder(s, time.Minute, func() time.Time { return *now }), s
}

// THE NUMBER THAT MATTERS. Fifty events from one flapping camera is not a
// surge; nine devices producing one each is the shape a jammer makes.
func TestOneNoisyThingIsOneEntity(t *testing.T) {
	now := t0
	r, _ := recorder(t, &now)

	for i := 0; i < 50; i++ {
		r.Observe("protect/cam-1", t0)
	}
	got := r.Open()
	if got.Events != 50 {
		t.Errorf("events = %d, want 50", got.Events)
	}
	if got.Entities != 1 {
		t.Errorf("entities = %d, want 1 -- a surge test built on volume alone "+
			"would page somebody for a loose PoE connection", got.Entities)
	}
}

func TestDistinctThingsAreCounted(t *testing.T) {
	now := t0
	r, _ := recorder(t, &now)

	for _, k := range []string{"protect/a", "protect/b", "access/a", "network/c"} {
		r.Observe(k, t0)
	}
	if got := r.Open().Entities; got != 4 {
		t.Errorf("entities = %d, want 4 (the same id under two sources is two things)", got)
	}
}

// A bucket closes when the clock moves past it, and what it held is written.
func TestABucketIsWrittenWhenItCloses(t *testing.T) {
	now := t0
	r, s := recorder(t, &now)

	r.Observe("protect/cam-1", t0)
	r.Observe("protect/cam-2", t0)
	r.Observe("protect/cam-1", t0.Add(90*time.Second)) // the next bucket

	if len(s.put) != 1 {
		t.Fatalf("wrote %d buckets, want 1", len(s.put))
	}
	if s.put[0].Events != 2 || s.put[0].Entities != 2 {
		t.Errorf("wrote %+v, want 2 events across 2 entities", s.put[0])
	}
	if !s.put[0].Start.Equal(t0) {
		t.Errorf("start = %v, want the bucket's left edge %v", s.put[0].Start, t0)
	}
}

// SILENCE IS THE CASE THIS EXISTS FOR, and a site that goes quiet stops
// calling Observe. Without a tick the last busy bucket would stay open and the
// quiet hour would never be recorded at all.
func TestTheClockClosesABucketWithNoEvents(t *testing.T) {
	now := t0
	r, s := recorder(t, &now)
	r.Observe("protect/cam-1", t0)

	now = t0.Add(3 * time.Minute)
	r.Tick()

	if len(s.put) != 1 {
		t.Fatalf("wrote %d buckets, want the one that had something in it", len(s.put))
	}
	if got := r.Open().Events; got != 0 {
		t.Errorf("the open bucket still holds %d events", got)
	}
}

// A gap is a gap. Writing zeros for the buckets nothing happened in would
// erase the difference between a quiet site and a daemon that was not running,
// and only the baseline can tell those apart.
func TestEmptyBucketsAreNotWritten(t *testing.T) {
	now := t0
	r, s := recorder(t, &now)
	r.Observe("protect/cam-1", t0)

	now = t0.Add(30 * time.Minute)
	r.Tick()

	if len(s.put) != 1 {
		t.Errorf("wrote %d buckets across a 30-minute gap, want 1", len(s.put))
	}
}

// A socket reconnect can deliver something minutes old. Rewriting a closed
// bucket would mean a number an alert already quoted stops matching what is
// stored.
func TestALateEventDoesNotRewriteAClosedBucket(t *testing.T) {
	now := t0
	r, s := recorder(t, &now)
	r.Observe("protect/cam-1", t0)
	r.Observe("protect/cam-2", t0.Add(2*time.Minute))
	r.Observe("protect/cam-3", t0) // arrives late, belongs to a closed bucket

	if len(s.put) != 1 {
		t.Fatalf("wrote %d buckets, want 1", len(s.put))
	}
	if s.put[0].Events != 1 {
		t.Errorf("the closed bucket was rewritten: %+v", s.put[0])
	}
	if got := r.Open().Events; got != 1 {
		t.Errorf("the late event was counted into the open bucket: %d", got)
	}
}

// This is a measurement of the site. The site's alarms do not wait for it.
func TestAFailedWriteCostsABucketAndNothingElse(t *testing.T) {
	now := t0
	s := &fakeStore{err: errors.New("disk full")}
	r := NewRecorder(s, time.Minute, func() time.Time { return now })

	r.Observe("protect/cam-1", t0)
	now = t0.Add(2 * time.Minute)
	r.Tick()
	r.Observe("protect/cam-2", now)

	if got := r.Open().Events; got != 1 {
		t.Errorf("recording continued wrongly after a failed write: %d", got)
	}
}

// Bounded memory, and the bound does not distort the number that matters.
func TestTheEntitySetIsBounded(t *testing.T) {
	now := t0
	r, _ := recorder(t, &now)

	for i := 0; i < maxEntitiesPerBucket+500; i++ {
		r.Observe(string(rune(i%1000))+"/"+time.Duration(i).String(), t0)
	}
	if got := r.Open().Entities; got < maxEntitiesPerBucket {
		t.Errorf("entities = %d, want at least the cap: above it the count is "+
			"approximate, never smaller", got)
	}
}

// The flapping-camera invariant, at the boundary where it stops being free.
//
// Below the cap a map makes it automatic: adding the same key twice is one
// key. AT the cap the set stops accepting new keys and starts counting
// overflow, and without the already-seen check a single camera repeating
// itself would increment that counter on every event -- which is precisely
// the "volume masquerading as spread" this whole measurement exists to avoid,
// reintroduced at the one size where nobody would look for it.
func TestARepeatedEntityDoesNotInflateTheCount(t *testing.T) {
	now := t0
	r, _ := recorder(t, &now)

	for i := 0; i < maxEntitiesPerBucket; i++ {
		r.Observe("thing-"+time.Duration(i).String(), t0)
	}
	full := r.Open().Entities

	for i := 0; i < 500; i++ {
		r.Observe("thing-0s", t0) // one camera, five hundred events
	}
	if got := r.Open().Entities; got != full {
		t.Errorf("entities went from %d to %d because one thing repeated itself", full, got)
	}
}
