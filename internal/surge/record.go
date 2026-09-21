// Package surge measures how busy a site is, so an alert can say whether it
// arrived alone or in a crowd.
//
// THE MOTIVATING CASE IS SILENCE, NOT NOISE. A wireless jammer ahead of a
// break-in does not announce itself; it shows up as several devices going
// quiet at once, none of which is decisive on its own. No single event in that
// picture is worth waking somebody, and the picture is.
//
// What this package does NOT do is decide. It counts, it compares, and it
// hands back a sentence. The severity, the ladder and the escalation are
// untouched -- a statistical signal nudging a real alarm up a tier is how a
// firmware rollout becomes a phone call at 3am, and the cost of being wrong
// there is measured in an operator who stops trusting the product.
package surge

import (
	"sync"
	"time"
)

// DefaultWidth is the bucket width.
//
// Wide enough that an ordinary quiet site is not measuring mostly-empty
// buckets, narrow enough that "the last ten minutes" is a handful of them
// rather than a smear. It is a constructor argument because the right answer
// is a property of the data rather than of this code, and the tests set it
// explicitly so none of them depends on this number.
const DefaultWidth = 5 * time.Minute

// maxEntitiesPerBucket bounds the set held for the open bucket.
//
// The distinct-entity count is the half of this that matters -- fifty events
// from one flapping camera is not a surge and must never read as one -- so it
// is tracked exactly up to this point and approximated above it. A site with
// more than this many distinct things producing events inside one bucket is
// already far past any threshold; the exact number stops mattering long before
// the memory does.
const maxEntitiesPerBucket = 4096

// Bucket is one closed interval of site activity.
type Bucket struct {
	// Start is the bucket's left edge, truncated to the width.
	Start time.Time

	// Events is every observation that reached the engine in it, INCLUDING
	// the ones rules silenced. A site whose motion is suppressed is still a
	// site with motion in it, and the suppressed events are exactly what a
	// jammer removes.
	Events int

	// Entities is how many distinct things produced them. The number that
	// separates one noisy camera from nine devices dropping together.
	Entities int
}

// Store persists closed buckets and reads them back.
//
// Deliberately not the audit log, which is where this data already exists in
// another form: that file rotates by size, so a busy site would quietly lose
// the history a baseline is computed from, and the loss would be invisible
// because the baseline would simply be computed from less.
type Store interface {
	PutBucket(b Bucket) error
	Buckets(from, to time.Time) ([]Bucket, error)
}

// Recorder accumulates the open bucket and flushes closed ones.
type Recorder struct {
	width time.Duration
	store Store
	now   func() time.Time

	mu       sync.Mutex
	start    time.Time
	events   int
	entities map[string]struct{}
	overflow int
}

// NewRecorder returns a recorder writing buckets of width into store.
func NewRecorder(store Store, width time.Duration, now func() time.Time) *Recorder {
	if width <= 0 {
		width = DefaultWidth
	}
	if now == nil {
		now = time.Now
	}
	return &Recorder{width: width, store: store, now: now, entities: map[string]struct{}{}}
}

// Observe counts one event, identified by the thing it was about.
//
// The key is the caller's business: source and entity id, so the same camera
// under two sources counts twice and two cameras under one source count twice.
// An empty key still counts as an event and adds no entity, because an event
// about nothing in particular is still activity.
func (r *Recorder) Observe(key string, at time.Time) {
	if at.IsZero() {
		at = r.now()
	}
	start := at.Truncate(r.width)

	r.mu.Lock()
	defer r.mu.Unlock()

	// AN EVENT FROM BEFORE THE OPEN BUCKET IS DROPPED, not backdated. Sources
	// carry their own times and a socket reconnect can deliver something
	// minutes old; rewriting a closed bucket would mean the number an alert
	// already quoted stops matching what is stored.
	if !r.start.IsZero() && start.Before(r.start) {
		return
	}
	if r.start.IsZero() {
		r.start = start
	}
	if start.After(r.start) {
		r.flushLocked(start)
	}

	r.events++
	if key == "" {
		return
	}
	if _, seen := r.entities[key]; seen {
		return
	}
	if len(r.entities) >= maxEntitiesPerBucket {
		r.overflow++
		return
	}
	r.entities[key] = struct{}{}
}

// Tick closes any bucket that the clock has moved past.
//
// Called on a timer as well as by Observe, because a site that goes SILENT
// stops calling Observe -- and silence is the case this package exists for. A
// bucket that only closes when the next event arrives would leave the quiet
// hour unrecorded until the site got busy again.
func (r *Recorder) Tick() {
	now := r.now().Truncate(r.width)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.start.IsZero() || !now.After(r.start) {
		return
	}
	r.flushLocked(now)
}

// flushLocked writes the open bucket and opens the one starting at next.
//
// Intervening empty buckets are NOT written. A gap in the series is a gap --
// either nothing happened or nothing was running -- and the two are told apart
// when the baseline is computed, which is the only place that distinction can
// be made honestly. Writing zeros here would erase it.
func (r *Recorder) flushLocked(next time.Time) {
	b := Bucket{Start: r.start, Events: r.events, Entities: len(r.entities) + r.overflow}
	r.start = next
	r.events = 0
	r.overflow = 0
	r.entities = map[string]struct{}{}

	if b.Events == 0 || r.store == nil {
		return
	}
	// A failed write costs a bucket and never an event: this is a measurement
	// of the site, and the site's alarms do not wait for it.
	_ = r.store.PutBucket(b)
}

// Open reports the bucket being accumulated right now, for the interface.
func (r *Recorder) Open() Bucket {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Bucket{Start: r.start, Events: r.events, Entities: len(r.entities) + r.overflow}
}
