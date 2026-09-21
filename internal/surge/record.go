// Package surge measures how busy a site is, so an alert can say whether it
// arrived alone or in a crowd.
//
// THE MOTIVATING CASE IS A DROP-OFF BURST. A wireless jammer ahead of a
// break-in does not announce itself; it shows up as several devices going
// quiet at once, none of which is decisive on its own. No single event in that
// picture is worth waking somebody, and the picture is.
//
// NOT as unusual silence, which is the intuitive reading and is wrong: a site
// that is normally silent at 3am carries no signal to lose, and a detector
// that called that a surge could not tell a jammer from a Tuesday. What is
// visible is the disconnect burst the jamming CAUSES -- cameras and clients
// dropping together -- which is the busy path, not the quiet one.
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

// Width is the bucket, aligned to the wall clock.
//
// Ten minutes is forced by the scenario at one end and by arithmetic at the
// other: deauth-then-entry plays out in minutes, so an hourly bucket cannot
// describe "now", while a one-minute bucket is zero-inflated on a quiet site
// -- median zero everywhere, every statistic degenerate -- and costs ten times
// the rows. Ten minutes gives six samples per hour per day, which is what
// makes a baseline earnable in a fortnight rather than a season.
const Width = 10 * time.Minute

// maxEntities bounds the set held for the open bucket.
//
// The distinct-entity count is the half that matters -- fifty events from one
// flapping camera is not a surge and must never read as one -- so it is exact
// up to here and reported as "at least" above it. No real site approaches it;
// it exists so the bound is provable rather than argued.
const maxEntities = 10000

// maxClockSkew is how far the wall clock may disagree with elapsed time before
// a bucket is discarded.
//
// A machine without a battery-backed clock comes up in 1970 and NTP snaps it
// forward; the bucket straddling that jump describes a span that did not
// happen. Thirty seconds is far outside ordinary drift and far inside any jump
// worth noticing.
const maxClockSkew = 30 * time.Second

// Bucket is one completed interval of site activity.
type Bucket struct {
	// Start is the bucket's left edge, aligned to Width in UTC.
	Start time.Time

	// Events is every observation that reached the engine in it, INCLUDING
	// the ones rules silenced. A site whose motion is suppressed is still a
	// site with motion in it, and the suppressed events are exactly what a
	// jammer removes.
	Events int

	// Devices is how many distinct things produced them. The number that
	// separates one noisy camera from nine devices dropping together.
	Devices int

	// Degraded says this product was not fully watching for part of the
	// bucket -- a source deadman tripped, or a configured source had not
	// connected yet.
	//
	// Written, because the time was still watched by whatever was up, and
	// excluded from the baseline PERMANENTLY: a blind hour would otherwise
	// contribute honest zeros meaning "we saw nothing", which is not the same
	// claim as "nothing happened", and a blind week is not a new normal.
	Degraded bool

	// Flagged records that this bucket was itself judged unusual when it
	// closed, so the baseline can exclude it and not learn an attack as
	// normal. See baseline.go for the re-admission clause that stops that
	// exclusion freezing a site which has genuinely changed.
	Flagged Verdict
}

// Store persists completed buckets and reads them back.
//
// Deliberately not the audit log, where this data already exists in another
// form: that file rotates by size, so a busy site would quietly lose the
// history a baseline is computed from, and the loss would be invisible because
// the baseline would simply be computed from less.
type Store interface {
	PutBucket(b Bucket) error
	Buckets(from, to time.Time) ([]Bucket, error)
}

// Recorder accumulates the open bucket and writes completed ones.
type Recorder struct {
	store Store
	now   func() time.Time

	// degraded reports whether this product is currently blind in any way it
	// knows about. Consulted per event rather than per bucket, so a deadman
	// that trips mid-bucket taints the bucket it tripped in.
	degraded func() bool

	mu sync.Mutex

	// start is the open bucket's left edge; openedAt is when accumulation
	// actually began, which is LATER than start for the first bucket after a
	// restart and is what makes that bucket incomplete.
	start     time.Time
	openedAt  time.Time
	events    int
	entities  map[string]struct{}
	overflow  int
	wasBlind  bool
	watching  bool
	partial   bool
	lastWrite Bucket
}

// NewRecorder returns a recorder writing completed buckets into store.
//
// degraded may be nil, which means this build cannot tell when it is blind --
// every bucket is then treated as sound, which is the honest default for a
// caller that supplies no better information.
func NewRecorder(store Store, now func() time.Time, degraded func() bool) *Recorder {
	if now == nil {
		now = time.Now
	}
	if degraded == nil {
		degraded = func() bool { return false }
	}
	return &Recorder{store: store, now: now, degraded: degraded, entities: map[string]struct{}{}}
}

// Observe counts one event, identified by the thing it was about.
//
// The key is the caller's business: source and entity id, the same identity
// the dedup key uses. An empty key still counts as an event and adds no
// device, because an event about nothing in particular is still activity.
func (r *Recorder) Observe(key string, at time.Time) {
	now := r.now()
	if at.IsZero() {
		at = now
	}
	start := at.UTC().Truncate(Width)

	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.watching {
		// THE FIRST BUCKET AFTER A RESTART IS USUALLY INCOMPLETE: its span
		// began before this process did, so its count is a fraction of what
		// happened in it, and a fraction written as a whole would drag the
		// baseline down on every config change and every upgrade. open()
		// decides, because a start exactly on a boundary missed nothing.
		r.open(start, now, now.After(start))
	}

	// An event from before the open bucket is dropped, not backdated. Sources
	// carry their own times and a socket reconnect can deliver something
	// minutes old; rewriting a closed bucket would mean a number an alert
	// already quoted stops matching what is stored.
	if start.Before(r.start) {
		return
	}
	if start.After(r.start) {
		r.roll(start, now)
	}

	r.events++
	if r.degraded() {
		r.wasBlind = true
	}
	if key == "" {
		return
	}
	if _, seen := r.entities[key]; seen {
		return
	}
	if len(r.entities) >= maxEntities {
		r.overflow++
		return
	}
	r.entities[key] = struct{}{}
}

// Tick closes any bucket the clock has moved past.
//
// Called on a timer as well as by Observe, because a site that goes SILENT
// stops calling Observe -- and a silent stretch is a real measurement, not an
// absence of one. A bucket that only closed when the next event arrived would
// leave the quiet hour unrecorded until the site got busy again.
func (r *Recorder) Tick() {
	now := r.now()
	start := now.UTC().Truncate(Width)

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.watching {
		r.open(start, now, now.After(start))
		return
	}
	if r.degraded() {
		r.wasBlind = true
	}
	if start.After(r.start) {
		r.roll(start, now)
	}
}

// open begins accumulating a bucket. partial says its span had already begun
// before this recorder was watching, which is true exactly once -- at startup,
// unless the process happened to come up on a boundary.
func (r *Recorder) open(start, now time.Time, partial bool) {
	r.start = start
	r.openedAt = now
	r.events = 0
	r.overflow = 0
	r.entities = map[string]struct{}{}
	r.wasBlind = r.degraded()
	r.watching = true
	r.partial = partial
}

// roll writes the open bucket if it was complete and opens the one at next.
//
// Intervening empty buckets ARE written, because a quiet ten minutes that this
// product watched in full is a measurement: the baseline needs to know that
// two events at 3am is normal here. What is never written is a bucket whose
// span this process did not see all of -- absence stays absence, and only the
// baseline can tell a quiet site from a daemon that was not running.
func (r *Recorder) roll(next, now time.Time) {
	closed := Bucket{
		Start:    r.start,
		Events:   r.events,
		Devices:  len(r.entities) + r.overflow,
		Degraded: r.wasBlind,
	}
	partial := r.partial
	openedAt := r.openedAt

	// Every whole bucket between the one closing and the one opening was
	// watched with nothing in it, so each is a real zero.
	var empties []Bucket
	for t := r.start.Add(Width); t.Before(next); t = t.Add(Width) {
		empties = append(empties, Bucket{Start: t, Degraded: r.wasBlind})
	}

	// NOT partial: this recorder was watching when the boundary passed, so
	// the bucket now opening was seen from its first second. Marking it
	// partial here discarded every bucket after the first, which is every
	// bucket a running daemon produces.
	r.open(next, now, false)

	if r.store == nil {
		return
	}
	if !partial && !skewed(openedAt, now, closed.Start, next) {
		// A failed write costs a bucket and never an event: this is a
		// measurement of the site, and the site's alarms do not wait for it.
		_ = r.store.PutBucket(closed)
		r.lastWrite = closed
	}
	for _, b := range empties {
		_ = r.store.PutBucket(b)
	}
}

// skewed reports whether the wall clock moved differently from elapsed time
// across this bucket.
//
// time.Time carries a monotonic reading; subtracting two of them uses it,
// while Round(0) strips it and leaves the wall clock. When those two
// measurements of the same span disagree, one of them is fiction.
func skewed(openedAt, now, start, next time.Time) bool {
	mono := now.Sub(openedAt)
	wall := now.Round(0).Sub(openedAt.Round(0))
	return jumped(wall, mono)
}

// jumped is skewed's arithmetic, separated so it can be tested without a clock
// that can be made to lie.
func jumped(wall, mono time.Duration) bool {
	d := wall - mono
	if d < 0 {
		d = -d
	}
	return d > maxClockSkew
}

// Open reports the bucket being accumulated right now, for the interface.
func (r *Recorder) Open() Bucket {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Bucket{
		Start:    r.start,
		Events:   r.events,
		Devices:  len(r.entities) + r.overflow,
		Degraded: r.wasBlind,
	}
}
