package surge

import (
	"sync"
	"time"
)

// The trailing window, and the decision about whether to say anything.
//
// "RIGHT NOW" IS NOT THE OPEN BUCKET. A bucket that opened forty seconds ago
// describes forty seconds; quoting it beside a ten-minute baseline compares
// two different spans and makes a quiet site look dead every ten minutes on
// the dot. So the figure an alert quotes comes from a trailing window of the
// same width as a bucket, which is the only way the two numbers in the
// sentence share a unit.

// Reporter answers "how busy is this site" at the moment an alert is composed.
type Reporter struct {
	store Store
	now   func() time.Time
	site  *time.Location

	// startedAt is when this process began watching. Below one window's worth
	// of uptime there is nothing honest to say: the trailing ten minutes
	// includes time nobody was looking at.
	startedAt time.Time

	// blindSince reports when this product last could not see the whole site,
	// or the zero time when it can. A quiet verdict while the product is
	// blind is exactly the wrong sentence, and the source deadman is already
	// saying the true one.
	blind func() (since time.Time, now bool)

	mu     sync.Mutex
	events []time.Time
	seen   map[string]time.Time
}

// NewReporter returns a reporter reading history from store.
func NewReporter(store Store, site *time.Location, now func() time.Time,
	blind func() (time.Time, bool)) *Reporter {
	if now == nil {
		now = time.Now
	}
	if blind == nil {
		blind = func() (time.Time, bool) { return time.Time{}, false }
	}
	return &Reporter{
		store: store, site: site, now: now, blind: blind,
		startedAt: now(), seen: map[string]time.Time{},
	}
}

// Observe records one event in the trailing window.
//
// Called alongside Recorder.Observe rather than instead of it: the recorder
// writes history and this answers about the present, and conflating them is
// what makes the two numbers in the sentence disagree.
func (r *Reporter) Observe(key string, at time.Time) {
	if at.IsZero() {
		at = r.now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, at)
	if key != "" {
		r.seen[key] = at
	}
	r.trimLocked(r.now())
}

// trimLocked drops everything older than one window.
//
// Bounded by the window rather than by a cap: a site producing ten thousand
// events in ten minutes is a site in the middle of the thing this exists to
// notice, and truncating the count there would understate exactly the moment
// that matters.
func (r *Reporter) trimLocked(now time.Time) {
	cutoff := now.Add(-Width)
	keep := r.events[:0]
	for _, t := range r.events {
		if !t.Before(cutoff) {
			keep = append(keep, t)
		}
	}
	r.events = keep
	for k, t := range r.seen {
		if t.Before(cutoff) {
			delete(r.seen, k)
		}
	}
}

// Window reports what has happened in the trailing ten minutes.
func (r *Reporter) Window() (events, devices int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trimLocked(r.now())
	return len(r.events), len(r.seen)
}

// Status is everything the interface shows about site activity.
//
// A SCREEN NEEDS THE REASON A NUMBER IS ABSENT, which an alert does not: an
// alert with no note simply has no note, while an operator looking at a panel
// with nothing in it is owed the difference between "this site is ordinary",
// "not enough history yet" and "we are not currently watching all of it".
type Status struct {
	// Saying is whether an alert right now would carry a sentence.
	Saying bool

	// Silent is why not, in one clause, when Saying is false and the reason
	// is this product rather than the site.
	Silent string

	Events  int
	Devices int

	Stats   Stats
	Slot    Slot
	Verdict Verdict

	// Sentence is what an alert would carry, "" when nothing would be said.
	Sentence string

	// Recent is the last few completed buckets, oldest first, so a surge can
	// be seen as a shape rather than read as a claim.
	Recent []Bucket
}

// Status answers what the interface shows.
func (r *Reporter) Status(at time.Time) Status {
	now := r.now()
	st := Status{Slot: SlotFor(now, r.site), Stats: r.Stats(now)}
	st.Events, st.Devices = r.Window()
	st.Verdict = Judge(st.Events, st.Devices, st.Stats)

	if r.store != nil {
		// Six buckets is the last hour: long enough to show a shape, short
		// enough that the row is readable on a phone.
		if got, err := r.store.Buckets(now.Add(-6*Width).Truncate(Width), now.Truncate(Width)); err == nil {
			st.Recent = got
		}
	}

	switch {
	case now.Sub(r.startedAt) < Width:
		st.Silent = "not long enough since this started to measure ten minutes of it"
		return st
	case r.isBlind(now):
		st.Silent = "a source is not reporting, so this would measure what still " +
			"reaches us rather than the site"
		return st
	}

	st.Saying = true
	st.Sentence = Sentence(st.Events, st.Devices, st.Stats, st.Slot, st.Verdict)
	return st
}

func (r *Reporter) isBlind(now time.Time) bool {
	since, blindNow := r.blind()
	return blindNow || (!since.IsZero() && now.Sub(since) < Width)
}

// Note is the sentence for an alert, or "" when there is nothing honest to
// say.
//
// THREE SILENCES, and each is a case where a sentence would be worse than
// none:
//
// Under one window of uptime, the trailing ten minutes includes time nobody
// was watching, so the count is a fraction presented as a total.
//
// While this product is blind -- a source deadman tripped, a socket dead --
// the count is not a measurement of the site but of what still reaches us.
// "Unusually quiet" is then the product reporting its own failure as the
// site's condition, which is the precise inversion this whole product exists
// to prevent.
//
// And when the baseline has not been earned, there is a count but no
// comparison; the sentence says so rather than implying one.
func (r *Reporter) Note(at time.Time) string {
	return r.Status(at).Sentence
}

// Stats reads the baseline for the slot containing at.
func (r *Reporter) Stats(at time.Time) Stats {
	if r.store == nil {
		return Stats{}
	}
	buckets, err := r.store.Buckets(at.Add(-Retention), at)
	if err != nil {
		// A baseline that could not be read is not a baseline of zero. The
		// sentence falls back to "no typical figure yet", which is true.
		return Stats{}
	}
	return Baseline(buckets, SlotFor(at, r.site), r.site)
}

// BucketsIn reads stored buckets in a span, for a caller that needs the row as
// it was written rather than as it was accumulated.
func (r *Reporter) BucketsIn(from, to time.Time) ([]Bucket, error) {
	if r.store == nil {
		return nil, nil
	}
	return r.store.Buckets(from, to)
}

// JudgeClosed decides what a completed bucket was, for flagging.
//
// The same function the alert uses, against the baseline as it stood when the
// bucket closed -- so a stretch is judged by the history before it rather than
// by a history it has already joined.
func (r *Reporter) JudgeClosed(b Bucket) Verdict {
	if b.Degraded {
		// Already excluded permanently; flagging it as well would say
		// something about the site that was really about us.
		return Ordinary
	}
	st := r.Stats(b.Start)
	return Judge(b.Events, b.Devices, st)
}
