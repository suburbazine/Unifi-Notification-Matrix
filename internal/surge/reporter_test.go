package surge

import (
	"strings"
	"testing"
	"time"
)

func reporter(now *time.Time, blind *bool, history []Bucket) *Reporter {
	s := &fakeStore{put: history}
	r := NewReporter(s, time.UTC, func() time.Time { return *now },
		func() (time.Time, bool) { return time.Time{}, blind != nil && *blind })
	r.startedAt = (*now).Add(-time.Hour)
	return r
}

// THE FIGURE IS A TRAILING TEN MINUTES, not the open bucket. Quoting a bucket
// that opened forty seconds ago beside a ten-minute baseline compares two
// different spans, and makes a quiet site look dead every ten minutes on the
// dot.
func TestTheWindowTrailsRatherThanResetting(t *testing.T) {
	now := t0
	r := reporter(&now, nil, nil)

	r.Observe("protect/a", t0.Add(-9*time.Minute))
	r.Observe("protect/b", t0.Add(-time.Minute))
	if ev, dev := r.Window(); ev != 2 || dev != 2 {
		t.Errorf("window = %d across %d, want 2 across 2", ev, dev)
	}

	// Five minutes later the older one has fallen out of the window, and
	// nothing about a bucket boundary was involved.
	now = t0.Add(5 * time.Minute)
	if ev, dev := r.Window(); ev != 1 || dev != 1 {
		t.Errorf("window = %d across %d, want 1 across 1", ev, dev)
	}
}

// Under one window of uptime the trailing ten minutes includes time nobody was
// watching, so the count is a fraction presented as a total.
func TestNothingIsSaidBeforeTheFirstWindowHasPassed(t *testing.T) {
	now := t0
	r := reporter(&now, nil, nil)
	r.startedAt = t0.Add(-9 * time.Minute)

	if got := r.Note(now); got != "" {
		t.Errorf("said %q with nine minutes of uptime", got)
	}
	r.startedAt = t0.Add(-11 * time.Minute)
	if got := r.Note(now); got == "" {
		t.Error("said nothing with eleven minutes of uptime")
	}
}

// "UNUSUALLY QUIET" WHILE BLIND IS THE PRODUCT REPORTING ITS OWN FAILURE AS
// THE SITE'S CONDITION -- the precise inversion this product exists to
// prevent, and the source deadman is already saying the true thing.
func TestNothingIsSaidWhileBlind(t *testing.T) {
	now, blind := t0, true
	r := reporter(&now, &blind, nil)

	if got := r.Note(now); got != "" {
		t.Errorf("said %q while a source was known to be dead", got)
	}
	blind = false
	if got := r.Note(now); got == "" {
		t.Error("said nothing once the site was fully watched again")
	}
}

// A baseline that could not be read is not a baseline of zero.
func TestAnUnreadableHistoryDoesNotBecomeAComparison(t *testing.T) {
	now := t0
	r := reporter(&now, nil, nil)
	r.Observe("protect/a", now)

	got := r.Note(now)
	if !strings.Contains(got, "no typical figure") {
		t.Errorf("note = %q, want it to say the comparison is not earned", got)
	}
}

// A stretch is judged against the history BEFORE it, not one it has joined.
func TestAClosedBucketIsJudgedAgainstEarlierHistory(t *testing.T) {
	now := t0
	r := reporter(&now, nil, learnedHistory(20, 3, 2))

	if got := r.JudgeClosed(Bucket{Start: t0, Events: 14, Devices: 9}); got != Busy {
		t.Errorf("verdict = %v, want busy", got)
	}
	// And a blind bucket says nothing about the site, so it is not flagged as
	// though it did.
	if got := r.JudgeClosed(Bucket{Start: t0, Events: 0, Devices: 0, Degraded: true}); got != Ordinary {
		t.Errorf("a degraded bucket was flagged %v", got)
	}
}

// learnedHistory is what an earned baseline actually looks like: whole days of
// buckets, not one sample a day.
//
// The first version of this test handed the baseline forty buckets on forty
// consecutive days and expected a verdict. It got Ordinary, correctly: a day
// counts as learned only with half a day of buckets in it, so forty days of
// one bucket each is zero learned days. The test was wrong about what a
// baseline is, which is worth more than the assertion it was making.
func learnedHistory(days, events, devices int) []Bucket {
	var out []Bucket
	for d := 1; d <= days; d++ {
		day := t0.AddDate(0, 0, -d).Truncate(24 * time.Hour)
		for i := 0; i < 144; i++ {
			out = append(out, Bucket{
				Start:   day.Add(time.Duration(i) * Width),
				Events:  events,
				Devices: devices,
			})
		}
	}
	return out
}
