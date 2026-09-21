package surge

import (
	"sort"
	"time"
)

// Verdict is what a stretch of activity was judged to be.
type Verdict int

const (
	// Ordinary is the answer almost always, and the one that produces no
	// sentence at all.
	Ordinary Verdict = iota
	Busy
	Quiet
)

// The baseline's shape.
//
// SLOT = (weekday | weekend) x hour-of-day, in the SITE's clock. Forty-eight
// of them.
//
// Hour-of-day alone merges Saturday 10:00 into Tuesday 10:00, and on an
// office, a school or a shop those differ by an order of magnitude -- and the
// weekend is when the break-in happens. Hour-of-week is more accurate and gets
// six samples per slot per week, so a median needs a month and a half, over
// which a site's rhythm genuinely drifts. Weekday/weekend captures the
// dominant rhythm at thirty or twelve samples a week, and names a slot an
// operator can say out loud: "a weekday at this hour".
const (
	// Retention is how far back the baseline looks, and how long rows are
	// kept. At 144 buckets a day this caps the table at 8,064 rows for ANY
	// site, busy or quiet, because a row costs the same whether it holds zero
	// events or ten thousand. Under a megabyte.
	Retention = 56 * 24 * time.Hour

	// MinDays and MinBucketsPerDay are what makes a day count as learned. Half
	// a day of buckets, because one bucket does not make a day.
	MinDays          = 14
	MinBucketsPerDay = 72

	// MinSamples is the smallest slot worth quoting a quantile from.
	//
	// At 24, nearest-rank P90 sits on the third-highest sample rather than the
	// maximum. Below that, "nine of ten such stretches" is not a sentence the
	// data can support, and this product does not state comparisons it has not
	// earned.
	MinSamples = 24

	// FlaggedShare is when a slot stops excluding its own flagged rows.
	//
	// THE RE-ADMISSION CLAUSE. Without it the baseline freezes: ten new
	// cameras double a site's volume, every bucket is flagged as busy, the
	// baseline never learns the new site, and every alert says "unusually
	// busy" for ever. With it a real change is re-admitted within days, while
	// an hour-long attack is a few per cent of a slot and stays excluded for
	// its full retention.
	//
	// Below ten per cent the tails are still poisonable; above half the median
	// is. A quarter sits between those and is the knob to turn if a site
	// disagrees.
	FlaggedShare = 0.25
)

// Slot identifies a comparable stretch: a day type and an hour.
type Slot struct {
	Weekend bool
	Hour    int
}

// SlotFor returns the slot a time falls in, in the site's own clock.
func SlotFor(at time.Time, site *time.Location) Slot {
	if site != nil {
		at = at.In(site)
	}
	d := at.Weekday()
	return Slot{Weekend: d == time.Saturday || d == time.Sunday, Hour: at.Hour()}
}

// Name is how the slot is spoken in a sentence.
func (s Slot) Name() string {
	if s.Weekend {
		return "a weekend at this hour"
	}
	return "a weekday at this hour"
}

// Stats are what a slot's history says is typical.
type Stats struct {
	// Samples is how many usable buckets the figures came from. Reported so a
	// thin baseline can say so rather than quoting numbers it cannot support.
	Samples int

	MedianEvents  int
	P90Events     int
	MedianDevices int
	P90Devices    int
	P10Devices    int

	// Earned says the history is deep enough to compare against. When it is
	// false the sentence states the raw count and says what it is waiting for.
	Earned bool

	// LearnedDays and SlotSamples are what it is waiting for, so the sentence
	// can name the shortfall instead of being vague about it.
	LearnedDays int
}

// Baseline computes what is typical for one slot from a window of buckets.
//
// The statistic is the MEDIAN and empirical quantiles, not a mean and not a
// deviation. One party evening puts four hundred events into a slot and lifts
// its mean for eight weeks; and on a quiet site a mean of "0.3 events" is a
// number nobody can picture. Deviation is worse: on a zero-inflated series the
// median absolute deviation is zero, so every deviation-scaled test divides by
// zero on exactly the sites where the floors matter most.
//
// The quantile is what the test uses and what the sentence quotes, in words an
// operator can check: "nine of ten such stretches see four devices or fewer".
func Baseline(all []Bucket, slot Slot, site *time.Location) Stats {
	var (
		usable  []Bucket
		flagged int
		days    = map[string]int{}
	)
	for _, b := range all {
		if b.Degraded {
			// Never re-admitted. A blind stretch is not a new normal, however
			// much of the history it covers.
			continue
		}
		days[b.Start.In(siteOr(site)).Format("2006-01-02")]++
		if SlotFor(b.Start, site) != slot {
			continue
		}
		if b.Flagged != Ordinary {
			flagged++
		}
		usable = append(usable, b)
	}

	learned := 0
	for _, n := range days {
		if n >= MinBucketsPerDay {
			learned++
		}
	}

	// The re-admission clause: a slot whose flagged rows are more than a
	// quarter of it has probably changed rather than been attacked.
	keep := usable
	if len(usable) > 0 && float64(flagged)/float64(len(usable)) <= FlaggedShare {
		keep = keep[:0]
		for _, b := range usable {
			if b.Flagged == Ordinary {
				keep = append(keep, b)
			}
		}
	}

	st := Stats{Samples: len(keep), LearnedDays: learned}
	if len(keep) == 0 {
		return st
	}

	events := make([]int, 0, len(keep))
	devices := make([]int, 0, len(keep))
	for _, b := range keep {
		events = append(events, b.Events)
		devices = append(devices, b.Devices)
	}
	sort.Ints(events)
	sort.Ints(devices)

	st.MedianEvents = median(events)
	st.P90Events = quantile(events, 0.9)
	st.MedianDevices = median(devices)
	st.P90Devices = quantile(devices, 0.9)
	st.P10Devices = quantile(devices, 0.1)
	st.Earned = learned >= MinDays && len(keep) >= MinSamples
	return st
}

func siteOr(l *time.Location) *time.Location {
	if l == nil {
		return time.UTC
	}
	return l
}

// median is the upper-middle sample: always a value that actually occurred,
// and the conservative side when calling something busy.
func median(sorted []int) int {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[len(sorted)/2]
}

// quantile is nearest-rank: the smallest sample at or above the fraction.
// An integer that happened, rather than an interpolation between two that did.
func quantile(sorted []int, q float64) int {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(float64(len(sorted))*q + 0.9999)
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}
