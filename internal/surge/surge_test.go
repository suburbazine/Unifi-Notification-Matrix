package surge

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A Tuesday, 03:00 UTC.
var t0 = time.Date(2026, 9, 22, 3, 0, 0, 0, time.UTC)

type fakeStore struct {
	put []Bucket
	err error
}

func (f *fakeStore) PutBucket(b Bucket) error { f.put = append(f.put, b); return f.err }
func (f *fakeStore) Buckets(time.Time, time.Time) ([]Bucket, error) {
	return append([]Bucket(nil), f.put...), nil
}

func recorder(now *time.Time, blind *bool) (*Recorder, *fakeStore) {
	s := &fakeStore{}
	return NewRecorder(s, func() time.Time { return *now },
		func() bool { return blind != nil && *blind }), s
}

// ---------------------------------------------------------------- counting

// THE NUMBER THAT MATTERS. Fifty events from one flapping camera is not a
// surge; nine devices producing one each is the shape a jammer makes.
func TestOneNoisyThingIsOneDevice(t *testing.T) {
	now, blind := t0, false
	r, _ := recorder(&now, &blind)

	for i := 0; i < 50; i++ {
		r.Observe("protect/cam-1", t0)
	}
	got := r.Open()
	if got.Events != 50 || got.Devices != 1 {
		t.Errorf("open = %d events across %d devices, want 50 across 1", got.Events, got.Devices)
	}
}

// A repeated key must not inflate the count at the cap, where a map no longer
// makes that free.
func TestARepeatedDeviceDoesNotInflateTheCount(t *testing.T) {
	now, blind := t0, false
	r, _ := recorder(&now, &blind)

	for i := 0; i < maxEntities; i++ {
		r.Observe("thing-"+time.Duration(i).String(), t0)
	}
	full := r.Open().Devices
	for i := 0; i < 500; i++ {
		r.Observe("thing-0s", t0)
	}
	if got := r.Open().Devices; got != full {
		t.Errorf("devices went %d -> %d because one thing repeated itself", full, got)
	}
}

// ---------------------------------------------------------- complete buckets

// THE FIRST BUCKET AFTER A RESTART IS A FRACTION OF ITS SPAN, and a fraction
// written as a whole drags the baseline down every time the daemon restarts --
// which is every config change and every upgrade.
func TestThePartialBucketAtStartupIsNotWritten(t *testing.T) {
	now, blind := t0.Add(3*time.Minute), false // started mid-bucket
	r, s := recorder(&now, &blind)

	r.Observe("protect/cam-1", now)
	now = t0.Add(Width + time.Minute)
	r.Tick()

	for _, b := range s.put {
		if b.Start.Equal(t0) {
			t.Errorf("the bucket in progress at startup was written: %+v", b)
		}
	}
}

// And the next one, whose whole span was watched, is.
func TestTheFirstCompleteBucketIsWritten(t *testing.T) {
	now, blind := t0.Add(3*time.Minute), false
	r, s := recorder(&now, &blind)
	r.Observe("protect/cam-1", now)

	now = t0.Add(Width + time.Minute)
	r.Tick()
	r.Observe("protect/cam-2", now)

	now = t0.Add(2*Width + time.Minute)
	r.Tick()

	var found bool
	for _, b := range s.put {
		if b.Start.Equal(t0.Add(Width)) && b.Events == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("the first complete bucket was not written: %+v", s.put)
	}
}

// A QUIET STRETCH THIS PRODUCT WATCHED IN FULL IS A MEASUREMENT. The baseline
// has to know that two events at 3am is normal here, and it can only know that
// from the zeros.
func TestWatchedEmptyBucketsAreWritten(t *testing.T) {
	now, blind := t0, false
	r, s := recorder(&now, &blind)
	r.Tick() // opens at t0, complete from here
	r.Observe("protect/cam-1", t0)

	now = t0.Add(4 * Width)
	r.Tick()

	var zeros int
	for _, b := range s.put {
		if b.Events == 0 {
			zeros++
		}
	}
	if zeros != 3 {
		t.Errorf("wrote %d empty buckets across three watched empty spans: %+v", zeros, s.put)
	}
}

// A bucket this product was blind for is written -- the time was still
// watched by whatever was up -- and marked, so the baseline can refuse it.
func TestABlindBucketIsMarkedDegraded(t *testing.T) {
	now, blind := t0, false
	r, s := recorder(&now, &blind)
	r.Tick()
	r.Observe("protect/cam-1", t0)

	blind = true
	r.Observe("protect/cam-2", t0.Add(time.Minute))

	now = t0.Add(Width + time.Minute)
	blind = false
	r.Tick()

	if len(s.put) == 0 {
		t.Fatal("nothing was written")
	}
	if !s.put[0].Degraded {
		t.Error("a bucket during which this product was blind is not marked")
	}
}

// A late frame from a reconnect must not rewrite a number an alert has quoted.
func TestALateEventDoesNotRewriteAClosedBucket(t *testing.T) {
	now, blind := t0, false
	r, s := recorder(&now, &blind)
	r.Tick()
	r.Observe("protect/cam-1", t0)
	r.Observe("protect/cam-2", t0.Add(Width+time.Minute))
	r.Observe("protect/cam-3", t0) // arrives late

	if len(s.put) == 0 {
		t.Fatal("nothing was written")
	}
	if s.put[0].Events != 1 {
		t.Errorf("the closed bucket was rewritten: %+v", s.put[0])
	}
}

// A measurement failing is not an alarm failing.
func TestAFailedWriteCostsABucketAndNothingElse(t *testing.T) {
	now := t0
	s := &fakeStore{err: errors.New("disk full")}
	r := NewRecorder(s, func() time.Time { return now }, nil)
	r.Tick()
	r.Observe("protect/cam-1", t0)

	now = t0.Add(Width + time.Minute)
	r.Tick()
	r.Observe("protect/cam-2", now)

	if got := r.Open().Events; got != 1 {
		t.Errorf("recording stopped after a failed write: %d", got)
	}
}

// A machine without a battery-backed clock comes up in 1970 and NTP snaps it
// forward. The bucket straddling that describes a span that did not happen.
func TestAClockJumpDiscardsTheBucket(t *testing.T) {
	if !jumped(3*time.Hour, 4*time.Minute) {
		t.Error("a three-hour wall jump across a four-minute span was accepted")
	}
	if jumped(10*time.Minute+time.Second, 10*time.Minute) {
		t.Error("ordinary drift was treated as a jump")
	}
}

// ---------------------------------------------------------------- baseline

func slotBuckets(n int, at time.Time, events, devices int) []Bucket {
	var out []Bucket
	for i := 0; i < n; i++ {
		// One per day at the same hour, so every bucket lands in the slot.
		out = append(out, Bucket{
			Start: at.AddDate(0, 0, -i), Events: events, Devices: devices,
		})
	}
	return out
}

// A comparison this product has not earned is one it does not state.
func TestAThinBaselineIsNotEarned(t *testing.T) {
	st := Baseline(slotBuckets(10, t0, 3, 2), SlotFor(t0, time.UTC), time.UTC)
	if st.Earned {
		t.Error("ten samples was treated as a baseline")
	}
	if Judge(99, 99, st) != Ordinary {
		t.Error("an unearned baseline produced a verdict")
	}
}

// One party evening must not move what is typical.
func TestOneHugeStretchDoesNotMoveTheMedian(t *testing.T) {
	buckets := slotBuckets(40, t0, 3, 2)
	buckets[0].Events, buckets[0].Devices = 400, 30

	st := Baseline(buckets, SlotFor(t0, time.UTC), time.UTC)
	if st.MedianEvents != 3 || st.MedianDevices != 2 {
		t.Errorf("median moved to %d across %d", st.MedianEvents, st.MedianDevices)
	}
}

// A blind stretch is not a new normal, however much of the history it covers.
func TestDegradedBucketsAreNeverUsed(t *testing.T) {
	buckets := slotBuckets(40, t0, 3, 2)
	for i := range buckets {
		if i%2 == 0 {
			buckets[i].Degraded = true
			buckets[i].Events, buckets[i].Devices = 0, 0
		}
	}
	st := Baseline(buckets, SlotFor(t0, time.UTC), time.UTC)
	if st.MedianEvents != 3 {
		t.Errorf("median = %d; blind zeros reached the baseline", st.MedianEvents)
	}
}

// THE RE-ADMISSION CLAUSE. Ten new cameras double a site's volume; without
// this every bucket is flagged, the baseline never learns the new site, and
// every alert says "unusually busy" for ever.
func TestASiteThatChangedIsRelearned(t *testing.T) {
	buckets := slotBuckets(40, t0, 30, 9)
	for i := range buckets {
		buckets[i].Flagged = Busy // the new normal, flagged as it arrived
	}
	st := Baseline(buckets, SlotFor(t0, time.UTC), time.UTC)
	if st.MedianDevices != 9 {
		t.Errorf("median devices = %d; a changed site never became normal", st.MedianDevices)
	}
}

// While an attack, which is a few per cent of a slot, stays out of it.
func TestAnAttackDoesNotBecomeNormal(t *testing.T) {
	buckets := slotBuckets(40, t0, 3, 2)
	for i := 0; i < 6; i++ {
		buckets[i].Events, buckets[i].Devices, buckets[i].Flagged = 200, 25, Busy
	}
	st := Baseline(buckets, SlotFor(t0, time.UTC), time.UTC)
	if st.P90Devices > 3 {
		t.Errorf("P90 devices = %d; six flagged stretches poisoned the tail", st.P90Devices)
	}
}

// Saturday 10:00 and Tuesday 10:00 are different slots, which is the whole
// reason there are forty-eight of them.
func TestWeekendAndWeekdayAreDifferentSlots(t *testing.T) {
	sat := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	tue := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	if SlotFor(sat, time.UTC) == SlotFor(tue, time.UTC) {
		t.Error("a Saturday and a Tuesday at the same hour are the same slot")
	}
}

// ---------------------------------------------------------------- verdicts

func earned(medEv, p90Ev, medDev, p90Dev, p10Dev int) Stats {
	return Stats{
		Samples: 240, Earned: true, LearnedDays: 56,
		MedianEvents: medEv, P90Events: p90Ev,
		MedianDevices: medDev, P90Devices: p90Dev, P10Devices: p10Dev,
	}
}

func TestVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name            string
		events, devices int
		st              Stats
		want            Verdict
	}{
		// The motivating case: nine devices where two is normal.
		{"devices dropping together", 14, 9, earned(3, 8, 2, 4, 1), Busy},
		// The case that must never fire: one camera, fifty events.
		{"one flapping camera", 50, 1, earned(3, 8, 2, 4, 1), Ordinary},
		{"a camera and a coincidence", 50, 2, earned(3, 8, 2, 4, 1), Ordinary},
		// The usual devices, all far busier: the honest volume exception.
		{"everything busier than usual", 210, 11, earned(20, 45, 9, 12, 5), Busy},
		{"volume concentrated on four", 210, 4, earned(20, 45, 9, 12, 5), Ordinary},
		// A bursty slot: high, but not rare here.
		{"busy for a busy hour", 25, 9, earned(10, 60, 9, 12, 5), Ordinary},
		// Above the quantile and barely above typical: not visibly busy.
		{"a rounding error above typical", 521, 15, earned(500, 520, 14, 14, 10), Ordinary},
		// A busy site where the device count cannot double.
		{"a busy site gets busier", 60, 24, earned(30, 50, 15, 18, 10), Busy},
		// Small numbers.
		{"two events on a silent slot", 2, 2, earned(0, 1, 0, 1, 0), Ordinary},
		{"three devices on a silent slot", 3, 3, earned(0, 1, 0, 1, 0), Busy},
		// Quiet, which needs a slot with something to lose.
		{"a busy hour gone silent", 1, 1, earned(22, 60, 8, 12, 5), Quiet},
		{"nothing at all on a busy hour", 0, 0, earned(22, 60, 8, 12, 5), Quiet},
		{"nothing at all at 3am", 0, 0, earned(1, 3, 1, 2, 0), Ordinary},
		{"low volume, normal spread", 3, 6, earned(30, 60, 8, 12, 5), Ordinary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Judge(tc.events, tc.devices, tc.st); got != tc.want {
				t.Errorf("Judge(%d, %d) = %v, want %v", tc.events, tc.devices, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------- sentences

func TestSentences(t *testing.T) {
	slot := Slot{Hour: 3}
	for _, tc := range []struct {
		name            string
		events, devices int
		st              Stats
		v               Verdict
		want            string
	}{
		{
			"learning days", 4, 3,
			Stats{LearnedDays: 5, Samples: 30}, Ordinary,
			"Site activity: 4 events across 3 devices in the last 10 minutes; " +
				"no typical figure yet (5 of 14 days learned).",
		},
		{
			"learning this hour", 4, 3,
			Stats{LearnedDays: 20, Samples: 17}, Ordinary,
			"Site activity: 4 events across 3 devices in the last 10 minutes; " +
				"no typical figure for this hour yet (17 of 24 comparable stretches seen).",
		},
		{
			"ordinary", 4, 3, earned(3, 8, 2, 4, 1), Ordinary,
			"Site activity: 4 events across 3 devices in the last 10 minutes; " +
				"typical for a weekday at this hour is 3 across 2.",
		},
		{
			"busy on spread", 14, 9, earned(3, 8, 2, 4, 1), Busy,
			"Site unusually busy: 14 events across 9 devices in the last 10 minutes; " +
				"typical for a weekday at this hour is 3 across 2, and 9 of 10 such " +
				"stretches see 4 devices or fewer.",
		},
		{
			"busy on volume", 210, 11, earned(20, 45, 9, 12, 5), Busy,
			"Site unusually busy: 210 events across 11 devices in the last 10 minutes; " +
				"typical for a weekday at this hour is 20 across 9, and 9 of 10 such " +
				"stretches see 45 events or fewer.",
		},
		{
			"quiet", 1, 1, earned(22, 60, 8, 12, 5), Quiet,
			"Site unusually quiet: 1 event across 1 device in the last 10 minutes; " +
				"typical for a weekday at this hour is 22 across 8, and 9 of 10 such " +
				"stretches see at least 5 devices.",
		},
		{
			"quiet with nothing at all", 0, 0, earned(22, 60, 8, 12, 5), Quiet,
			"Site unusually quiet: no events in the last 10 minutes; typical for " +
				"a weekday at this hour is 22 across 8, and 9 of 10 such stretches " +
				"see at least 5 devices.",
		},
		{
			"a slot that is normally silent", 1, 1, earned(0, 1, 0, 1, 0), Ordinary,
			"Site activity: 1 event across 1 device in the last 10 minutes; " +
				"typical for a weekday at this hour is none.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Sentence(tc.events, tc.devices, tc.st, slot, tc.v)
			if got != tc.want {
				t.Errorf("\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// The justification must never contradict the count printed beside it.
func TestTheJustificationAgreesWithTheCount(t *testing.T) {
	st := earned(20, 45, 9, 12, 5)
	got := Sentence(210, 11, st, Slot{Hour: 3}, Busy)
	if !strings.Contains(got, "45 events or fewer") {
		t.Errorf("a volume verdict quoted the wrong quantile: %s", got)
	}
	if strings.Contains(got, "devices or fewer") {
		t.Errorf("a volume verdict quoted the device quantile, which 11 does not exceed: %s", got)
	}
}
