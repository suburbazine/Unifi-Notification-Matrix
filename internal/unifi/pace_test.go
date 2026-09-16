package unifi

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"
)

// The pacer sits UNDER the console's measured ceiling, not at it. The rate
// window is server-side and its phase is unknown, so pacing exactly at the
// limit still trips whenever a burst straddles a boundary.
func TestTheDefaultIntervalSitsUnderTheConsoleCeiling(t *testing.T) {
	const measuredCeiling = 10.0 // requests per second, measured

	rate := float64(time.Second) / float64(PaceInterval)
	if rate >= measuredCeiling {
		t.Fatalf("PaceInterval %s is %.2f req/s, at or above the measured ceiling of %.0f", PaceInterval, rate, measuredCeiling)
	}
	if rate < measuredCeiling/4 {
		t.Fatalf("PaceInterval %s is %.2f req/s, so far under the ceiling that a reconciliation sweep of a real site would crawl", PaceInterval, rate)
	}
}

// This is the test the whole design of Wait exists for.
//
// The naive pacer -- read the timestamp, unlock, sleep until it -- has every
// waiter read the same stale value and depart together. It looks paced in
// source and arrives at the console as a burst, and the only thing that can
// tell the two implementations apart is launching N waiters at once and
// measuring when they actually left.
func TestConcurrentWaitersAreSpacedRatherThanReleasedTogether(t *testing.T) {
	const (
		n        = 8
		interval = 20 * time.Millisecond
	)
	p := NewPacer(interval)

	departures := make([]time.Duration, n)
	start := time.Now()

	var wg sync.WaitGroup
	// A start gate, so the waiters really are concurrent: staggered arrivals
	// would space themselves and prove nothing.
	gate := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-gate
			if err := p.Wait(context.Background()); err != nil {
				t.Errorf("Wait: %v", err)
				return
			}
			departures[i] = time.Since(start)
		}(i)
	}
	close(gate)
	wg.Wait()

	sort.Slice(departures, func(a, b int) bool { return departures[a] < departures[b] })

	// The last of n waiters cannot depart before (n-1) intervals have passed.
	// A burst implementation puts every one of them inside one interval.
	last := departures[n-1]
	floor := time.Duration(n-1) * interval
	if last < floor*8/10 {
		t.Fatalf("the last of %d concurrent waiters departed after %s; %d intervals is %s, so they left as a burst: %v",
			n, last, n-1, floor, departures)
	}

	// And they are spaced from each other, not merely spread out overall.
	for i := 1; i < n; i++ {
		gap := departures[i] - departures[i-1]
		if gap < interval/2 {
			t.Fatalf("waiters %d and %d departed %s apart, under half the %s interval: %v", i-1, i, gap, interval, departures)
		}
	}
}

// An idle pacer must not accumulate credit and then release a burst.
func TestAnIdlePacerDoesNotBankSlots(t *testing.T) {
	const interval = 20 * time.Millisecond
	p := NewPacer(interval)

	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * interval)

	// After a long idle the next caller goes immediately...
	start := time.Now()
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > interval/2 {
		t.Fatalf("a caller arriving at an idle pacer waited %s", d)
	}
	// ...and the one after it still waits a full interval, rather than
	// cashing in the four intervals nobody used.
	start = time.Now()
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < interval/2 {
		t.Fatalf("the following caller waited only %s; idle time was banked as credit", d)
	}
}

func TestWaitStopsWhenTheContextDoes(t *testing.T) {
	p := NewPacer(10 * time.Second)
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := p.Wait(ctx); err == nil {
		t.Fatal("Wait returned nil after its context expired; a shutdown would block for the whole interval")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Wait took %s to notice a cancelled context", d)
	}
}

func TestAnAlreadyCancelledContextNeverDeparts(t *testing.T) {
	p := NewPacer(time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Wait(ctx); err == nil {
		t.Fatal("Wait let a request through on a cancelled context")
	}
}

// One pacer per CONSOLE, not per client. Three independently paced clients
// against one UniFi OS host multiply the request rate by three against a
// single shared server-side budget.
func TestOneHostYieldsOnePacerHoweverItIsSpelled(t *testing.T) {
	spellings := []string{
		"console-under-test.invalid",
		"https://console-under-test.invalid",
		"https://console-under-test.invalid:443",
		"wss://Console-Under-Test.INVALID:443",
		"https://console-under-test.invalid:443/proxy/protect/integration/v1/cameras",
	}

	first := PacerFor(spellings[0])
	for _, s := range spellings[1:] {
		if got := PacerFor(s); got != first {
			t.Fatalf("PacerFor(%q) returned a second pacer for the same console; the request rate against it just doubled", s)
		}
	}

	if PacerFor("other-console.invalid") == first {
		t.Fatal("two different consoles were given the same pacer; one console's burst would throttle the other")
	}

	// A non-default port is a different endpoint and keeps its own pacer.
	if PacerFor("console-under-test.invalid:8443") == first {
		t.Fatal("an explicit non-default port collapsed onto the default-port console")
	}
}

func TestTheSharedRegistryIsSafeUnderConcurrentFirstUse(t *testing.T) {
	const n = 32
	got := make([]*Pacer, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i] = PacerFor("race-console.invalid")
		}(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if got[i] != got[0] {
			t.Fatal("concurrent first use produced more than one pacer for a single console")
		}
	}
}

func TestANonPositiveIntervalFallsBackToTheConsoleDefault(t *testing.T) {
	if got := NewPacer(0).Interval(); got != PaceInterval {
		t.Fatalf("NewPacer(0).Interval() = %s, want %s -- unset must not silently mean unpaced", got, PaceInterval)
	}
	if got := NewPacer(-time.Second).Interval(); got != PaceInterval {
		t.Fatalf("NewPacer(-1s).Interval() = %s, want %s", got, PaceInterval)
	}
}
