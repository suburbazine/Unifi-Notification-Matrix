package unifi

import (
	"net/http"
	"testing"
	"time"
)

// Full jitter can return ~0 and re-fire instantly, which against a rate
// limiter is exactly the behaviour backoff exists to prevent. Half jitter
// cannot: the floor is always half the ladder value.
func TestHalfJitterNeverCollapsesToZero(t *testing.T) {
	b := Backoff{Base: time.Second, Max: 32 * time.Second, Rand: func() float64 { return 0 }}

	// The pathological draw: a full-jitter implementation returns 0 here and
	// reconnects with no delay at all.
	for attempt := 1; attempt <= 10; attempt++ {
		got := b.Delay(attempt)
		if got <= 0 {
			t.Fatalf("attempt %d with rand()=0 returned %v; a zero delay is a reconnect storm", attempt, got)
		}
		if got < b.Base/2 {
			t.Fatalf("attempt %d returned %v, below the half-jitter floor of %v", attempt, got, b.Base/2)
		}
	}
}

// The contract, stated once: the result is always within [d/2, d).
func TestEveryDelayLandsInsideItsHalfJitterBand(t *testing.T) {
	const (
		base = 1 * time.Second
		max  = 30 * time.Second
	)
	rands := []float64{0, 0.25, 0.5, 0.999999}

	for attempt := 1; attempt <= 12; attempt++ {
		want := base
		for i := 1; i < attempt; i++ {
			want *= 2
			if want > max {
				want = max
				break
			}
		}
		if want > max {
			want = max
		}

		for _, r := range rands {
			got := Backoff{Base: base, Max: max, Rand: func() float64 { return r }}.Delay(attempt)
			if got < want/2 {
				t.Errorf("attempt %d rand %v: %v is below the band [%v,%v)", attempt, r, got, want/2, want)
			}
			if got >= want && want > 1 {
				t.Errorf("attempt %d rand %v: %v is at or above the band top %v", attempt, r, got, want)
			}
			if got > max {
				t.Errorf("attempt %d rand %v: %v exceeds the cap %v", attempt, r, got, max)
			}
		}
	}
}

// Jitter at all is mandatory because a console restart drops every client at
// the same instant. Two clients backing off must not return together.
func TestBackoffIsActuallyJittered(t *testing.T) {
	seen := map[time.Duration]bool{}
	vals := []float64{0.01, 0.31, 0.62, 0.93}
	for _, v := range vals {
		seen[Backoff{Base: time.Second, Max: time.Minute, Rand: func() float64 { return v }}.Delay(5)] = true
	}
	if len(seen) < len(vals) {
		t.Fatalf("jitter collapsed %d distinct draws into %d delays", len(vals), len(seen))
	}
}

func TestTheZeroBackoffIsTheConsoleDefaultLadder(t *testing.T) {
	var b Backoff
	b.Rand = func() float64 { return 0 }

	if got, want := b.Delay(1), DefaultBackoffBase/2; got != want {
		t.Fatalf("first attempt = %v, want the floor of the %v base ladder (%v)", got, DefaultBackoffBase, want)
	}
	for attempt := 1; attempt <= 20; attempt++ {
		if got := b.Delay(attempt); got > DefaultBackoffMax {
			t.Fatalf("attempt %d = %v, past the %v cap", attempt, got, DefaultBackoffMax)
		}
	}
	// And it reaches the cap rather than stalling short of it.
	if got := b.Delay(20); got < DefaultBackoffMax/2 {
		t.Fatalf("attempt 20 = %v, nowhere near the %v cap", got, DefaultBackoffMax)
	}
}

func TestBackoffToleratesAnOutOfRangeGenerator(t *testing.T) {
	for _, r := range []float64{-5, 1, 42} {
		got := Backoff{Base: time.Second, Max: time.Minute, Rand: func() float64 { return r }}.Delay(3)
		if got <= 0 || got > time.Minute {
			t.Fatalf("rand()=%v produced %v, outside every sane bound", r, got)
		}
	}
}

func TestBackoffWithNoGeneratorStillJitters(t *testing.T) {
	b := Backoff{Base: time.Second, Max: time.Minute}
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		seen[b.Delay(5)] = true
	}
	if len(seen) < 2 {
		t.Fatal("a Backoff with no injected generator produced a single fixed delay; every dropped client returns together")
	}
}

func TestAnAttemptBelowOneIsTreatedAsTheFirst(t *testing.T) {
	b := Backoff{Base: time.Second, Max: time.Minute, Rand: func() float64 { return 0 }}
	if b.Delay(0) != b.Delay(1) || b.Delay(-7) != b.Delay(1) {
		t.Fatal("a non-positive attempt must behave as the first attempt, not as an empty ladder")
	}
}

// Retry-After is honoured only in its delta-seconds form and only within a
// sane bound. The HTTP-date form needs both clocks to agree, and the console
// most likely to send one is the one that just rebooted.
func TestRetryAfterIsHonouredOnlyInItsDeltaSecondsForm(t *testing.T) {
	tests := []struct {
		name   string
		header string
		wantOK bool
		wantAt time.Duration // the floor, before jitter
	}{
		{"delta seconds are honoured", "20", true, 20 * time.Second},
		{"the bound itself is honoured", "30", true, 30 * time.Second},
		{"one second past the bound is not", "31", false, 0},
		{"an HTTP-date is ignored rather than trusted", "Wed, 21 Oct 2026 07:28:00 GMT", false, 0},
		{"an absurd delay is ignored: a watchdog that sleeps for hours is not one", "36000", false, 0},
		{"zero is ignored", "0", false, 0},
		{"a negative value is ignored", "-10", false, 0},
		{"junk is ignored", "soon", false, 0},
		{"no header at all", "", false, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			if tc.header != "" {
				resp.Header.Set("Retry-After", tc.header)
			}
			got, ok := RetryAfter(resp, func() float64 { return 0.5 })
			if ok != tc.wantOK {
				t.Fatalf("honoured = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got < tc.wantAt {
				t.Fatalf("delay %v is shorter than the advised %v", got, tc.wantAt)
			}
			if got > tc.wantAt*2 {
				t.Fatalf("delay %v is far beyond the advised %v", got, tc.wantAt)
			}
		})
	}

	// Jitter on top matters: the console advised the same delay to every client
	// it just dropped, and they must not all come back together.
	a, _ := RetryAfter(retryAfterHeader("20"), func() float64 { return 0.1 })
	b, _ := RetryAfter(retryAfterHeader("20"), func() float64 { return 0.9 })
	if a == b {
		t.Fatal("an advised delay was obeyed with no jitter; every dropped client returns in the same instant")
	}
	if a < 20*time.Second || b < 20*time.Second {
		t.Fatal("jitter must be added to the advised delay, never subtracted from it")
	}
}

func retryAfterHeader(v string) *http.Response {
	r := &http.Response{Header: http.Header{}}
	r.Header.Set("Retry-After", v)
	return r
}

func TestANilResponseCarriesNoAdvice(t *testing.T) {
	if _, ok := RetryAfter(nil, nil); ok {
		t.Fatal("a failed dial with no response must not produce an advised delay")
	}
}
