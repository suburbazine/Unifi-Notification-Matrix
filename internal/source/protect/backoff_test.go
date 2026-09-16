package protect

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// Full jitter can return ~0 and re-fire instantly, which against a rate
// limiter is exactly the behaviour backoff exists to prevent. Half jitter
// cannot: the floor is always half the ladder value.
func TestHalfJitterNeverCollapsesToZero(t *testing.T) {
	const (
		base = 1 * time.Second
		max  = 32 * time.Second
	)

	// The pathological generator: a full-jitter implementation returns 0 here
	// and reconnects with no delay at all.
	for attempt := 1; attempt <= 10; attempt++ {
		got := backoffDelay(attempt, base, max, func() float64 { return 0 })
		if got <= 0 {
			t.Fatalf("attempt %d with rand()=0 returned %v; a zero delay is a reconnect storm", attempt, got)
		}
		if got < base/2 {
			t.Fatalf("attempt %d returned %v, which is below the half-jitter floor of %v", attempt, got, base/2)
		}
	}
}

func TestBackoffLadderStaysWithinItsBandAndCaps(t *testing.T) {
	const (
		base = 1 * time.Second
		max  = 30 * time.Second
	)
	rands := []float64{0, 0.5, 0.999999}

	for attempt := 1; attempt <= 12; attempt++ {
		// The undithered ladder value this attempt is drawn from.
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
			got := backoffDelay(attempt, base, max, func() float64 { return r })
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
		seen[backoffDelay(5, time.Second, time.Minute, func() float64 { return v })] = true
	}
	if len(seen) < len(vals) {
		t.Fatalf("jitter collapsed %d distinct draws into %d delays", len(vals), len(seen))
	}
}

func TestBackoffToleratesAnOutOfRangeGenerator(t *testing.T) {
	for _, r := range []float64{-5, 1, 42} {
		got := backoffDelay(3, time.Second, time.Minute, func() float64 { return r })
		if got <= 0 || got > time.Minute {
			t.Fatalf("rand()=%v produced %v, which is outside every sane bound", r, got)
		}
	}
}

// Some Protect URLs embed a path token that is all anyone on the network needs
// to watch a camera, so nothing past the authority ever reaches a log.
func TestRedactedURLKeepsOnlySchemeHostAndPort(t *testing.T) {
	u, err := url.Parse("wss://10.0.0.1:443/proxy/protect/integration/v1/subscribe/events?token=SUPERSECRET#frag")
	if err != nil {
		t.Fatal(err)
	}
	got := redactURL(u)
	const want = "wss://10.0.0.1:443"
	if got != want {
		t.Fatalf("redactURL = %q, want %q", got, want)
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
		{"delta seconds are honoured", "30", true, 30 * time.Second},
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
			got, ok := retryAfterDelay(resp, func() float64 { return 0.5 })
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
	a, _ := retryAfterDelay(header("20"), func() float64 { return 0.1 })
	b, _ := retryAfterDelay(header("20"), func() float64 { return 0.9 })
	if a == b {
		t.Fatal("an advised delay was obeyed with no jitter; every dropped client returns in the same instant")
	}
	if a < 20*time.Second || b < 20*time.Second {
		t.Fatal("jitter must be added to the advised delay, never subtracted from it")
	}
}

func header(v string) *http.Response {
	r := &http.Response{Header: http.Header{}}
	r.Header.Set("Retry-After", v)
	return r
}

func TestANilResponseCarriesNoAdvice(t *testing.T) {
	if _, ok := retryAfterDelay(nil, nil); ok {
		t.Fatal("a failed dial with no response must not produce an advised delay")
	}
}
