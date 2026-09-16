package unifi

import (
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// Backoff ladder bounds. A console restart is the common case these were
// chosen for: fast enough that a five-second blip costs one reconnect, slow
// enough that a console that is still initialising is not hammered.
const (
	DefaultBackoffBase = 500 * time.Millisecond
	DefaultBackoffMax  = 5 * time.Second
)

// Backoff is an exponential ladder with HALF jitter.
//
// Half, not full. Full jitter can return a value near zero and re-fire
// immediately, which against a rate limiter is exactly the behaviour a backoff
// exists to prevent. Jitter at all is mandatory: a console restart drops every
// client at the same instant, and an unjittered ladder brings them all back at
// the same instant too.
//
//	delay = d/2 + rand[0,1) * d/2      where d = min(Base * 2^(attempt-1), Max)
//
// so the result is always in [d/2, d) -- never zero, never past the cap.
//
// The zero value is usable and means Base=DefaultBackoffBase,
// Max=DefaultBackoffMax and the package random source.
type Backoff struct {
	Base time.Duration
	Max  time.Duration

	// Rand returns a value in [0,1). Injectable so tests are deterministic;
	// an out-of-range value from a caller-supplied generator is clamped rather
	// than trusted, because the alternative is a negative or unbounded sleep.
	Rand func() float64
}

// Delay returns the wait before attempt n (1-based).
func (b Backoff) Delay(attempt int) time.Duration {
	base := b.Base
	if base <= 0 {
		base = DefaultBackoffBase
	}
	max := b.Max
	if max <= 0 {
		max = DefaultBackoffMax
	}
	if max < base {
		max = base
	}
	if attempt < 1 {
		attempt = 1
	}

	d := base
	for i := 1; i < attempt; i++ {
		if d >= max/2 {
			d = max
			break
		}
		d *= 2
	}
	if d > max {
		d = max
	}

	half := d / 2
	if half <= 0 {
		half = 1
	}
	return half + time.Duration(jitter(b.Rand)*float64(half))
}

// jitter draws a value in [0,1), tolerating a generator that does not.
func jitter(rnd func() float64) float64 {
	if rnd == nil {
		rnd = rand.Float64
	}
	r := rnd()
	if r < 0 {
		return 0
	}
	if r >= 1 {
		return 0.999999
	}
	return r
}

// MaxRetryAfter bounds a server-advised delay.
//
// Thirty seconds, because a watchdog that obeys "come back in six hours" has
// stopped being a watchdog, and the console most likely to advise something
// absurd is the one that has just rebooted.
const MaxRetryAfter = 30 * time.Second

// RetryAfter honours a rejected response's Retry-After header, in its
// DELTA-SECONDS form only and only within MaxRetryAfter.
//
// The HTTP-date form is ignored entirely rather than parsed and bounded. It
// requires both clocks to agree, and the console most likely to send one is
// the one that just came back up with no NTP yet -- which is how an advisory
// "wait five seconds" becomes a wait until next Tuesday.
//
// Jitter is added on top of the advised delay, never subtracted from it. The
// console gave the same number to every client it just dropped, so obeying it
// exactly returns them all in the same instant, which is the stampede the
// advice existed to prevent.
func RetryAfter(resp *http.Response, rnd func() float64) (time.Duration, bool) {
	if resp == nil {
		return 0, false
	}
	raw := resp.Header.Get("Retry-After")
	if raw == "" {
		return 0, false
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return 0, false
	}
	d := time.Duration(secs) * time.Second
	if d > MaxRetryAfter {
		return 0, false
	}
	return d + time.Duration(jitter(rnd)*float64(d)/2), true
}
