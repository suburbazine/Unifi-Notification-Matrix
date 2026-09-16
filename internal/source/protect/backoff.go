package protect

import (
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// backoffDelay returns the next reconnect delay with HALF jitter.
//
// Half, not full. Full jitter can return a value near zero and re-fire
// immediately, which against a rate limiter is precisely the behaviour the
// backoff exists to prevent. Jitter at all is mandatory: a console restart
// drops every client at the same instant, and an unjittered ladder brings them
// all back at the same instant too.
//
//	delay = d/2 + rand[0,1) * d/2      where d = min(base * 2^(attempt-1), max)
//
// so the result is always in [d/2, d) -- never zero, never longer than the cap.
func backoffDelay(attempt int, base, max time.Duration, rnd func() float64) time.Duration {
	if base <= 0 {
		base = defaultMinBackoff
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

	r := 0.0
	if rnd != nil {
		r = rnd()
	}
	// A caller-supplied generator is not trusted to stay in range; an out-of
	// -range value would otherwise produce a negative or unbounded sleep.
	if r < 0 {
		r = 0
	}
	if r >= 1 {
		r = 0.999999
	}

	half := d / 2
	if half <= 0 {
		half = 1
	}
	return half + time.Duration(r*float64(half))
}

// maxRetryAfter bounds a server-advised delay. A console that has just
// rebooted is exactly the one most likely to advise something absurd, and a
// source that obeys "come back in six hours" has stopped being a watchdog.
const maxRetryAfter = 5 * time.Minute

// retryAfterDelay honours a rejected handshake's Retry-After header, in its
// DELTA-SECONDS form only.
//
// The HTTP-date form is deliberately ignored: it requires both clocks to
// agree, and the console most likely to send it is the one that just rebooted
// with no NTP yet, which is how an advisory "wait 5 seconds" becomes a wait
// until next Tuesday.
//
// Jitter is still added on top. The advised delay is identical for every
// client the console just dropped, so obeying it exactly brings them all back
// in the same instant -- which is the stampede the advice existed to prevent.
func retryAfterDelay(resp *http.Response, rnd func() float64) (time.Duration, bool) {
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
	if d > maxRetryAfter {
		return 0, false
	}

	r := 0.0
	if rnd != nil {
		r = rnd()
	}
	if r < 0 || r >= 1 {
		r = 0
	}
	return d + time.Duration(r*float64(d)/2), true
}

// redactURL renders a URL as scheme://host[:port] and nothing else.
//
// Protect's stream and snapshot URLs embed a path token that is all anyone on
// the network needs to watch a camera, so no path, query or fragment from this
// console ever reaches a log line or an error string. It costs nothing to
// apply the rule to every URL rather than only to the ones known to carry one.
func redactURL(u *url.URL) string {
	if u == nil {
		return "<nil>"
	}
	r := url.URL{Scheme: u.Scheme, Host: u.Host}
	return r.String()
}
