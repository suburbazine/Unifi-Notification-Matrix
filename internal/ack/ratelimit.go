package ack

import (
	"sync"
	"time"
)

// THE ONE PORT THAT FACES THE INTERNET.
//
// Everything else in this product is reachable only from the LAN. An
// acknowledgement has to be tappable from a phone on mobile data at 3am, so
// this port gets forwarded, and a forwarded port is found by background
// scanning within days and then probed indefinitely. It will be hammered; the
// question is only what that costs.
//
// A limit here can be far tighter than one on an API, because the legitimate
// traffic is unusually well understood. A human receives one alert, opens one
// link and taps one button: two requests, seconds apart, then nothing for
// hours. Nothing real arrives in a sustained stream.
//
// What this protects is NOT this endpoint. A refused acknowledgement is
// cheap and recoverable. It protects the rest of the daemon: this handler
// shares a process, a SQLite connection pool and a write lock with the
// escalation engine, and the failure worth preventing is an alarm that cannot
// be delivered because the ack port is busy.

// DefaultBurst is how many requests one source may make before it has to wait.
//
// Generous against real use -- a person needs two, and a handful more if they
// reload or share the link -- and nowhere near enough to be a load generator.
const DefaultBurst = 20

// DefaultRefill is how often one request is handed back.
//
// Six seconds is ten a minute sustained, which no human approaches and no
// scanner finds useful.
const DefaultRefill = 6 * time.Second

// maxSources bounds the table.
//
// Keyed by address, and the addresses come from whoever is calling, so an
// unbounded map here would be the memory exhaustion the limiter exists to
// prevent -- arriving through the limiter. At the cap the table is DROPPED
// rather than pruned by least-recently-used: eviction under a flood of
// distinct addresses costs a scan per request, and the flood is exactly when
// the cost lands. Dropping it hands everybody a fresh allowance, which is the
// limiter briefly being more generous rather than the daemon running out of
// memory.
const maxSources = 1 << 16

type bucket struct {
	tokens int
	last   time.Time
}

// limiter is a token bucket per source address.
type limiter struct {
	mu     sync.Mutex
	seen   map[string]*bucket
	burst  int
	refill time.Duration
}

func newLimiter(burst int, refill time.Duration) *limiter {
	if refill <= 0 {
		refill = DefaultRefill
	}
	return &limiter{seen: map[string]*bucket{}, burst: burst, refill: refill}
}

// allow reports whether this source may be answered now, and spends a token if
// so.
//
// now is passed rather than read so the handler's injected clock governs this
// too: a limiter reading the wall clock inside a test that controls time is a
// limiter nobody can test the expiry of.
func (l *limiter) allow(source string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.seen[source]
	if !ok {
		if len(l.seen) >= maxSources {
			l.seen = make(map[string]*bucket, 1024)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.seen[source] = b
	}

	// Refill by elapsed time, clamped. A clock that went backwards -- which on
	// a machine that just synchronised its time is not exotic -- must not
	// produce a negative refill and silently empty somebody's bucket.
	if elapsed := now.Sub(b.last); elapsed > 0 {
		if gained := int(elapsed / l.refill); gained > 0 {
			b.tokens += gained
			if b.tokens > l.burst {
				b.tokens = l.burst
			}
			// Advance only by what was actually converted into tokens, so a
			// remainder short of one refill is not thrown away and a caller
			// sending just under the rate is never starved.
			b.last = b.last.Add(time.Duration(gained) * l.refill)
		}
	} else if elapsed < 0 {
		b.last = now
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// size reports how many sources are being tracked. For tests.
func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.seen)
}
