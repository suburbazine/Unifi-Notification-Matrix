package link

import (
	"errors"
	"sync"
	"time"
)

// PerPeerRate is how many requests one paired peer may make in a minute.
//
// 120 is the figure the three products agreed, and it is not a tuning
// parameter arrived at by guessing. A peer's measured load on a busy site is
// about half a request an hour for events, plus one heartbeat every five
// minutes: call it thirteen an hour at the top of the range. The limit sits
// roughly five hundred times above that.
//
// Which is the point. A limit close to real load throttles the operator's own
// product during the one hour it matters -- an alarm storm at three in the
// morning is exactly when a peer legitimately sends more than usual, and a
// limiter that trips then has taken the side of the attacker. This one cannot
// be reached by anything that is working correctly, so tripping it means a
// loop, a broken retry, or somebody with a credential they should not have.
const PerPeerRate = 120

// RateWindow is the period PerPeerRate is counted over.
//
// A fixed window rather than a token bucket, on purpose: the worst case is
// that a peer sends 120 at the end of one window and 120 at the start of the
// next, which is 240 in a moment and still nothing. Buying smoothness here
// would cost a structure somebody has to understand later.
const RateWindow = time.Minute

// ErrRateLimited is returned when a peer exceeds PerPeerRate.
var ErrRateLimited = errors.New("link: peer is sending faster than the agreed rate")

// limiter counts requests per paired peer.
//
// COUNTED AFTER AUTHENTICATION, which is the whole design and the opposite of
// what is obvious. Limiting on the link id in the HEADER would mean anybody
// who can reach the port can name a real peer and exhaust its allowance --
// turning a protection into a way to silence the doors from outside. The same
// reasoning the replay cache already uses for consuming a nonce last.
//
// The cost is that an unauthenticated flood still pays for a signature scan
// before being refused. That is a connection-level problem with a
// connection-level answer, and pretending to solve it here would mean
// accepting the header as identity, which is worse than not solving it.
type limiter struct {
	mu     sync.Mutex
	counts map[string]*rateCount
}

type rateCount struct {
	windowStart time.Time
	n           int
}

func newLimiter() *limiter {
	return &limiter{counts: map[string]*rateCount{}}
}

// allow records a request and reports whether it is within the rate.
func (l *limiter) allow(linkID string, now time.Time, limit int, window time.Duration) bool {
	if limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	c := l.counts[linkID]
	if c == nil {
		// Unbounded only in the number of PAIRED peers, which is a number the
		// operator sets by pairing and cannot be grown from outside: this is
		// only ever reached with an authenticated link id.
		c = &rateCount{windowStart: now}
		l.counts[linkID] = c
	}
	if now.Sub(c.windowStart) >= window {
		c.windowStart = now
		c.n = 0
	}
	c.n++
	return c.n <= limit
}
