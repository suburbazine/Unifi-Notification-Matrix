// Package unifi is the shared per-console layer: pacing, backoff and TLS with
// certificate pinning.
//
// It exists because this product talks to three applications -- Protect,
// Access and Network -- that live behind ONE UniFi OS host. The console
// rate-limits per host, presents one certificate per host, and reboots as one
// host. Anything that is a property of the console rather than of an
// application belongs here so that adding the second and third client cannot
// quietly triple the request rate or introduce a second, differently-pinned
// view of the same certificate.
//
// The reasoning behind every rule in this package is recorded in
// docs/DESIGN-RULES.md §1. The rule is the summary; the reason is the part
// worth arguing with.
package unifi

import (
	"context"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PaceInterval is the minimum spacing between requests to one console:
// ~4.5 requests per second against a measured ceiling of about 10.
//
// UNDER the limit, not at it. The rate window is server-side and its phase is
// unknown to us, so a client pacing exactly at the observed limit still trips
// the limiter whenever a burst straddles a window boundary. The margin buys
// nothing but not being rate-limited, which is the entire point.
const PaceInterval = 220 * time.Millisecond

// Pacer spaces requests to a single console.
//
// The zero value is not usable; call NewPacer, or PacerFor to get the shared
// one for a host.
type Pacer struct {
	interval time.Duration

	mu sync.Mutex
	// next is the earliest instant the next caller may depart. It is written
	// UNDER the mutex by every caller, which is what makes the reservation a
	// reservation rather than a suggestion.
	next time.Time

	// now is injectable for tests. Sleeping is not: a test that fakes the
	// sleep proves nothing about whether callers were actually spaced.
	now func() time.Time
}

// NewPacer returns a pacer spacing departures by interval.
//
// A non-positive interval gets PaceInterval, because "unset" and "no pacing at
// all" must not be the same value: the second one is a decision and has to be
// spelled out by using no pacer.
func NewPacer(interval time.Duration) *Pacer {
	if interval <= 0 {
		interval = PaceInterval
	}
	return &Pacer{interval: interval, now: time.Now}
}

// Interval is the spacing this pacer enforces.
func (p *Pacer) Interval() time.Duration { return p.interval }

// Wait blocks until this caller's reserved slot, or until ctx is done.
//
// The slot is RESERVED UNDER THE MUTEX AND SLEPT OUTSIDE IT. The obvious
// alternative -- read the timestamp, unlock, sleep until it -- has N
// goroutines all read the same stale value, all compute the same target and
// all depart in the same instant. That code looks paced when you read it and
// arrives at the console as a burst, which is precisely the failure the pacer
// exists to prevent. Reserving first means the Nth concurrent caller leaves at
// N-1 intervals, whatever order they arrived in.
//
// A cancelled context still consumes the slot. That is deliberate and it errs
// the safe way: the alternative is handing the abandoned slot to the next
// caller, who then departs early.
func (p *Pacer) Wait(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	p.mu.Lock()
	now := p.now()
	slot := p.next
	if slot.Before(now) {
		// Idle long enough that the previous reservation has expired; this
		// caller goes now and the next one goes an interval later.
		slot = now
	}
	p.next = slot.Add(p.interval)
	p.mu.Unlock()

	d := slot.Sub(now)
	if d <= 0 {
		return nil
	}

	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

var (
	pacersMu sync.Mutex
	pacers   = map[string]*Pacer{}
)

// PacerFor returns THE pacer for a console host, creating it on first use.
//
// One pacer per console, not per client. This product runs Protect, Access and
// Network clients against a single UniFi OS host; three independently paced
// clients multiply the request rate by three against one shared server-side
// budget, and each of them looks correct in isolation. A registry keyed by
// host means a new caller cannot accidentally create a second pacer -- the
// only thing it can do is join the existing one.
//
// Calling this is the easy path on purpose. Constructing a private Pacer is
// possible and is a decision a reviewer should ask about.
func PacerFor(host string) *Pacer {
	key := ConsoleKey(host)

	pacersMu.Lock()
	defer pacersMu.Unlock()
	if p, ok := pacers[key]; ok {
		return p
	}
	p := NewPacer(PaceInterval)
	pacers[key] = p
	return p
}

// ConsoleKey normalises a host into the identity of one console.
//
// "10.0.0.1", "https://10.0.0.1", "wss://10.0.0.1:443/proxy/protect/..." and
// "HTTPS://10.0.0.1:443" are one console and must share one pacer and one
// certificate pin. Anything that fails to normalise is used verbatim rather
// than discarded: an unparseable host that gets its own pacer is worse than
// ideal, but an unparseable host that collides with every other unparseable
// host is worse still.
func ConsoleKey(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}
	if !strings.Contains(h, "://") {
		h = "https://" + h
	}
	u, err := url.Parse(h)
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimSpace(host))
	}

	name := strings.ToLower(u.Hostname())
	port := u.Port()
	switch port {
	case "", "443":
		// The console's own port. Every application behind it answers here, so
		// the default and the explicit form are the same console.
		return name
	}
	// JoinHostPort rather than concatenation, so an IPv6 literal keeps the
	// brackets that make it parseable again.
	return net.JoinHostPort(name, port)
}
