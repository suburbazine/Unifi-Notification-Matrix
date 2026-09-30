package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

// A paired peer's deadman.
//
// A DEAD SOURCE AND A QUIET SITE LOOK IDENTICAL FROM OUTSIDE, which is the
// sentence this product's own sources were built around. Peers were exempt by
// accident: their heartbeats landed only in a capability claim, so for a peer
// that claims nothing -- a loyalty system, a POS bridge, most of them -- a
// shop PC that died on Friday night was noticed by nothing, and every event it
// would have sent over the weekend simply did not exist. Found while answering
// the first two peers that claim nothing.
//
// For a peer that DOES claim a capability this is additional rather than
// redundant: losing the claim brings our native source back, which keeps the
// doors watched, but nobody was told that the peer had stopped.

// peerLiveness tracks when each paired peer was last heard from.
type peerLiveness struct {
	silentAfter time.Duration

	// windowFor is each peer's own window, when the operator set one. Nil,
	// or a zero answer, falls back to silentAfter.
	windowFor func(slug string) time.Duration

	// raise and resolve open and close the incident. Injected so the decision
	// can be tested without an engine.
	raise   func(ctx context.Context, slug, why string) error
	resolve func(ctx context.Context, slug string) error

	mu      sync.Mutex
	started time.Time
	last    map[string]time.Time
	raised  map[string]bool

	// gap is the longest wait between two contacts from each peer, over the
	// recent ones. It is what says, before anybody is paged, that a window is
	// shorter than the peer actually keeps to -- an older client still
	// heartbeating every five minutes against a two-minute window is
	// reported silent between every beat.
	gap map[string]time.Duration

	// told is the window that was in force at each peer's last contact --
	// which is the window its last reply told it to keep to. See check.
	told map[string]time.Duration
}

// slowestBeat is the slowest heartbeat any peer may be on: the rate a peer
// keeps when nobody has told it otherwise, and the ceiling on what it can be
// told. No peer can be required to make contact faster than this before it
// has had the chance to hear it should.
const slowestBeat = 5 * time.Minute

// observedGap is the longest recent wait between two contacts from a peer,
// and whether there has been enough contact to say.
func (l *peerLiveness) observedGap(slug string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	g, ok := l.gap[slug]
	return g, ok
}

// windowFor is REQUIRED, not an optional field set afterwards. It was a field,
// and the daemon wiring it up was one line no test could see: dropped, every
// peer fell back to the default window without a sound -- including a
// critical one set to two minutes. As a parameter, leaving it out does not
// compile. nil is still accepted, and means the default for everyone.
func newPeerLiveness(started time.Time, silentAfter time.Duration,
	windowFor func(slug string) time.Duration,
	raise func(context.Context, string, string) error,
	resolve func(context.Context, string) error) *peerLiveness {
	return &peerLiveness{
		silentAfter: silentAfter, windowFor: windowFor, raise: raise, resolve: resolve,
		started: started, last: map[string]time.Time{}, raised: map[string]bool{},
		gap: map[string]time.Duration{}, told: map[string]time.Duration{},
	}
}

// contact records that a peer was heard from, and closes its incident if one
// is open. Closed HERE rather than at the next check, because "it is back" is
// news worth delivering the moment it is true.
func (l *peerLiveness) contact(slug string, now time.Time) {
	window := l.window(slug) // outside the lock: it reads the configuration
	l.mu.Lock()
	l.told[slug] = window
	if prev, ok := l.last[slug]; ok && now.After(prev) {
		// Decays: a new gap replaces the recorded one unless it is longer,
		// and a recorded one is halved on each shorter gap, so a peer that
		// has since started keeping to a faster rate stops being flagged
		// within a few contacts rather than never.
		g := now.Sub(prev)
		if old := l.gap[slug]; g < old {
			g = max(g, old/2)
		}
		l.gap[slug] = g
	}
	l.last[slug] = now
	was := l.raised[slug]
	delete(l.raised, slug)
	l.mu.Unlock()

	if was && l.resolve != nil {
		_ = l.resolve(context.Background(), slug)
	}
}

// check raises for every paired peer that has gone quiet, and resolves for
// any that is no longer paired at all.
//
// A PEER NEVER HEARD FROM IS GIVEN A FULL WINDOW FROM WHEN THIS STARTED. The
// last contact before a restart is not remembered, and treating "not heard
// from yet" as "silent since forever" would raise for every peer on every
// start. Treating it as "fine" would never raise for a peer that died before
// the restart. The window from start is the only answer that is right both
// ways.
func (l *peerLiveness) check(ctx context.Context, paired []string, now time.Time) {
	type edge struct {
		slug, why string
		up        bool
	}
	var edges []edge

	l.mu.Lock()
	present := make(map[string]bool, len(paired))
	for _, slug := range paired {
		present[slug] = true
		if l.raised[slug] {
			continue // raised once; not re-raised every tick
		}
		since, heard := l.last[slug]
		if !heard {
			since = l.started
		}
		quiet := now.Sub(since)
		window := l.window(slug)

		// A PEER CANNOT BE HELD TO A WINDOW IT HAS NOT BEEN TOLD ABOUT.
		//
		// It learns its heartbeat rate from the replies to its own requests,
		// so a window shortened here reaches it at its next contact -- up to
		// one old interval away. Judged by the new window in the meantime, a
		// perfectly healthy peer is reported silent because the operator
		// changed a number. Found by the Rewards session in the live test,
		// before anybody was paged for it.
		//
		// So: until it has made contact under the current window, it is held
		// to the window that was in force when it last did. And one never
		// heard from since this started may be on any rate up to the slowest,
		// so it is given at least that, and a minute.
		if heard {
			if prev := l.told[slug]; prev > window {
				window = prev
			}
		} else if floor := slowestBeat + time.Minute; window < floor {
			window = floor
		}
		if quiet <= window {
			continue
		}
		beat := link.Peer{SilentAfter: window}.HeartbeatEvery()
		l.raised[slug] = true
		why := fmt.Sprintf("Nothing has arrived from %s for %s, against a window of %s. "+
			"It is asked to heartbeat every %s, so it has missed at least three: "+
			"whatever it would have sent in that time has not reached this product.",
			slug, quiet.Round(time.Second), window, beat)
		if !heard {
			why = fmt.Sprintf("Nothing has arrived from %s since this started %s ago. "+
				"It is paired, but it may have stopped before this did -- the last "+
				"contact before a restart is not remembered.",
				slug, quiet.Round(time.Minute))
		}
		edges = append(edges, edge{slug: slug, why: why})
	}
	// Unpaired while raised: the incident is about something that no longer
	// exists, and would escalate about it for ever.
	for slug := range l.raised {
		if !present[slug] {
			delete(l.raised, slug)
			delete(l.last, slug)
			edges = append(edges, edge{slug: slug, up: true})
		}
	}
	l.mu.Unlock()

	// Outside the lock: raising reaches the store and the engine, and a
	// contact arriving meanwhile must not wait behind them.
	for _, e := range edges {
		if e.up {
			if l.resolve != nil {
				_ = l.resolve(ctx, e.slug)
			}
			continue
		}
		if l.raise != nil {
			_ = l.raise(ctx, e.slug, e.why)
		}
	}
}

func (l *peerLiveness) run(ctx context.Context, paired func() []string, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			l.check(ctx, paired(), now)
		}
	}
}

// peerEntity is what a peer's silence is an incident about.
func peerEntity(slug string) event.Entity {
	return event.Entity{ID: "peer/" + slug, Name: slug + " (peer link)", Kind: "service"}
}

// peerSilentSeverity matches a native source going silent: the same fact,
// the same weight.
const peerSilentSeverity = incident.SeverityHigh

// window is a peer's configured window, or the default.
func (l *peerLiveness) window(slug string) time.Duration {
	if l.windowFor != nil {
		if w := l.windowFor(slug); w > 0 {
			return w
		}
	}
	return l.silentAfter
}
