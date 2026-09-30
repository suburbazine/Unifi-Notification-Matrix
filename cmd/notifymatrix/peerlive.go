package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
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

	// raise and resolve open and close the incident. Injected so the decision
	// can be tested without an engine.
	raise   func(ctx context.Context, slug, why string) error
	resolve func(ctx context.Context, slug string) error

	mu      sync.Mutex
	started time.Time
	last    map[string]time.Time
	raised  map[string]bool
}

func newPeerLiveness(started time.Time, silentAfter time.Duration,
	raise func(context.Context, string, string) error,
	resolve func(context.Context, string) error) *peerLiveness {
	return &peerLiveness{
		silentAfter: silentAfter, raise: raise, resolve: resolve,
		started: started, last: map[string]time.Time{}, raised: map[string]bool{},
	}
}

// contact records that a peer was heard from, and closes its incident if one
// is open. Closed HERE rather than at the next check, because "it is back" is
// news worth delivering the moment it is true.
func (l *peerLiveness) contact(slug string, now time.Time) {
	l.mu.Lock()
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
		if quiet <= l.silentAfter {
			continue
		}
		l.raised[slug] = true
		why := fmt.Sprintf("Nothing has arrived from %s for %s. It heartbeats every "+
			"five minutes, so it has missed at least three: whatever it would have "+
			"sent in that time has not reached this product.",
			slug, quiet.Round(time.Minute))
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
