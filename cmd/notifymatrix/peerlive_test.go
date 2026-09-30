package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type liveRecorder struct {
	mu       sync.Mutex
	raised   []string
	why      []string
	resolved []string
}

func newLiveFixture(start time.Time) (*peerLiveness, *liveRecorder) {
	r := &liveRecorder{}
	l := newPeerLiveness(start, 16*time.Minute,
		func(_ context.Context, slug, why string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.raised = append(r.raised, slug)
			r.why = append(r.why, why)
			return nil
		},
		func(_ context.Context, slug string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.resolved = append(r.resolved, slug)
			return nil
		})
	return l, r
}

var liveT0 = time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)

// A PEER THAT CLAIMS NOTHING STILL HAS A DEADMAN.
//
// Heartbeats used to land only in a capability claim. For a peer that claims
// nothing -- the loyalty system, the POS bridge -- a shop PC that died was
// noticed by nothing, and every event it would have sent simply did not
// exist. A dead source and a quiet site look identical from outside, and this
// product exists to tell them apart.
func TestASilentPeerRaisesOnceAndClearsWhenItReturns(t *testing.T) {
	l, r := newLiveFixture(liveT0)
	paired := []string{"lsrewards"}
	ctx := context.Background()

	l.contact("lsrewards", liveT0)
	l.check(ctx, paired, liveT0.Add(10*time.Minute))
	if len(r.raised) != 0 {
		t.Fatal("raised for a peer heard from ten minutes ago; its window is sixteen")
	}

	l.check(ctx, paired, liveT0.Add(17*time.Minute))
	if len(r.raised) != 1 || r.raised[0] != "lsrewards" {
		t.Fatalf("raised = %v after 17 minutes of nothing, want [lsrewards] -- a dead "+
			"peer is noticed by nothing", r.raised)
	}

	// Once, not every tick.
	l.check(ctx, paired, liveT0.Add(18*time.Minute))
	l.check(ctx, paired, liveT0.Add(40*time.Minute))
	if len(r.raised) != 1 {
		t.Errorf("raised %d times; a silent peer is re-raised on every check", len(r.raised))
	}

	// Back: cleared at once, not at the next check.
	l.contact("lsrewards", liveT0.Add(41*time.Minute))
	if len(r.resolved) != 1 {
		t.Fatalf("resolved = %v after the peer came back, want it cleared immediately", r.resolved)
	}

	// And it can go silent again.
	l.check(ctx, paired, liveT0.Add(60*time.Minute))
	if len(r.raised) != 2 {
		t.Errorf("a peer that came back and went quiet again was not raised the second time")
	}
}

// A PEER NEVER HEARD FROM GETS A FULL WINDOW FROM START, which is the only
// answer that is right both ways: "silent since forever" raises for every
// peer on every restart, and "fine until heard from" never raises for a peer
// that died before this did.
func TestAPeerNeverHeardFromIsGivenAWindowFromStart(t *testing.T) {
	l, r := newLiveFixture(liveT0)
	ctx := context.Background()

	l.check(ctx, []string{"lsprotect"}, liveT0.Add(time.Minute))
	if len(r.raised) != 0 {
		t.Fatal("raised for a peer one minute after this started; every restart would " +
			"page about every peer")
	}
	l.check(ctx, []string{"lsprotect"}, liveT0.Add(20*time.Minute))
	if len(r.raised) != 1 {
		t.Fatal("a peer that has not been heard from since this started was never " +
			"raised: one that died before a restart is noticed by nothing")
	}
	if !strings.Contains(r.why[0], "since this started") {
		t.Errorf("the incident says %q; it should say the peer has not been heard from "+
			"since this started, which is a different claim from 'went quiet at noon'",
			r.why[0])
	}
}

// Unpaired while raised: the incident is about something that no longer
// exists and would otherwise escalate about it for ever.
func TestUnpairingASilentPeerResolvesItsIncident(t *testing.T) {
	l, r := newLiveFixture(liveT0)
	ctx := context.Background()

	l.check(ctx, []string{"lsrewards"}, liveT0.Add(20*time.Minute))
	if len(r.raised) != 1 {
		t.Fatal("setup: the silent peer was not raised")
	}
	l.check(ctx, nil, liveT0.Add(21*time.Minute))
	if len(r.resolved) != 1 || r.resolved[0] != "lsrewards" {
		t.Errorf("resolved = %v after the peer was unpaired, want [lsrewards]", r.resolved)
	}
}
