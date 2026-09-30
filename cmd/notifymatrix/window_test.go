package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

// A CRITICAL PEER'S CLAIM LAPSES AT ITS OWN WINDOW.
//
// A Sentry update bricked a site. For sixteen minutes -- the one window every
// peer shared -- Sentry still held Access, so this product's own Access
// ingest stood down, and nothing at all watched the doors. With Sentry given a
// two-minute window, our own source must be back at two minutes.
func TestACriticalPeersClaimLapsesAtItsOwnWindow(t *testing.T) {
	now := time.Now()
	peers := []link.Peer{
		{Slug: "sentry", LinkID: "lnk_S", Manifest: link.Manifest{Capability: "access"},
			SilentAfter: 2 * time.Minute},
		{Slug: "lsrewards", LinkID: "lnk_R"},
	}
	s := newLinkState(peers)
	c := s.claimFor(peers, "sentry")
	if c == nil {
		t.Fatal("setup: sentry has no claim")
	}
	ev := event.Event{Source: "access"}
	window := windowForCapability(peers, "access")
	if window != 2*time.Minute {
		t.Fatalf("the window for the peer holding access is %s, want its own 2m", window)
	}

	// Heartbeating every 40 s -- the rate it is asked for -- through the
	// resume hysteresis, as a real one does.
	var last time.Time
	for at := now; at.Before(now.Add(link.DefaultResumeAfter + time.Minute)); at = at.Add(40 * time.Second) {
		c.Heartbeat(at)
		last = at
	}
	if !s.suppressedByPeer(ev, last.Add(time.Second), window) {
		t.Fatal("setup: a healthy Sentry heartbeating on schedule is not holding access")
	}
	// Bricked: nothing more arrives.
	if s.suppressedByPeer(ev, last.Add(2*time.Minute+time.Second), window) {
		t.Error("two minutes into Sentry's silence, our own access events are still " +
			"held back; the doors are watched by nothing until the old sixteen minutes")
	}
}

// The deadman fires at each peer's own window, and only that peer's.
func TestEachPeerIsDeclaredSilentAtItsOwnWindow(t *testing.T) {
	l, r := newLiveFixture(liveT0)
	l.windowFor = func(slug string) time.Duration {
		if slug == "sentry" {
			return 2 * time.Minute
		}
		return 0 // the default
	}
	paired := []string{"sentry", "lsrewards"}
	l.contact("sentry", liveT0)
	l.contact("lsrewards", liveT0)

	l.check(context.Background(), paired, liveT0.Add(2*time.Minute+30*time.Second))
	if len(r.raised) != 1 || r.raised[0] != "sentry" {
		t.Fatalf("raised = %v at 2m30s, want only sentry -- its window is 2m and "+
			"lsrewards' is the default", r.raised)
	}
	if !strings.Contains(r.why[0], "40s") {
		t.Errorf("the incident says %q; it should say the peer was asked to heartbeat "+
			"every 40s, not the old fixed five minutes", r.why[0])
	}
}

// And the window reaches the peer from the configuration file.
func TestTheWindowIsReadFromTheConfiguration(t *testing.T) {
	cfg := &config.Config{Links: []config.Link{{
		Slug: "sentry", LinkID: "lnk_S", Key: "0123456789abcdef0123456789abcdef",
		SilentAfter: "2m",
	}}}
	peers, _ := config.BuildLinks(cfg)
	if len(peers) != 1 || peers[0].Silence() != 2*time.Minute {
		t.Fatalf("silent_after: 2m in config.yaml did not reach the peer (got %v)", peers)
	}
	if got := peers[0].HeartbeatEvery(); got != 40*time.Second {
		t.Errorf("a 2m window asks for a heartbeat every %s, want 40s", got)
	}
}

// A SHORT WINDOW ON A PEER THAT DOES NOT KEEP TO IT IS SAID ON THE PAGE
// before anybody is paged. The ordinary cause is a window set while the
// peer's client still heartbeats every five minutes, and every gap between
// its beats would otherwise be a silence alarm.
func TestAPeerNotKeepingToItsWindowIsFlagged(t *testing.T) {
	l, _ := newLiveFixture(liveT0)
	for i := 0; i < 3; i++ { // an old client: every five minutes
		l.contact("lsprotect", liveT0.Add(time.Duration(i)*5*time.Minute))
	}
	cfg := &config.Config{Links: []config.Link{{
		Slug: "lsprotect", LinkID: "lnk_P", SilentAfter: "2m",
	}}}
	s := newLinkState(nil)
	v := s.view(func() *config.Config { return cfg }, nil, liveT0.Add(11*time.Minute),
		liveT0, l.observedGap)
	if len(v.Peers) != 1 || !v.Peers[0].Behind {
		t.Fatalf("a peer going 5m between contacts against a 2m window is not flagged: %+v", v.Peers)
	}
	if v.Peers[0].ObservedGapSeconds != 300 {
		t.Errorf("observed gap = %ds, want 300", v.Peers[0].ObservedGapSeconds)
	}

	// Updated client: every 40 s. The warning clears within a few contacts,
	// or an operator who fixed it goes on being told it is broken.
	at := liveT0.Add(10 * time.Minute)
	for i := 1; i <= 5; i++ {
		l.contact("lsprotect", at.Add(time.Duration(i)*40*time.Second))
	}
	v = s.view(func() *config.Config { return cfg }, nil, at.Add(4*time.Minute),
		liveT0, l.observedGap)
	if v.Peers[0].Behind {
		t.Errorf("five contacts at 40 s after updating, it is still flagged as behind "+
			"(gap %ds)", v.Peers[0].ObservedGapSeconds)
	}
}

// SHORTENING A WINDOW MUST NOT PAGE ANYBODY ABOUT A HEALTHY PEER.
//
// The peer learns its rate from the reply to its next request, up to one old
// interval away. Judged by the new window in the meantime, it is silent
// because an operator changed a number. Found by the Rewards session in the
// live test.
func TestShorteningAWindowWaitsForThePeerToHearOfIt(t *testing.T) {
	l, r := newLiveFixture(liveT0)
	window := 16 * time.Minute
	l.windowFor = func(string) time.Duration { return window }
	ctx := context.Background()

	l.contact("sentry", liveT0) // told: 16m, so heartbeat every 5m
	window = time.Minute        // the operator shortens it

	// Three minutes on, a peer on its old five-minute rate has not been told.
	l.check(ctx, []string{"sentry"}, liveT0.Add(3*time.Minute))
	if len(r.raised) != 0 {
		t.Fatal("a healthy peer was reported silent three minutes after its window " +
			"was shortened, before it could have heard of the change")
	}

	// It makes contact and is told the new rate; now it is held to it.
	l.contact("sentry", liveT0.Add(5*time.Minute))
	l.check(ctx, []string{"sentry"}, liveT0.Add(6*time.Minute+30*time.Second))
	if len(r.raised) != 1 {
		t.Errorf("after making contact under the new window it went 90 s silent and "+
			"was not reported against its 1m window (raised %v)", r.raised)
	}
}

// After a restart a peer may be on any rate up to five minutes, so a short
// window must not fire before it could have made contact.
func TestAfterARestartAShortWindowWaitsForTheSlowestBeat(t *testing.T) {
	l, r := newLiveFixture(liveT0)
	l.windowFor = func(string) time.Duration { return time.Minute }
	ctx := context.Background()

	l.check(ctx, []string{"sentry"}, liveT0.Add(4*time.Minute))
	if len(r.raised) != 0 {
		t.Fatal("four minutes after a restart, a 1m-window peer never heard from was " +
			"reported silent; one still on a five-minute beat is healthy")
	}
	l.check(ctx, []string{"sentry"}, liveT0.Add(6*time.Minute+30*time.Second))
	if len(r.raised) != 1 {
		t.Error("a peer not heard from in over six minutes after a restart was never reported")
	}
}
