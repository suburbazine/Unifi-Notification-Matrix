package main

import (
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

func peerCfg() *config.Config {
	return &config.Config{Links: []config.Link{
		{Slug: "sentry", LinkID: "lnk_sentry", Key: secret.Secret("k"), Capability: "access"},
		{Slug: "other", LinkID: "lnk_other", Key: secret.Secret("k")},
	}}
}

func TestForgettingAPeerRemovesOnlyThatOneAndReportsItsCapability(t *testing.T) {
	next, capability, found := forgetPeer(peerCfg(), "sentry")
	if !found {
		t.Fatal("a paired peer was not found")
	}
	if capability != "access" {
		t.Errorf("capability = %q, want access; the claim cannot be released "+
			"without it and the peer's suppression would outlive the peer", capability)
	}
	if len(next.Links) != 1 || next.Links[0].Slug != "other" {
		t.Errorf("links after forgetting = %+v, want only \"other\"", next.Links)
	}
}

func TestForgettingIsCaseInsensitiveAndUnknownPeersAreNotFound(t *testing.T) {
	if _, _, found := forgetPeer(peerCfg(), "SENTRY"); !found {
		t.Error("the slug did not match with different case; the interface " +
			"sends back what the server printed, but an operator may not")
	}
	next, _, found := forgetPeer(peerCfg(), "nobody")
	if found {
		t.Error("an unknown peer reported as forgotten")
	}
	if len(next.Links) != 2 {
		t.Errorf("forgetting nothing changed the configuration: %+v", next.Links)
	}
}

// REVOKING A PEER MUST ALSO STOP SUPPRESSING OUR OWN SOURCE.
//
// Suppression is the only behaviour change pairing makes: while a peer serves
// a capability, this product's own events for it are not raised, so one real
// event does not become two incidents. If the claim outlived the credential,
// revoking a peer would stop the peer's events AND keep ours held back --
// the doors watched by nobody, on a page still saying a peer was serving them.
func TestReleasingACapabilityStopsSuppressingOurOwnEvents(t *testing.T) {
	now := time.Now()
	peers := []link.Peer{{Slug: "sentry", LinkID: "lnk_sentry",
		Manifest: link.Manifest{Capability: "access"}}}
	s := newLinkState(peers)

	// A peer that has just heartbeated and reported itself healthy holds the
	// capability, so our own access events are held back.
	c := s.claimFor(peers, "sentry")
	if c == nil {
		t.Fatal("a configured peer has no claim to hold")
	}
	c.Heartbeat(now)

	// Past the resume hysteresis, or the peer is still "recovering" and does
	// not hold the capability yet -- which would make the release below look
	// like it worked for the wrong reason.
	settled := now.Add(link.DefaultResumeAfter + time.Second)

	ev := event.Event{Source: "access"}
	if !s.suppressedByPeer(ev, settled, peerSilentAfter) {
		t.Fatal("a serving peer is not suppressing our own source, so this test " +
			"cannot show that revoking restores it")
	}

	s.release("access")
	if s.suppressedByPeer(ev, settled, peerSilentAfter) {
		t.Error("our own access events are still suppressed after the peer was " +
			"forgotten; nothing is watching the doors and nothing says so")
	}
}

// A PEER THAT PAIRS WHILE THE DAEMON IS RUNNING MUST GET A CLAIM.
//
// The claim map is built from the configuration AT START. Without adopt, a
// peer paired from the interface would send events and heartbeat and never
// hold the capability it claimed -- healthy on every indicator, and the
// takeover silently not happening until somebody restarted.
func TestAPeerPairedAtRuntimeGetsAClaim(t *testing.T) {
	s := newLinkState(nil)
	peers := []link.Peer{{Slug: "sentry", Manifest: link.Manifest{Capability: "access"}}}
	if s.claimFor(peers, "sentry") != nil {
		t.Fatal("a claim existed before pairing; this test is checking nothing")
	}
	s.adopt("access")
	if s.claimFor(peers, "sentry") == nil {
		t.Error("a peer paired while running has no claim, so it can never take " +
			"over the capability it just claimed")
	}
}

func TestReceiptsAreBoundedAndNewestFirstInTheView(t *testing.T) {
	s := newLinkState(nil)
	for i := 0; i < maxReceipts+50; i++ {
		s.record(link.Receipt{At: time.Now(), Route: "/link/v1/events", Reason: string(rune('a' + i%26))})
	}
	if got := len(s.Receipts()); got != maxReceipts {
		t.Errorf("held %d receipts, want the cap of %d: this is reachable from "+
			"outside and must not grow memory", got, maxReceipts)
	}

	last := link.Receipt{At: time.Now(), Route: "/link/pair", Reason: "the latest"}
	s.record(last)
	now := time.Now()
	v := s.view(func() *config.Config { return &config.Config{} }, nil, now,
		now.Add(-90*time.Second))
	if len(v.Receipts) != shownReceipts {
		t.Errorf("the view shows %d receipts, want %d", len(v.Receipts), shownReceipts)
	}
	// The window the receipts cover is reported, because they are in memory
	// and an empty list two minutes after a restart means something quite
	// different from an empty list on a week-old install.
	if v.SinceSeconds < 89 || v.SinceSeconds > 91 {
		t.Errorf("since_seconds = %d, want about 90; without it the empty state "+
			"tells an operator a peer cannot reach this machine when the truth "+
			"is that this service restarted a moment ago", v.SinceSeconds)
	}
	if v.Receipts[0].Reason != "the latest" {
		t.Errorf("the view leads with %q, not the most recent refusal; an "+
			"operator wants the one that just happened", v.Receipts[0].Reason)
	}
}
