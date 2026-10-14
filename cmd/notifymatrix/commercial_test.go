package main

import (
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

// A REFUSED PARTNER HOLDS NOTHING.
//
// Sentry holding Access makes this product's own Access ingest stand down. If
// that claim were honoured while every door event Sentry sends is refused for
// want of commercial permission, nothing would be watching the doors. So while
// partner events are refused, no claim is honoured, and the moment a partner
// grants permission the claim is back.
func TestARefusedPartnerDoesNotHoldItsCapability(t *testing.T) {
	now := time.Now()
	peers := []link.Peer{{Slug: "sentry", LinkID: "lnk_sentry",
		Manifest: link.Manifest{Capability: "access"}}}
	s := newLinkState(peers)
	s.permissions = link.NewPermissions(now.Add(-time.Hour), link.DefaultPermissionGrace)
	s.setPaired(func() []link.Peer { return peers })

	s.claimFor(peers, "sentry").Heartbeat(now)
	settled := now.Add(link.DefaultResumeAfter + time.Second)
	ev := event.Event{Source: "access"}

	s.permissions.Note("sentry", false, now)
	if s.suppressedByPeer(ev, settled, link.DefaultSilentAfter) {
		t.Fatal("our own access events are held back for a partner whose door " +
			"events are all being refused: nothing is watching the doors")
	}
	if held, why := s.holds("access", settled, link.DefaultSilentAfter); held ||
		!strings.Contains(why, "commercial") {
		t.Errorf("holds = %v, %q; want not held, saying why", held, why)
	}

	s.permissions.Note("sentry", true, now)
	if !s.suppressedByPeer(ev, settled, link.DefaultSilentAfter) {
		t.Error("with permission granted the partner's claim is still not honoured")
	}
}

// Nothing paired, nothing refused -- and a state never told where its
// partners are refuses nothing either.
func TestNoPartnersMeansNoRejection(t *testing.T) {
	if newLinkState(nil).rejecting(time.Now().Add(time.Hour)) {
		t.Error("a state with no partner source rejects partner events")
	}
	s := newLinkState(nil)
	s.setPaired(func() []link.Peer { return nil })
	if s.rejecting(time.Now().Add(time.Hour)) {
		t.Error("an installation with no partners rejects partner events")
	}
}
