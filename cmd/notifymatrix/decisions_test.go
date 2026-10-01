package main

import (
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

// THE COUNT ON EVERY TAB. At Trailbound, Rewards 0.3.5's two new conditions
// were refused over and over, and all that said so was a receipt inside
// Settings -> Peer link. The status page now carries how many kinds are
// waiting and how many events have been turned away for them.
func TestPendingDecisionsCountKindsAndRefusals(t *testing.T) {
	p := link.NewProposals()
	at := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		p.Note("lsrewards", "lsrewards-reward-revoked", incident.SeverityMedium, "revoked", at)
	}
	p.Note("lsrewards", "lsrewards-reward-used-before-return", incident.SeverityMedium, "used", at)

	got := pendingDecisions(p.All())
	if got.Kinds != 2 || got.Refused != 4 {
		t.Errorf("pending = %+v, want 2 kinds refused 4 times", got)
	}
	if z := pendingDecisions(nil); z.Kinds != 0 || z.Refused != 0 {
		t.Errorf("nothing pending reads as %+v", z)
	}
}
