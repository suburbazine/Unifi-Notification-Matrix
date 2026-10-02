package main

import (
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/setup"
)

// The checklist the board, the header and Setup all read is built from the
// configuration here, so a paired product has to reach it from the file.
func TestAPairedProductReachesTheChecklist(t *testing.T) {
	c := &config.Config{Links: []config.Link{{Slug: "lsrewards", LinkID: "lnk_A"}}}
	c.Channels.Ntfy = &config.Ntfy{Enabled: true, ServerURL: "https://ntfy.sh", Topic: "t"}

	in := fromConfig(setup.Input{}, c)
	if in.PairedPeers != 1 {
		t.Fatalf("PairedPeers = %d, want 1", in.PairedPeers)
	}
	if !setup.Ready(in) {
		t.Error("a Rewards-only installation with a channel is reported not set up")
	}
}
