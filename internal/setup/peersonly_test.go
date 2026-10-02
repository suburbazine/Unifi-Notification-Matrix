package setup

import (
	"strings"
	"testing"
)

// AN INSTALLATION FED ONLY BY PAIRED PRODUCTS IS WATCHING SOMETHING.
//
// Used with Rewards and no UniFi console, it was "not set up" everywhere: the
// header, a red Setup count, and a box across the incident board saying
// nothing could raise an incident -- while its peers were raising them.
func TestPairedProductsAloneAreSomethingToWatch(t *testing.T) {
	in := workable()
	in.Consoles, in.HasConsoleKey, in.SourceNames = 0, false, nil

	if Ready(in) {
		t.Fatal("setup: with no console and no peer, nothing is being watched")
	}
	in.PairedPeers = 1
	if !Ready(in) {
		t.Error("an installation with a paired product and a channel is called not ready")
	}
	for _, title := range []string{"console", "watch"} {
		got := step(t, in, title)
		if got.Status != Optional || !strings.Contains(got.State, "1 paired product") {
			t.Errorf("%q step = %s (%s), want optional, saying the paired product covers it",
				title, got.Status, got.State)
		}
	}

	// Still needs a way to be told.
	in.ChannelsEnabled = nil
	if Ready(in) {
		t.Error("ready with a peer and no channel: nothing would be delivered")
	}
}

// A console that is configured badly is still a to-do, peer or not: the
// operator chose UniFi, and it is not working.
func TestAPeerDoesNotHideABrokenConsole(t *testing.T) {
	in := workable()
	in.PairedPeers = 2
	in.HasConsoleKey = false
	if got := step(t, in, "console"); got.Status != Todo {
		t.Errorf("console step = %s (%s), want todo: a console with no key is broken",
			got.Status, got.State)
	}
}
