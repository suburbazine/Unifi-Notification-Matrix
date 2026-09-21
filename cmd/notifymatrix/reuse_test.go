package main

import (
	"context"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
)

// namedSource is a stand-in. What matters here is IDENTITY -- two of these
// with the same name are different values, which is exactly the case the
// supervisor cannot tell apart on its own.
type namedSource struct {
	name string
	tag  string // what this instance is, for the test to assert on
}

func (s *namedSource) Name() string { return s.name }
func (s *namedSource) Run(ctx context.Context, _ event.Sink) error {
	<-ctx.Done()
	return nil
}
func (s *namedSource) Liveness() time.Duration { return 0 }

// AN UNRELATED SAVE MUST NOT DROP A CONSOLE'S CONNECTION.
//
// Protect holds a WebSocket, a backoff ladder and the table that turns an
// update frame into a clear. Rebuilding those because somebody saved a
// notification channel costs all three and leaves a gap in the coverage --
// and the gap is silent, which is the only kind this product must not have.
func TestASourceNobodyChangedIsHandedBackUnchanged(t *testing.T) {
	running := &namedSource{name: "protect", tag: "the one that is connected"}
	live := map[string]event.Source{"key-protect": running}

	// The same console, rebuilt: a new value, the same fingerprint.
	want, next := reuseSources(live, []config.KeyedSource{
		{Key: "key-protect", Source: &namedSource{name: "protect", tag: "freshly built"}},
	})

	if len(want) != 1 {
		t.Fatalf("sources = %d, want 1", len(want))
	}
	if want[0] != event.Source(running) {
		t.Errorf("a console nobody touched was handed to Replace as a new value, so "+
			"its connection is dropped and rebuilt: got %q", want[0].(*namedSource).tag)
	}
	if next["key-protect"] != event.Source(running) {
		t.Error("the map of what is running now points at a source that was never started")
	}
}

// AND A CHANGED KEY MUST NOT BE MISTAKEN FOR IT.
//
// Every Protect source is called "protect", so the corrected one and the
// broken one it replaces are indistinguishable by name. Keeping the wrong one
// leaves a daemon holding a 401 and reporting itself healthy.
func TestACorrectedConsoleReplacesTheBrokenOne(t *testing.T) {
	broken := &namedSource{name: "protect", tag: "401s on every sweep"}
	live := map[string]event.Source{"key-old": broken}

	fixed := &namedSource{name: "protect", tag: "the corrected key"}
	want, next := reuseSources(live, []config.KeyedSource{{Key: "key-new", Source: fixed}})

	if want[0] != event.Source(fixed) {
		t.Errorf("the source with the corrected key was dropped in favour of the "+
			"broken one it replaces, because they share a name: got %q",
			want[0].(*namedSource).tag)
	}
	if _, stale := next["key-old"]; stale {
		t.Error("the replaced source is still recorded as running")
	}
}

// TWO CONSOLES CONFIGURED IDENTICALLY SHARE A FINGERPRINT.
//
// One connection cannot be two sources, and Replace refuses the same value
// twice -- so the second one has to get the freshly built source rather than a
// second reference to the first.
func TestOneRunningSourceIsNotHandedOutTwice(t *testing.T) {
	running := &namedSource{name: "protect", tag: "already connected"}
	live := map[string]event.Source{"same": running}

	a := &namedSource{name: "protect", tag: "built A"}
	b := &namedSource{name: "protect", tag: "built B"}
	want, _ := reuseSources(live, []config.KeyedSource{
		{Key: "same", Source: a}, {Key: "same", Source: b},
	})

	if len(want) != 2 {
		t.Fatalf("sources = %d, want 2", len(want))
	}
	if want[0] == want[1] {
		t.Fatal("the same running source was handed to Replace twice; it refuses that, " +
			"so a duplicated console would stop the reload dead")
	}
	if want[0] != event.Source(running) {
		t.Error("the first of the two did not keep the connection that already exists")
	}
}

// A source that has gone is not carried forward.
func TestARemovedConsoleLeavesTheRunningSet(t *testing.T) {
	gone := &namedSource{name: "access", tag: "console deleted"}
	kept := &namedSource{name: "protect", tag: "still configured"}
	live := map[string]event.Source{"a": gone, "p": kept}

	want, next := reuseSources(live, []config.KeyedSource{
		{Key: "p", Source: &namedSource{name: "protect", tag: "rebuilt"}},
	})

	if len(want) != 1 || want[0] != event.Source(kept) {
		t.Fatalf("want exactly the kept source, got %d", len(want))
	}
	if len(next) != 1 {
		t.Errorf("the running set has %d entries after a console was removed, want 1", len(next))
	}
}
