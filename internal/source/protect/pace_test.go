package protect

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/unifi"
)

// The WebSocket dials used to bypass the pacer, and that was the defect.
//
// A console reboot brings BOTH of this source's sockets back in the same
// instant, each reconnect fires a three-request sweep behind it, and Access
// and Network dial the same host on the same budget. A handshake is a request
// to the same rate-limited front door as a REST read.
func TestBothWebSocketDialsGoThroughTheConsolePacer(t *testing.T) {
	console := newFakeConsole(t)

	var paced atomic.Int64
	startSource(t, console, &fakeStates{}, func(c *Config) {
		c.Pace = func(ctx context.Context) error {
			paced.Add(1)
			return nil
		}
	})

	waitConn(t, console.events)
	waitConn(t, console.devices)

	waitUntil(t, "both dials to have been paced", func() bool { return paced.Load() >= 2 })

	// And no dial escaped it: the pacer was consulted at least as often as the
	// console was dialled.
	dials := int64(console.dialCount(pathEvents) + console.dialCount(pathDevices))
	if got := paced.Load(); got < dials {
		t.Fatalf("the console was dialled %d times but the pacer was consulted %d times; a dial went around it", dials, got)
	}
}

// A refused slot is a refused dial. A pacer that can be ignored is not one.
func TestAWebSocketDialIsAbandonedWhenThePacerRefuses(t *testing.T) {
	console := newFakeConsole(t)

	refused := errors.New("budget exhausted")
	var asked atomic.Int64
	startSource(t, console, &fakeStates{}, func(c *Config) {
		c.Pace = func(ctx context.Context) error {
			asked.Add(1)
			return refused
		}
	})

	waitUntil(t, "the pacer to be consulted", func() bool { return asked.Load() >= 2 })
	time.Sleep(100 * time.Millisecond)

	if n := console.dialCount(pathEvents) + console.dialCount(pathDevices); n != 0 {
		t.Fatalf("the console was dialled %d times while the pacer was refusing every slot", n)
	}
}

// One pacer per CONSOLE, not per client. A source that is told nothing about
// pacing joins the console's existing pacer rather than starting a second one,
// because a second pacer for one host doubles the request rate and looks
// perfectly correct in review.
func TestASourceWithNoPacerJoinsTheSharedConsolePacer(t *testing.T) {
	const host = "console-for-protect-test.invalid"

	a, err := New(Config{Host: host, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{Host: "https://" + host + ":443", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}

	if a.pacer == nil || b.pacer == nil {
		t.Fatal("a source with no Pace configured was left unpaced; nothing would limit it against the console")
	}
	if a.pacer != b.pacer {
		t.Fatal("two sources against one console took two pacers; the request rate against that host just doubled")
	}
	if a.pacer != unifi.PacerFor(host) {
		t.Fatal("the source built a private pacer instead of joining the registry's")
	}
	if got := a.pacer.Interval(); got != unifi.PaceInterval {
		t.Fatalf("the shared pacer's interval is %s, want %s", got, unifi.PaceInterval)
	}
	if a.cfg.Pace == nil {
		t.Fatal("Pace was left nil, so the REST sweep would be unpaced too")
	}
}

// An injected pacer is still honoured: tests and a future caller that really
// does want its own budget have to be able to say so out loud.
func TestAnInjectedPacerIsNotReplaced(t *testing.T) {
	called := 0
	src, err := New(Config{
		Host:   "10.9.9.9",
		APIKey: "k",
		Pace:   func(context.Context) error { called++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if src.pacer != nil {
		t.Fatal("an injected pacer was shadowed by the shared one")
	}
	if err := src.cfg.Pace(context.Background()); err != nil || called != 1 {
		t.Fatalf("the injected pacer was not the one used: called=%d err=%v", called, err)
	}
}

// The ladder this source retries on is the shared console one, configured from
// the source's own bounds rather than reimplemented beside it.
func TestTheReconnectLadderIsTheSharedHalfJitterBackoff(t *testing.T) {
	src, err := New(Config{
		Host:       "10.9.9.9",
		APIKey:     "k",
		MinBackoff: time.Second,
		MaxBackoff: 8 * time.Second,
		Rand:       func() float64 { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}

	want := unifi.Backoff{Base: time.Second, Max: 8 * time.Second, Rand: func() float64 { return 0 }}
	for attempt := 1; attempt <= 8; attempt++ {
		got := src.backoff.Delay(attempt)
		if got != want.Delay(attempt) {
			t.Fatalf("attempt %d: source delay %v, shared ladder %v", attempt, got, want.Delay(attempt))
		}
		if got <= 0 {
			t.Fatalf("attempt %d produced a zero delay", attempt)
		}
		if got > 8*time.Second {
			t.Fatalf("attempt %d produced %v, past the configured cap", attempt, got)
		}
	}
}
