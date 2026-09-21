package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
)

// A CONFIGURATION WITH NO ACKNOWLEDGEMENT KEY MUST STILL PRODUCE AN INTERFACE.
//
// It did not. The daemon's entire web surface -- the interface, the
// acknowledgement endpoint, the peer link -- was inside
// `if !cfg.Web.AckKey.IsZero()`, and the key was minted only by config.Save.
// So a config.yaml written by hand, or restored from a backup that predates
// the key, started a daemon that came up, logged that it had started, watched
// the site, sent alerts carrying acknowledgement links that pointed at nothing
// -- and served no page on any port, while saying not one word about why. The
// operator's only symptom is a browser that cannot connect to a service the
// service manager says is running.
//
// Written as raw YAML on purpose: Save mints the key, so the only way to
// produce a file without one is the way an operator does, by editing it.
//
// This starts a real daemon on a real port rather than asserting on the
// config, because the config was never the thing that was broken: every field
// in it was correct, and what was wrong was what the daemon did with it.
func TestADaemonWithNoAckKeyInItsConfigStillServesTheInterface(t *testing.T) {
	dir := t.TempDir()

	// A port that was free a moment ago. Racy in principle; the alternative is
	// a fixed port, and on this machine 8322 belongs to an installed service.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	handEdited := fmt.Sprintf("version: %d\nweb:\n  listen: %s\n", config.SchemaVersion, addr)
	if err := os.WriteFile(config.Path(dir), []byte(handEdited), 0o600); err != nil {
		t.Fatal(err)
	}

	// Guard: if the file somehow arrived with a key, this test proves nothing.
	loaded, err := config.Load(dir)
	if err != nil {
		t.Fatalf("the hand-written configuration does not load: %v", err)
	}
	if !loaded.Web.AckKey.IsZero() {
		t.Fatal("the hand-written configuration already has an acknowledgement key; " +
			"this test would pass without the fix")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, dir) }()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("the daemon stopped instead of serving: %v", err)
		default:
		}
		resp, err := client.Get("http://" + addr + "/")
		if err == nil {
			resp.Body.Close()
			cancel()
			<-done
			return
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("nothing answered on %s within 20s -- a daemon with no acknowledgement "+
		"key in its configuration is serving no interface at all: %v", addr, last)
}

// And the key it mints is KEPT, because a key that changed on every start
// would invalidate every acknowledgement link already sent.
func TestTheMintedAckKeySurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	handEdited := fmt.Sprintf("version: %d\nweb:\n  listen: 127.0.0.1:8322\n", config.SchemaVersion)
	if err := os.WriteFile(config.Path(dir), []byte(handEdited), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := config.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.Web.AckKey.IsZero() {
		t.Fatal("opening a keyless configuration did not mint a key")
	}

	again, err := config.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := again.Web.AckKey.Reveal(), first.Web.AckKey.Reveal(); got != want {
		t.Error("the acknowledgement key changed across a restart; every link " +
			"already sent would stop working")
	}

	// And it reached the file, not just the returned struct: the next process
	// reads the file and nothing else.
	raw, err := os.ReadFile(config.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "ack_key:") {
		t.Errorf("the minted key was never written down:\n%s", raw)
	}
}
