package access

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// CAPTURED FROM A REAL ENVR, by the probe, on the socket that actually
// connects. Six of the seven frames in thirty seconds were the first shape.
const (
	keepaliveFrame = `"pong"`
	infoFrame      = `{"data":{"top_log_count":0},"event":"access.base.info",` +
		`"event_object_id":"1f7a","receiver_id":"","save_to_history":false}`
)

// A KEEPALIVE IS NOT A FRAME WE FAILED TO UNDERSTAND.
//
// The stream-mute alarm exists for unfamiliar hardware sending door state in a
// shape nothing here can read: it raises HIGH and says door-forced detection
// is degraded. Counting protocol noise towards it means a console whose socket
// is working perfectly raises that alarm after fifty keepalives -- on a site
// where nobody has opened a door yet, which is most sites at 3am.
func TestAKeepaliveIsNotAnUnreadableFrame(t *testing.T) {
	s := newTestSource(t, newFakeConsole(t), nil)
	sink := &collector{}

	for i := 0; i < s.cfg.MuteThreshold*2; i++ {
		s.handleFrame([]byte(keepaliveFrame), sink)
	}

	if got := s.Health().Unrecognised; got != 0 {
		t.Errorf("unrecognised = %d; keepalives are not failures to understand", got)
	}
	for _, ev := range sink.all() {
		if ev.Kind == "stream-unintelligible" {
			t.Fatal("a working socket raised the unintelligible alarm on keepalives")
		}
	}
}

// The informational event the same console sends. It carries no door state and
// is not a door notification nobody could read.
func TestAnInformationalEventIsNotEvidenceOfAMuteStream(t *testing.T) {
	s := newTestSource(t, newFakeConsole(t), nil)
	sink := &collector{}

	for i := 0; i < s.cfg.MuteThreshold*2; i++ {
		s.handleFrame([]byte(infoFrame), sink)
	}

	for _, ev := range sink.all() {
		if ev.Kind == "stream-unintelligible" {
			t.Fatal("access.base.info raised the unintelligible alarm")
		}
	}
}

// And the alarm must still fire for what it was built for: frames shaped like
// door notifications that this build cannot read.
func TestAnUnreadableDoorFrameStillRaisesTheAlarm(t *testing.T) {
	s := newTestSource(t, newFakeConsole(t), nil)
	sink := &collector{}

	frame, err := json.Marshal(map[string]any{
		"event": "access.door.something_new",
		"data":  map[string]any{"door_id": "d1", "unknown_shape": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < s.cfg.MuteThreshold+1; i++ {
		s.handleFrame(frame, sink)
	}

	var raised bool
	for _, ev := range sink.all() {
		if ev.Kind == "stream-unintelligible" {
			raised = true
		}
	}
	if !raised {
		t.Error("a door-shaped frame nothing could read did not raise the alarm")
	}
}

// THE SOCKET MOVED, and a real console proved it: on an ENVR running current
// Access, the `api` path answers 404 to a key whose `integration` REST paths
// return 28 doors, while the `integration` socket connects and delivers.
//
// Both are kept and tried in order, because the older path is where the only
// two door-state message shapes this build knows were ever captured, and a
// site running that firmware must not lose its socket to a fix for another.
func TestBothNotificationPathsAreTried(t *testing.T) {
	s := newTestSource(t, newFakeConsole(t), nil)

	paths := s.wsCandidates()
	if len(paths) < 2 {
		t.Fatalf("candidates = %v, want both the integration and api paths", paths)
	}
	var integration, api bool
	for _, p := range paths {
		if p == "/proxy/access/integration/v1/developer/devices/notifications" {
			integration = true
		}
		if p == "/proxy/access/api/v1/developer/devices/notifications" {
			api = true
		}
	}
	if !integration || !api {
		t.Errorf("candidates = %v, want both paths", paths)
	}
	// The one a current console answers on comes first: a 404 costs a
	// reconnect delay, and the common case should not pay it.
	if paths[0] != "/proxy/access/integration/v1/developer/devices/notifications" {
		t.Errorf("first candidate = %q, want the one current firmware answers", paths[0])
	}
}

// Direct mode talks to Access's own port, where the REST base has no
// "integration" segment at all, so it keeps its own single path.
func TestDirectModeIsUnchanged(t *testing.T) {
	s := newTestSource(t, newFakeConsole(t), func(c *Config) { c.Mode = ModeDirect })
	got := s.wsCandidates()
	if len(got) != 1 || got[0] != directWSPath {
		t.Errorf("direct candidates = %v, want just %q", got, directWSPath)
	}
}

// THE FALLBACK ITSELF, dialled rather than listed.
//
// The first version of this test asserted on wsCandidates() and passed while
// the dial loop was mutated to give up after the first 404 -- a list is not a
// behaviour. This serves 404 at the path tried first and a real upgrade at
// the other, which is the firmware split that exists in the field.
func TestA404FallsBackToTheOtherPath(t *testing.T) {
	var tried []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tried = append(tried, r.URL.Path)
		if r.URL.Path != proxyWSPath {
			http.NotFound(w, r)
			return
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	s, err := New(Config{
		Host: srv.URL, APIKey: "test-key",
		Pace: func(context.Context) error { return nil },
		Now:  time.Now,
		Dialer: &websocket.Dialer{
			NetDialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _, _ = s.readSocket(ctx, &collector{}) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done

	if len(tried) < 2 {
		t.Fatalf("tried %v; a 404 on the first path must be answered by asking the other", tried)
	}
	if tried[0] == proxyWSPath {
		t.Fatalf("tried %v, want the integration path first", tried)
	}
	// And the one that worked is remembered, so a reconnect does not pay the
	// 404 again.
	if got := s.wsCandidates()[0]; got != proxyWSPath {
		t.Errorf("after connecting on %s, the next attempt starts at %s", proxyWSPath, got)
	}
}
