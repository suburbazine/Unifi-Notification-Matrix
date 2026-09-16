package access

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// SHUTDOWN MUST NOT WAIT FOR THE CONSOLE TO SAY SOMETHING.
//
// gorilla's DialContext stops watching the context once the handshake
// succeeds, and this socket is chatty at idle rather than quiet, so
// ReadMessage kept returning happily and the read loop never looked at the
// context again. Cancelling therefore did nothing until the read deadline
// expired -- up to PongWait, well past the 25 seconds the Windows service
// manager allows a stop. The process was killed before the clean-shutdown
// marker could be written, so the NEXT start raised an "did not shut down
// cleanly" incident about a shutdown that had been fine.
func TestCancellingTheContextStopsTheSocketReader(t *testing.T) {
	// A console that upgrades and then says nothing at all.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Hold it open until the client goes away.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	s, err := New(Config{
		Host:   srv.URL,
		APIKey: "test-key",
		Pace:   func(context.Context) error { return nil },
		Now:    time.Now,
		// The source dials wss:// unconditionally. Handing back a plain
		// connection for the TLS dial points it at the test server without
		// needing certificates.
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
	go func() {
		defer close(done)
		_, _ = s.readSocket(ctx, &collector{})
	}()

	// Let the handshake complete, then ask it to stop.
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("readSocket did not return within 5s of its context being cancelled; " +
			"a stop would be killed by the service manager before the shutdown marker is written")
	}
}
