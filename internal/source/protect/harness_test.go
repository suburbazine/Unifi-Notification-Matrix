package protect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
)

// fakeConsole is a REAL gorilla/websocket server behind httptest.
//
// Real frames rather than a mocked reader, because the traps this source
// exists to survive -- a bulk envelope, an unintelligible frame, a rejected
// handshake, an idle timeout -- all live in frame handling. A mocked socket
// tests the mock.
type fakeConsole struct {
	*httptest.Server

	events  chan *websocket.Conn
	devices chan *websocket.Conn

	pings atomic.Int64

	// swallowPings answers nothing at all to a ping, which is how a console
	// under load behaves while it is still delivering frames. It exists so a
	// test can prove the read deadline is refreshed by DATA and not only by a
	// pong.
	swallowPings atomic.Bool

	mu       sync.Mutex
	dials    map[string]int
	keysSeen []string
	queries  []string
	failLeft map[string]int
	failWith int
}

func newFakeConsole(t *testing.T) *fakeConsole {
	t.Helper()
	c := &fakeConsole{
		events:   make(chan *websocket.Conn, 8),
		devices:  make(chan *websocket.Conn, 8),
		dials:    map[string]int{},
		failLeft: map[string]int{},
		failWith: http.StatusUnauthorized,
	}
	c.Server = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.Server.Close)
	return c
}

func (c *fakeConsole) serve(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.dials[r.URL.Path]++
	c.keysSeen = append(c.keysSeen, r.Header.Get("X-Api-Key"))
	c.queries = append(c.queries, r.URL.RawQuery)
	status := 0
	if c.failLeft[r.URL.Path] > 0 {
		c.failLeft[r.URL.Path]--
		status = c.failWith
	}
	c.mu.Unlock()

	if status != 0 {
		http.Error(w, "rejected", status)
		return
	}

	up := websocket.Upgrader{}
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn.SetPingHandler(func(data string) error {
		c.pings.Add(1)
		if c.swallowPings.Load() {
			return nil
		}
		return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
	})
	// The ping handler only runs while something is reading.
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	target := c.events
	if r.URL.Path == pathDevices {
		target = c.devices
	}
	select {
	case target <- conn:
	case <-time.After(2 * time.Second):
		conn.Close()
	}
}

func (c *fakeConsole) dialCount(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dials[path]
}

func (c *fakeConsole) rejectNext(path string, n, status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failLeft[path] = n
	c.failWith = status
}

func (c *fakeConsole) apiKeysSeen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.keysSeen...)
}

func (c *fakeConsole) queriesSeen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.queries...)
}

func waitConn(t *testing.T, ch chan *websocket.Conn) *websocket.Conn {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the source to connect")
		return nil
	}
}

func send(t *testing.T, conn *websocket.Conn, payload string) {
	t.Helper()
	if err := conn.WriteMessage(websocket.TextMessage, []byte(payload)); err != nil {
		t.Fatalf("writing frame: %v", err)
	}
}

// collector is an event.Sink that never blocks, matching the contract a real
// sink must honour: a source stalled on delivery stops reading its socket, and
// there is no cursor to recover what it misses.
type collector struct {
	mu  sync.Mutex
	all []event.Event
	ch  chan event.Event
}

func newCollector() *collector {
	return &collector{ch: make(chan event.Event, 256)}
}

func (c *collector) Emit(e event.Event) {
	c.mu.Lock()
	c.all = append(c.all, e)
	c.mu.Unlock()
	select {
	case c.ch <- e:
	default:
	}
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.all)
}

// waitFor drains until an event matches, so a test can assert about one event
// without caring how many reconciliation events preceded it.
func (c *collector) waitFor(t *testing.T, what string, pred func(event.Event) bool) event.Event {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-c.ch:
			if pred(e) {
				return e
			}
		case <-deadline:
			c.mu.Lock()
			seen := append([]event.Event(nil), c.all...)
			c.mu.Unlock()
			t.Fatalf("timed out waiting for %s; saw %d events: %v", what, len(seen), summarise(seen))
			return event.Event{}
		}
	}
}

func (c *collector) expectNone(t *testing.T, d time.Duration, what string) {
	t.Helper()
	select {
	case e := <-c.ch:
		t.Fatalf("expected no %s, got %s/%s clears=%v", what, e.Kind, e.Condition, e.Clears)
	case <-time.After(d):
	}
}

func summarise(evs []event.Event) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Kind+"/"+e.Condition+"/"+e.Entity.ID)
	}
	return out
}

// fakeStates is the injected reconciliation read.
type fakeStates struct {
	mu      sync.Mutex
	calls   int
	devices []DeviceState
	err     error
	hook    func(call int)
}

func (f *fakeStates) Devices(ctx context.Context) ([]DeviceState, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	devices := append([]DeviceState(nil), f.devices...)
	err := f.err
	hook := f.hook
	f.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	return devices, err
}

func (f *fakeStates) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeStates) set(devices []DeviceState, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices = append([]DeviceState(nil), devices...)
	f.err = err
}

// startSource wires a source to a fake console and runs it, returning when
// Run has been started. tune runs before defaults are applied.
func startSource(t *testing.T, c *fakeConsole, states StateReader, tune func(*Config)) (*Source, *collector) {
	t.Helper()

	cfg := Config{
		Host:   c.Server.URL,
		APIKey: "test-key",
		States: states,

		PingInterval: 40 * time.Millisecond,
		PongWait:     5 * time.Second,
		MinBackoff:   5 * time.Millisecond,
		MaxBackoff:   40 * time.Millisecond,
		StableAfter:  time.Millisecond,

		SweepEvery:    time.Hour,
		SweepDebounce: -1, // no debounce: tests want the sweep to happen now
		Logf:          t.Logf,
	}
	if tune != nil {
		tune(&cfg)
	}

	src, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sink := newCollector()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, sink) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned %v; a dropped connection is not a configuration fault", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancellation")
		}
	})
	return src, sink
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
