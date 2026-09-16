package protect

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Two sockets, not one. A source that subscribes only to /subscribe/events
// never learns a camera went dark, because disconnect is not an event type.
func TestBothChannelsAreSubscribedWithTheKeyInAHeader(t *testing.T) {
	console := newFakeConsole(t)
	startSource(t, console, &fakeStates{}, nil)

	waitConn(t, console.events)
	waitConn(t, console.devices)

	if n := console.dialCount(pathEvents); n == 0 {
		t.Error("the events channel was never subscribed")
	}
	if n := console.dialCount(pathDevices); n == 0 {
		t.Error("the devices channel was never subscribed -- camera disconnect would never be seen")
	}

	for _, k := range console.apiKeysSeen() {
		if k != "test-key" {
			t.Fatalf("API key header = %q, want the configured key", k)
		}
	}
	// Never put a secret in a URL. Headers only.
	for _, q := range console.queriesSeen() {
		if q != "" {
			t.Fatalf("subscribe URL carried a query string %q; credentials travel in headers only", q)
		}
	}
}

func TestCameraDisconnectArrivesAsAStateFlipOnTheDevicesChannel(t *testing.T) {
	console := newFakeConsole(t)
	src, sink := startSource(t, console, &fakeStates{}, nil)
	_ = src

	devices := waitConn(t, console.devices)

	send(t, devices, `{"type":"update","item":{"modelKey":"camera","id":"cam-1","name":"Front Door","state":"DISCONNECTED"}}`)

	ev := sink.waitFor(t, "camera offline", func(e event.Event) bool {
		return e.Condition == ConditionOffline && !e.Clears
	})
	if ev.Entity.ID != "cam-1" || ev.Entity.Kind != "camera" {
		t.Errorf("entity = %+v, want cam-1/camera", ev.Entity)
	}
	if ev.Entity.Name != "Front Door" {
		t.Errorf("entity name = %q, want the name from the frame", ev.Entity.Name)
	}
	if ev.Severity != incident.SeverityHigh {
		t.Errorf("severity = %q, want high", ev.Severity)
	}
	if !ev.AtIsArrivalTime {
		t.Error("a device state flip carries no timestamp, so At must be flagged as arrival time")
	}
	if ev.Source != SourceName {
		t.Errorf("source = %q, want %q", ev.Source, SourceName)
	}

	// Without the clear, nothing ever resolves.
	send(t, devices, `{"type":"update","item":{"modelKey":"camera","id":"cam-1","state":"CONNECTED"}}`)
	clear := sink.waitFor(t, "camera back online", func(e event.Event) bool {
		return e.Condition == ConditionOffline && e.Clears
	})
	if clear.DedupKey() != ev.DedupKey() {
		t.Fatalf("the clear must share the dedup key it resolves: %q vs %q", clear.DedupKey(), ev.DedupKey())
	}
}

// devicesBulkUpdate carries ONE payload covering MANY devices, with id as an
// array. Reading it as a string drops the whole envelope silently.
func TestBulkDeviceEnvelopeReachesEveryDeviceItCovers(t *testing.T) {
	console := newFakeConsole(t)
	_, sink := startSource(t, console, &fakeStates{}, nil)
	devices := waitConn(t, console.devices)

	send(t, devices, `{"type":"devicesBulkUpdate","item":{"modelKey":"camera","id":["cam-1","cam-2","cam-3"],"state":"DISCONNECTED"}}`)

	got := map[string]bool{}
	for i := 0; i < 3; i++ {
		ev := sink.waitFor(t, "offline event from the bulk envelope", func(e event.Event) bool {
			return e.Condition == ConditionOffline && !e.Clears
		})
		got[ev.Entity.ID] = true
	}
	for _, want := range []string{"cam-1", "cam-2", "cam-3"} {
		if !got[want] {
			t.Errorf("%s never produced an event; a bulk envelope was dropped", want)
		}
	}
}

func TestBulkRemoveIsUnderstoodRatherThanCountedAsGibberish(t *testing.T) {
	console := newFakeConsole(t)
	src, _ := startSource(t, console, &fakeStates{}, nil)
	devices := waitConn(t, console.devices)

	send(t, devices, `{"type":"devicesBulkRemove","item":{"id":["cam-1","cam-2"]}}`)

	waitUntil(t, "the remove to be counted as understood", func() bool {
		return src.Health().Recognised["devices"] >= 1
	})
	if n := src.Health().Unrecognised["devices"]; n != 0 {
		t.Fatalf("a documented bulk remove was counted unrecognised %d times", n)
	}
}

func TestEventStartIsReadAsUnixMilliseconds(t *testing.T) {
	console := newFakeConsole(t)
	_, sink := startSource(t, console, &fakeStates{}, nil)
	events := waitConn(t, console.events)

	const startMS = 1760282368873
	send(t, events, `{"type":"add","item":{"id":"ev-1","modelKey":"event","type":"ring","device":"cam-7","start":1760282368873}}`)

	ev := sink.waitFor(t, "doorbell ring", func(e event.Event) bool { return e.Condition == ConditionRing })
	want := time.UnixMilli(startMS).UTC()
	if !ev.At.Equal(want) {
		t.Fatalf("At = %s, want %s -- start is milliseconds, and read as seconds it lands in 1970", ev.At, want)
	}
	if ev.AtIsArrivalTime {
		t.Error("the frame carried a real observation time; it must not be flagged as arrival time")
	}
	if ev.Entity.ID != "cam-7" {
		t.Errorf("entity = %+v, want the device id from the frame", ev.Entity)
	}
	if ev.Severity != incident.SeverityLow {
		t.Errorf("a doorbell ring came out as %q", ev.Severity)
	}
}

func TestAnEventWithNoTimestampSaysItIsArrivalTime(t *testing.T) {
	console := newFakeConsole(t)
	_, sink := startSource(t, console, &fakeStates{}, nil)
	events := waitConn(t, console.events)

	send(t, events, `{"type":"add","item":{"id":"ev-2","type":"sensorWaterLeak","device":"sense-1"}}`)

	ev := sink.waitFor(t, "water leak", func(e event.Event) bool { return e.Condition == ConditionWaterLeak })
	if !ev.AtIsArrivalTime {
		t.Fatal("an event with no start must be flagged, or the alert sends somebody scrubbing to a time that means nothing")
	}
	if ev.At.IsZero() {
		t.Fatal("At must still be populated with arrival time")
	}
}

// Update frames carry only `end` -- no type, no device -- so resolving them
// depends on remembering the event that was opened.
func TestMotionEndUpdateResolvesTheMotionItOpened(t *testing.T) {
	console := newFakeConsole(t)
	_, sink := startSource(t, console, &fakeStates{}, nil)
	events := waitConn(t, console.events)

	send(t, events, `{"type":"add","item":{"id":"ev-9","type":"motion","device":"cam-1","start":1760282368000}}`)
	open := sink.waitFor(t, "motion", func(e event.Event) bool {
		return e.Condition == ConditionMotion && !e.Clears
	})

	send(t, events, `{"type":"update","item":{"id":"ev-9","end":1760282378000}}`)
	clear := sink.waitFor(t, "motion end", func(e event.Event) bool {
		return e.Condition == ConditionMotion && e.Clears
	})

	if clear.DedupKey() != open.DedupKey() {
		t.Fatalf("the clear must share the dedup key it resolves: %q vs %q", clear.DedupKey(), open.DedupKey())
	}
	if !clear.At.Equal(time.UnixMilli(1760282378000).UTC()) {
		t.Errorf("clear At = %s, want the end timestamp", clear.At)
	}
}

// The end of an alarm's event WINDOW is not the end of the alarm. Treating it
// as one would resolve a smoke incident nobody has looked at.
func TestAnAlarmEndUpdateDoesNotResolveTheAlarm(t *testing.T) {
	console := newFakeConsole(t)
	_, sink := startSource(t, console, &fakeStates{}, nil)
	events := waitConn(t, console.events)

	send(t, events, `{"type":"add","item":{"id":"ev-smoke","type":"sensorAlarm","device":"sense-2","start":1760282368000,"metadata":{"alarmType":{"text":"smoke"}}}}`)
	ev := sink.waitFor(t, "smoke alarm", func(e event.Event) bool { return e.Condition == ConditionSmoke })
	if ev.Severity != incident.SeverityCritical {
		t.Fatalf("smoke severity = %q, want critical", ev.Severity)
	}

	send(t, events, `{"type":"update","item":{"id":"ev-smoke","end":1760282378000}}`)
	sink.expectNone(t, 200*time.Millisecond, "clear for a smoke alarm")
}

// A stream that connects and is never understood is a fault, not a success:
// unfamiliar hardware otherwise produces a live-looking, never-updating source.
func TestASocketThatIsNeverUnderstoodIsReportedAsAFault(t *testing.T) {
	console := newFakeConsole(t)
	src, sink := startSource(t, console, &fakeStates{}, func(c *Config) { c.MuteThreshold = 3 })
	devices := waitConn(t, console.devices)

	send(t, devices, `{"type":"quantumFluxChanged","item":{"id":"x"}}`)
	send(t, devices, `{"type":"quantumFluxChanged","item":{"id":"y"}}`)
	send(t, devices, `not json at all`)

	fault := sink.waitFor(t, "the mute-socket fault", func(e event.Event) bool {
		return e.Condition == ConditionStreamMute && !e.Clears
	})
	if fault.Severity != incident.SeverityHigh {
		t.Errorf("mute fault severity = %q, want high", fault.Severity)
	}

	h := src.Health()
	if h.Unrecognised["devices"] < 3 {
		t.Errorf("unrecognised count = %d, want at least 3", h.Unrecognised["devices"])
	}
	if h.UnknownTypes["devices/quantumFluxChanged"] < 2 {
		t.Errorf("unknown type was not recorded by name: %#v", h.UnknownTypes)
	}
	if !h.StreamMuteReported["devices"] {
		t.Error("Health does not report the socket as mute")
	}

	// And it recovers: one understood frame clears the fault.
	send(t, devices, `{"type":"update","item":{"modelKey":"camera","id":"cam-1","state":"DISCONNECTED"}}`)
	sink.waitFor(t, "the mute fault to clear", func(e event.Event) bool {
		return e.Condition == ConditionStreamMute && e.Clears
	})
	waitUntil(t, "health to stop reporting mute", func() bool {
		return !src.Health().StreamMuteReported["devices"]
	})
}

func TestAnUnderstoodSocketIsNeverReportedMute(t *testing.T) {
	console := newFakeConsole(t)
	src, sink := startSource(t, console, &fakeStates{}, func(c *Config) { c.MuteThreshold = 2 })
	devices := waitConn(t, console.devices)

	send(t, devices, `{"type":"update","item":{"modelKey":"camera","id":"cam-1","state":"DISCONNECTED"}}`)
	sink.waitFor(t, "camera offline", func(e event.Event) bool { return e.Condition == ConditionOffline })

	send(t, devices, `{"type":"quantumFluxChanged","item":{"id":"x"}}`)
	send(t, devices, `{"type":"quantumFluxChanged","item":{"id":"y"}}`)
	send(t, devices, `{"type":"quantumFluxChanged","item":{"id":"z"}}`)

	waitUntil(t, "the unknown frames to be counted", func() bool {
		return src.Health().Unrecognised["devices"] >= 3
	})
	if src.Health().StreamMuteReported["devices"] {
		t.Fatal("a socket that HAS been understood must not be reported mute for later unknown types")
	}
}

// After a console restart the reverse proxy answers 4xx and 5xx for a while as
// applications re-initialise. Treating 401 as terminal permanently kills
// ingest for a key that was correct all along.
func TestARejectedCredentialIsRetriedRatherThanTreatedAsFatal(t *testing.T) {
	console := newFakeConsole(t)
	console.rejectNext(pathEvents, 3, http.StatusUnauthorized)

	_, sink := startSource(t, console, &fakeStates{}, nil)

	// The socket comes up anyway, on a later attempt.
	events := waitConn(t, console.events)
	if n := console.dialCount(pathEvents); n < 4 {
		t.Fatalf("events channel was dialled %d times; the rejections were not retried", n)
	}

	send(t, events, `{"type":"add","item":{"id":"ev-1","type":"ring","device":"cam-1","start":1760282368873}}`)
	sink.waitFor(t, "an event after the rejections", func(e event.Event) bool { return e.Condition == ConditionRing })
}

func TestServerErrorsAreRetriedToo(t *testing.T) {
	console := newFakeConsole(t)
	console.rejectNext(pathDevices, 2, http.StatusBadGateway)

	startSource(t, console, &fakeStates{}, nil)
	waitConn(t, console.devices)

	if n := console.dialCount(pathDevices); n < 3 {
		t.Fatalf("devices channel was dialled %d times; 502s were not retried", n)
	}
}

// Idle tunnels get killed at around ten minutes, and a socket killed for
// idleness looks healthy until the read deadline expires.
func TestTheSocketIsPingedWhileIdle(t *testing.T) {
	console := newFakeConsole(t)
	startSource(t, console, &fakeStates{}, func(c *Config) {
		c.PingInterval = 20 * time.Millisecond
		c.PongWait = 2 * time.Second
	})
	waitConn(t, console.events)
	waitConn(t, console.devices)

	waitUntil(t, "keepalive pings", func() bool { return console.pings.Load() >= 4 })
}

// The ping interval must sit well inside the read deadline, or every healthy
// connection is killed on schedule by its own timeout.
func TestPongWaitIsNeverShorterThanThePingInterval(t *testing.T) {
	c := Config{PingInterval: time.Minute, PongWait: 10 * time.Second}
	c.applyDefaults()
	if c.PongWait <= c.PingInterval {
		t.Fatalf("PongWait %s <= PingInterval %s would kill every healthy connection", c.PongWait, c.PingInterval)
	}
}

func TestConfigurationFaultsAreReportedRatherThanRetried(t *testing.T) {
	if _, err := New(Config{APIKey: "k"}); err != ErrNoHost {
		t.Errorf("missing host: err = %v, want ErrNoHost", err)
	}
	if _, err := New(Config{Host: "10.0.0.1"}); err != ErrNoAPIKey {
		t.Errorf("missing key: err = %v, want ErrNoAPIKey", err)
	}
}

func TestLivenessIsAUsableDeadmanWindow(t *testing.T) {
	src, err := New(Config{Host: "10.0.0.1", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if got := src.Liveness(); got != defaultLiveness {
		t.Fatalf("Liveness = %s, want %s", got, defaultLiveness)
	}
	if src.Name() != SourceName {
		t.Fatalf("Name = %q, want %q", src.Name(), SourceName)
	}
}

// An unbounded in-flight table turns a busy site, or a firmware that stops
// sending `end`, into a memory leak that eventually takes the watchdog down.
func TestTheInFlightEventTableIsBounded(t *testing.T) {
	src, err := New(Config{Host: "10.0.0.1", APIKey: "k", MaxOpenEvents: 3})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		src.putOpen(fmt.Sprintf("ev-%d", i), pendingEvent{condition: ConditionMotion})
	}

	src.mu.Lock()
	n := len(src.open)
	seq := len(src.openSeq)
	src.mu.Unlock()
	if n > 3 || seq > 3 {
		t.Fatalf("in-flight table grew to %d entries (%d in sequence) with a cap of 3", n, seq)
	}

	// The newest survive; the oldest are the ones we give up resolving.
	if _, ok := src.takeOpen("ev-49"); !ok {
		t.Error("the most recent event was evicted")
	}
	if _, ok := src.takeOpen("ev-0"); ok {
		t.Error("the oldest event should have been evicted")
	}
}

// A mute-socket fault opens an INCIDENT, and an incident outlives the
// connection that raised it. If the socket then drops and comes back speaking
// something we understand, the clear must still be emitted -- otherwise the
// stream-unintelligible incident nags forever with nothing left that could
// ever resolve it.
func TestTheMuteFaultIsStillClearedAfterTheSocketReconnects(t *testing.T) {
	console := newFakeConsole(t)
	src, sink := startSource(t, console, &fakeStates{}, func(c *Config) { c.MuteThreshold = 2 })
	devices := waitConn(t, console.devices)

	send(t, devices, `{"type":"quantumFluxChanged","item":{"id":"x"}}`)
	send(t, devices, `{"type":"quantumFluxChanged","item":{"id":"y"}}`)
	sink.waitFor(t, "the mute-socket fault", func(e event.Event) bool {
		return e.Condition == ConditionStreamMute && !e.Clears
	})

	// The console restarts and comes back intelligible.
	devices.Close()
	devices = waitConn(t, console.devices)
	send(t, devices, `{"type":"update","item":{"modelKey":"camera","id":"cam-1","state":"DISCONNECTED"}}`)

	sink.waitFor(t, "the mute fault to clear on the new connection", func(e event.Event) bool {
		return e.Condition == ConditionStreamMute && e.Clears
	})
	waitUntil(t, "health to stop reporting the socket mute", func() bool {
		return !src.Health().StreamMuteReported["devices"]
	})
}

// The read deadline is refreshed by ANY frame, not only by a pong. A console
// that is busy talking but not answering pings must not be killed by our own
// timeout: the reconnect loses everything sent during the gap and neither
// socket carries a cursor to recover it.
func TestAnyFrameKeepsTheReadDeadlineAlive(t *testing.T) {
	console := newFakeConsole(t)
	console.swallowPings.Store(true)

	startSource(t, console, &fakeStates{}, func(c *Config) {
		c.PingInterval = 50 * time.Millisecond
		c.PongWait = 600 * time.Millisecond
	})
	events := waitConn(t, console.events)

	// Frames well inside the deadline, for twice as long as the deadline: with
	// no pong ever arriving, only the per-frame refresh can keep this alive.
	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := events.WriteMessage(websocket.TextMessage,
			[]byte(`{"type":"add","item":{"id":"ev-1","type":"ring","device":"cam-1","start":1760282368873}}`)); err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if n := console.dialCount(pathEvents); n != 1 {
		t.Fatalf("the events socket was dialled %d times; a socket that was delivering frames was killed by our own read deadline", n)
	}
	if console.pings.Load() == 0 {
		t.Error("no ping was ever sent, so this test proved nothing about pongs")
	}
}
