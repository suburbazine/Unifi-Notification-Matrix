package protect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// There is no resume cursor on either socket, so a reconnect loses everything
// that happened during the gap with no way to detect that it did. The sweep is
// the only thing that can notice, which is why it has to run on EVERY connect
// rather than only at startup.
func TestEveryReconnectTriggersAReconciliationSweep(t *testing.T) {
	console := newFakeConsole(t)
	states := &fakeStates{}
	startSource(t, console, states, nil)

	events := waitConn(t, console.events)
	waitConn(t, console.devices)

	waitUntil(t, "the cold-start sweep", func() bool { return states.callCount() >= 1 })
	before := states.callCount()

	// Drop one socket the way a console reboot does.
	events.Close()
	waitConn(t, console.events)

	waitUntil(t, "a sweep after the reconnect", func() bool { return states.callCount() > before })
}

func TestColdStartReDerivesCamerasThatAreAlreadyOffline(t *testing.T) {
	console := newFakeConsole(t)
	states := &fakeStates{}
	states.set([]DeviceState{
		{ID: "cam-1", Name: "Front Door", Kind: "camera", State: stateDisconnected},
		{ID: "cam-2", Name: "Garage", Kind: "camera", State: stateConnected},
	}, nil)

	_, sink := startSource(t, console, states, nil)

	ev := sink.waitFor(t, "the already-offline camera", func(e event.Event) bool {
		return e.Condition == ConditionOffline && !e.Clears
	})
	if ev.Entity.ID != "cam-1" {
		t.Fatalf("offline event was for %q, want cam-1", ev.Entity.ID)
	}
	if ev.Kind != "reconcile" {
		t.Errorf("kind = %q, want the event to admit it came from a sweep", ev.Kind)
	}
	if !ev.AtIsArrivalTime {
		t.Error("a sweep knows what is true now and nothing about when it became true; At must be flagged")
	}

	// The healthy camera must produce nothing at all. Re-announcing every
	// connected camera on every sweep buries the one that is not.
	sink.expectNone(t, 200*time.Millisecond, "event for a healthy camera")
}

// The recovery this exists for: the camera came back while we were
// disconnected, so the CONNECTED frame that would have cleared the incident
// was never delivered and can never be replayed.
func TestSweepClearsAnOutageThatEndedWhileTheStreamWasDown(t *testing.T) {
	console := newFakeConsole(t)
	states := &fakeStates{}
	_, sink := startSource(t, console, states, nil)

	devices := waitConn(t, console.devices)
	send(t, devices, `{"type":"update","item":{"modelKey":"camera","id":"cam-1","state":"DISCONNECTED"}}`)
	open := sink.waitFor(t, "camera offline", func(e event.Event) bool {
		return e.Condition == ConditionOffline && !e.Clears
	})

	// While we are away the camera recovers.
	states.set([]DeviceState{{ID: "cam-1", Name: "Front Door", Kind: "camera", State: stateConnected}}, nil)
	devices.Close()
	waitConn(t, console.devices)

	clear := sink.waitFor(t, "the sweep-derived clear", func(e event.Event) bool {
		return e.Condition == ConditionOffline && e.Clears
	})
	if clear.DedupKey() != open.DedupKey() {
		t.Fatalf("the clear must share the dedup key it resolves: %q vs %q", clear.DedupKey(), open.DedupKey())
	}
}

// A sweep read that started BEFORE a stream update must not overwrite it, or
// the outage is erased by the very mechanism that exists to catch outages.
func TestAFresherStreamStateIsNotOverwrittenByAnOlderSweep(t *testing.T) {
	reg := newRegistry()
	sweepStart := time.Date(2026, 9, 15, 3, 0, 0, 0, time.UTC)
	streamAt := sweepStart.Add(500 * time.Millisecond)
	sweepDone := sweepStart.Add(2 * time.Second)

	// The camera was fine when the sweep began.
	reg.observe(DeviceState{ID: "cam-1", Kind: "camera", State: stateConnected}, sweepStart.Add(-time.Minute))
	// Mid-sweep it drops, and the stream tells us so.
	reg.observe(DeviceState{ID: "cam-1", Kind: "camera", State: stateDisconnected}, streamAt)

	// The sweep, which read the console before the drop, now lands.
	transitions := reg.applySweep([]DeviceState{
		{ID: "cam-1", Name: "Front Door", Kind: "camera", State: stateConnected},
	}, sweepStart, sweepDone)

	if len(transitions) != 0 {
		t.Fatalf("stale sweep produced %+v; it would have erased a live outage", transitions)
	}
	d, _ := reg.lookup("cam-1")
	if d.State != stateDisconnected {
		t.Fatalf("state = %q, want the fresher streamed DISCONNECTED", d.State)
	}
	if d.Name != "Front Door" {
		t.Errorf("identity fields from the sweep should still be merged, got name %q", d.Name)
	}
}

// /v1/nvrs carries no state field at all. An unreadable state must yield "no
// information", never a plausible default.
func TestARecordWithNoStateMakesNoClaimAboutHealth(t *testing.T) {
	reg := newRegistry()
	now := time.Now()
	transitions := reg.applySweep([]DeviceState{
		{ID: "nvr-1", Name: "Dream Machine", Kind: "nvr", MAC: "AA:BB:CC:DD:EE:FF"},
		{ID: "cam-9", Name: "Odd", Kind: "camera", State: "SOMETHING_NEW"},
	}, now.Add(-time.Second), now)

	if len(transitions) != 0 {
		t.Fatalf("a stateless or unreadable record produced %+v", transitions)
	}
	if d, ok := reg.lookup("nvr-1"); !ok || d.MAC == "" {
		t.Fatal("identity from a stateless record should still be recorded for the MAC map")
	}
}

// Protect's Alarm Manager webhook identifies devices by bare MAC and nothing
// else, so without this map a disk-failure alarm names a string nobody can act
// on.
func TestTheSweepBuildsTheMACMapAlarmManagerNeeds(t *testing.T) {
	console := newFakeConsole(t)
	states := &fakeStates{}
	states.set([]DeviceState{
		{ID: "cam-1", Name: "Front Door", Kind: "camera", MAC: "AA:BB:CC:DD:EE:FF", State: stateConnected},
	}, nil)

	src, sink := startSource(t, console, states, nil)
	waitUntil(t, "the sweep to populate the registry", func() bool { return src.Health().DevicesKnown >= 1 })

	for _, form := range []string{"AA:BB:CC:DD:EE:FF", "aabbccddeeff", "aa-bb-cc-dd-ee-ff"} {
		d, ok := src.ResolveMAC(form)
		if !ok {
			t.Fatalf("MAC %q did not resolve", form)
		}
		if d.ID != "cam-1" {
			t.Fatalf("MAC %q resolved to %q", form, d.ID)
		}
	}

	// And the identity learned by the sweep enriches later stream events.
	events := waitConn(t, console.events)
	send(t, events, `{"type":"add","item":{"id":"ev-1","type":"ring","device":"cam-1","start":1760282368873}}`)
	ev := sink.waitFor(t, "doorbell ring", func(e event.Event) bool { return e.Condition == ConditionRing })
	if ev.Entity.Name != "Front Door" || ev.Entity.MAC == "" {
		t.Fatalf("entity was not enriched from the sweep: %+v", ev.Entity)
	}
}

func TestAFailingSweepIsRetriedAndSurfacedInHealth(t *testing.T) {
	console := newFakeConsole(t)
	states := &fakeStates{}
	states.set(nil, errors.New("console still re-initialising"))

	src, _ := startSource(t, console, states, nil)

	waitUntil(t, "the sweep to be retried", func() bool { return states.callCount() >= 2 })
	waitUntil(t, "the failure to reach Health", func() bool {
		return strings.Contains(src.Health().LastSweepErr, "re-initialising")
	})

	// And it recovers on its own rather than needing a restart.
	states.set([]DeviceState{{ID: "cam-1", Kind: "camera", State: stateConnected}}, nil)
	waitUntil(t, "health to clear", func() bool { return src.Health().LastSweepErr == "" })
}

func TestReconcileAppliesWhatArrivedEvenWhenPartOfTheReadFailed(t *testing.T) {
	src, err := New(Config{Host: "10.0.0.1", APIKey: "k", SweepDebounce: -1})
	if err != nil {
		t.Fatal(err)
	}
	states := &fakeStates{}
	states.set([]DeviceState{{ID: "cam-1", Kind: "camera", State: stateDisconnected}}, errors.New("sensors read failed"))
	src.cfg.States = states

	sink := newCollector()
	if err := src.Reconcile(context.Background(), sink); err == nil {
		t.Fatal("a partial sweep must still report its error")
	}
	if sink.count() != 1 {
		t.Fatalf("emitted %d events; the records that DID arrive are real and must be acted on", sink.count())
	}
}

// --- the REST reader itself -------------------------------------------------

func TestRESTReaderCollectsCamerasSensorsAndNVRs(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Api-Key")
		switch r.URL.Path {
		case pathCameras:
			fmt.Fprint(w, `[{"id":"cam-1","name":"Front Door","mac":"AABBCCDDEEFF","state":"DISCONNECTED"},{"id":"cam-2","name":"Garage","state":"CONNECTED"}]`)
		case pathSensors:
			fmt.Fprint(w, `[{"id":"sense-1","name":"Back Door","state":"CONNECTED"}]`)
		case pathNVRs:
			fmt.Fprint(w, `[{"id":"nvr-1","name":"Dream Machine","mac":"112233445566"}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	r := newRESTReader(mustURL(t, srv.URL), secret.Secret("k"), srv.Client(), nil)
	devices, err := r.Devices(context.Background())
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(devices) != 4 {
		t.Fatalf("got %d devices, want 4: %+v", len(devices), devices)
	}
	if gotKey != "k" {
		t.Errorf("API key header = %q", gotKey)
	}

	byID := map[string]DeviceState{}
	for _, d := range devices {
		byID[d.ID] = d
	}
	if byID["cam-1"].State != stateDisconnected || byID["cam-1"].Kind != "camera" {
		t.Errorf("cam-1 = %+v", byID["cam-1"])
	}
	if byID["sense-1"].Kind != "sensor" {
		t.Errorf("sense-1 kind = %q", byID["sense-1"].Kind)
	}
	if byID["nvr-1"].State != "" {
		t.Errorf("the NVR endpoint carries no state; got %q", byID["nvr-1"].State)
	}
}

func TestOneUnreadableRecordDoesNotCostTheWholeSite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == pathCameras {
			fmt.Fprint(w, `[{"id":"cam-1","state":"CONNECTED"},{"id":42,"state":false},{"id":"cam-3","state":"DISCONNECTED"}]`)
			return
		}
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()

	r := newRESTReader(mustURL(t, srv.URL), secret.Secret("k"), srv.Client(), nil)
	devices, err := r.Devices(context.Background())
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("got %d devices, want the two readable ones: %+v", len(devices), devices)
	}
}

// Truncation is detected, not returned: reading exactly the cap cannot
// distinguish a complete body from a longer one, and a silently truncated
// array makes every camera past the cut look like it does not exist.
func TestAnOversizedBodyIsRefusedRatherThanTruncated(t *testing.T) {
	big := "[" + strings.Repeat(`{"id":"cam-x","state":"CONNECTED"},`, 200)
	big = strings.TrimSuffix(big, ",") + "]"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, big)
	}))
	defer srv.Close()

	r := newRESTReader(mustURL(t, srv.URL), secret.Secret("k"), srv.Client(), nil)
	r.maxBody = 64
	if _, err := r.Devices(context.Background()); !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
}

// HTTP 200 is not success on this hardware.
func TestA200CarryingAnObjectIsAFailureNotAnEmptySite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":"not authorised for this endpoint"}`)
	}))
	defer srv.Close()

	r := newRESTReader(mustURL(t, srv.URL), secret.Secret("k"), srv.Client(), nil)
	devices, err := r.Devices(context.Background())
	if err == nil {
		t.Fatal("a 200 with an error object must not read as an empty site")
	}
	if len(devices) != 0 {
		t.Fatalf("got %d devices from an error envelope", len(devices))
	}
}

// Never log a response body from a credential-bearing endpoint: these
// responses carry stream and snapshot URLs whose path token is all anyone on
// the network needs to watch a camera.
func TestErrorsNeverCarryTheResponseBodyOrAPath(t *testing.T) {
	const secretish = "rtsps://10.0.0.1:7441/SUPERSECRETTOKEN"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"streamUrl":%q}`, secretish)
	}))
	defer srv.Close()

	r := newRESTReader(mustURL(t, srv.URL), secret.Secret("k"), srv.Client(), nil)
	_, err := r.Devices(context.Background())
	if err == nil {
		t.Fatal("a 403 must be an error")
	}
	msg := err.Error()
	if strings.Contains(msg, "SUPERSECRET") {
		t.Fatalf("error leaked the response body: %s", msg)
	}
	if strings.Contains(msg, "/proxy/protect") {
		t.Fatalf("error leaked the URL path: %s", msg)
	}
	if !strings.Contains(msg, "403") {
		t.Fatalf("error should still name the status: %s", msg)
	}
}

// One pacer per console, shared with every other caller: three independently
// paced clients against one host multiply the request rate by three against a
// single shared budget.
func TestEverySweepRequestGoesThroughTheSharedPacer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()

	paced := 0
	r := newRESTReader(mustURL(t, srv.URL), secret.Secret("k"), srv.Client(), func(context.Context) error {
		paced++
		return nil
	})
	if _, err := r.Devices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if paced != 3 {
		t.Fatalf("pacer was consulted %d times for 3 requests", paced)
	}
}

func TestSweepStopsWhenThePacerRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a refused pacer must not let a request through")
	}))
	defer srv.Close()

	want := errors.New("budget exhausted")
	r := newRESTReader(mustURL(t, srv.URL), secret.Secret("k"), srv.Client(), func(context.Context) error {
		return want
	})
	if _, err := r.Devices(context.Background()); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := parseHost(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	return u
}

// The API key is written into the header MAP under the exact casing working
// clients send. Header.Set canonicalises to "X-Api-Key"; header names are
// case-insensitive by specification, but the reverse proxy in front of this
// console is nobody here's to control, so the casing known to work in the
// field is the casing that goes on the wire.
//
// Asserted on the map key, because an HTTP server canonicalises on parse and
// would therefore accept either -- an end-to-end test cannot see this at all.
func TestTheAPIKeyHeaderKeepsTheCasingWorkingClientsSend(t *testing.T) {
	h := http.Header{}
	setAPIKey(h, secret.Secret("k"))

	v, ok := h["X-API-KEY"]
	if !ok {
		t.Fatalf("header map keys = %v, want the literal X-API-KEY (Header.Set would have canonicalised it)", headerKeys(h))
	}
	if len(v) != 1 || v[0] != "k" {
		t.Fatalf("X-API-KEY = %v, want the configured key", v)
	}
	if _, canonical := h["X-Api-Key"]; canonical {
		t.Errorf("the key was also written canonicalised: %v", headerKeys(h))
	}
	if len(h) != 1 {
		t.Errorf("setAPIKey wrote %d headers: %v", len(h), headerKeys(h))
	}
}

func headerKeys(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	return out
}

// A devices-channel update carrying only `state` must not blank what the sweep
// taught us. Without that, the first offline alert names the camera and every
// one after it names a device id -- and the MAC map an Alarm Manager webhook
// resolves against loses its entry.
func TestAStateOnlyUpdateDoesNotEraseWhatWeAlreadyKnow(t *testing.T) {
	reg := newRegistry()
	now := time.Now()

	reg.applySweep([]DeviceState{
		{ID: "cam-1", Name: "Front Door", Kind: "camera", MAC: "AA:BB:CC:DD:EE:FF", State: stateConnected},
	}, now.Add(-time.Second), now)

	// The wire shape that actually arrives: an id and a state, nothing else.
	reg.observe(DeviceState{ID: "cam-1", State: stateDisconnected}, now)

	d, ok := reg.lookup("cam-1")
	if !ok {
		t.Fatal("the device disappeared from the registry")
	}
	if d.Name != "Front Door" {
		t.Errorf("name = %q; a state-only update erased the human name every alert needs", d.Name)
	}
	if d.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MAC = %q; a state-only update erased the MAC Alarm Manager resolves against", d.MAC)
	}
	if d.Kind != "camera" {
		t.Errorf("kind = %q; a state-only update erased it", d.Kind)
	}
	if d.State != stateDisconnected {
		t.Errorf("state = %q, want the update's DISCONNECTED", d.State)
	}
}

// HTTP 200 is not success on this hardware, and `null` is the shape that gets
// through everything else: it decodes cleanly into an empty slice, so a
// console answering 200/null would read as a site with no cameras at all --
// every device silently unknown and the sweep reporting itself healthy.
func TestA200CarryingNullIsAFailureNotAnEmptySite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `null`)
	}))
	defer srv.Close()

	r := newRESTReader(mustURL(t, srv.URL), secret.Secret("k"), srv.Client(), nil)
	devices, err := r.Devices(context.Background())
	if err == nil {
		t.Fatal("a 200 with a null body must not read as an empty site")
	}
	if len(devices) != 0 {
		t.Fatalf("got %d devices from a null body", len(devices))
	}
}

// blockingStates is a StateReader that never answers on its own -- the console
// that accepts the connection and goes away, which is a normal thing for one
// to do while it reboots.
type blockingStates struct{ calls atomic.Int64 }

func (b *blockingStates) Devices(ctx context.Context) ([]DeviceState, error) {
	b.calls.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

// The sweeper is a single goroutine and the only thing that re-derives state
// after a gap, so one read that never returns would stop every later sweep
// INCLUDING the periodic backstop -- and the source would go on reporting
// itself connected while nothing checked the truth again.
func TestAHangingReconciliationReadIsBoundedRatherThanWedgingTheSweeper(t *testing.T) {
	console := newFakeConsole(t)
	states := &blockingStates{}

	src, _ := startSource(t, console, states, func(c *Config) {
		c.SweepTimeout = 50 * time.Millisecond
	})

	waitUntil(t, "the hung sweep to be abandoned and retried", func() bool {
		return states.calls.Load() >= 2
	})
	waitUntil(t, "the hung sweep to reach Health", func() bool {
		return src.Health().LastSweepErr != ""
	})
}
