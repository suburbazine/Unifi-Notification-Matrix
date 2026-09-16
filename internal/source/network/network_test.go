package network

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
)

var t0 = time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

type collector struct {
	mu sync.Mutex
	ev []event.Event
}

func (c *collector) Emit(e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ev = append(c.ev, e)
}

func (c *collector) all() []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]event.Event(nil), c.ev...)
}

// fakeConsole answers the Network Integration API.
type fakeConsole struct {
	mu sync.Mutex

	sitesBody   string
	devicesBody string

	// status fails everything; devicesStatus fails only the device listing.
	// Separate, because "the site listed and its devices did not" is a
	// distinct case with a distinct rule -- and a fake that cannot produce it
	// leaves that rule untested.
	status        int
	devicesStatus int

	headers []http.Header
	paths   []string
	srv     *httptest.Server
}

func newFakeConsole(t *testing.T) *fakeConsole {
	t.Helper()
	f := &fakeConsole{
		sitesBody:   `{"offset":0,"limit":25,"count":1,"totalCount":1,"data":[{"id":"s1","name":"Head Office","internalReference":"default"}]}`,
		devicesBody: `{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/network/integration/v1/sites", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.mu.Lock()
		st, body := f.status, f.sitesBody
		f.mu.Unlock()
		if st != 0 {
			w.WriteHeader(st)
			return
		}
		_, _ = io.WriteString(w, body)
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/s1/devices", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.mu.Lock()
		st, body := f.status, f.devicesBody
		if f.devicesStatus != 0 {
			st = f.devicesStatus
		}
		f.mu.Unlock()
		if st != 0 {
			w.WriteHeader(st)
			return
		}
		_, _ = io.WriteString(w, body)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeConsole) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = append(f.headers, r.Header.Clone())
	f.paths = append(f.paths, r.URL.RequestURI())
}

func (f *fakeConsole) seenPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func newTestSource(t *testing.T, f *fakeConsole, tweak func(*Config)) *Source {
	t.Helper()
	cfg := Config{
		Host: f.srv.URL, APIKey: "test-key",
		Pace: func(context.Context) error { return nil },
		Now:  func() time.Time { return t0 },
	}
	if tweak != nil {
		tweak(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func devicesPage(items string) string {
	return `{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[` + items + `]}`
}

// The header Ubiquiti's own Network documentation names. It matters because
// the OpenAPI spec declares no security scheme at all -- the keys are absent
// from it, not null -- so this could not be inferred from the sibling
// products.
func TestTheAPIKeyHeaderIsTheOneNetworkDocuments(t *testing.T) {
	f := newFakeConsole(t)
	s := newTestSource(t, f, nil)

	h := http.Header{}
	h["X-API-Key"] = []string{"test-key"}
	if _, err := s.listSites(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.headers) == 0 {
		t.Fatal("the console was never called")
	}
	if got := f.headers[0].Get("X-API-Key"); got != "test-key" {
		t.Errorf("X-API-Key = %q", got)
	}
}

// THE WHOLE MECHANISM. The Integration API has no events, so a device that
// WENT down is only distinguishable from one that is merely still down by
// having looked before.
func TestADeviceGoingDownIsRaisedAndComingBackClearsIt(t *testing.T) {
	f := newFakeConsole(t)
	now := t0
	s := newTestSource(t, f, func(c *Config) {
		c.Now = func() time.Time { return now }
		c.DownFor = 3 * time.Minute
	})
	c := &collector{}

	f.devicesBody = devicesPage(`{"id":"d1","name":"Core Switch","model":"USW-Pro-24","macAddress":"aa:bb:cc:dd:ee:ff","state":"ONLINE"}`)
	s.poll(context.Background(), c)
	if n := len(c.all()); n != 0 {
		t.Fatalf("a healthy device produced %d event(s)", n)
	}

	// It goes down. Not raised immediately -- a poll landing during a reboot
	// must not page anybody.
	f.devicesBody = devicesPage(`{"id":"d1","name":"Core Switch","model":"USW-Pro-24","macAddress":"aa:bb:cc:dd:ee:ff","state":"OFFLINE"}`)
	now = t0.Add(time.Minute)
	s.poll(context.Background(), c)
	if n := len(c.all()); n != 0 {
		t.Fatalf("raised after one minute; the threshold is what stops a reboot "+
			"from paging somebody: %+v", c.all())
	}

	// Still down past the threshold.
	now = t0.Add(5 * time.Minute)
	s.poll(context.Background(), c)
	got := c.all()
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	if got[0].Condition != event.ConditionOffline || got[0].Clears {
		t.Errorf("event = %+v, want an offline raise", got[0])
	}
	if got[0].Entity.Name != "Core Switch" || got[0].Entity.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("entity = %+v", got[0].Entity)
	}
	if !strings.Contains(got[0].Detail, "Head Office") {
		t.Errorf("detail does not name the site: %q", got[0].Detail)
	}

	// Raised once, not once per poll.
	now = t0.Add(10 * time.Minute)
	s.poll(context.Background(), c)
	if n := len(c.all()); n != 1 {
		t.Errorf("events = %d; a still-down device was re-raised on every poll", n)
	}

	// Back online clears it.
	f.devicesBody = devicesPage(`{"id":"d1","name":"Core Switch","state":"ONLINE"}`)
	now = t0.Add(12 * time.Minute)
	s.poll(context.Background(), c)
	got = c.all()
	if len(got) != 2 || !got[1].Clears {
		t.Fatalf("a device that came back did not clear: %+v", got)
	}
}

// A device being adopted or upgraded is doing what it was told to do.
func TestATransitionalStateIsNotAnOutage(t *testing.T) {
	f := newFakeConsole(t)
	now := t0
	s := newTestSource(t, f, func(c *Config) {
		c.Now = func() time.Time { return now }
		c.DownFor = time.Minute
	})
	c := &collector{}

	// Each state is held ACROSS the threshold, not merely seen once. The first
	// version of this test moved to the next state on every poll, so nothing
	// ever aged past DownFor -- it passed with "UPDATING" reclassified as an
	// outage, which is exactly the regression it was written to catch.
	for _, state := range []string{"ADOPTING", "UPDATING", "PENDING_ADOPTION", "GETTING_READY"} {
		f.devicesBody = devicesPage(`{"id":"d1","name":"New AP","state":"` + state + `"}`)
		for i := 0; i < 3; i++ {
			now = now.Add(10 * time.Minute)
			s.poll(context.Background(), c)
		}
		if n := len(c.all()); n != 0 {
			t.Fatalf("state %q raised an outage after 30 minutes: %+v", state, c.all())
		}
	}

	// And a device that really is down still crosses it, so this is not
	// passing because the threshold never fires at all.
	f.devicesBody = devicesPage(`{"id":"d1","name":"New AP","state":"OFFLINE"}`)
	now = now.Add(10 * time.Minute)
	s.poll(context.Background(), c)
	now = now.Add(10 * time.Minute)
	s.poll(context.Background(), c)
	if len(c.all()) == 0 {
		t.Error("a genuinely offline device was never raised, so this test proves nothing")
	}
}

// THE UNCOMFORTABLE TRADE, asserted so it cannot be changed silently.
//
// These state lists came from documentation, not from hardware. A state absent
// from all three is never alarmed on -- which means a future firmware value
// meaning "down" would pass unreported. The alternative pages the operator
// every time Ubiquiti adds a value, and an alarm product that cries wolf gets
// switched off. So the unknown is made VISIBLE instead.
func TestAnUnrecognisedStateIsNeverAlarmedOnButIsAlwaysCounted(t *testing.T) {
	f := newFakeConsole(t)
	now := t0
	s := newTestSource(t, f, func(c *Config) {
		c.Now = func() time.Time { return now }
		c.DownFor = time.Minute
	})
	c := &collector{}

	f.devicesBody = devicesPage(`{"id":"d1","name":"Odd Device","state":"SOMETHING_NEW"}`)
	s.poll(context.Background(), c)
	now = t0.Add(time.Hour)
	s.poll(context.Background(), c)

	if n := len(c.all()); n != 0 {
		t.Fatalf("an unrecognised state raised an incident: %+v", c.all())
	}
	h := s.Health()
	if h.UnknownStates["SOMETHING_NEW"] == 0 {
		t.Fatalf("the unrecognised state was not counted by name, so the blind "+
			"spot is silent: %+v", h.UnknownStates)
	}
	if h.ByState["unknown"] != 1 {
		t.Errorf("ByState = %+v, want the device counted as unknown", h.ByState)
	}
}

// Reporting a switch as healthy because a field was unreadable is reporting
// health on no evidence.
func TestAMissingStateIsNotOnline(t *testing.T) {
	for _, body := range []string{
		`{"id":"d1","name":"No State"}`,
		`{"id":"d1","name":"Null State","state":null}`,
		`{"id":"d1","name":"Blank State","state":""}`,
	} {
		got, _ := classifyState(mustField(t, body, "state"))
		if got == StateOnline {
			t.Errorf("%s classified as online", body)
		}
		if got != StateUnknown {
			t.Errorf("%s = %q, want unknown", body, got)
		}
	}
}

func mustField(t *testing.T, body, field string) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	return m[field]
}

// A device missing from the list is a statement about the console's inventory,
// not about the device's power.
func TestADeviceWithAnOpenIncidentIsNotForgotten(t *testing.T) {
	f := newFakeConsole(t)
	now := t0
	s := newTestSource(t, f, func(c *Config) {
		c.Now = func() time.Time { return now }
		c.DownFor = time.Minute
	})
	c := &collector{}

	f.devicesBody = devicesPage(`{"id":"d1","name":"Core Switch","state":"OFFLINE"}`)
	s.poll(context.Background(), c)
	now = t0.Add(5 * time.Minute)
	s.poll(context.Background(), c)
	if len(c.all()) != 1 {
		t.Fatalf("setup did not raise: %+v", c.all())
	}

	// The console stops listing it entirely.
	f.devicesBody = devicesPage(``)
	now = t0.Add(10 * time.Minute)
	s.poll(context.Background(), c)

	if s.devices.count() != 1 {
		t.Error("a device with an open incident was forgotten when the console " +
			"stopped listing it -- which is more worrying than being down, not less")
	}
}

// The clock still runs when the console goes quiet: a device that was already
// down is still down as far as anybody knows.
func TestAFailedPollDoesNotStopTheClock(t *testing.T) {
	f := newFakeConsole(t)
	now := t0
	s := newTestSource(t, f, func(c *Config) {
		c.Now = func() time.Time { return now }
		c.DownFor = 3 * time.Minute
	})
	c := &collector{}

	f.devicesBody = devicesPage(`{"id":"d1","name":"Core Switch","state":"OFFLINE"}`)
	s.poll(context.Background(), c)

	f.mu.Lock()
	f.status = http.StatusInternalServerError
	f.mu.Unlock()
	now = t0.Add(5 * time.Minute)
	s.poll(context.Background(), c)

	if len(c.all()) != 1 {
		t.Errorf("the threshold stopped being checked when the console did: %+v", c.all())
	}
	if h := s.Health(); h.LastPollErr == "" {
		t.Error("the failing poll was not recorded in Health")
	}
}

// A site that failed to list is a site whose devices were not seen. Dropping
// them because they were absent from a list we never received would lose their
// state.
func TestDevicesAreNotForgottenWhenASiteFailsToList(t *testing.T) {
	f := newFakeConsole(t)
	now := t0
	s := newTestSource(t, f, func(c *Config) { c.Now = func() time.Time { return now } })
	c := &collector{}

	f.devicesBody = devicesPage(`{"id":"d1","name":"Core Switch","state":"ONLINE"}`)
	s.poll(context.Background(), c)
	if s.devices.count() != 1 {
		t.Fatalf("setup: devices = %d", s.devices.count())
	}

	// Sites still lists; its devices do not. This is the case the rule is for,
	// and a fake that failed both would never reach it -- the poll would
	// return at the site listing, and the mutation that removes the guard
	// would pass unnoticed.
	f.mu.Lock()
	f.devicesStatus = http.StatusInternalServerError
	f.mu.Unlock()

	now = t0.Add(time.Minute)
	s.poll(context.Background(), c)
	if s.devices.count() != 1 {
		t.Error("a device was forgotten because its site's device listing failed -- " +
			"a list we never received is not evidence that the device is gone")
	}
	if h := s.Health(); h.LastPollErr == "" {
		t.Error("the failed device listing was not recorded in Health")
	}
}

// The documented envelope wraps the array; a bare array is accepted too,
// because being wrong about which one this console sends should cost nothing.
func TestBothListShapesDecode(t *testing.T) {
	wrapped := []byte(`{"offset":0,"limit":25,"count":2,"totalCount":2,"data":[{"id":"a"},{"id":"b"}]}`)
	bare := []byte(`[{"id":"a"},{"id":"b"}]`)

	for _, body := range [][]byte{wrapped, bare} {
		items, total, err := decodePage(body)
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if len(items) != 2 || total != 2 {
			t.Errorf("%s: items = %d, total = %d", body, len(items), total)
		}
	}

	if items, total, err := decodePage([]byte(`{"data":null}`)); err != nil || len(items) != 0 || total != 0 {
		t.Errorf("an empty list did not decode cleanly: %v %v %v", items, total, err)
	}
}

func TestPagingWalksEveryPage(t *testing.T) {
	f := newFakeConsole(t)
	s := newTestSource(t, f, func(c *Config) { c.PageLimit = 2 })

	// totalCount says three devices; the page carries two.
	f.mu.Lock()
	f.devicesBody = `{"offset":0,"limit":2,"count":2,"totalCount":3,"data":[{"id":"a"},{"id":"b"}]}`
	f.mu.Unlock()

	if _, err := s.listDevices(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	if n := len(f.seenPaths()); n < 2 {
		t.Errorf("made %d request(s); totalCount said there was another page", n)
	}
	for _, p := range f.seenPaths() {
		if !strings.Contains(p, "limit=2") {
			t.Errorf("page size was not sent: %s", p)
		}
	}
}

// A 404 on this path means the controller predates the Local Integration API,
// which is a different problem from a wrong key and needs a different fix.
func TestAnOldControllerIsToldApartFromABadKey(t *testing.T) {
	f := newFakeConsole(t)
	s := newTestSource(t, f, nil)

	f.mu.Lock()
	f.status = http.StatusNotFound
	f.mu.Unlock()
	_, err := s.listSites(context.Background())
	if err == nil || !strings.Contains(err.Error(), "9.0") {
		t.Errorf("error = %v, want one naming the version that introduced the API", err)
	}

	f.mu.Lock()
	f.status = http.StatusUnauthorized
	f.mu.Unlock()
	_, err = s.listSites(context.Background())
	if err == nil || !strings.Contains(err.Error(), "separate") {
		t.Errorf("error = %v, want one saying the Network key is its own key", err)
	}
}

// This source opts out of the deadman, and the reason has to stay visible: a
// healthy network emits nothing for weeks, so a deadman here would fire on
// every quiet site and get the whole mechanism switched off.
func TestThisSourceMakesNoLivenessPromise(t *testing.T) {
	f := newFakeConsole(t)
	s := newTestSource(t, f, nil)
	if s.Liveness() != 0 {
		t.Errorf("Liveness = %v, want zero", s.Liveness())
	}
}

func TestAMissingKeyOrHostIsAConfigurationFault(t *testing.T) {
	if _, err := New(Config{APIKey: "k"}); err != ErrNoHost {
		t.Errorf("no host: err = %v, want ErrNoHost", err)
	}
	if _, err := New(Config{Host: "10.0.0.1"}); err != ErrNoAPIKey {
		t.Errorf("no key: err = %v, want ErrNoAPIKey", err)
	}
}

// One pacer per console. Network polling every minute and Protect sweeping on
// its own timer draw on one server-side budget.
func TestTheSharedConsolePacerIsTheDefault(t *testing.T) {
	f := newFakeConsole(t)
	a, err := New(Config{Host: f.srv.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{Host: f.srv.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if a.pacer == nil || a.pacer != b.pacer {
		t.Error("two sources for one console took different pacers")
	}
}
