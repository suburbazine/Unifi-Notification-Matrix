package access

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

// collector is an event.Sink that remembers everything.
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

func (c *collector) find(condition string) (event.Event, bool) {
	for _, e := range c.all() {
		if e.Condition == condition {
			return e, true
		}
	}
	return event.Event{}, false
}

// fakeConsole records what it was asked and answers what it is told to.
type fakeConsole struct {
	mu sync.Mutex

	doorsBody string
	doorsCode string
	logsBody  string

	headers  []http.Header
	logQuery []string
	logBody  []string
	srv      *httptest.Server
}

func newFakeConsole(t *testing.T) *fakeConsole {
	t.Helper()
	f := &fakeConsole{
		doorsCode: "SUCCESS",
		doorsBody: `[]`,
		logsBody:  `{"code":"SUCCESS","data":{"hits":[]}}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/access/integration/v1/developer/doors", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.mu.Lock()
		code, body := f.doorsCode, f.doorsBody
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// Always HTTP 200. The console's own code is what says yes or no.
		_, _ = io.WriteString(w, `{"code":"`+code+`","msg":"","data":`+body+`}`)
	})
	mux.HandleFunc("/proxy/access/integration/v1/developer/system/logs", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		f.mu.Lock()
		f.logQuery = append(f.logQuery, r.URL.RawQuery)
		f.logBody = append(f.logBody, string(b))
		body := f.logsBody
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	})
	mux.HandleFunc("/api/v1/developer/doors", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		_, _ = io.WriteString(w, `{"code":"SUCCESS","data":[]}`)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeConsole) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = append(f.headers, r.Header.Clone())
}

func (f *fakeConsole) seenHeaders() []http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]http.Header(nil), f.headers...)
}

func newTestSource(t *testing.T, f *fakeConsole, tweak func(*Config)) *Source {
	t.Helper()
	cfg := Config{
		Host:   f.srv.URL,
		APIKey: "test-key",
		// Pacing is the shared console limiter and is exercised on its own
		// below; here it would add a fifth of a second to every request for no
		// assertion.
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

// The header name is assigned into the map rather than set through
// Header.Set, which would canonicalise it to X-Api-Key.
//
// Asserted on the header this source BUILDS, not on one read back from a
// server: net/http canonicalises inbound header names when it parses a
// request, so a round trip shows X-Api-Key whatever went on the wire and the
// test would pass either way. The value arriving at the console is checked
// separately, below.
func TestTheAPIKeyTravelsInTheHeaderConsolesExpect(t *testing.T) {
	f := newFakeConsole(t)
	s := newTestSource(t, f, nil)

	h := http.Header{}
	s.authorise(h)
	v, ok := h["X-API-KEY"]
	if !ok {
		t.Fatalf("header keys = %v, want the literal X-API-KEY (Header.Set would "+
			"have canonicalised it)", keysOf(h))
	}
	if len(v) != 1 || v[0] != "test-key" {
		t.Errorf("X-API-KEY = %v", v)
	}

	// And it reaches the console.
	if _, err := s.listDoors(context.Background()); err != nil {
		t.Fatal(err)
	}
	hdrs := f.seenHeaders()
	if len(hdrs) == 0 {
		t.Fatal("the console was never called")
	}
	if got := hdrs[0].Get("X-API-KEY"); got != "test-key" {
		t.Errorf("the console received %q", got)
	}
}

func TestDirectModeSendsABearerToken(t *testing.T) {
	f := newFakeConsole(t)
	s := newTestSource(t, f, func(c *Config) {
		c.Mode = ModeDirect
		// The fake console listens on the httptest port, so point the direct
		// mode at it rather than at 12445.
		c.DirectPort = portOf(t, f.srv.URL)
	})
	if _, err := s.listDoors(context.Background()); err != nil {
		t.Fatal(err)
	}
	hdrs := f.seenHeaders()
	if len(hdrs) == 0 {
		t.Fatal("the console was never called")
	}
	if got := hdrs[0].Get("Authorization"); got != "Bearer test-key" {
		t.Errorf("Authorization = %q, want a bearer token", got)
	}
	if _, ok := hdrs[0]["X-API-KEY"]; ok {
		t.Error("direct mode sent the proxy header too")
	}
}

// Access answers HTTP 200 with a failure code. A client that trusts the status
// reads a refusal as an empty result -- and for a DOOR LIST, an empty result
// means every door silently stops being watched.
func TestAnErrorCodeOnHTTP200IsNotAnEmptyDoorList(t *testing.T) {
	f := newFakeConsole(t)
	f.doorsCode = "CODE_SYSTEM_ERROR"
	f.doorsBody = "null"
	s := newTestSource(t, f, nil)

	_, err := s.listDoors(context.Background())
	if err == nil {
		t.Fatal("a refusal was read as a site with no doors")
	}
	if !strings.Contains(err.Error(), "CODE_SYSTEM_ERROR") {
		t.Errorf("error = %v, want the console's own code", err)
	}
}

// page_num and page_size MUST be query parameters. Placed in the body they are
// silently ignored and the console returns the entire log -- a
// nineteen-megabyte response has been observed.
func TestLogPagingUsesQueryParametersAndSecondTimestamps(t *testing.T) {
	f := newFakeConsole(t)
	s := newTestSource(t, f, nil)

	since := t0.Add(-10 * time.Minute)
	if _, err := s.fetchLogPage(context.Background(), topicDoorOpenings, since, t0, 2); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	q, body := f.logQuery[0], f.logBody[0]
	f.mu.Unlock()

	if !strings.Contains(q, "page_num=2") || !strings.Contains(q, "page_size=") {
		t.Errorf("query = %q, want page_num and page_size", q)
	}
	if strings.Contains(body, "page_num") || strings.Contains(body, "page_size") {
		t.Errorf("paging was sent in the body, where the console ignores it: %s", body)
	}

	var sent map[string]any
	if err := json.Unmarshal([]byte(body), &sent); err != nil {
		t.Fatal(err)
	}
	// since and until are UNIX SECONDS. Milliseconds are rejected outright --
	// which is the opposite of event.published inside the rows this returns.
	wantSince := float64(since.Unix())
	if sent["since"] != wantSince {
		t.Errorf("since = %v, want %v (seconds, not milliseconds)", sent["since"], wantSince)
	}
	if sent["topic"] != topicDoorOpenings {
		t.Errorf("topic = %v", sent["topic"])
	}
}

// `data` is an OBJECT with `.hits`, not a bare array. The usual "data is the
// array" assumption decodes to nothing at all, silently.
func TestLogRowsAreReadFromTheHitsObject(t *testing.T) {
	f := newFakeConsole(t)
	f.logsBody = `{"code":"SUCCESS","data":{"hits":[
	  {"_id":"r1","@timestamp":"2026-09-16T02:59:00Z","_source":{
	     "actor":{"id":"0f8f1f4c-1f2b-4a5b-9c3d-1a2b3c4d5e6f","type":"user","display_name":"Ada"},
	     "event":{"type":"access","log_key":"access.door.denied","display_message":"card not recognised"},
	     "target":[{"id":"d1","type":"door","display_name":"Front Door"}],
	     "authentication":{"credential_provider":"NFC"}}}]}}`
	s := newTestSource(t, f, nil)

	hits, err := s.fetchLogPage(context.Background(), topicDoorOpenings, t0.Add(-time.Hour), t0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != "r1" {
		t.Fatalf("hits = %+v, want one row read out of data.hits", hits)
	}
}

// End to end: a denial in the log becomes an incident naming the door and the
// person, at a severity that will actually escalate.
func TestADenialBecomesAnEvent(t *testing.T) {
	f := newFakeConsole(t)
	f.logsBody = `{"code":"SUCCESS","data":{"hits":[
	  {"_id":"r1","@timestamp":"2026-09-16T02:59:00Z","_source":{
	     "actor":{"id":"0f8f1f4c-1f2b-4a5b-9c3d-1a2b3c4d5e6f","type":"user","display_name":"Ada"},
	     "event":{"type":"access","log_key":"access.door.denied","display_message":"card not recognised"},
	     "target":[{"id":"u1","type":"user"},{"id":"d1","type":"door","display_name":"Front Door"}],
	     "authentication":{"credential_provider":"NFC"}}}]}}`
	s := newTestSource(t, f, nil)
	c := &collector{}

	s.pollLogs(context.Background(), c)

	ev, ok := c.find(event.ConditionAccessDenied)
	if !ok {
		t.Fatalf("no denial event; got %+v", c.all())
	}
	if ev.Entity.ID != "d1" {
		t.Errorf("entity = %+v, want the door found by type", ev.Entity)
	}
	if !strings.Contains(ev.Detail, "Ada") || !strings.Contains(ev.Detail, "NFC") {
		t.Errorf("detail = %q, want the person and the credential type", ev.Detail)
	}
	if ev.AtIsArrivalTime {
		t.Error("a row that carried @timestamp was marked as arrival-stamped")
	}
	if ev.ID != "r1" {
		t.Errorf("event ID = %q, want the row id so a restart cannot re-emit it", ev.ID)
	}
}

// The log lags minutes behind; the door poll is the only timely surface. A
// failed door read must not stop the held-open clock, because a door that was
// open before the console went quiet is still open as far as anybody knows.
func TestAFailedDoorReadDoesNotStopTheHeldOpenClock(t *testing.T) {
	f := newFakeConsole(t)
	f.doorsBody = `[{"id":"d1","name":"Front Door","door_lock_relay_status":"unlock","door_position_status":"open"}]`

	now := t0
	s := newTestSource(t, f, func(c *Config) {
		c.Now = func() time.Time { return now }
		c.HeldAfter = 60 * time.Second
	})
	c := &collector{}

	// Seen shut first, so the source is not in its cold-start state.
	f.doorsBody = `[{"id":"d1","name":"Front Door","door_lock_relay_status":"unlock","door_position_status":"close"}]`
	s.sweepPositions(context.Background(), c)

	f.doorsBody = `[{"id":"d1","name":"Front Door","door_lock_relay_status":"unlock","door_position_status":"open"}]`
	now = t0.Add(time.Second)
	s.sweepPositions(context.Background(), c)

	// The console now refuses every read.
	f.mu.Lock()
	f.doorsCode = "CODE_SYSTEM_ERROR"
	f.mu.Unlock()
	now = t0.Add(2 * time.Minute)
	s.sweepPositions(context.Background(), c)

	if _, ok := c.find(event.ConditionDoorHeld); !ok {
		t.Fatalf("the held-open clock stopped when the console did; got %+v", c.all())
	}
	if h := s.Health(); h.LastPositionErr == "" {
		t.Error("the failing read was not recorded in Health")
	}
}

// Both known message shapes came from one hub model on one day. Different
// hardware plausibly gives a socket that connects, streams, and updates
// nothing -- which looks exactly like a healthy quiet site unless it is
// counted.
func TestAConnectedButUnintelligibleSocketIsReported(t *testing.T) {
	f := newFakeConsole(t)
	s := newTestSource(t, f, func(c *Config) { c.MuteThreshold = 5 })
	c := &collector{}

	for i := 0; i < 10; i++ {
		s.handleFrame([]byte(`{"event":"access.data.v9.something.new","data":{"whatever":1}}`), c)
	}

	ev, ok := c.find(event.ConditionStreamMute)
	if !ok {
		t.Fatalf("a socket that understood nothing was never reported; got %+v", c.all())
	}
	if !strings.Contains(ev.Detail, "probe") {
		t.Errorf("detail = %q, want it to say how to find out what the console "+
			"is actually sending", ev.Detail)
	}
	// Reported once, not once per frame after the threshold.
	n := 0
	for _, e := range c.all() {
		if e.Condition == event.ConditionStreamMute {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the mute fault was raised %d times", n)
	}
	if h := s.Health(); h.UnknownEvents["access.data.v9.something.new"] != 10 {
		t.Errorf("unknown events = %v, want the name counted so it is actionable",
			h.UnknownEvents)
	}
}

// Health reports how much of a site is actually observable. A measurement
// across 28 doors found 26 with no position sensor, and an operator who
// believes this product watches every door when it can watch two has been
// misled by the product rather than by the console.
func TestHealthReportsHowManyDoorsCanActuallyBeWatched(t *testing.T) {
	f := newFakeConsole(t)
	f.doorsBody = `[
	  {"id":"d1","name":"Gate","door_position_status":"close"},
	  {"id":"d2","name":"Side","door_position_status":"none"},
	  {"id":"d3","name":"Rear","door_position_status":"none"}]`
	s := newTestSource(t, f, nil)
	s.sweepPositions(context.Background(), &collector{})

	h := s.Health()
	if h.DoorsKnown != 3 {
		t.Errorf("DoorsKnown = %d, want 3", h.DoorsKnown)
	}
	if h.DoorsWithPosition != 1 {
		t.Errorf("DoorsWithPosition = %d, want 1 -- the other two have no sensor "+
			"and nothing about them is derivable", h.DoorsWithPosition)
	}
}

// One pacer per console, not per application. Access polling door position
// every ten seconds and Protect sweeping on its own timer are one server-side
// budget; a second pacer doubles the rate and looks correct in review.
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

func TestAMissingKeyOrHostIsAConfigurationFault(t *testing.T) {
	if _, err := New(Config{APIKey: "k"}); err != ErrNoHost {
		t.Errorf("no host: err = %v, want ErrNoHost", err)
	}
	if _, err := New(Config{Host: "10.0.0.1"}); err != ErrNoAPIKey {
		t.Errorf("no key: err = %v, want ErrNoAPIKey", err)
	}
}

// A wrong header is indistinguishable from a wrong key in the console's reply,
// so the error has to name both possibilities or an operator debugs the wrong
// one.
func TestARefusedCredentialNamesTheModeAsWellAsTheKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	s, err := New(Config{Host: srv.URL, APIKey: "k", Pace: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.listDoors(context.Background())
	if err == nil {
		t.Fatal("a 401 was not reported")
	}
	for _, want := range []string{"proxy", "X-API-KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

func keysOf(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	return out
}

func portOf(t *testing.T, rawurl string) int {
	t.Helper()
	i := strings.LastIndex(rawurl, ":")
	if i < 0 {
		t.Fatalf("no port in %s", rawurl)
	}
	n := 0
	for _, c := range rawurl[i+1:] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
