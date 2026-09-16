package inbound

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

var t0 = time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

type sink struct {
	mu sync.Mutex
	ev []event.Event
}

func (s *sink) emit(e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ev = append(s.ev, e)
}

func (s *sink) all() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Event(nil), s.ev...)
}

const (
	wanBearer    = "bearer-wan-abcdefghijklmnop"
	threatBearer = "bearer-threat-qrstuvwxyz0123"
)

func testHooks() []Hook {
	return []Hook{
		{Name: "wan", Token: "tok-wan-1234567890", Bearer: wanBearer, Product: "network",
			Condition: event.ConditionWANDown, Severity: incident.SeverityCritical,
			EntityName: "Head office WAN"},
		{Name: "threat", Token: "tok-threat-098765", Bearer: threatBearer, Product: "network",
			Condition: event.ConditionThreat, Severity: incident.SeverityHigh},
	}
}

// bearerFor returns the header a console must send for a hook, by name.
func bearerFor(name string) string {
	for _, h := range testHooks() {
		if h.Name == name {
			return HeaderValueFor(h)
		}
	}
	return ""
}

func newTestReceiver(t *testing.T) (*Receiver, *sink) {
	t.Helper()
	s := &sink{}
	return New(testHooks(), Options{Emit: s.emit, Now: func() time.Time { return t0 }}), s
}

// post sends an authorised request, which is what an Alarm Manager rule that
// was configured correctly does.
func post(t *testing.T, r *Receiver, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return postAs(t, r, path, body, bearerOfPath(path))
}

// bearerOfPath picks the right bearer for whichever hook the path names, so a
// test that means "authorised" does not have to restate it.
func bearerOfPath(path string) string {
	if strings.Contains(path, "tok-threat") {
		return bearerFor("threat")
	}
	return bearerFor("wan")
}

func postAs(t *testing.T, r *Receiver, path, body, authz string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// THE DESIGN DECISION. The payload is undocumented and has spelled its message
// field four different ways across firmware, so what an alarm MEANS comes from
// the URL the operator chose when they made the rule, not from the body.
func TestTheHookURLDecidesWhatTheAlarmMeans(t *testing.T) {
	r, s := newTestReceiver(t)

	// A body that says nothing useful at all.
	if w := post(t, r, PathPrefix+"tok-wan-1234567890", `{"foo":1}`); w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	got := s.all()
	if len(got) != 1 {
		t.Fatalf("emitted %d events, want 1", len(got))
	}
	if got[0].Condition != event.ConditionWANDown {
		t.Errorf("condition = %q, want the hook's own meaning", got[0].Condition)
	}
	if got[0].Severity != incident.SeverityCritical {
		t.Errorf("severity = %q, want the hook's", got[0].Severity)
	}
	if got[0].Entity.Name != "Head office WAN" {
		t.Errorf("entity = %q", got[0].Entity.Name)
	}
}

// Four spellings for one field, across firmware revisions.
func TestTheMessageIsFoundUnderEverySpellingItHasUsed(t *testing.T) {
	for _, key := range []string{"message", "msg", "text", "description"} {
		r, s := newTestReceiver(t)
		post(t, r, PathPrefix+"tok-wan-1234567890", `{"`+key+`":"WAN1 is down"}`)
		got := s.all()
		if len(got) != 1 {
			t.Fatalf("%s: emitted %d", key, len(got))
		}
		if !strings.Contains(got[0].Detail, "WAN1 is down") {
			t.Errorf("spelling %q was not read: detail = %q", key, got[0].Detail)
		}
	}
}

// Some firmware nests the whole alarm one level down.
func TestANestedPayloadIsStillRead(t *testing.T) {
	r, s := newTestReceiver(t)
	post(t, r, PathPrefix+"tok-wan-1234567890",
		`{"alarm":{"msg":"WAN1 is down","mac":"aa:bb:cc:dd:ee:ff","trigger":"WAN Offline"}}`)
	got := s.all()
	if len(got) != 1 {
		t.Fatalf("emitted %d", len(got))
	}
	if !strings.Contains(got[0].Detail, "WAN1 is down") {
		t.Errorf("nested message missed: %q", got[0].Detail)
	}
	if got[0].Entity.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("nested MAC missed: %q", got[0].Entity.MAC)
	}
	if !strings.Contains(got[0].Detail, "WAN Offline") {
		t.Errorf("the rule name was dropped: %q", got[0].Detail)
	}
}

// Alarm Manager offers GET or POST, and the operator may pick either. This is
// the opposite of the acknowledgement endpoint's rule, and deliberately so --
// nothing prefetches a hook URL, because it is never sent to anybody.
func TestAGETWithQueryParametersIsAccepted(t *testing.T) {
	r, s := newTestReceiver(t)
	req := httptest.NewRequest(http.MethodGet,
		PathPrefix+"tok-wan-1234567890?message=WAN1+is+down", nil)
	req.Header.Set("Authorization", bearerFor("wan"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	got := s.all()
	if len(got) != 1 || !strings.Contains(got[0].Detail, "WAN1 is down") {
		t.Errorf("a GET alarm was not read: %+v", got)
	}
}

// An operator may want a self-describing URL in the Alarm Manager UI.
func TestATrailingSegmentIsTolerated(t *testing.T) {
	r, s := newTestReceiver(t)
	post(t, r, PathPrefix+"tok-wan-1234567890/wan-down", `{}`)
	if len(s.all()) != 1 {
		t.Error("a self-describing suffix broke the hook")
	}
}

// The token is a credential: anyone holding it can raise an incident here.
func TestAnUnknownTokenIsRefusedWithoutSayingWhy(t *testing.T) {
	r, s := newTestReceiver(t)

	for _, path := range []string{
		PathPrefix + "wrong-token",
		PathPrefix + "tok-wan-123456789", // one character short
		PathPrefix,
		PathPrefix + "",
	} {
		w := post(t, r, path, `{"message":"x"}`)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404 -- a wrong token must not be "+
				"distinguishable from a wrong path", path, w.Code)
		}
	}
	if n := len(s.all()); n != 0 {
		t.Errorf("%d event(s) were raised by unauthenticated requests", n)
	}
}

// An empty token must never match an empty configured token.
func TestAnEmptyTokenMatchesNothing(t *testing.T) {
	s := &sink{}
	r := New([]Hook{{Name: "broken", Token: "", Bearer: wanBearer, Condition: "x"}},
		Options{Emit: s.emit, Now: func() time.Time { return t0 }})

	if w := post(t, r, PathPrefix, `{}`); w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if len(s.all()) != 0 {
		t.Error("a hook with no token accepted a request with no token")
	}
}

// THE VERIFICATION STEP. Alarm Manager rules cannot be created through any
// API, so the only way to know the operator got it right is to observe an
// alarm arriving. Every setup surface reads this.
func TestReceiptsRecordWhetherAnythingHasEverArrived(t *testing.T) {
	r, _ := newTestReceiver(t)

	before := r.Receipts()
	if len(before) != 2 {
		t.Fatalf("receipts = %d, want one per hook", len(before))
	}
	for _, rec := range before {
		if rec.Count != 0 || !rec.LastAt.IsZero() {
			t.Errorf("%s: reported traffic before any arrived: %+v", rec.Name, rec)
		}
	}

	post(t, r, PathPrefix+"tok-wan-1234567890", `{"message":"test"}`)
	post(t, r, PathPrefix+"tok-wan-1234567890", `{"message":"test"}`)

	after := r.Receipts()
	var wan, threat Receipt
	for _, rec := range after {
		switch rec.Name {
		case "wan":
			wan = rec
		case "threat":
			threat = rec
		}
	}
	if wan.Count != 2 || wan.LastAt.IsZero() {
		t.Errorf("wan receipt = %+v, want two arrivals", wan)
	}
	if threat.Count != 0 {
		t.Errorf("threat receipt = %+v, want none -- a hook nobody has tested "+
			"must keep saying so", threat)
	}
}

// Network's Alarm Manager payload carries no controller timestamp at all,
// unlike Protect's. Presenting an arrival time as an observation time sends
// somebody scrubbing to the wrong point in the footage.
func TestArrivalTimeIsStampedAndSaidToBeStamped(t *testing.T) {
	r, s := newTestReceiver(t)
	post(t, r, PathPrefix+"tok-wan-1234567890", `{"message":"x"}`)
	got := s.all()[0]
	if !got.AtIsArrivalTime {
		t.Error("an arrival-stamped time was presented as an observation time")
	}
	if !got.At.Equal(t0) {
		t.Errorf("At = %v, want the injected clock", got.At)
	}
}

// A body that is not JSON is still the console's own description of what
// happened -- but an HTML error page is not a message, so it is capped.
func TestANonJSONBodyIsKeptAsTextAndCapped(t *testing.T) {
	r, s := newTestReceiver(t)
	post(t, r, PathPrefix+"tok-wan-1234567890", "WAN1 went down at 03:00")
	got := s.all()
	if len(got) != 1 || !strings.Contains(got[0].Detail, "WAN1 went down") {
		t.Fatalf("a plain-text body was discarded: %+v", got)
	}

	r2, s2 := newTestReceiver(t)
	post(t, r2, PathPrefix+"tok-wan-1234567890", strings.Repeat("x", 100_000))
	if d := s2.all()[0].Detail; len(d) > 1000 {
		t.Errorf("an oversized body produced a %d-character detail", len(d))
	}
}

// An alarm with nothing readable in it is still an alarm, and saying so beats
// raising an incident whose detail is empty.
func TestAnUnreadableAlarmStillSaysWhichHookItCameFrom(t *testing.T) {
	r, s := newTestReceiver(t)
	post(t, r, PathPrefix+"tok-threat-098765", `{}`)
	got := s.all()
	if len(got) != 1 {
		t.Fatalf("emitted %d", len(got))
	}
	if !strings.Contains(got[0].Detail, "threat") {
		t.Errorf("detail = %q, want it to name the hook so the operator can "+
			"find the Alarm Manager rule that fired", got[0].Detail)
	}
}

func TestAnOversizedBodyIsNotReadIntoMemoryWholesale(t *testing.T) {
	r, s := newTestReceiver(t)
	req := httptest.NewRequest(http.MethodPost, PathPrefix+"tok-wan-1234567890",
		strings.NewReader(strings.Repeat("a", 4<<20)))
	req.Header.Set("Authorization", bearerFor("wan"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
	if got := s.all(); len(got) != 1 {
		t.Fatalf("emitted %d", len(got))
	}
}

func TestAnUnsupportedMethodIsRefused(t *testing.T) {
	r, _ := newTestReceiver(t)
	req := httptest.NewRequest(http.MethodDelete, PathPrefix+"tok-wan-1234567890", nil)
	req.Header.Set("Authorization", bearerFor("wan"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

// The URL an operator pastes into Alarm Manager carries the token, so it is a
// credential and has to look like one when it is shown.
func TestURLForBuildsThePasteableURL(t *testing.T) {
	h := testHooks()[0]
	got := URLFor("http://192.168.1.50:8322/", h)
	want := "http://192.168.1.50:8322" + PathPrefix + "tok-wan-1234567890"
	if got != want {
		t.Errorf("URLFor = %q, want %q", got, want)
	}
	if !strings.Contains(URLFor("", h), "<this-machine>") {
		t.Error("with no base URL configured, the placeholder must be obviously " +
			"a placeholder rather than something that looks pasteable")
	}
}

// THE POINT OF THE BEARER. A URL is not an authenticator: it travels through
// the Alarm Manager form, the console's configuration backup, browser history
// and every proxy log on the path. Knowing it must not be enough to raise a
// false alarm on somebody's security system.
func TestTheRightURLWithNoHeaderIsRefused(t *testing.T) {
	r, s := newTestReceiver(t)

	w := postAs(t, r, PathPrefix+"tok-wan-1234567890", `{"message":"fake"}`, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if n := len(s.all()); n != 0 {
		t.Fatalf("%d alarm(s) were raised by a request with no Authorization header", n)
	}
}

func TestTheRightURLWithTheWrongHeaderIsRefused(t *testing.T) {
	r, s := newTestReceiver(t)

	for _, authz := range []string{
		"Bearer wrong",
		"Bearer " + threatBearer,    // another hook's bearer
		wanBearer,                   // the value without the scheme
		"bearer " + wanBearer,       // wrong case on the scheme
		"Bearer " + wanBearer + "x", // one character too long
		"Bearer " + wanBearer[:len(wanBearer)-1],
	} {
		w := postAs(t, r, PathPrefix+"tok-wan-1234567890", `{"message":"fake"}`, authz)
		if w.Code != http.StatusNotFound {
			t.Errorf("%q: status = %d, want 404", authz, w.Code)
		}
	}
	if n := len(s.all()); n != 0 {
		t.Errorf("%d alarm(s) were raised by a wrong header", n)
	}
}

// A 404 whatever went wrong, so a leaked URL discloses nothing -- but an
// operator who pasted the URL and forgot the header must be able to find out
// why nothing works. The diagnosis lives behind the session gate.
func TestARefusedArrivalIsCountedAgainstItsHookWithAReason(t *testing.T) {
	r, _ := newTestReceiver(t)

	postAs(t, r, PathPrefix+"tok-wan-1234567890", `{}`, "")
	postAs(t, r, PathPrefix+"tok-wan-1234567890", `{}`, "Bearer nope")

	var wan Receipt
	for _, rec := range r.Receipts() {
		if rec.Name == "wan" {
			wan = rec
		}
	}
	if wan.Rejected != 2 {
		t.Fatalf("rejected = %d, want 2 -- an operator who forgot the header "+
			"would otherwise see only \"nothing has ever arrived\"", wan.Rejected)
	}
	if wan.Count != 0 {
		t.Errorf("a refused arrival was counted as a real one")
	}
	if !strings.Contains(wan.LastReject, "Authorization") {
		t.Errorf("last reject = %q, want it to name what was wrong", wan.LastReject)
	}
	if wan.LastRejectAt.IsZero() {
		t.Error("the refusal was not timestamped")
	}
}

// Fail closed. A hook with no bearer is not an open endpoint, it is a dead
// one -- the alternative is a live URL anybody who learns it can feed alarms
// to, which is exactly what the bearer exists to prevent.
func TestAHookWithNoBearerAcceptsNothing(t *testing.T) {
	s := &sink{}
	r := New([]Hook{{Name: "broken", Token: "tok-broken-12345678", Condition: "x"}},
		Options{Emit: s.emit, Now: func() time.Time { return t0 }})

	for _, authz := range []string{"", "Bearer ", "Bearer anything"} {
		w := postAs(t, r, PathPrefix+"tok-broken-12345678", `{}`, authz)
		if w.Code != http.StatusNotFound {
			t.Errorf("%q: status = %d, want 404", authz, w.Code)
		}
	}
	if n := len(s.all()); n != 0 {
		t.Errorf("a hook with no bearer raised %d alarm(s)", n)
	}
}

// The operator has to be given something to paste, in the form the console
// wants it.
func TestHeaderValueForRendersThePasteableHeader(t *testing.T) {
	h := testHooks()[0]
	if got := HeaderValueFor(h); got != "Bearer "+wanBearer {
		t.Errorf("HeaderValueFor = %q", got)
	}
	if HeaderName != "Authorization" {
		t.Errorf("HeaderName = %q, want the header Alarm Manager sends", HeaderName)
	}
	if got := HeaderValueFor(Hook{Name: "x"}); got != "" {
		t.Errorf("a hook with no bearer offered %q to paste", got)
	}
}
