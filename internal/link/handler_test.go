package link

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
)

// harness wires a receiver to in-memory stand-ins for the rest of the product.
type harness struct {
	rc    *Receiver
	cred  Credential
	peer  Peer
	claim *Claim

	mu        sync.Mutex
	ingested  []event.Event
	receipts  []Receipt
	seen      map[string]time.Time
	ingestErr error
	channels  []ChannelState
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	p := sentry()
	p.LinkID = "lnk_sentry"

	h := &harness{
		cred:     Credential{LinkID: p.LinkID, Key: []byte("sentry-shared-secret")},
		peer:     p,
		claim:    NewClaim("access", time.Minute),
		seen:     map[string]time.Time{},
		channels: []ChannelState{{Name: "email", Enabled: true}},
	}
	v := NewVerifier()
	v.Now = func() time.Time { return now }

	h.rc = NewReceiver(Deps{
		Peers:       func() []Peer { return []Peer{h.peer} },
		Credentials: func() []Credential { return []Credential{h.cred} },
		Ingest: func(_ context.Context, e event.Event) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.ingestErr != nil {
				return h.ingestErr
			}
			h.ingested = append(h.ingested, e)
			return nil
		},
		Seen: func(_ context.Context, linkID, eventID string, at time.Time, _ time.Duration) (bool, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			k := linkID + "/" + eventID
			if _, dup := h.seen[k]; dup {
				return true, nil
			}
			h.seen[k] = at
			return false, nil
		},
		Forget: func(_ context.Context, linkID, eventID string) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			delete(h.seen, linkID+"/"+eventID)
			return nil
		},
		Channels: func() []ChannelState { h.mu.Lock(); defer h.mu.Unlock(); return h.channels },
		Claim:    func(slug string) *Claim { return h.claim },
		Record:   func(r Receipt) { h.mu.Lock(); defer h.mu.Unlock(); h.receipts = append(h.receipts, r) },
		Now:      func() time.Time { return now },
		Verifier: v,
	})
	return h
}

// post signs and sends a request the way a correct peer would.
func (h *harness) post(path string, body []byte, nonce string) *httptest.ResponseRecorder {
	stamp := strconv.FormatInt(now.Unix(), 10)
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	r.Header.Set(HeaderLinkID, h.cred.LinkID)
	r.Header.Set(HeaderTimestamp, stamp)
	r.Header.Set(HeaderNonce, nonce)
	r.Header.Set("Authorization", Scheme+" "+
		Sign(h.cred.Key, Canonical(http.MethodPost, path, h.cred.LinkID, stamp, nonce, body)))
	w := httptest.NewRecorder()
	h.rc.ServeHTTP(w, r)
	return w
}

func (h *harness) envelope(t *testing.T, mutate func(*Envelope)) []byte {
	t.Helper()
	e := sweep()
	if mutate != nil {
		mutate(&e)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (h *harness) count() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.ingested) }

func decode(t *testing.T, w *httptest.ResponseRecorder) reply {
	t.Helper()
	var got reply
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("reply is not the bounded JSON a peer parses: %v\n%s", err, w.Body.String())
	}
	return got
}

func TestAnEventIsAcceptedAndIngested(t *testing.T) {
	h := newHarness(t)
	w := h.post(RouteEvents, h.envelope(t, nil), "n1")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\n%s", w.Code, w.Body.String())
	}
	got := decode(t, w)
	if !got.Accepted || got.Duplicate {
		t.Errorf("reply = %+v, want accepted and not duplicate", got)
	}
	if got.Delivery != DeliveryOK {
		t.Errorf("delivery = %q, want %q", got.Delivery, DeliveryOK)
	}
	if h.count() != 1 {
		t.Errorf("ingested %d events, want 1", h.count())
	}
}

// THE RETRY. The peer resends with the SAME event id after a timeout, so an
// event accepted here whose reply never arrived must not raise a second alarm
// -- and must be answered with the same success, because an error would just
// be retried again.
func TestARetriedEventIdIsANoOp(t *testing.T) {
	h := newHarness(t)
	body := h.envelope(t, nil)

	if w := h.post(RouteEvents, body, "n1"); w.Code != http.StatusOK {
		t.Fatalf("first attempt: %d", w.Code)
	}
	// A retry is a new request: new nonce, same event id.
	w := h.post(RouteEvents, body, "n2")
	if w.Code != http.StatusOK {
		t.Fatalf("a retry was refused with %d; the peer would retry again", w.Code)
	}
	got := decode(t, w)
	if !got.Accepted || !got.Duplicate {
		t.Errorf("reply = %+v, want accepted AND duplicate", got)
	}
	if h.count() != 1 {
		t.Errorf("the retry raised the alarm again: %d incidents", h.count())
	}
}

// An event that was recorded as seen and then failed to become an incident
// must NOT leave its id behind. Otherwise the peer's retry is answered as a
// duplicate of something that never existed, and both ends agree an alarm was
// handled when nobody was told.
func TestAFailedIngestReleasesTheEventId(t *testing.T) {
	h := newHarness(t)
	h.ingestErr = errors.New("store is unwell")
	body := h.envelope(t, nil)

	if w := h.post(RouteEvents, body, "n1"); w.Code != http.StatusNotFound {
		t.Fatalf("a failed ingest answered %d; the peer must retry", w.Code)
	}

	h.mu.Lock()
	h.ingestErr = nil
	h.mu.Unlock()

	w := h.post(RouteEvents, body, "n2")
	if w.Code != http.StatusOK {
		t.Fatalf("the retry was refused: %d", w.Code)
	}
	if got := decode(t, w); got.Duplicate {
		t.Error("the retry was answered as a duplicate of an event that never became an incident")
	}
	if h.count() != 1 {
		t.Errorf("ingested %d, want 1 -- the retry should have landed", h.count())
	}
}

// Every failure is the same failure on the wire. The reason exists only in the
// receipt, where a signed-in operator can read it.
func TestEveryFailureIsABare404WithTheReasonOnlyInTheReceipt(t *testing.T) {
	h := newHarness(t)

	// Unsigned.
	r := httptest.NewRequest(http.MethodPost, RouteEvents, strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h.rc.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("an unsigned request answered %d", w.Code)
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "signature") ||
		strings.Contains(strings.ToLower(w.Body.String()), "unauthor") {
		t.Errorf("the wire answer explained the failure: %q", w.Body.String())
	}

	// An unknown route, and a method that is not POST.
	if w := h.post("/link/v1/nope", []byte("{}"), "n2"); w.Code != http.StatusNotFound {
		t.Errorf("an unknown route answered %d", w.Code)
	}
	req := httptest.NewRequest(http.MethodGet, RouteEvents, nil)
	rec := httptest.NewRecorder()
	h.rc.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET answered %d", rec.Code)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	var reasons int
	for _, rc := range h.receipts {
		if !rc.Accepted && rc.Reason != "" {
			reasons++
		}
	}
	if reasons == 0 {
		t.Error("no refusal recorded a reason; an operator has no way to see a peer being refused")
	}
}

// A condition outside the approved manifest is refused, and refused the same
// way everything else is.
func TestAnUnapprovedConditionIsRefusedAtTheEndpoint(t *testing.T) {
	h := newHarness(t)
	body := h.envelope(t, func(e *Envelope) { e.Condition = "sentry-invented" })
	if w := h.post(RouteEvents, body, "n1"); w.Code != http.StatusNotFound {
		t.Errorf("an unapproved condition answered %d", w.Code)
	}
	if h.count() != 0 {
		t.Error("an unapproved condition was ingested")
	}
}

// A body over the cap is refused without being read into memory whole.
func TestAnOversizedBodyIsRefused(t *testing.T) {
	h := newHarness(t)
	big := make([]byte, MaxEventBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	if w := h.post(RouteEvents, big, "n1"); w.Code != http.StatusNotFound {
		t.Errorf("an oversized body answered %d", w.Code)
	}
}

// The claim moves on the edges of a claim-demoting condition, and the peer
// keeps its claim through ordinary alarms.
func TestAClaimDemotingEventDemotesTheClaim(t *testing.T) {
	h := newHarness(t)

	// Heartbeat first so the claim is held at all.
	if w := h.post(RouteHeartbeat, []byte(`{}`), "hb"); w.Code != http.StatusOK {
		t.Fatalf("heartbeat answered %d", w.Code)
	}
	if held, why := h.claim.Held(now.Add(2*time.Minute), 15*time.Minute); !held {
		t.Fatalf("the claim was not held after a heartbeat: %s", why)
	}

	// An ordinary alarm changes nothing.
	ordinary := h.envelope(t, func(e *Envelope) { e.EventID = "ord" })
	h.post(RouteEvents, ordinary, "n-ord")
	if held, why := h.claim.Held(now.Add(2*time.Minute), 15*time.Minute); !held {
		t.Errorf("an ordinary alarm demoted the claim: %s", why)
	}

	// The blind condition does.
	blind := h.envelope(t, func(e *Envelope) {
		e.EventID = "blind"
		e.Condition = "sentry-blocked-locally"
		e.Severity = "critical"
		e.Entity = Party{Kind: "site", ID: "site-1", Name: "The site"}
	})
	if w := h.post(RouteEvents, blind, "n-blind"); w.Code != http.StatusOK {
		t.Fatalf("the claim-demoting event was refused: %d", w.Code)
	}
	held, why := h.claim.Held(now, 15*time.Minute)
	if held {
		t.Error("a peer reporting it cannot reach the console kept its claim")
	}
	if !strings.Contains(why, "sentry-blocked-locally") {
		t.Errorf("reason %q does not name the condition", why)
	}

	// ...and the clear restores it, after the hysteresis.
	clear := h.envelope(t, func(e *Envelope) {
		e.EventID = "blind-clear"
		e.Condition = "sentry-blocked-locally"
		e.Severity = "critical"
		e.State = StateCleared
		e.Entity = Party{Kind: "site", ID: "site-1", Name: "The site"}
	})
	if w := h.post(RouteEvents, clear, "n-clear"); w.Code != http.StatusOK {
		t.Fatalf("the clear was refused: %d", w.Code)
	}
	if held, why := h.claim.Held(now.Add(2*time.Minute), 15*time.Minute); !held {
		t.Errorf("the claim did not recover after the clear: %s", why)
	}
}

// The reply carries channel health so a peer can decide to tell the human
// itself. Not a receipt for this event: at this moment nothing has happened to
// it yet.
func TestTheReplyReportsDegradedChannels(t *testing.T) {
	h := newHarness(t)
	h.channels = []ChannelState{{Name: "email", Enabled: true, ConsecutiveFails: 3}}

	got := decode(t, h.post(RouteEvents, h.envelope(t, nil), "n1"))
	if got.Delivery != DeliveryDegraded {
		t.Errorf("delivery = %q, want %q", got.Delivery, DeliveryDegraded)
	}
	if !got.Accepted {
		t.Error("a degraded notifier refused the event; it must still be tracked here")
	}
}

func TestHeartbeatAndPingAreServed(t *testing.T) {
	h := newHarness(t)
	for _, route := range []string{RouteHeartbeat, RoutePing} {
		w := h.post(route, []byte(`{}`), "n-"+route)
		if w.Code != http.StatusOK {
			t.Errorf("%s answered %d", route, w.Code)
		}
		if got := decode(t, w); !got.Accepted || got.ServerTime == "" {
			t.Errorf("%s reply = %+v, want accepted with a server time", route, got)
		}
	}
}

// TWO LINK IDS DIFFERING ONLY IN CASE MUST NOT BE CONFUSED.
//
// Authentication matched byte for byte and the peer lookup matched
// case-insensitively, so a request could authenticate against one credential
// and then resolve to the OTHER peer -- arriving under the wrong product's
// slug, with the wrong manifest deciding what it is allowed to send. Ids are
// machine-minted and never retyped, so nothing legitimate needed the
// leniency.
func TestAPeerLookupDoesNotMatchADifferentCase(t *testing.T) {
	peers := []Peer{
		{Slug: "sentry", LinkID: "lnk_abc"},
		{Slug: "doormatrix", LinkID: "LNK_ABC"},
	}
	rc := NewReceiver(Deps{Peers: func() []Peer { return peers }})

	got, ok := rc.peer("lnk_abc")
	if !ok || got.Slug != "sentry" {
		t.Fatalf("exact lookup returned %+v ok=%v", got, ok)
	}
	got, ok = rc.peer("LNK_ABC")
	if !ok || got.Slug != "doormatrix" {
		t.Fatalf("the other exact lookup returned %+v ok=%v", got, ok)
	}
	if _, ok := rc.peer("Lnk_Abc"); ok {
		t.Error("a spelling matching neither credential resolved to a peer; " +
			"an authenticated request would then arrive under the wrong " +
			"product's slug and manifest")
	}
}

// receiptCount reports how many receipts the harness has recorded, under the
// lock the listener tests need because the receiver runs on its own goroutine.
func (h *harness) receiptCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.receipts)
}
