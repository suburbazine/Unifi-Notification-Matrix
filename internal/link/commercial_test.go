package link

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// WHEN PARTNER EVENTS ARE REFUSED: at least one partner paired, none granting
// commercial use -- with a partner not yet heard from since start given the
// benefit of the doubt for the grace, and no longer.
func TestRejecting(t *testing.T) {
	start := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	inGrace := start.Add(time.Minute)
	after := start.Add(DefaultPermissionGrace + time.Second)

	for _, tc := range []struct {
		name  string
		slugs []string
		said  map[string]bool // slug -> granted; absent = not heard
		at    time.Time
		want  bool
	}{
		{"nothing paired: nothing to refuse", nil, nil, after, false},
		{"the only partner grants it", []string{"lsrewards"}, map[string]bool{"lsrewards": true}, after, false},
		{"the only partner does not", []string{"lsrewards"}, map[string]bool{"lsrewards": false}, after, true},
		{"one of two grants it, for both", []string{"sentry", "lsrewards"},
			map[string]bool{"sentry": false, "lsrewards": true}, after, false},
		{"neither grants it", []string{"sentry", "lsprotect"},
			map[string]bool{"sentry": false, "lsprotect": false}, after, true},
		{"not heard yet, inside the grace", []string{"sentry", "lsrewards"},
			map[string]bool{"sentry": false}, inGrace, false},
		// The grace is for partners not heard from yet. One that has already
		// said no has answered.
		{"said no, inside the grace", []string{"lsrewards"},
			map[string]bool{"lsrewards": false}, inGrace, true},
		{"not heard yet, after the grace", []string{"sentry", "lsrewards"},
			map[string]bool{"sentry": false}, after, true},
		{"slugs compared without case", []string{"LSRewards"}, map[string]bool{"lsrewards": true}, after, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPermissions(start, DefaultPermissionGrace)
			for s, g := range tc.said {
				p.Note(s, g, start)
			}
			if got := p.Rejecting(tc.slugs, tc.at); got != tc.want {
				t.Errorf("Rejecting = %v, want %v", got, tc.want)
			}
		})
	}
}

// A lapsed Pro tier stops granting at its next word, with nothing here to
// expire: the latest thing a partner said is the answer.
func TestTheLatestWordWins(t *testing.T) {
	start := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	p := NewPermissions(start, 0)
	p.Note("lsrewards", true, start)
	p.Note("lsrewards", false, start.Add(time.Minute))
	if !p.Rejecting([]string{"lsrewards"}, start.Add(2*time.Minute)) {
		t.Error("a partner that stopped granting permission is still treated as granting it")
	}
	if got := p.State("lsrewards"); got != PermissionNotGranted {
		t.Errorf("state = %q", got)
	}
}

// The signal in a heartbeat or ping body: only an explicit true grants.
func TestCommercialSignal(t *testing.T) {
	for body, want := range map[string]bool{
		`{"commercial_permission":true}`:  true,
		`{"commercial_permission":false}`: false,
		`{}`:                              false,
		``:                                false,
		`not json`:                        false,
		`{"commercial_permission":"yes"}`: false,
	} {
		if got := commercialSignal([]byte(body)); got != want {
			t.Errorf("commercialSignal(%q) = %v, want %v", body, got, want)
		}
	}
}

// withPermissions wires the harness's receiver to a real record, started an
// hour ago so the grace is long over.
func withPermissions(h *harness) *Permissions {
	p := NewPermissions(now.Add(-time.Hour), DefaultPermissionGrace)
	h.rc.deps.Permit = p.Note
	h.rc.deps.Rejecting = func(at time.Time) bool { return p.Rejecting([]string{h.peer.Slug}, at) }
	return p
}

// THE REJECT, end to end through a signed request: an event from the only
// partner, granting nothing, is refused -- not ingested, not remembered, and
// recorded with its reason.
func TestAPartnerEventWithoutPermissionIsRefused(t *testing.T) {
	h := newHarness(t)
	withPermissions(h)

	w := h.post(RouteEvents, h.envelope(t, nil), "n1")
	if w.Code != http.StatusNotFound {
		t.Fatalf("an event with no commercial permission answered %d, want the bare 404", w.Code)
	}
	if h.count() != 0 {
		t.Fatal("the refused event was ingested")
	}
	last := h.receipts[len(h.receipts)-1]
	if last.Cause != CauseNoCommercialPermission {
		t.Errorf("receipt cause = %q, want %q", last.Cause, CauseNoCommercialPermission)
	}

	// Not remembered as seen: the retry, once permission is granted, lands.
	w = h.post(RouteEvents, h.envelope(t, func(e *Envelope) { e.CommercialPermission = true }), "n2")
	if w.Code != http.StatusOK || h.count() != 1 {
		t.Fatalf("the retry carrying permission answered %d and ingested %d; a refused "+
			"event must not be remembered as delivered", w.Code, h.count())
	}
	if decode(t, w).Duplicate {
		t.Error("the retry was answered as a duplicate of an event that was refused")
	}
}

// Heartbeats are taken regardless, carry the permission, and say whether this
// product is refusing -- so the partner can tell its own operator why.
func TestHeartbeatsCarryThePermissionAndAreAlwaysTaken(t *testing.T) {
	h := newHarness(t)
	p := withPermissions(h)

	w := h.post(RouteHeartbeat, []byte(`{}`), "h1")
	if w.Code != http.StatusOK {
		t.Fatalf("a heartbeat granting nothing answered %d; it must still be taken", w.Code)
	}
	if !decode(t, w).CommercialPermissionRequired {
		t.Error("the heartbeat reply does not tell the partner its events are being refused")
	}

	w = h.post(RouteHeartbeat, []byte(`{"commercial_permission":true}`), "h2")
	if decode(t, w).CommercialPermissionRequired {
		t.Error("the reply to a heartbeat granting permission still says it is required")
	}
	if p.State(h.peer.Slug) != PermissionGranted {
		t.Errorf("state after a granting heartbeat = %q", p.State(h.peer.Slug))
	}
	// And the next event goes through on the strength of its own word.
	w = h.post(RouteEvents, h.envelope(t, func(e *Envelope) { e.CommercialPermission = true }), "e1")
	if w.Code != http.StatusOK {
		t.Errorf("an event from a partner granting permission answered %d", w.Code)
	}
}

// Nothing wired, nothing refused: a build that does not care is unaffected.
func TestNoPermissionRecordMeansNoRejection(t *testing.T) {
	h := newHarness(t)
	if w := h.post(RouteEvents, h.envelope(t, nil), "n1"); w.Code != http.StatusOK {
		t.Errorf("without a permission record an event answered %d", w.Code)
	}
}

// A Pro partner grants permission as it pairs, so its first event is not
// refused while its first heartbeat is still on the way.
func TestPairingCarriesThePermission(t *testing.T) {
	base, fp, h, client := liveLink(t)
	p := withPermissions(h)

	code, err := h.rc.deps.Pairer.Offer()
	if err != nil {
		t.Fatal(err)
	}
	req := pairReq(FormatCode(code), fp)
	req.CommercialPermission = true
	body, _ := json.Marshal(req)
	resp, err := client.Post(base+RoutePair, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pairing answered %d", resp.StatusCode)
	}
	if got := p.State("sentry"); got != PermissionGranted {
		t.Errorf("after pairing with permission, state = %q, want granted", got)
	}
}
