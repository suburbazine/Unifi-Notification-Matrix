package link

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// contacts wires a recorder into the harness's receiver.
func (h *harness) contacts() *[]string {
	var got []string
	h.rc.deps.Contact = func(slug string, _ time.Time) {
		h.mu.Lock()
		defer h.mu.Unlock()
		got = append(got, slug)
	}
	return &got
}

// EVERY AUTHENTICATED REQUEST IS PROOF OF LIFE.
//
// Heartbeats used to land only in a capability claim, so a peer that claims
// nothing -- a loyalty system, a POS bridge, most peers -- could stop and be
// noticed by nothing. And an event is as good a sign of life as a heartbeat:
// a peer busy sending must not be reported silent because its heartbeat timer
// ran late.
func TestAnAuthenticatedRequestCountsAsContact(t *testing.T) {
	h := newHarness(t)
	got := h.contacts()

	h.post(RouteHeartbeat, []byte(`{}`), "n-beat")
	h.post(RoutePing, []byte(`{}`), "n-ping")
	h.post(RouteEvents, h.envelope(t, nil), "n-event")
	// Refused for its CONTENT, but it authenticated: the peer is there.
	h.post(RouteEvents, h.envelope(t, func(e *Envelope) { e.Condition = "sentry-never-declared" }), "n-bad")

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(*got) != 4 {
		t.Fatalf("contact recorded %d times for four authenticated requests: %v", len(*got), *got)
	}
	for _, slug := range *got {
		if slug != h.peer.Slug {
			t.Errorf("contact recorded for %q, want the peer's slug %q", slug, h.peer.Slug)
		}
	}
}

// AND NOTHING UNAUTHENTICATED IS.
//
// A deadman that anybody on the network can refresh by sending garbage at the
// port is a deadman anybody can disarm -- kill the shop PC, then keep poking
// the port, and it never reports silent.
func TestAnUnauthenticatedRequestIsNotContact(t *testing.T) {
	h := newHarness(t)
	got := h.contacts()

	stamp := strconv.FormatInt(now.Unix(), 10)
	for _, auth := range []string{
		"",                                    // unsigned
		Scheme + " " + "bm90LWEtc2lnbmF0dXJl", // signed with nothing
	} {
		r := httptest.NewRequest(http.MethodPost, RouteHeartbeat, strings.NewReader(`{}`))
		r.Header.Set(HeaderLinkID, h.cred.LinkID) // the right id, which is not a secret
		r.Header.Set(HeaderTimestamp, stamp)
		r.Header.Set(HeaderNonce, "n-forged-"+strconv.Itoa(len(auth)))
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.rc.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("a forged heartbeat answered %d", w.Code)
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(*got) != 0 {
		t.Errorf("an unauthenticated request counted as contact %d time(s): anybody who "+
			"can reach the port can keep a dead peer looking alive", len(*got))
	}
}

// EVERY REPLY TELLS THE PEER HOW OFTEN TO HEARTBEAT, so a window changed here
// reaches a peer paired months ago at its next contact, with nothing re-paired.
func TestEveryReplyCarriesThePeersHeartbeatRate(t *testing.T) {
	h := newHarness(t)
	h.peer.SilentAfter = 2 * time.Minute
	for _, route := range []string{RouteHeartbeat, RoutePing} {
		w := h.post(route, []byte(`{}`), "n-"+route)
		if got := decode(t, w); got.HeartbeatSeconds != 40 {
			t.Errorf("%s replied heartbeat_seconds %d, want 40 for a 2m window",
				route, got.HeartbeatSeconds)
		}
	}
	w := h.post(RouteEvents, h.envelope(t, nil), "n-event")
	if got := decode(t, w); got.HeartbeatSeconds != 40 {
		t.Errorf("an event reply carried heartbeat_seconds %d, want 40", got.HeartbeatSeconds)
	}
}
