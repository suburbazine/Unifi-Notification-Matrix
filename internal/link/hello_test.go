package link

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getHello(h *harness) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, RouteHello, nil)
	w := httptest.NewRecorder()
	h.rc.ServeHTTP(w, r)
	return w
}

// THE WINDOW IS THE WHOLE DESIGN.
//
// A peer asked for a permanently open identify endpoint, and the reason was
// good: it wants to refuse the wrong product rather than burn one of five
// pairing attempts against it, and on the fifth void the operator's code in a
// way that reads as a typo. But every other failure on this listener is a bare
// 404 precisely so nothing confirms that something is listening, and an
// endpoint that names the product and its version to anyone who asks hands a
// scanner the product, the version to look up, and the fact that this machine
// is the one watching the doors.
//
// Answering only while the operator has a code on offer keeps both properties.
func TestIdentifyAnswersOnlyWhileAPairingCodeIsOnOffer(t *testing.T) {
	h := newHarness(t)
	p := NewPairer(fpA)
	h.rc.deps.Pairer = p

	if w := getHello(h); w.Code != http.StatusNotFound {
		t.Fatalf("identified itself with no pairing window open: %d %s",
			w.Code, w.Body.String())
	}

	if _, err := p.Offer(); err != nil {
		t.Fatal(err)
	}
	w := getHello(h)
	if w.Code != http.StatusOK {
		t.Fatalf("refused to identify itself during an open window: %d", w.Code)
	}
	var got Hello
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the answer is not the JSON a peer parses: %v\n%s", err, w.Body.String())
	}
	if got.Product != ProductSlug || got.Protocol != ProtocolName {
		t.Errorf("hello = %+v, want product %q and protocol %q -- a peer matches "+
			"on BOTH, or it pairs happily across an incompatible protocol",
			got, ProductSlug, ProtocolName)
	}
	if got.Role != RoleReceiver {
		t.Errorf("role = %q, want %q", got.Role, RoleReceiver)
	}
	if got.Fingerprint != p.Fingerprint {
		t.Errorf("fingerprint = %q, want the certificate this product presents", got.Fingerprint)
	}

	// Cancelled, and the port goes quiet again.
	p.Cancel()
	if w := getHello(h); w.Code != http.StatusNotFound {
		t.Errorf("still identifying itself after the code was cancelled: %d", w.Code)
	}
}

// A closed window answers the SAME bare 404 as everything else, or the
// endpoint has become the thing it was written to avoid: a way to tell that
// something is there.
func TestIdentifyOutsideTheWindowIsIndistinguishableFromNoRoute(t *testing.T) {
	h := newHarness(t)
	h.rc.deps.Pairer = NewPairer(fpA)

	closed := getHello(h)
	absent := httptest.NewRecorder()
	h.rc.ServeHTTP(absent, httptest.NewRequest(http.MethodGet, "/link/nothing-here", nil))

	if closed.Code != absent.Code {
		t.Errorf("a closed identify window answered %d and a route that does not "+
			"exist answered %d; the difference says something is there",
			closed.Code, absent.Code)
	}
	if closed.Body.String() != absent.Body.String() {
		t.Errorf("the bodies differ:\n%q\n%q", closed.Body.String(), absent.Body.String())
	}
	if strings.Contains(strings.ToLower(closed.Body.String()), "notifymatrix") {
		t.Error("the refusal names the product, which is what the window exists to withhold")
	}
}

// The operator can still find out that somebody looked. A probe that arrives
// before the window opens is not an attack and not a misconfiguration, and
// "my probe found nothing" deserves an answer on this end.
func TestAnIdentifyProbeOutsideTheWindowIsRecorded(t *testing.T) {
	h := newHarness(t)
	h.rc.deps.Pairer = NewPairer(fpA)
	getHello(h)

	if got := h.lastCause(t); got != CauseHelloClosed {
		t.Errorf("cause = %q, want %q", got, CauseHelloClosed)
	}
}

// A build with no pairer has no identify endpoint either, and says so the same
// way it says everything else.
func TestWithNoPairerIdentifyIsAlsoA404(t *testing.T) {
	h := newHarness(t)
	h.rc.deps.Pairer = nil
	if w := getHello(h); w.Code != http.StatusNotFound {
		t.Errorf("a build that cannot pair still answered identify: %d", w.Code)
	}
}

// GET IS ALLOWED FOR THIS ROUTE AND NOTHING ELSE.
//
// Widening the method check is the easy way to turn one read-only endpoint
// into a hole: every other route here takes a signed POST, and a GET that
// reached them would be a request nothing authenticated.
func TestGetIsStillRefusedOnEveryOtherRoute(t *testing.T) {
	h := newHarness(t)
	h.rc.deps.Pairer = NewPairer(fpA)
	if _, err := h.rc.deps.Pairer.Offer(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{RouteEvents, RouteHeartbeat, RoutePing, RoutePair} {
		w := httptest.NewRecorder()
		h.rc.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s answered %d during a pairing window", path, w.Code)
		}
	}
}
