package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

func helloOf(t *testing.T, h *harness) Hello {
	t.Helper()
	res, body := h.do("GET", "/hello", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /hello returned %d: %s", res.StatusCode, body)
	}
	var got Hello
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("the answer is not the JSON a peer parses: %v\n%s", err, body)
	}
	return got
}

// IDENTIFYING THE PRODUCT IS UNAUTHENTICATED, and has to be.
//
// A peer that cannot ask what a port is before sending a pairing code has to
// guess, and a guess that lands on the wrong product does not fail cleanly: it
// burns one of five pairing attempts, and the fifth voids the operator's code
// in a way that reads as a mistyped code.
//
// It discloses nothing this listener was not already disclosing. GET / serves
// the product name in a title and its version in the header to anybody who
// asks, and /api/status is public so a wall display can show it. The one new
// fact is the link listener's port.
func TestTheProductIdentifiesItselfWithoutASession(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)

	got := helloOf(t, h)
	if got.Product != link.ProductSlug {
		t.Errorf("product = %q, want %q", got.Product, link.ProductSlug)
	}
	if got.Name == "" || got.Channels == nil {
		t.Errorf("hello = %+v, want a name and a channels list (empty, not absent)", got)
	}

	// The claim that this adds nothing has to be true, not assumed.
	_, page := h.do("GET", "/", nil)
	if !strings.Contains(strings.ToLower(string(page)), "notification matrix") {
		t.Error("the root page no longer names the product to a signed-out reader, " +
			"so /hello is now disclosing something new and the reasoning in " +
			"hello.go needs revisiting")
	}
}

// AN ADVERTISEMENT THAT GOES NOWHERE IS WORSE THAN SILENCE.
//
// A peer follows what this says and confirms the channel before calling a
// candidate found. Advertising a link channel on an installation that has no
// link listener would turn "I could not find it" into "I found the wrong
// thing", which is the failure the advertisement exists to prevent.
func TestNoLinkListenerMeansNoChannelIsAdvertised(t *testing.T) {
	h := newHarness(t)
	if got := helloOf(t, h); len(got.Channels) != 0 {
		t.Errorf("channels = %+v on an installation with no link listener", got.Channels)
	}

	// Configured but reporting unavailable is the same answer.
	h.srv.deps.LinkState = func() LinkPairing {
		return LinkPairing{Available: false, Address: "0.0.0.0:8433"}
	}
	if got := helloOf(t, h); len(got.Channels) != 0 {
		t.Errorf("channels = %+v when the link listener is not available", got.Channels)
	}
}

// THE PORT IS THE POINT.
//
// This product's operator interface is plain HTTP on one port and its peer
// link is TLS on another, so a peer following only a path from here lands on
// the web listener, where the link routes do not exist.
func TestAConfiguredLinkListenerIsAdvertisedWithItsPortAndTLS(t *testing.T) {
	h := newHarness(t)
	h.srv.deps.LinkState = func() LinkPairing {
		return LinkPairing{Available: true, Address: "0.0.0.0:18433"}
	}

	got := helloOf(t, h)
	if len(got.Channels) != 1 {
		t.Fatalf("channels = %+v, want exactly the link channel", got.Channels)
	}
	c := got.Channels[0]
	if c.Protocol != link.ProtocolName || c.Role != link.RoleReceiver {
		t.Errorf("channel = %+v, want protocol %q and role %q",
			c, link.ProtocolName, link.RoleReceiver)
	}
	if c.Port != 18433 {
		t.Errorf("port = %d, want 18433 -- without it a peer follows the path to "+
			"the wrong listener", c.Port)
	}
	if !c.TLS {
		t.Error("the link channel is advertised as plain; it is TLS, and a peer " +
			"that believes this will not connect at all")
	}
	if c.Path != "/link" {
		t.Errorf("path = %q, want /link", c.Path)
	}

	// The BIND HOST must not travel. A peer reaches this product at whatever
	// address it reached this listener on; "0.0.0.0" is a worse answer than
	// none, and an internal address is somebody else's business.
	if strings.Contains(c.Path, "0.0.0.0") {
		t.Error("the bind host leaked into the advertisement")
	}

	// And the channel says when its own hello will answer, because this one
	// answers only inside a pairing window. A peer that did not know that
	// would read a silent channel hello as the wrong product.
	if c.Hello != HelloWhilePairing {
		t.Errorf("hello = %q, want %q: the link listener is silent outside a "+
			"pairing window, and a peer has no way to know that unless it is said",
			c.Hello, HelloWhilePairing)
	}
}

// An address that is not host:port advertises nothing rather than something
// wrong. "auto" before the listener has bound is exactly this case.
func TestAnUnresolvedAddressAdvertisesNothing(t *testing.T) {
	h := newHarness(t)
	for _, addr := range []string{"auto", "", "not an address"} {
		h.srv.deps.LinkState = func() LinkPairing {
			return LinkPairing{Available: true, Address: addr}
		}
		if got := helloOf(t, h); len(got.Channels) != 0 {
			t.Errorf("address %q advertised %+v", addr, got.Channels)
		}
	}
}
