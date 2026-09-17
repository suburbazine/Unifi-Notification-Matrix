package main

import (
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/setup"
)

// A HOOK URL MUST POINT AT THE LISTENER THAT SERVES HOOKS.
//
// It was built from web.ack_base_url, which is the address of the
// acknowledgement LINKS. When web.ack_listen is set -- which the checklist
// recommends, because it lets a port forward publish acknowledgements without
// publishing the status page -- that address reaches a listener serving ONLY
// /ack/. A hook URL built from it 404s.
//
// And the receiver answers every unknown path with a bare 404 by design, so
// nothing is recorded as rejected either: the console reports success, the
// rule looks perfect in UniFi, and the alarms it carries simply never arrive.
// Steps 4 and 5 of the checklist are adjacent, so following them produced it.
func TestAHookURLNeverUsesTheAcknowledgementAddress(t *testing.T) {
	in := setup.Input{
		Listen:     "0.0.0.0:8322",
		AckBaseURL: "http://notifymatrix.example.com",
		AckListen:  "0.0.0.0:50001",
	}
	got := hookBase(in)

	if strings.Contains(got, "notifymatrix.example.com") {
		t.Errorf("the hook URL points at the acknowledgement address (%s); "+
			"with ack_listen set, that listener serves only /ack/ and the "+
			"alarm would 404", got)
	}
	if strings.Contains(got, "50001") {
		t.Errorf("the hook URL uses the acknowledgement-only port: %s", got)
	}
	if !strings.HasSuffix(got, ":8322") {
		t.Errorf("hook base = %q, want this machine on web.listen's port 8322", got)
	}
}

// A listener bound to one address is already the answer and must be used
// verbatim: it is more likely to be right than anything guessed from the
// interface list.
func TestASpecificListenAddressIsUsedAsGiven(t *testing.T) {
	got := hookBase(setup.Input{Listen: "192.168.20.115:8330"})
	if got != "http://192.168.20.115:8330" {
		t.Errorf("hook base = %q, want the configured address verbatim", got)
	}
}

// Bound to everything: the console needs this machine's address on the network
// they share, and the port the hook receiver actually answers on.
func TestAWildcardListenResolvesToThisMachine(t *testing.T) {
	got := hookBase(setup.Input{Listen: "0.0.0.0:9001"})
	if !strings.HasSuffix(got, ":9001") {
		t.Errorf("hook base = %q, want port 9001", got)
	}
	if strings.Contains(got, "0.0.0.0") {
		t.Errorf("hook base = %q; a console cannot post to 0.0.0.0", got)
	}
	if strings.Contains(got, "127.0.0.1") || strings.Contains(got, "localhost") {
		t.Errorf("hook base = %q; a console is not this machine", got)
	}
}

// Loopback is a misconfiguration the checklist already reports at the step
// that fixes it. What matters here is that the URL never says 127.0.0.1,
// which no other device can reach.
func TestALoopbackListenNeverProducesALoopbackHookURL(t *testing.T) {
	got := hookBase(setup.Input{Listen: "127.0.0.1:8322"})
	if strings.Contains(got, "127.0.0.1") || strings.Contains(got, "localhost") {
		t.Errorf("hook base = %q; a UniFi console cannot reach this machine's loopback", got)
	}
	if !strings.HasSuffix(got, ":8322") {
		t.Errorf("hook base = %q, want the configured port kept", got)
	}
}

// No port configured at all still has to produce something pasteable.
func TestAMissingPortFallsBackToTheDefault(t *testing.T) {
	got := hookBase(setup.Input{Listen: ""})
	if !strings.HasSuffix(got, ":8322") {
		t.Errorf("hook base = %q, want the documented default port", got)
	}
}
