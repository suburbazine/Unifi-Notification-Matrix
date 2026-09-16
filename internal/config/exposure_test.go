package config

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestPrivateAndVPNAddressesAreNotTreatedAsPublic(t *testing.T) {
	for _, u := range []string{
		"http://192.168.1.50:8322",
		"http://10.0.0.5:8322",
		"http://172.16.4.4:8322",
		"http://127.0.0.1:8322",
		"http://[::1]:8322",
		// Tailscale hands out RFC 6598 space, and a Tailscale address is the
		// GOOD answer to reaching an alarm from off-site. Warning about it
		// would push people away from the safest option.
		"http://100.101.102.103:8322",
		"http://nm.local:8322",
		"http://nm.lan:8322",
		"http://alarmbox:8322",
		"",
	} {
		if LooksInternetFacing(u) {
			t.Errorf("%q was treated as internet-facing", u)
		}
	}
}

func TestPublicAddressesAreRecognised(t *testing.T) {
	for _, u := range []string{
		"https://alarms.example.com",
		"http://alarms.example.com:49152",
		"http://203.0.113.10:8322",
	} {
		if !LooksInternetFacing(u) {
			t.Errorf("%q was not recognised as internet-facing", u)
		}
	}
}

func publicConfig() Config {
	c := workable()
	c.Web.AckBaseURL = "https://alarms.example.com"
	// Bound to every interface, which is what makes a forward to it possible
	// and therefore what makes the warning meaningful.
	c.Web.Listen = "0.0.0.0:8322"
	return c
}

// THE WARNING THIS WHOLE MECHANISM EXISTS FOR.
//
// A NAT forward cannot scope by path, so a forward aimed at the main listener
// publishes the status page -- cameras, doors, open alarms -- and the settings
// sign-in, to the internet.
func TestAPublicAckURLWithNoScopedListenerIsWarnedAbout(t *testing.T) {
	c := publicConfig()

	w := strings.Join(c.Warnings(), "\n")
	if !strings.Contains(w, "ack_listen is not set") {
		t.Fatalf("no warning about an unscoped public address: %v", c.Warnings())
	}
	if !strings.Contains(w, "status page") {
		t.Error("the warning does not say WHAT would be published")
	}

	// A reverse proxy in front means web.listen is on loopback and nothing is
	// forwardable, so the warning must not fire.
	quiet := c
	quiet.Web.Listen = "127.0.0.1:8322"
	if w := strings.Join(quiet.Warnings(), "; "); strings.Contains(w, "ack_listen is not set") {
		t.Errorf("warned about a loopback-bound main listener, which cannot be "+
			"forwarded at all: %v", quiet.Warnings())
	}

	// Scoped: the warning goes away.
	c.Web.AckListen = "0.0.0.0:49152"
	if w := strings.Join(c.Warnings(), "\n"); strings.Contains(w, "ack_listen is not set") {
		t.Errorf("still warned after the listener was scoped: %v", c.Warnings())
	}
}

// The acknowledgement token travels in the URL.
func TestAPublicAckURLOverPlainHTTPIsWarnedAbout(t *testing.T) {
	c := publicConfig()
	c.Web.AckListen = "0.0.0.0:49152"
	c.Web.AckBaseURL = "http://alarms.example.com"

	w := strings.Join(c.Warnings(), "\n")
	if !strings.Contains(w, "plain http") {
		t.Fatalf("no warning about a public token in the clear: %v", c.Warnings())
	}

	c.Web.AckBaseURL = "https://alarms.example.com"
	if w := strings.Join(c.Warnings(), "\n"); strings.Contains(w, "plain http") {
		t.Errorf("warned about https: %v", c.Warnings())
	}
}

// A second listener on the same address scopes nothing, and one bound to
// loopback cannot receive a forward.
func TestAnAckListenerThatScopesNothingIsWarnedAbout(t *testing.T) {
	c := publicConfig()
	c.Web.AckListen = c.Web.Listen
	if !strings.Contains(strings.Join(c.Warnings(), "\n"), "scopes nothing") {
		t.Errorf("a duplicate address was not reported: %v", c.Warnings())
	}

	c = publicConfig()
	c.Web.AckListen = "127.0.0.1:49152"
	if !strings.Contains(strings.Join(c.Warnings(), "\n"), "will not reach it") {
		t.Errorf("a loopback-only ack listener was not reported: %v", c.Warnings())
	}
}

// None of these refuse the start. Somebody deliberately exposing this has a
// reason, and refusing to run would leave them with an alarm system that does
// not run.
func TestExposureProblemsAreWarningsNotRefusals(t *testing.T) {
	c := publicConfig()
	c.Web.AckListen = c.Web.Listen
	if err := c.Validate(); err != nil {
		t.Errorf("an exposed configuration was refused outright: %v", err)
	}
	if len(c.Warnings()) == 0 {
		t.Error("...and it was not warned about either")
	}
}

// ---------------------------------------------------------------------------
// The randomised, pinned port
// ---------------------------------------------------------------------------

func TestAutoIsAcceptedInEitherForm(t *testing.T) {
	cases := map[string]string{
		"auto":             "0.0.0.0",
		"AUTO":             "0.0.0.0",
		"0.0.0.0:auto":     "0.0.0.0",
		"192.168.1.5:auto": "192.168.1.5",
		":auto":            "0.0.0.0",
	}
	for in, wantHost := range cases {
		host, ok := WantsRandomAckPort(in)
		if !ok {
			t.Errorf("%q was not recognised as a request for a random port", in)
			continue
		}
		if host != wantHost {
			t.Errorf("%q gave host %q, want %q", in, host, wantHost)
		}
	}
	for _, in := range []string{"", "0.0.0.0:49152", "auto:8322", "nonsense"} {
		if _, ok := WantsRandomAckPort(in); ok {
			t.Errorf("%q was mistaken for a request for a random port", in)
		}
	}
}

func TestARandomPortIsInTheDynamicRange(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 50; i++ {
		p, err := RandomEphemeralPort()
		if err != nil {
			t.Fatal(err)
		}
		if p < ephemeralLow || p > ephemeralHigh {
			t.Fatalf("port %d is outside the IANA dynamic range %d-%d",
				p, ephemeralLow, ephemeralHigh)
		}
		seen[p] = true
	}
	// A "random" port that is always the same is a well-known port with extra
	// steps.
	if len(seen) < 25 {
		t.Errorf("50 draws produced %d distinct ports", len(seen))
	}
}

// The listener is returned rather than closed and reopened. Closing it first
// leaves a window for something else to take the port -- and the address would
// then be pinned to a port this daemon cannot bind, which is worse than not
// pinning at all.
func TestResolveReturnsAListenerAlreadyHoldingThePort(t *testing.T) {
	resolved, ln, err := ResolveAckListen("127.0.0.1:auto")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if !strings.HasPrefix(resolved, "127.0.0.1:") {
		t.Errorf("resolved = %q, want the host that was asked for", resolved)
	}
	_, portStr, err := net.SplitHostPort(resolved)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < ephemeralLow || port > ephemeralHigh {
		t.Fatalf("port %q is not in the dynamic range", portStr)
	}
	if ln.Addr().String() != resolved {
		t.Errorf("the listener is on %s but %s was reported", ln.Addr(), resolved)
	}

	// Nothing else can take it while we hold it.
	if second, err := net.Listen("tcp", resolved); err == nil {
		second.Close()
		t.Error("the resolved port was not actually held")
	}
}

func TestAnExplicitAddressIsUsedAsGiven(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()

	resolved, ln, err := ResolveAckListen(addr)
	if err != nil {
		t.Skipf("the port was taken between probe and bind: %v", err)
	}
	defer ln.Close()
	if resolved != addr {
		t.Errorf("resolved = %q, want the address as given (%q)", resolved, addr)
	}
}

// "auto" is a legal value in the file, because the port is only chosen at
// first start.
func TestAutoPassesValidation(t *testing.T) {
	c := workable()
	for _, v := range []string{"auto", "0.0.0.0:auto", "0.0.0.0:49152"} {
		c.Web.AckListen = v
		if err := c.Validate(); err != nil {
			t.Errorf("ack_listen %q was refused: %v", v, err)
		}
	}
	c.Web.AckListen = "not-an-address"
	if err := c.Validate(); err == nil {
		t.Error("a malformed ack_listen was accepted")
	}
}

// The combination that produces a perfectly configured-looking install whose
// every acknowledgement link is dead: the address names somewhere other than
// this machine, and nothing is listening anywhere a phone could reach. The
// alert arrives, the link is tapped, nothing answers, and the alarm keeps
// repeating with no way to stop it but the web UI -- on the machine the
// operator is not standing at.
//
// Found on a real installation. Nothing checked it.
func TestAnAckAddressWithNothingListeningForItIsWarnedAbout(t *testing.T) {
	c := Default()
	c.Web.Listen = "127.0.0.1:8322"
	c.Web.AckBaseURL = "https://alerts.example.com"
	c.Web.AckListen = ""

	if !warnsAbout(c, "nothing is listening") {
		t.Fatalf("no warning for an ack address nothing can answer:\n%v", c.Warnings())
	}
	// It has to name the address, or an operator with more than one does not
	// know which is wrong.
	if !warnsAbout(c, "alerts.example.com") {
		t.Errorf("the warning does not name the address:\n%v", c.Warnings())
	}
}

// A LAN address with the listener bound to every interface is the ordinary
// working setup and must be silent, or the warning is noise.
func TestAReachableAckAddressIsNotWarnedAbout(t *testing.T) {
	c := Default()
	c.Web.Listen = "0.0.0.0:8322"
	c.Web.AckBaseURL = "http://192.168.20.115:8322"

	if warnsAbout(c, "nothing is listening") {
		t.Fatalf("a working LAN setup was warned about:\n%v", c.Warnings())
	}
}

// A tunnel or reverse proxy on this machine connecting to loopback is
// legitimate, which is why this is a warning and not a refusal -- but the
// scoped ack listener bound to every interface is ALSO a working shape and
// must not be nagged.
func TestAScopedAckListenerOnEveryInterfaceIsNotWarnedAbout(t *testing.T) {
	c := Default()
	c.Web.Listen = "127.0.0.1:8322"
	c.Web.AckBaseURL = "https://alerts.example.com"
	c.Web.AckListen = "0.0.0.0:51234"

	if warnsAbout(c, "nothing is listening") {
		t.Fatalf("a scoped, forwardable ack listener was warned about:\n%v", c.Warnings())
	}
}

func warnsAbout(c Config, substr string) bool {
	for _, w := range c.Warnings() {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}
