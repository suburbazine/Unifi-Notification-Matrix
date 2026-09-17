package config

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// aMachine stands in for the one the test runs on: a LAN address, and a
// public hostname that resolves to the router rather than to it. The shape of
// the installation this was found on.
func aMachine(t *testing.T) {
	t.Helper()
	oldAddrs, oldLookup := localAddrs, lookupIP
	t.Cleanup(func() { localAddrs, lookupIP = oldAddrs, oldLookup })

	localAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.168.20.115"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		}, nil
	}
	lookupIP = func(host string) ([]net.IP, error) {
		switch host {
		case "notifymatrix.example.com":
			return []net.IP{net.ParseIP("68.119.190.126")}, nil
		case "this-box":
			return []net.IP{net.ParseIP("192.168.20.115")}, nil
		}
		return nil, errors.New("no such host")
	}
}

// THE FAILURE THIS EXISTS FOR.
//
// Told to set web.ack_listen and forward that port, an operator put the public
// hostname they were forwarding there. It passed the host:port check, was
// saved, and stopped the service at its next start -- taking down the
// interface that could have fixed it.
func TestThePublicHostnameInAckListenIsRefused(t *testing.T) {
	aMachine(t)
	c := workable()
	c.Web.Listen = "0.0.0.0:8322"
	c.Web.AckListen = "notifymatrix.example.com:50001"

	err := c.Validate()
	if err == nil {
		t.Fatal("a listen address this machine does not have was accepted -- " +
			"the service would not start")
	}
	msg := err.Error()
	for _, want := range []string{
		"web.ack_listen",
		"not an address this machine has",
		"will not start",
		"0.0.0.0:50001",    // what to type instead, with THEIR port
		"web.ack_base_url", // and where the value they typed belongs
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, msg)
		}
	}
}

// The same failure is available on the main listener, with the same result.
func TestANonLocalMainListenAddressIsRefused(t *testing.T) {
	aMachine(t)
	c := workable()
	c.Web.Listen = "notifymatrix.example.com:8322"

	err := c.Validate()
	if err == nil {
		t.Fatal("web.listen naming another machine was accepted")
	}
	if msg := err.Error(); !strings.Contains(msg, "web.listen") || !strings.Contains(msg, "0.0.0.0:8322") {
		t.Errorf("the refusal does not name the field and the fix:\n%s", msg)
	}
	// "auto" is an ack_listen idea only; offering it for web.listen would be
	// advice that is itself refused.
	if strings.Contains(err.Error(), `"auto"`) {
		t.Errorf("offered \"auto\" for web.listen:\n%s", err)
	}
}

func TestAnAddressLiteralFromAnotherMachineIsRefused(t *testing.T) {
	aMachine(t)
	c := workable()
	c.Web.AckListen = "10.9.9.9:50001"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "10.9.9.9") {
		t.Errorf("an address literal this machine does not have was not refused: %v", err)
	}
}

func TestANameThatDoesNotResolveIsRefused(t *testing.T) {
	aMachine(t)
	c := workable()
	c.Web.AckListen = "nowhere.example.com:50001"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "does not resolve") {
		t.Errorf("an unresolvable listen name was not refused: %v", err)
	}
}

// Every shape that actually binds must keep working. A check that refused a
// working install would stop a service that runs today.
func TestEveryAddressThisMachineCanListenOnIsAccepted(t *testing.T) {
	aMachine(t)
	for _, v := range []string{
		"0.0.0.0:50001",
		"[::]:50001",
		":50001",
		"127.0.0.1:50001",
		"[::1]:50001",
		"localhost:50001",
		"192.168.20.115:50001", // this machine's own LAN address
		"this-box:50001",       // a name that resolves to it
		"auto",
		"0.0.0.0:auto",
		"192.168.20.115:auto",
	} {
		c := workable()
		c.Web.AckListen = v
		if err := c.Validate(); err != nil {
			t.Errorf("ack_listen %q binds on this machine but was refused: %v", v, err)
		}
	}
}

// "host:auto" still binds the host, so the host is still checked.
func TestTheHostInHostAutoIsChecked(t *testing.T) {
	aMachine(t)
	c := workable()
	c.Web.AckListen = "notifymatrix.example.com:auto"
	if err := c.Validate(); err == nil {
		t.Error("a non-local host with an automatic port was accepted")
	}
}

// When the interfaces cannot be read, nothing can be decided -- and refusing on
// a guess would stop a service that might have started.
func TestUnreadableInterfacesRefuseNothing(t *testing.T) {
	aMachine(t)
	localAddrs = func() ([]net.Addr, error) { return nil, errors.New("denied") }
	c := workable()
	c.Web.AckListen = "10.9.9.9:50001"
	if err := c.Validate(); err != nil {
		t.Errorf("refused without being able to see this machine's addresses: %v", err)
	}
}

// A save is refused only by problems it ADDS, found by comparing the problem
// text before and after. A message that differed between two calls would make
// a problem already present look new and block every unrelated edit.
func TestTheRefusalReadsTheSameEveryTime(t *testing.T) {
	aMachine(t)
	c := workable()
	c.Web.AckListen = "notifymatrix.example.com:50001"
	first, second := c.Validate(), c.Validate()
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Errorf("the same config produced different problems:\n%v\n%v", first, second)
	}
}
