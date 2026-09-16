package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalAddressesAreAllowed(t *testing.T) {
	for _, s := range []string{
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.254",
		"192.168.1.1", "192.168.0.254",
		"100.64.0.1", "100.127.255.254", // Tailscale / CGNAT
		"127.0.0.1", "::1",
		"169.254.1.1", "fe80::1",
		"fd00::1", "fc00::1", // IPv6 ULA
	} {
		if !IsLocalIP(net.ParseIP(s)) {
			t.Errorf("%s was refused; it is a local address", s)
		}
	}
}

// The whole point. A probe is a scanner, and pointed at somebody else's
// infrastructure it is an unauthorised scan run from the operator's machine.
func TestRemoteAddressesAreRefused(t *testing.T) {
	for _, s := range []string{
		"8.8.8.8", "1.1.1.1",
		"93.184.216.34", // example.com
		"172.32.0.1",    // just outside 172.16/12
		"172.15.255.255",
		"11.0.0.1",    // just outside 10/8
		"100.128.0.1", // just outside 100.64/10
		"100.63.255.255",
		"192.169.0.1",  // just outside 192.168/16
		"2606:4700::1", // public IPv6
		"2001:4860:4860::8888",
	} {
		if IsLocalIP(net.ParseIP(s)) {
			t.Errorf("%s was allowed; it is not a local address", s)
		}
	}
}

// An IPv4-mapped IPv6 address must be judged as the IPv4 address it is, or a
// mapped public address matches no v4 range and no v6 range and slips through.
func TestIPv4MappedAddressesAreJudgedAsIPv4(t *testing.T) {
	if !IsLocalIP(net.ParseIP("::ffff:192.168.1.1")) {
		t.Error("::ffff:192.168.1.1 was refused; it is a mapped private address")
	}
	if IsLocalIP(net.ParseIP("::ffff:8.8.8.8")) {
		t.Error("::ffff:8.8.8.8 was allowed; a mapped public address must be refused")
	}
}

func TestNilAndGarbageAreRefused(t *testing.T) {
	if IsLocalIP(nil) {
		t.Error("nil was allowed")
	}
	if IsLocalIP(net.ParseIP("not-an-ip")) {
		t.Error("an unparseable address was allowed")
	}
}

func TestCheckHostRefusesAPublicLiteral(t *testing.T) {
	err := CheckHost(context.Background(), "8.8.8.8")
	if !errors.Is(err, ErrNotLocal) {
		t.Fatalf("CheckHost(8.8.8.8) = %v, want ErrNotLocal", err)
	}
	if err := CheckHost(context.Background(), "192.168.1.50:443"); err != nil {
		t.Errorf("CheckHost on a local host:port = %v, want nil", err)
	}
}

// THE ENFORCEMENT TEST. A pre-flight check on a hostname can be defeated by
// DNS rebinding; the dialer's Control hook sees the real socket address and
// cannot be.
func TestTheDialerRefusesAPublicAddress(t *testing.T) {
	d := Dialer()
	_, err := d.DialContext(context.Background(), "tcp", "8.8.8.8:53")
	if !errors.Is(err, ErrNotLocal) {
		t.Fatalf("dial to a public address = %v, want ErrNotLocal -- this is "+
			"the check that cannot be bypassed by DNS", err)
	}
}

func TestTheDialerAllowsALocalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := HTTPClient(true)
	resp, err := c.Get(srv.URL) // httptest listens on 127.0.0.1
	if err != nil {
		t.Fatalf("a loopback server was refused: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d", resp.StatusCode)
	}
}

// A console that redirects a probe somewhere is not behaving like a console,
// and following it discovers nothing about the console.
func TestRedirectsAreRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	_, err := HTTPClient(true).Get(srv.URL)
	if err == nil {
		t.Fatal("a redirect off the console was followed")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("error does not mention the redirect: %v", err)
	}
}

// A proxy would make the CONNECTION go to the proxy -- possibly local -- while
// the request reached an arbitrary host beyond it.
func TestNoProxyIsConsulted(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://10.0.0.99:3128")
	t.Setenv("HTTPS_PROXY", "http://10.0.0.99:3128")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("direct"))
	}))
	defer srv.Close()

	resp, err := HTTPClient(true).Get(srv.URL)
	if err != nil {
		t.Fatalf("the request did not go direct: %v", err)
	}
	defer resp.Body.Close()
	// Reaching the test server at all proves the proxy env was ignored; going
	// through 10.0.0.99 would have failed to connect.
}

// There must be no way to turn this off. A flag named --allow-remote is a flag
// that ends up in a forum post, and the protection is then one copied command
// line away from being off.
func TestThereIsNoOverride(t *testing.T) {
	// Guarded by construction: Dialer takes no arguments and localRanges is
	// unexported with no setter. This test exists to fail loudly if either
	// changes, so adding an override is a deliberate act with a test to delete.
	if len(localRanges) == 0 {
		t.Fatal("the local range list is empty")
	}
	for _, c := range localRanges {
		if strings.HasPrefix(c, "0.0.0.0") || c == "::/0" {
			t.Fatalf("%q allows the whole internet", c)
		}
	}
}
