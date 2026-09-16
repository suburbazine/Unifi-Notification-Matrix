// Package probe discovers what a UniFi console actually exposes, so this
// product can be told about firmware revisions nobody here has seen.
//
// This file is the part that decides where it is allowed to look.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// ErrNotLocal means the target is outside the local network.
var ErrNotLocal = errors.New("the probe may only be pointed at a local network")

// localRanges are the networks a probe may reach.
//
// A probe is a scanner. Pointed at an address the operator does not own it is
// an unauthorised port and endpoint scan against somebody else's
// infrastructure, run from their machine, on their IP -- and shipping a tool
// that can do that is shipping a liability with a friendly CLI.
//
// So the rule is: local networks only, enforced in the dialer, with NO
// override flag. An escape hatch was considered and deliberately not added --
// a flag named something like --allow-remote is a flag that ends up in a forum
// post, and the whole protection is then one copied command line away from
// being off.
var localRanges = []string{
	// RFC 1918 private IPv4. The ordinary case: a console on a LAN.
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",

	// RFC 6598 shared address space. Included because it is what Tailscale
	// hands out, and Tailscale is a common and entirely legitimate way to
	// reach a console remotely. It is also ISP CGNAT space, which is a real
	// (if narrow) widening -- accepted because refusing it would break the
	// remote-access pattern this audience actually uses.
	"100.64.0.0/10",

	// Loopback, for a console proxied to this machine.
	"127.0.0.0/8",
	"::1/128",

	// Link-local, including IPv4 APIPA and IPv6 fe80::.
	"169.254.0.0/16",
	"fe80::/10",

	// IPv6 unique local addresses -- the v6 equivalent of RFC 1918.
	"fc00::/7",
}

var localNets = func() []*net.IPNet {
	out := make([]*net.IPNet, 0, len(localRanges))
	for _, c := range localRanges {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("probe: bad local range " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}()

// IsLocalIP reports whether addr is inside a network the probe may reach.
func IsLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// An IPv4-mapped IPv6 address (::ffff:10.0.0.1) must be judged as the IPv4
	// address it is, or a mapped public address slips past the v4 ranges and
	// fails to match the v6 ones either.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range localNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckHost resolves host and reports whether EVERY address it resolves to is
// local.
//
// Every address, not any: a name that resolves to one private and one public
// address must be refused, because which one gets connected to is not ours to
// decide.
//
// This is a courtesy check for a clear error message at the CLI. It is NOT the
// enforcement -- see Dialer. A name checked here and connected to later can
// resolve differently in between, which is the whole DNS-rebinding trick.
func CheckHost(ctx context.Context, host string) error {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		if !IsLocalIP(ip) {
			return fmt.Errorf("%w: %s is not a local address", ErrNotLocal, host)
		}
		return nil
	}

	var r net.Resolver
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("probe: cannot resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("probe: %s resolves to nothing", host)
	}
	for _, a := range addrs {
		if !IsLocalIP(a.IP) {
			return fmt.Errorf("%w: %s resolves to %s, which is not local",
				ErrNotLocal, host, a.IP)
		}
	}
	return nil
}

// Dialer returns a dialer that refuses any connection to a non-local address.
//
// THIS IS THE ENFORCEMENT, and it is in Control rather than in a pre-flight
// check for a specific reason: Control runs after DNS resolution and before
// connect, with the ACTUAL socket address. That closes the gap a pre-flight
// check leaves open —
//
//   - a hostname that resolved to a private address when checked and a public
//     one when dialled (DNS rebinding),
//   - a redirect to a public host,
//   - a second address on a multi-homed name,
//
// all of which reach Control, and none of which a check on the original
// hostname would catch.
func Dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%w: cannot read the address %q", ErrNotLocal, address)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				// Control is handed a resolved address; anything else means
				// an assumption here is wrong, and the safe reading of "I do
				// not understand this address" is to refuse it.
				return fmt.Errorf("%w: %q is not an IP address", ErrNotLocal, host)
			}
			if !IsLocalIP(ip) {
				return fmt.Errorf("%w: refusing to connect to %s", ErrNotLocal, ip)
			}
			return nil
		},
	}
}

// HTTPClient returns a client that can only reach local addresses.
func HTTPClient(insecureSkipVerify bool) *http.Client {
	d := Dialer()
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: d.DialContext,
			// No proxy. A proxy would make the connection go to the PROXY's
			// address -- which may well be local -- while the request reaches
			// an arbitrary host beyond it, defeating the whole guard.
			Proxy:               nil,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     tlsConfig(insecureSkipVerify),
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Redirects are refused outright rather than followed and
			// re-checked. The dialer would catch a redirect to a public
			// address anyway, but a console that redirects a probe somewhere
			// is not behaving like a console, and following it discovers
			// nothing about the console.
			return fmt.Errorf("probe: refusing to follow a redirect to %s", req.URL.Host)
		},
	}
}
