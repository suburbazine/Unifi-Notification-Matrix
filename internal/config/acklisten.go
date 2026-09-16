package config

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
)

// AckListenAuto asks for a port to be chosen at random and then kept.
//
// Accepted on its own ("auto") or as the port of an address
// ("0.0.0.0:auto"). Bare "auto" means every interface, because the only
// reason to run a second listener at all is to have something a firewall can
// forward to.
const AckListenAuto = "auto"

// The IANA dynamic/private port range. A port picked here will not collide
// with a registered service.
const (
	ephemeralLow  = 49152
	ephemeralHigh = 65535
)

// WantsRandomAckPort reports whether an address asks for a random port, and
// returns the host part to bind on.
func WantsRandomAckPort(addr string) (host string, ok bool) {
	a := strings.TrimSpace(addr)
	if a == "" {
		return "", false
	}
	if strings.EqualFold(a, AckListenAuto) {
		return "0.0.0.0", true
	}
	h, port, err := net.SplitHostPort(a)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(port), AckListenAuto) {
		return "", false
	}
	if h = strings.TrimSpace(h); h == "" {
		h = "0.0.0.0"
	}
	return h, true
}

// RandomEphemeralPort returns a port in the IANA dynamic range.
//
// WHAT THIS IS AND IS NOT FOR. A random port is not a security control: a port
// scan finds an open port in seconds regardless of its number, and anyone who
// can reach the forward can reach it. What it actually buys is quieter: it
// keeps the forwarded port off the handful of numbers that automated scanners
// and drive-by traffic probe constantly, and it avoids colliding with whatever
// else the operator happens to run. The acknowledgement token is what protects
// an acknowledgement; this just means the endpoint is not sitting on 8080.
//
// crypto/rand rather than math/rand, because a port derived from the clock is
// guessable by anyone who knows roughly when the service was installed -- and
// the point of not being on a well-known port is undone by being on a
// predictable one.
func RandomEphemeralPort() (int, error) {
	span := int64(ephemeralHigh - ephemeralLow + 1)
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return 0, fmt.Errorf("config: choosing a port: %w", err)
	}
	return ephemeralLow + int(n.Int64()), nil
}

// ResolveAckListen turns an "auto" address into a concrete one by finding a
// port that actually binds, and hands back the listener it proved with.
//
// The listener is RETURNED rather than closed and reopened. Closing it first
// leaves a window in which something else takes the port, and the address
// would then be pinned to a port this daemon cannot bind -- which is the one
// outcome worse than not pinning at all, because the firewall rule and every
// acknowledgement link would point at it forever.
func ResolveAckListen(addr string) (resolved string, ln net.Listener, err error) {
	host, auto := WantsRandomAckPort(addr)
	if !auto {
		l, err := net.Listen("tcp", strings.TrimSpace(addr))
		if err != nil {
			return "", nil, err
		}
		return strings.TrimSpace(addr), l, nil
	}

	// A handful of attempts. The range holds 16384 ports, so a collision is
	// already unlikely; ten tries makes it not worth thinking about, and a
	// bounded loop cannot hang a service start.
	const attempts = 10
	var lastErr error
	for i := 0; i < attempts; i++ {
		port, err := RandomEphemeralPort()
		if err != nil {
			return "", nil, err
		}
		candidate := net.JoinHostPort(host, strconv.Itoa(port))
		l, err := net.Listen("tcp", candidate)
		if err != nil {
			lastErr = err
			continue
		}
		return candidate, l, nil
	}
	return "", nil, fmt.Errorf("config: could not find a free port in %d-%d after %d tries: %w",
		ephemeralLow, ephemeralHigh, attempts, lastErr)
}

// AckPortPinnedMessage explains what just happened, once, in the terminal.
func AckPortPinnedMessage(resolved, path string) string {
	_, port, err := net.SplitHostPort(resolved)
	if err != nil {
		port = resolved
	}
	return fmt.Sprintf(
		"picked port %s for acknowledgements and wrote it to %s.\n"+
			"         It will not change again. Forward THAT port, and set\n"+
			"         web.ack_base_url to the address it is reachable on.",
		port, path)
}
