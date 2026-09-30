package setup

import (
	"net"
	"strconv"
	"strings"
)

// LocalAddress returns an address on this machine that another device on the
// same network could actually reach, or "" when there is no obvious one.
//
// Used so the acknowledgement instructions can print the operator's OWN
// address rather than a made-up 192.168.1.50. That setting is the one people
// get wrong most, and "for example http://192.168.1.50:8322" has been
// pasted verbatim more than once by somebody whose network is not that.
func LocalAddress() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var best string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			// A physical interface beats a virtual switch. Hyper-V and WSL
			// present addresses that look perfectly ordinary and that a phone
			// on the real network cannot reach, and picking one of those would
			// hand somebody an address that fails in exactly the way this is
			// trying to prevent.
			if looksVirtual(ifc.Name) {
				if best == "" {
					best = ip.String()
				}
				continue
			}
			return ip.String()
		}
	}
	return best
}

func looksVirtual(name string) bool {
	n := strings.ToLower(name)
	for _, hint := range []string{"vethernet", "virtual", "vmware", "hyper-v", "docker", "wsl", "loopback"} {
		if strings.Contains(n, hint) {
			return true
		}
	}
	return false
}

// ListenIsLoopbackOnly reports whether this listen address serves only the
// machine it runs on.
func ListenIsLoopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ListenIsOneAddress reports whether this listen address is pinned to a single
// interface rather than to every one.
//
// It matters because the consequence is invisible and counter-intuitive:
// binding to 192.168.20.115 means 127.0.0.1 STOPS WORKING, so every message,
// document and habit that says "open http://127.0.0.1:8322" is suddenly wrong
// and the interface looks dead while the process is plainly running.
func ListenIsOneAddress(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" {
		return false
	}
	if host == "0.0.0.0" || host == "::" || host == "*" {
		return false
	}
	if ListenIsLoopbackOnly(addr) {
		return false // loopback-only is its own, separately reported, case
	}
	return net.ParseIP(host) != nil
}

// ListenPort is the port part, or "" when it cannot be read.
func ListenPort(addr string) string {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	if _, err := strconv.Atoi(port); err != nil {
		return ""
	}
	return port
}

// SuggestedAckListen is the literal value for web.ack_listen.
//
// The step used to say only that web.ack_listen was not set, and the obvious
// thing to type -- the public hostname and port about to be forwarded -- names
// an address this machine does not have, which stops the service at its next
// start. So name the value: when the acknowledgement address already carries
// a port that is not the main listener's, that is the port being forwarded;
// otherwise "auto".
func SuggestedAckListen(ackURL, listen string) string {
	if p := portOfURL(strings.TrimSpace(ackURL)); p != "" && p != ListenPort(listen) {
		return "0.0.0.0:" + p
	}
	return `"auto"`
}

// AckURLTargetsThePlainListener reports whether an https acknowledgement URL
// points at the daemon's own listener, which speaks plain HTTP.
//
// This is a configuration that cannot work and looks entirely reasonable: the
// address is right, the port is right, the scheme is the one everybody knows
// they should be using, and nothing answers. It only works when something
// terminating TLS sits in front, and nothing in the config can tell whether
// one does -- so this reports the shape and lets the operator say.
func AckURLTargetsThePlainListener(ackURL, listen, ackListen string) bool {
	raw := strings.TrimSpace(ackURL)
	if !strings.HasPrefix(strings.ToLower(raw), "https://") {
		return false
	}
	port := portOfURL(raw)
	if port == "" {
		return false // https with no explicit port is 443, which is never ours
	}
	for _, addr := range []string{listen, ackListen} {
		if p := ListenPort(addr); p != "" && p == port {
			return true
		}
	}
	return false
}

func portOfURL(raw string) string {
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	i := strings.LastIndex(rest, ":")
	if i < 0 || strings.Contains(rest[i+1:], "]") {
		return ""
	}
	port := rest[i+1:]
	if _, err := strconv.Atoi(port); err != nil {
		return ""
	}
	return port
}

// AckPortProblem says so when the acknowledgement address names no port and
// the port it therefore means is not one this program answers on. "" when
// there is nothing to say.
//
// Found on a real site: web.ack_base_url was http://<public name>, the
// ack-only listener was on 50001, and every Acknowledge button in every alert
// went to port 80, where nothing was listening. Each half looked right on its
// own, the checklist called the step all but done, and the only symptom was a
// phone saying it could not connect -- discovered by the channel test that
// exists to find exactly this.
//
// Only plain http with NO port. An https address with no port is 443, which is
// a TLS proxy in front -- the recommended shape, and never a port of ours. An
// explicit port that differs from ours may be a deliberate NAT remap, and was
// typed on purpose. A missing port was almost certainly not a decision.
func AckPortProblem(ackURL, listen, ackListen string) string {
	raw := strings.TrimSpace(ackURL)
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") || portOfURL(raw) != "" {
		return ""
	}
	// The listener that answers acknowledgements: the scoped one when there
	// is one, the main one otherwise. A loopback-only one is reported by the
	// step's own earlier case, and a port that cannot be read says nothing.
	serving := strings.TrimSpace(ackListen)
	if serving == "" {
		serving = strings.TrimSpace(listen)
	}
	port := ListenPort(serving)
	if port == "" || port == "80" || ListenIsLoopbackOnly(serving) {
		return ""
	}
	// A main listener on 80 that the LAN can reach answers the link too.
	if ListenPort(listen) == "80" && !ListenIsLoopbackOnly(listen) {
		return ""
	}
	fixed := withPort(raw, port)
	return raw + " names no port, so every acknowledgement link goes to port 80 -- " +
		"but acknowledgements are answered on port " + port + ". Set " +
		"web.ack_base_url to " + fixed + " (and forward that port, if the address " +
		"is public), unless something already forwards port 80 to " + port
}

// withPort puts a port on an address that has none, keeping any path.
func withPort(raw, port string) string {
	scheme, rest := "", raw
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme, rest = raw[:i+3], raw[i+3:]
	}
	host, path := rest, ""
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return scheme + net.JoinHostPort(host, port) + path
}
