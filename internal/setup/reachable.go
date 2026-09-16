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
