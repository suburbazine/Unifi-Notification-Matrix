package config

import (
	"net"
	"net/url"
	"strings"
)

// internalSuffixes are hostname endings that are never on the public internet.
//
// Used only to keep a warning from firing on an obviously-internal name. A
// name that is not on this list is not necessarily public -- it is merely not
// provably private, which for a warning is the right side to err on.
var internalSuffixes = []string{
	".local", ".lan", ".internal", ".home", ".home.arpa", ".localdomain",
	".intranet", ".corp", ".localhost",
}

// LooksInternetFacing reports whether a URL is plausibly reachable from the
// open internet.
//
// Deliberately imprecise, and only ever used to raise a WARNING. There is no
// way to know from a string whether an address is forwarded, and guessing
// wrong in the cautious direction costs a line of text -- guessing wrong in
// the other direction means a status page naming somebody's cameras is
// published and nothing said so.
func LooksInternetFacing(rawurl string) bool {
	rawurl = strings.TrimSpace(rawurl)
	if rawurl == "" {
		return false
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !isPrivateIP(ip)
	}

	lower := strings.ToLower(host)
	if lower == "localhost" || !strings.Contains(lower, ".") {
		// A bare name is resolved by the local network's own DNS, so it is not
		// a public address even when it is reachable from elsewhere.
		return false
	}
	for _, suffix := range internalSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	return true
}

// isPrivateIP covers the ranges that cannot be routed from the internet, plus
// the one that usually is not: RFC 6598, which is both ISP CGNAT space and
// what Tailscale hands out. A Tailscale address is the GOOD answer to reaching
// an acknowledgement link from off-site, so it must not be warned about.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	_, cgnat, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return cgnat.Contains(v4)
	}
	return false
}

// listensOnEveryInterface reports whether an address accepts connections from
// anywhere rather than only from this machine.
func listensOnEveryInterface(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	host = strings.Trim(host, "[]")
	return host == "" || host == "0.0.0.0" || host == "::"
}

// WantsRandom reports whether an address is still asking for a port to be
// chosen. Until it is, there is nothing to say about which interface it binds.
func WantsRandom(addr string) bool {
	_, ok := WantsRandomAckPort(addr)
	return ok
}

// exposureWarnings reports configurations that publish more than the operator
// probably meant to.
//
// Warnings rather than refusals, throughout. Somebody deliberately exposing
// this has a reason, and refusing to start would leave them with an alarm
// system that does not run. Saying it every time they start is the right
// amount of pressure.
// httpsAimedAtOurOwnPort reports an https acknowledgement address whose port
// is one of the ports this daemon listens on.
func httpsAimedAtOurOwnPort(ackURL, listen, ackListen string) bool {
	raw := strings.TrimSpace(ackURL)
	if !strings.HasPrefix(strings.ToLower(raw), "https://") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	port := u.Port()
	if port == "" {
		return false // 443, which is never one of ours
	}
	for _, addr := range []string{listen, ackListen} {
		if _, p, err := net.SplitHostPort(strings.TrimSpace(addr)); err == nil && p == port {
			return true
		}
	}
	return false
}

// ackURLIsThisMachine reports whether the acknowledgement address names
// loopback, which validate() already refuses for its own reasons.
func ackURLIsThisMachine(rawurl string) bool {
	u, err := url.Parse(strings.TrimSpace(rawurl))
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// ackHost is the host part, for saying WHICH address will not answer.
func ackHost(rawurl string) string {
	if u, err := url.Parse(strings.TrimSpace(rawurl)); err == nil && u.Host != "" {
		return u.Host
	}
	return strings.TrimSpace(rawurl)
}

// ackListenNote deliberately avoids the phrase "ack_listen is not set".
//
// That exact wording belongs to the OTHER warning -- the one about forwarding
// a port to the main listener and publishing the status page with it -- and
// two warnings sharing a distinguishing phrase is how a test asserting on one
// starts matching the other. It did.
func ackListenNote(ackListen string) string {
	if strings.TrimSpace(ackListen) == "" {
		return ", and there is no separate acknowledgement listener"
	}
	return ", and the acknowledgement listener is bound to this machine only"
}

func (c Config) exposureWarnings() []string {
	var w []string

	public := LooksInternetFacing(c.Web.AckBaseURL)
	scoped := strings.TrimSpace(c.Web.AckListen) != ""

	// The main listener being bound to every interface is what makes a forward
	// to it possible at all. Somebody running a reverse proxy in front has
	// web.listen on loopback, is already scoping by path, and must not be
	// nagged every start about a risk they have already dealt with.
	forwardable := listensOnEveryInterface(c.Web.Listen)

	if public && !scoped && forwardable {
		// The whole point of AckListen. A forward aimed at the main listener
		// publishes the status page and the settings sign-in along with the
		// acknowledgement routes, because a NAT rule cannot scope by path.
		w = append(w, "web.ack_base_url looks like a public address but "+
			"web.ack_listen is not set -- if you have forwarded a port to the "+
			"main listener, the status page (which names your cameras, doors "+
			"and open alarms) and the settings sign-in are on the internet "+
			"too. Set web.ack_listen to a second port and forward THAT; see "+
			"docs/SETUP.md")
	}
	if public && strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.Web.AckBaseURL)), "http://") {
		// The acknowledgement token travels in the path. Over plain HTTP on
		// the open internet, anyone between the phone and here can read it and
		// silence the alarm.
		w = append(w, "web.ack_base_url is a public address over plain http -- "+
			"the acknowledgement token is in the URL, so anyone on the path can "+
			"read it and silence an alarm. Put TLS in front of it, or reach it "+
			"over a VPN instead")
	}
	// An https acknowledgement address aimed at a port THIS program serves.
	//
	// It serves plain HTTP. The address is right, the port is right, the
	// scheme is the one everybody knows they should be using, and nothing
	// connects -- which is a failure that looks like a network problem rather
	// than a configuration one. Legitimate only with a reverse proxy in front,
	// and nothing in the config can tell whether one is there.
	if httpsAimedAtOurOwnPort(c.Web.AckBaseURL, c.Web.Listen, c.Web.AckListen) {
		w = append(w, "web.ack_base_url is https but names a port this program "+
			"serves itself, and it serves plain HTTP -- nothing will connect "+
			"unless a reverse proxy is terminating TLS in front of it. If there "+
			"is no proxy, this address needs to be http://")
	}
	if scoped && strings.EqualFold(strings.TrimSpace(c.Web.AckListen), strings.TrimSpace(c.Web.Listen)) {
		w = append(w, "web.ack_listen is the same address as web.listen, so it "+
			"scopes nothing -- give it a different port")
	}
	// Not conditioned on the URL: a loopback-bound second listener cannot
	// receive a forward whatever the acknowledgement address says, and if that
	// address IS public the link points somewhere nothing can answer.
	// An acknowledgement address that names somewhere other than this machine,
	// while NOTHING is listening anywhere a phone could reach.
	//
	// This is the combination that produces a perfectly configured-looking
	// install whose every acknowledgement link is dead: the alert arrives, the
	// link is tapped, nothing answers, and the alarm keeps repeating with no
	// way to stop it but the web UI -- which is on the machine the operator is
	// not standing at.
	//
	// A warning and not a refusal, because there is a legitimate shape here: a
	// tunnel or reverse proxy running ON this machine and connecting to
	// loopback. Only the operator knows whether one exists.
	if strings.TrimSpace(c.Web.AckBaseURL) != "" && !ackURLIsThisMachine(c.Web.AckBaseURL) &&
		!forwardable && (!scoped || (!WantsRandom(c.Web.AckListen) &&
		!listensOnEveryInterface(c.Web.AckListen))) {
		w = append(w, "web.ack_base_url points at "+ackHost(c.Web.AckBaseURL)+
			" but nothing is listening anywhere a phone could reach: web.listen "+
			"is bound to this machine only"+ackListenNote(c.Web.AckListen)+
			". Acknowledgement links will time out unless a tunnel or reverse "+
			"proxy on this machine forwards to it. For a phone on the LAN, set "+
			"web.listen to 0.0.0.0 and use this machine's LAN address")
	}
	if scoped && !WantsRandom(c.Web.AckListen) && !listensOnEveryInterface(c.Web.AckListen) {
		w = append(w, "web.ack_listen is set but only accepts connections from "+
			"this machine, so a forwarded port will not reach it -- use "+
			"0.0.0.0 rather than 127.0.0.1")
	}
	return w
}
