package config

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// A listen address has to name THIS machine.
//
// web.listen and web.ack_listen are where this program accepts connections,
// and the operating system will only open a socket on an address the machine
// actually has. Anything else passes the host:port check, is saved, and then
// stops the service at its next start with "the requested address is not
// valid in its context".
//
// Found on a real installation. Told to set web.ack_listen and forward that
// port, the operator put their PUBLIC hostname there -- a reasonable reading,
// since a public name is what a forward is for. The save was accepted, the
// service restarted into the failure, and the interface that could have fixed
// it went down with it.
//
// Package variables so a test can describe a machine instead of depending on
// the one it happens to run on.
var (
	localAddrs = net.InterfaceAddrs
	lookupIP   = func(host string) ([]net.IP, error) {
		// Bounded: this runs at startup, and a resolver that hangs must not
		// hang the service with it.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return net.DefaultResolver.LookupIP(ctx, "ip", host)
	}
)

// listenHostProblem reports why this machine cannot listen on addr, or "" when
// it can -- or when that cannot be decided from here, because a refusal on a
// guess would stop a service that might have started.
//
// The message must be the same every time for the same input. A save is
// refused only by problems it ADDS, found by comparing the problem text
// before and after, so a message that varied between calls would turn a
// problem already present into a "new" one and block unrelated edits.
func listenHostProblem(field, addr string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "" // the caller reports "not host:port"
	}
	host = strings.Trim(host, "[]")
	switch strings.ToLower(host) {
	case "", "0.0.0.0", "::", "localhost":
		return ""
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return ""
		}
		ips = []net.IP{ip}
	} else {
		ips, err = lookupIP(host)
		if err != nil || len(ips) == 0 {
			return fmt.Sprintf("%s %q: %s does not resolve to an address, so "+
				"nothing can listen there and the service will not start. %s",
				field, addr, host, listenAdvice(field, port))
		}
	}

	mine, known := onThisMachine(ips)
	if !known || mine {
		return ""
	}
	return fmt.Sprintf("%s %q: %s is not an address this machine has, so "+
		"nothing can listen there and the service will not start. %s",
		field, addr, host, listenAdvice(field, port))
}

// listenAdvice says what goes here instead, and where the value that was
// typed actually belongs -- because the value is usually right, just in the
// wrong field.
func listenAdvice(field, port string) string {
	if port == "" || port == AckListenAuto {
		port = "PORT"
	}
	s := "This setting is where this machine LISTENS: use 0.0.0.0:" + port +
		" for every interface"
	if field == "web.ack_listen" {
		s += `, or "auto"`
	}
	return s + ". The address a phone uses -- a public hostname, or this " +
		"machine's LAN address -- belongs in web.ack_base_url."
}

// onThisMachine reports whether any of ips is an address of a local interface
// or loopback. known is false when the interfaces could not be read.
func onThisMachine(ips []net.IP) (mine, known bool) {
	addrs, err := localAddrs()
	if err != nil {
		return false, false
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return true, true
		}
		for _, a := range addrs {
			var local net.IP
			switch v := a.(type) {
			case *net.IPNet:
				local = v.IP
			case *net.IPAddr:
				local = v.IP
			}
			if local != nil && local.Equal(ip) {
				return true, true
			}
		}
	}
	return false, true
}
