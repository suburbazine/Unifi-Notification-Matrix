package web

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

// Hello is the PRODUCT-level answer to "what is this, and where are its
// channels".
//
// Unauthenticated, on the operator listener, and it discloses nothing that
// listener did not already disclose: GET / serves the product's name in a
// <title> and its version in the header badge to anybody who asks, and
// /api/status is public so a wall display can show it. The one new fact is the
// peer link's PORT, which is a port and not a secret -- nothing on it answers
// without a signature, and it is discoverable by scanning in any case.
//
// The alternative was putting this on the link listener, which is where a peer
// cannot find it without already knowing where the link listener is. That is
// the thing discovery exists to solve.
type Hello struct {
	Product  string         `json:"product"`
	Name     string         `json:"name"`
	Version  string         `json:"version"`
	Channels []HelloChannel `json:"channels"`
}

// HelloChannel is one protocol this product speaks, and where.
type HelloChannel struct {
	Protocol string `json:"protocol"`
	Role     string `json:"role"`
	Path     string `json:"path"`

	// Port and TLS exist because this product's layout needs them: the
	// operator interface is plain HTTP on one port and the peer link is TLS on
	// another. A peer following only a path from here would land on the web
	// listener, where the link routes are not.
	Port int  `json:"port,omitempty"`
	TLS  bool `json:"tls"`

	// Hello says when the channel's OWN hello will answer.
	//
	// "only-while-pairing" is this product's answer and it is deliberate: the
	// link listener is silent by design, so following this advertisement
	// outside a pairing window returns the same bare 404 as a route that does
	// not exist. A peer that treats a silent channel hello as "wrong product"
	// would be wrong, and this field is how it can tell the difference without
	// having to know anything about this product in particular.
	Hello string `json:"hello,omitempty"`
}

// HelloWhilePairing is the value of HelloChannel.Hello for a channel that
// identifies itself only inside an open pairing window.
const HelloWhilePairing = "only-while-pairing"

// handleHello identifies the product.
//
// Never gated, and it carries nothing an operator would mind a neighbour
// seeing. What it must NOT do is advertise a channel that is not there: an
// advertised location that goes nowhere converts "I could not find it" into
// "I found the wrong thing", which is worse than saying nothing at all.
func (s *Server) handleHello(w http.ResponseWriter, r *http.Request) {
	h := Hello{
		Product:  link.ProductSlug,
		Name:     link.ProductName,
		Version:  s.deps.Version,
		Channels: []HelloChannel{},
	}
	if port, ok := s.linkPort(); ok {
		h.Channels = append(h.Channels, HelloChannel{
			Protocol: link.ProtocolName,
			Role:     link.RoleReceiver,
			Path:     strings.TrimSuffix(link.PathPrefix, "/"),
			Port:     port,
			TLS:      true,
			Hello:    HelloWhilePairing,
		})
	}
	writeJSON(w, http.StatusOK, h)
}

// linkPort is the port the link listener actually bound.
//
// Taken from the running state rather than from the configuration, because the
// configuration may say "auto" -- in which case the configured value is not a
// port and the bound one is the only true answer. Only the port is advertised,
// never the bind host: a peer reaches this product at whatever address it
// reached THIS listener on, and "0.0.0.0" would be a worse answer than none.
func (s *Server) linkPort() (int, bool) {
	if s.deps.LinkState == nil {
		return 0, false
	}
	st := s.deps.LinkState()
	if !st.Available || st.Address == "" {
		return 0, false
	}
	_, p, err := net.SplitHostPort(strings.TrimSpace(st.Address))
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}
