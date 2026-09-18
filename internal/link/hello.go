package link

import (
	"encoding/json"
	"net/http"
	"time"
)

// RouteHello identifies this product to something about to pair with it.
//
// GET, unauthenticated, and answered ONLY WHILE A PAIRING CODE IS ON OFFER.
// That condition is the whole design, and it is a narrower answer than the
// peer asked for.
//
// The ask was reasonable: a peer wants to confirm that the port it is about to
// send a code to is really this product, so it can refuse the wrong one rather
// than burning one of five attempts against it -- and on the fifth, voiding the
// operator's code in a way that reads as a typo. An operator wants the same
// confirmation before typing a credential into something.
//
// But a permanently open identify endpoint undoes the property the rest of
// this listener is built around. Every other failure here is a bare 404
// precisely so that nothing confirms something is listening, and an endpoint
// that answers "notifymatrix 0.1.9, protocol xtremission-link/v1" to anyone
// who asks is a scanner's dream: it names the product, the version to look up,
// and the fact that this machine is the one watching the doors.
//
// Tying it to a live code keeps both. The operator opens a ten-minute window
// deliberately, by pressing a button; inside it the port will say what it is,
// which is exactly when a peer and an operator need to know. Outside it the
// port is as silent as it ever was. Nothing is gated on being ALREADY PAIRED,
// which is the mistake that makes an identify endpoint useless for the only
// question it answers.
const RouteHello = "/link/hello"

// Hello is what a peer reads to decide whether to pair.
type Hello struct {
	// Product and Protocol are what a peer matches on. Both, because a peer
	// that matched only the product would pair happily across an incompatible
	// protocol version.
	Product  string `json:"product"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Protocol string `json:"protocol"`

	// Role says which end this is. A receiver takes events; it does not send
	// them. A peer configured backwards finds out here instead of after a
	// pairing that can never carry anything.
	Role string `json:"role"`

	// Fingerprint is the certificate this product will present, repeated here
	// so a peer can compare it with what its own TLS layer saw.
	//
	// It is NOT a substitute for observing the certificate. A peer that took
	// this value as the one to hash into its pairing proof would be trusting
	// whatever answered, which is the man in the middle the proof exists to
	// defeat. Sent so the two can be compared and disagree loudly.
	Fingerprint string `json:"cert_fingerprint,omitempty"`
}

// ProductSlug and ProtocolName are what a peer matches on.
const (
	ProductSlug  = "notifymatrix"
	ProductName  = "UniFi Notification Matrix"
	ProtocolName = "xtremission-link/v1"
	RoleReceiver = "receiver"
)

// hello answers the identify probe, or refuses it exactly like anything else.
func (rc *Receiver) hello(w http.ResponseWriter, r *http.Request, now time.Time,
	deny func(string, Cause, string)) {

	if rc.deps.Pairer == nil {
		deny("", CausePairUnavailable, "this build cannot pair")
		return
	}
	// The window, and the only thing that opens it. Offered() is already the
	// single source of truth for "is a code live", so this cannot drift from
	// what the operator sees on the page.
	if code, _ := rc.deps.Pairer.Offered(); code == "" {
		deny("", CauseHelloClosed,
			"identified itself to nobody: no pairing code is on offer, so this "+
				"listener says nothing about what it is")
		return
	}

	rc.record(Receipt{At: now, LinkID: "", Route: r.URL.Path, Accepted: true,
		Reason: "identified itself during an open pairing window"})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(Hello{
		Product:     ProductSlug,
		Name:        ProductName,
		Version:     rc.deps.Version,
		Protocol:    ProtocolName,
		Role:        RoleReceiver,
		Fingerprint: rc.deps.Pairer.Fingerprint,
	})
}
