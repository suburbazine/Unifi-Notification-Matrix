package web

import (
	"net/http"
	"time"
)

// LinkPairing is what the interface shows about pairing a peer.
type LinkPairing struct {
	// Available says this build has a link listener running. False means
	// web.link_listen is unset, and the honest answer is that there is nowhere
	// for a peer to pair TO rather than that pairing failed.
	Available bool `json:"available"`

	// Address and Fingerprint are what the operator gives the peer. The
	// fingerprint is the identity the peer pins, so it is shown in full: a
	// truncated one is a value somebody will paste and then wonder about.
	Address     string `json:"address,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`

	// Code is the live pairing code, empty when none is on offer, with the
	// seconds left on it. Short-lived and single-use by design, so the screen
	// has to say how long is left rather than imply it is a standing secret.
	Code           string `json:"code,omitempty"`
	ExpiresSeconds int    `json:"expires_seconds,omitempty"`

	// Peers is what is paired now.
	Peers []LinkPeerView `json:"peers"`
}

// LinkPeerView is one paired peer, as an operator needs to see it.
type LinkPeerView struct {
	Product    string `json:"product"`
	LinkID     string `json:"link_id"`
	Capability string `json:"capability,omitempty"`
	Conditions int    `json:"conditions"`

	// Holding says the peer is currently serving its capability, and Why
	// explains it when it is not.
	//
	// THIS IS THE SURFACE FOR "who is watching the doors right now". A peer can
	// be perfectly alive and unable to see a single door, and in that state
	// every other indicator reads healthy -- so the reason has to be shown
	// here rather than inferred.
	Holding bool   `json:"holding"`
	Why     string `json:"why,omitempty"`
}

// handleLinkState reports pairing state.
func (s *Server) handleLinkState(w http.ResponseWriter, r *http.Request) {
	if s.deps.LinkState == nil {
		writeJSON(w, http.StatusOK, LinkPairing{})
		return
	}
	writeJSON(w, http.StatusOK, s.deps.LinkState())
}

// handleLinkPairCode offers a fresh pairing code.
//
// Gated behind a session, because a code is a credential: anybody holding one
// for the next ten minutes can pair a peer that will then be able to raise
// alarms here and take over a capability.
func (s *Server) handleLinkPairCode(w http.ResponseWriter, r *http.Request) {
	if s.deps.LinkOfferCode == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "this installation has no peer link listener, so there is " +
				"nowhere for a peer to pair. Set web.link_listen and restart.",
		})
		return
	}
	code, expires, err := s.deps.LinkOfferCode()
	if err != nil {
		s.fail(w, r, "offering a pairing code", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code":            code,
		"expires_seconds": int(expires / time.Second),
	})
}
