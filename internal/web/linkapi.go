package web

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
)

// noLinkListener is the one answer every link route gives when this build has
// no listener: there is nowhere for a peer to pair TO, which is a different
// thing from pairing having failed.
const noLinkListener = "this installation has no peer link listener, so there " +
	"is nowhere for a peer to pair. Set web.link_listen and restart."

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

	// Receipts is what peers have actually done here, most recent first,
	// INCLUDING every refusal and why.
	//
	// The link port answers every failure with a bare 404 -- unknown link id,
	// bad signature, stale clock, replayed nonce, fingerprint mismatch, all
	// identical -- because an endpoint that distinguishes them tells an
	// attacker which half to keep working on. That is right on the wire and
	// useless to an operator, who is then debugging a number. This is the
	// other side of that trade: the real reason, on a page that already needs
	// a password.
	Receipts []LinkReceiptView `json:"receipts"`

	// Proposals are conditions paired peers have sent that their approved
	// manifest does not contain, waiting for a decision.
	//
	// The event was REFUSED, and stays refused until the operator says yes.
	// What this list changes is only that saying yes stops being a text
	// editor: a peer shipping a twelfth condition used to mean opening the
	// configuration file by hand, or re-pairing the product -- rotating a
	// working credential to fix a spelling.
	Proposals []LinkProposalView `json:"proposals"`

	// SinceSeconds is how long this service has been collecting receipts:
	// the receipts are IN MEMORY and start empty at every restart.
	//
	// It exists because the empty state was giving confidently wrong advice.
	// "Nothing has reached the link listener yet -- a peer that appears to be
	// trying and is not here is not reaching this machine at all" is true
	// after a fresh install and a lie two minutes after a restart, and it
	// sends the operator to check firewalls and ports when nothing is wrong.
	// Found by rendering the page against a daemon that had just restarted.
	SinceSeconds int `json:"since_seconds"`
}

// LinkReceiptView is one thing a peer did, as an operator needs to read it.
type LinkReceiptView struct {
	At        time.Time `json:"at"`
	LinkID    string    `json:"link_id,omitempty"`
	Route     string    `json:"route"`
	Accepted  bool      `json:"accepted"`
	Duplicate bool      `json:"duplicate,omitempty"`

	// Cause is the countable label and Reason the sentence with the specifics
	// in it. Both are sent: the label is what lets the page say "four of these
	// are the same problem" instead of showing four sentences that happen to
	// be identical.
	Cause  string `json:"cause,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// LinkProposalView is one condition a peer is asking to be allowed to send.
type LinkProposalView struct {
	Product   string `json:"product"`
	Condition string `json:"condition"`

	// Severity and Title are the peer's own words from the refused event,
	// offered as a starting point for the form rather than as a decision. A
	// meaning nobody wrote is a meaning nobody reviewed.
	Severity string `json:"severity,omitempty"`
	Title    string `json:"title,omitempty"`

	// Count is how many events have been refused for this, which separates a
	// peer that fired once during its own testing from a door that has been
	// reporting something real and unheard for two days.
	Count int       `json:"count"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`

	// Unusable and Overflowed are what this peer sent that is NOT in the list:
	// names that could never be approved because they do not begin with the
	// peer's slug, and names that arrived after the list was full. Carried on
	// each row so the page can say it without a second shape; the server sends
	// the same numbers on every row of a peer.
	Unusable   int `json:"unusable,omitempty"`
	Overflowed int `json:"overflowed,omitempty"`
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
		writeJSON(w, http.StatusNotFound, errorBody(noLinkListener))
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

// handleLinkCancelCode withdraws an offered pairing code.
//
// A code is live for its full ten minutes whether or not the operator still
// wants it to be. Without a way to take one back, "I read it out to the wrong
// person" or "I pasted it in the wrong window" is ten minutes of a working
// credential sitting somewhere it should not, and the only remedy is to wait.
func (s *Server) handleLinkCancelCode(w http.ResponseWriter, r *http.Request) {
	if s.deps.LinkCancelCode == nil {
		writeJSON(w, http.StatusNotFound, errorBody(noLinkListener))
		return
	}
	s.deps.LinkCancelCode()
	s.record(r, audit.Entry{
		Kind: audit.KindService, Actor: "web",
		Summary: "withdrew the peer pairing code",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

// handleLinkUnpair forgets a paired peer.
//
// The other half of pairing, and it is not optional. Pairing from this page
// grants a credential that can raise alarms here and take a capability away
// from this product's own sources; a grant that can only be revoked by editing
// YAML is a grant most operators cannot revoke at all.
func (s *Server) handleLinkUnpair(w http.ResponseWriter, r *http.Request) {
	if s.deps.LinkUnpair == nil {
		writeJSON(w, http.StatusNotFound, errorBody(noLinkListener))
		return
	}
	slug := strings.TrimSpace(r.PathValue("slug"))
	if slug == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("which peer?"))
		return
	}
	found, err := s.deps.LinkUnpair(slug)
	if err != nil {
		s.fail(w, r, "forgetting a peer link", err)
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound,
			errorBody("no peer named "+slug+" is paired here"))
		return
	}
	s.record(r, audit.Entry{
		Kind: audit.KindService, Actor: "web",
		Summary: "forgot a peer link",
		Fields:  map[string]string{"product": slug},
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "forgotten"})
}

// ---------------------------------------------------------------------------
// Amending an approved manifest
//
// The vocabulary a peer may use is closed, and stays closed: this does not
// widen what arrives, it changes what SAYING YES costs. Before it, a peer
// shipping one more condition meant hand-editing YAML on the operator's
// machine, or re-pairing the product -- which rotates a working credential in
// order to fix a spelling, and is how a second site's credential gets revoked
// by accident (see storePeer).
//
// Everything a pairing manifest has to satisfy, an amendment satisfies too:
// the name must begin with the peer's slug, the severity must be real, the
// meaning must be written by the person approving it, and the whole manifest
// is revalidated before it is saved. And it may only name a condition a peer
// has ACTUALLY TRIED to send, so this is not a general way to write config.
// ---------------------------------------------------------------------------

// approveConditionRequest is the operator's decision about one proposal.
type approveConditionRequest struct {
	Condition string `json:"condition"`

	// Meaning is what they are approving and is REQUIRED. The peer's event
	// title is offered as a starting point by the page; a condition with no
	// meaning cannot be reviewed by whoever reads the list next year.
	Meaning  string `json:"meaning"`
	Severity string `json:"severity"`

	// Momentary is the operator's classification. The peer cannot propose it
	// here -- an event envelope carries no such flag -- so unlike at pairing
	// there is nothing to override, and this is simply their answer.
	Momentary bool `json:"momentary"`
}

// handleLinkApproveCondition adds one proposed condition to a peer's manifest.
func (s *Server) handleLinkApproveCondition(w http.ResponseWriter, r *http.Request) {
	if s.deps.LinkApproveCondition == nil {
		writeJSON(w, http.StatusNotFound, errorBody(noLinkListener))
		return
	}
	slug := strings.TrimSpace(r.PathValue("slug"))
	if slug == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("which peer?"))
		return
	}
	var req approveConditionRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("that request could not be read"))
		return
	}
	req.Condition = strings.TrimSpace(req.Condition)
	req.Meaning = strings.TrimSpace(req.Meaning)
	if req.Condition == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("which condition?"))
		return
	}
	if req.Meaning == "" {
		writeJSON(w, http.StatusBadRequest, errorBody(
			"write what this condition means before approving it; a condition "+
				"with no meaning cannot be reviewed by anybody later"))
		return
	}
	if len([]rune(req.Meaning)) > 200 {
		req.Meaning = string([]rune(req.Meaning)[:200])
	}

	err := s.deps.LinkApproveCondition(slug, ApprovedCondition{
		Condition: req.Condition,
		Meaning:   req.Meaning,
		Severity:  req.Severity,
		Momentary: req.Momentary,
	})
	switch {
	case errors.Is(err, ErrNotProposed):
		// Covers the stale page and the invented name in one answer: this is
		// not a way to write a condition a peer has never tried to send.
		writeJSON(w, http.StatusConflict, errorBody(
			"that peer is not asking for "+req.Condition+" — it may have been "+
				"approved already, or this page may be out of date"))
	case errors.Is(err, config.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
	case err != nil:
		s.fail(w, r, "approving a peer condition", err)
	default:
		s.record(r, audit.Entry{
			Kind: audit.KindConfigChanged, Actor: "web",
			Summary: "approved a new condition for a paired peer",
			Fields: map[string]string{
				"product": slug, "condition": req.Condition,
				"severity": req.Severity,
			},
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
	}
}

// handleLinkDismissCondition drops a proposal without approving it.
//
// Not the same as refusing for ever, and the page says so: the peer goes on
// sending it and the proposal comes back. There is no "never ask again",
// because a peer that keeps sending something is a fact about the peer, and a
// product that lets an operator hide a fact about a peer is one that will be
// asked why it stopped mentioning it.
func (s *Server) handleLinkDismissCondition(w http.ResponseWriter, r *http.Request) {
	if s.deps.LinkDismissCondition == nil {
		writeJSON(w, http.StatusNotFound, errorBody(noLinkListener))
		return
	}
	slug := strings.TrimSpace(r.PathValue("slug"))
	cond := strings.TrimSpace(r.PathValue("condition"))
	if slug == "" || cond == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("which peer, and which condition?"))
		return
	}
	s.deps.LinkDismissCondition(slug, cond)
	writeJSON(w, http.StatusOK, map[string]string{"status": "dismissed"})
}
