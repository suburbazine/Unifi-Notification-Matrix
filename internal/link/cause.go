package link

import (
	"crypto/subtle"
	"errors"
)

// Cause is why a link request was refused, as a value rather than as a
// sentence.
//
// The receipts carried only prose. It read perfectly well and could not
// answer the one question worth asking of a wall of refusals -- "how many of
// these are an unknown peer rather than a wrong signature?" -- which is the
// distinction that makes the difference between checking a credential and
// checking a clock. Door Matrix hit this on the other side of the same
// construction and named it; the same defect was here.
//
// The sentence stays, because it carries the specifics a label cannot: which
// route, how far off the clock was, what the envelope got wrong. The label is
// what makes them countable.
type Cause string

const (
	CauseNone Cause = ""

	// Transport: something arrived and did not authenticate.
	CauseMethod         Cause = "method-not-allowed"
	CauseNoRoute        Cause = "no-such-route"
	CauseBodyUnreadable Cause = "body-unreadable"
	CauseBodyTooLarge   Cause = "body-over-limit"
	CauseUnsigned       Cause = "unsigned"
	CauseMalformedAuth  Cause = "malformed-auth"
	CauseUnknownLink    Cause = "unknown-link-id"
	CauseBadSignature   Cause = "bad-signature"
	CauseClockSkew      Cause = "clock-skew"
	CauseReplay         Cause = "replayed-nonce"
	CauseNonceFull      Cause = "nonce-table-full"
	CauseNoPeer         Cause = "no-peer-for-link"
	CauseRateLimited    Cause = "over-the-rate-limit"

	// The request authenticated and its contents did not hold up.
	CauseMalformedEnvelope Cause = "malformed-envelope"
	CauseInvalidEnvelope   Cause = "invalid-envelope"

	// CauseEnvelopeVersion is split out from CauseInvalidEnvelope because the
	// two need opposite responses. An invalid envelope is a peer claiming
	// something it did not declare, which is the operator's business. A
	// version mismatch is two builds that do not speak the same protocol,
	// which is somebody's upgrade. Merged, the wall of refusals says "your
	// peer is misbehaving" about a peer that is merely older.
	//
	// Split after the first live pairing, where every event was refused for
	// this and the label said only "invalid-envelope".
	CauseEnvelopeVersion Cause = "envelope-version"

	// CauseUndeclaredCondition is split out from CauseInvalidEnvelope for the
	// same reason CauseEnvelopeVersion is: the operator does a DIFFERENT thing
	// about it. Every other invalid envelope is a bug to report to the peer's
	// author; this one is usually their next release carrying a condition
	// nobody has been asked about yet, and the answer is a button. See
	// propose.go.
	CauseUndeclaredCondition Cause = "undeclared-condition"

	// CauseDedupKey is split out for the third time this pattern has been
	// needed, and for the same reason: the operator does a different thing
	// about it.
	//
	// The invalid-envelope sentence sends somebody to the manifest they
	// approved. A disagreeing dedup key has nothing to do with the manifest:
	// both ends believe they are right, and the consequence is that the same
	// alarm would be filed twice and never merge. Found on the first live
	// pairing with Sentry, where every event was refused with a label that
	// pointed at the wrong thing to go and read.
	CauseDedupKey Cause = "dedup-key-disagreement"
	CauseStore    Cause = "store-failed"
	CauseIngest   Cause = "ingest-failed"

	// Pairing, which is the one route a stranger can reach.
	CausePairUnavailable Cause = "pairing-unavailable"
	CausePairBody        Cause = "pairing-body"
	CausePairNoneOffered Cause = "pairing-none-offered"
	CausePairExpired     Cause = "pairing-code-expired"
	CausePairUsed        Cause = "pairing-code-used"
	CausePairVoided      Cause = "pairing-code-voided"
	CausePairBadProof    Cause = "pairing-bad-proof"
	CausePairFingerprint Cause = "pairing-fingerprint-mismatch"
	CausePairManifest    Cause = "pairing-manifest"
	CausePairStore       Cause = "pairing-store-failed"

	// CauseHelloClosed is an identify probe outside a pairing window. Not an
	// attack and not a misconfiguration: somebody looked before the operator
	// opened the door. Recorded so "my probe found nothing" has an answer.
	CauseHelloClosed Cause = "identify-window-closed"
)

// verifyCause labels a verification failure.
//
// CauseUnknownLink and CauseBadSignature are NOT distinguished by Verify, and
// deliberately: a caller that can tell them apart can enumerate link ids. They
// are distinguished HERE, for the receipt only, because the operator is the
// one person for whom that difference is the whole diagnosis -- "the peer you
// revoked is still trying" and "the peer you paired disagrees with you about
// the key" are different afternoons.
func verifyCause(creds []Credential, linkID string, err error) Cause {
	switch {
	case errors.Is(err, ErrNoSignature):
		return CauseUnsigned
	case errors.Is(err, ErrMalformed):
		return CauseMalformedAuth
	case errors.Is(err, ErrSkew):
		return CauseClockSkew
	case errors.Is(err, ErrReplay):
		return CauseReplay
	case errors.Is(err, ErrNonceFull):
		return CauseNonceFull
	case errors.Is(err, ErrUnknownLink):
		return CauseUnknownLink
	case errors.Is(err, ErrBadSignature):
		if !knownLink(creds, linkID) {
			return CauseUnknownLink
		}
		return CauseBadSignature
	}
	return CauseBadSignature
}

// knownLink reports whether any credential carries this link id.
//
// Scanned with no early break and compared in constant time, like the
// verification itself. The answer never reaches the wire, so this is belt and
// braces -- but a lookup that returns faster for an absent id is the exact
// shape of the leak the bare 404 exists to prevent, and it costs nothing to
// not have it.
func knownLink(creds []Credential, linkID string) bool {
	var hits int
	for _, c := range creds {
		hits += subtle.ConstantTimeCompare([]byte(c.LinkID), []byte(linkID))
	}
	return hits > 0
}

// pairCause labels a pairing failure.
func pairCause(err error) Cause {
	switch {
	case errors.Is(err, ErrNoPairing):
		return CausePairNoneOffered
	case errors.Is(err, ErrCodeExpired):
		return CausePairExpired
	case errors.Is(err, ErrCodeUsed):
		return CausePairUsed
	case errors.Is(err, ErrCodeVoided):
		return CausePairVoided
	case errors.Is(err, ErrFingerprint):
		return CausePairFingerprint
	case errors.Is(err, ErrManifestNeeded):
		return CausePairManifest
	case errors.Is(err, ErrBadProof):
		return CausePairBadProof
	}
	return CausePairBadProof
}

// AllCauses is every label a refusal can carry.
//
// Exported so the interface can be checked against it: a cause the operator's
// page has no words for renders as a slug like "unknown-link-id", which is the
// label doing the job the sentence was supposed to do. The list is written out
// rather than derived because Go cannot enumerate its own constants, so a new
// one has to be added here -- and the test that reads this is what makes
// forgetting visible.
func AllCauses() []Cause {
	return []Cause{
		CauseUndeclaredCondition,
		CauseMethod, CauseNoRoute, CauseBodyUnreadable, CauseBodyTooLarge,
		CauseUnsigned, CauseMalformedAuth, CauseUnknownLink, CauseBadSignature,
		CauseClockSkew, CauseReplay, CauseNonceFull, CauseNoPeer,
		CauseRateLimited,
		CauseMalformedEnvelope, CauseInvalidEnvelope, CauseEnvelopeVersion,
		CauseStore, CauseIngest,
		CausePairUnavailable, CausePairBody, CausePairNoneOffered,
		CausePairExpired, CausePairUsed, CausePairVoided, CausePairBadProof,
		CausePairFingerprint, CausePairManifest, CausePairStore,
		CauseHelloClosed,
	}
}
