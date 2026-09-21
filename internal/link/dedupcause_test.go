package link

import (
	"errors"
	"testing"
)

// A dedup-key disagreement was labelled "invalid-envelope", whose sentence on
// the page is "it sent something outside the manifest you approved -- a
// severity, a state or a field that does not match what it declared".
//
// THAT SENDS THE OPERATOR TO THE MANIFEST, where they will find nothing
// wrong. A disagreeing key is not a manifest violation: both products
// believe they are right, and the consequence is that they would file the
// same alarm as two incidents that never merge. It is a bug report for the
// peer's author, with the two keys already in hand.
//
// Split for the same reason the version mismatch and the undeclared condition
// were split out before it: the operator does a different thing about it.
func TestADedupDisagreementIsNotAManifestViolation(t *testing.T) {
	if CauseDedupKey == CauseInvalidEnvelope {
		t.Fatal("a dedup disagreement carries the manifest label")
	}
	if got := causeFor(errors.New("some other envelope problem")); got != CauseInvalidEnvelope {
		t.Errorf("an ordinary envelope failure = %q, want invalid-envelope", got)
	}
	if got := causeFor(ErrDedupKey); got != CauseDedupKey {
		t.Errorf("a dedup disagreement = %q, want %q", got, CauseDedupKey)
	}
	if got := causeFor(ErrVersion); got != CauseEnvelopeVersion {
		t.Errorf("a version mismatch = %q; the existing splits must keep working", got)
	}
	if got := causeFor(ErrCondition); got != CauseUndeclaredCondition {
		t.Errorf("an undeclared condition = %q; the existing splits must keep working", got)
	}
}
