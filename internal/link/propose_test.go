package link

import (
	"fmt"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

var tp0 = time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)

func TestAnUndeclaredConditionBecomesAProposal(t *testing.T) {
	p := NewProposals()
	p.Note("sentry", "sentry-door-missing", incident.SeverityHigh,
		"Door 3 is not answering", tp0)

	got := p.For("sentry")
	if len(got) != 1 {
		t.Fatalf("proposals = %+v", got)
	}
	if got[0].Condition != "sentry-door-missing" || got[0].Severity != incident.SeverityHigh {
		t.Errorf("proposal = %+v", got[0])
	}
	if got[0].Title != "Door 3 is not answering" {
		t.Errorf("the peer's own words were dropped: %q", got[0].Title)
	}
	if got[0].Count != 1 {
		t.Errorf("count = %d", got[0].Count)
	}
}

// THE COUNT IS THE DIFFERENCE BETWEEN A TEST AND AN OUTAGE.
//
// A peer that fired once while somebody was developing it and a door that has
// been reporting something real and unheard for two days look identical
// without it.
func TestRetriesAccumulateRatherThanMultiplying(t *testing.T) {
	p := NewProposals()
	for i := 0; i < 5; i++ {
		p.Note("sentry", "sentry-door-missing", incident.SeverityHigh, "x",
			tp0.Add(time.Duration(i)*time.Minute))
	}
	got := p.For("sentry")
	if len(got) != 1 {
		t.Fatalf("one condition became %d rows", len(got))
	}
	if got[0].Count != 5 {
		t.Errorf("count = %d, want 5", got[0].Count)
	}
	if !got[0].Last.After(got[0].First) {
		t.Error("first and last are the same; the row is not being touched")
	}
}

// The peer corrected its severity in the next release. Reviewing the version
// it has stopped sending would be reviewing the wrong thing.
func TestTheLatestAttemptDecidesTheSeverityAndTitle(t *testing.T) {
	p := NewProposals()
	p.Note("sentry", "sentry-x", incident.SeverityLow, "old words", tp0)
	p.Note("sentry", "sentry-x", incident.SeverityCritical, "new words", tp0.Add(time.Hour))

	got := p.For("sentry")[0]
	if got.Severity != incident.SeverityCritical || got.Title != "new words" {
		t.Errorf("proposal = %+v", got)
	}
}

// A blank or invalid severity must not erase a good one from an earlier try.
func TestAnAttemptWithNothingUsefulDoesNotEraseWhatWasKnown(t *testing.T) {
	p := NewProposals()
	p.Note("sentry", "sentry-x", incident.SeverityCritical, "real words", tp0)
	p.Note("sentry", "sentry-x", incident.Severity("nonsense"), "   ", tp0.Add(time.Minute))

	got := p.For("sentry")[0]
	if got.Severity != incident.SeverityCritical {
		t.Errorf("severity = %q", got.Severity)
	}
	if got.Title != "real words" {
		t.Errorf("title = %q", got.Title)
	}
}

// A NAME THAT COULD NEVER BE APPROVED IS COUNTED, NOT LISTED.
//
// The manifest requires the peer's slug as a prefix, so a name without one is
// a bug in the peer rather than a decision waiting for an operator. Listing it
// would put a button next to something the validator refuses.
func TestANameThatCouldNeverBeApprovedIsNotOffered(t *testing.T) {
	p := NewProposals()
	p.Note("sentry", "motion", incident.SeverityHigh, "x", tp0)
	p.Note("sentry", "door-open", incident.SeverityHigh, "x", tp0)
	p.Note("sentry", "sentry-"+longName(), incident.SeverityHigh, "x", tp0)

	if got := p.For("sentry"); len(got) != 0 {
		t.Fatalf("offered something unapprovable: %+v", got)
	}
	unusable, _ := p.Refused("sentry")
	if unusable != 3 {
		t.Errorf("unusable = %d, want 3; silently dropping them tells the "+
			"operator their peer sends nothing it does not declare", unusable)
	}
}

func longName() string {
	s := ""
	for len(s) <= MaxConditionNameChars {
		s += "x"
	}
	return s
}

// ONE PEER CANNOT BURY A REAL PROPOSAL UNDER A THOUSAND GENERATED NAMES.
func TestTheListIsBoundedAndSaysWhenItIsFull(t *testing.T) {
	p := NewProposals()
	p.Note("sentry", "sentry-the-real-one", incident.SeverityHigh, "x", tp0)
	for i := 0; i < 500; i++ {
		p.Note("sentry", fmt.Sprintf("sentry-generated-%d", i),
			incident.SeverityHigh, "x", tp0.Add(time.Duration(i)*time.Second))
	}

	got := p.For("sentry")
	if len(got) != MaxProposalsPerPeer {
		t.Fatalf("held %d proposals, the limit is %d", len(got), MaxProposalsPerPeer)
	}
	// THE FIRST ONES ARE KEPT, NOT THE LATEST. A list that rotates under an
	// operator reading it is worse than one that says it is full -- and the
	// real proposal is usually the one that arrived first.
	found := false
	for _, pr := range got {
		if pr.Condition == "sentry-the-real-one" {
			found = true
		}
	}
	if !found {
		t.Error("the first proposal was evicted by a flood of later ones")
	}
	if _, overflowed := p.Refused("sentry"); overflowed == 0 {
		t.Error("said nothing about the names it turned away")
	}
}

// A retry of something ALREADY LISTED must not be counted as an overflow: the
// list is not full for it, and counting it would make the page report a flood
// that is one peer retrying one condition.
func TestARetryOfSomethingAlreadyListedIsNotAnOverflow(t *testing.T) {
	p := NewProposals()
	for i := 0; i < MaxProposalsPerPeer; i++ {
		p.Note("sentry", fmt.Sprintf("sentry-%d", i), incident.SeverityHigh, "x", tp0)
	}
	for i := 0; i < 100; i++ {
		p.Note("sentry", "sentry-0", incident.SeverityHigh, "x", tp0.Add(time.Minute))
	}
	if _, overflowed := p.Refused("sentry"); overflowed != 0 {
		t.Errorf("overflowed = %d; a retry of a listed condition is not a new name", overflowed)
	}
}

// Has is the gate on the amendment route: an operator may approve what a peer
// ASKED for, not whatever a request body contains.
func TestHasOnlyAnswersForSomethingThePeerActuallySent(t *testing.T) {
	p := NewProposals()
	p.Note("sentry", "sentry-x", incident.SeverityHigh, "x", tp0)

	if !p.Has("sentry", "sentry-x") {
		t.Error("did not recognise its own proposal")
	}
	for _, c := range []string{"sentry-y", "", "sentry-x "} {
		if c == "sentry-x " {
			continue // trimmed, and that is deliberate
		}
		if p.Has("sentry", c) {
			t.Errorf("claimed %q was proposed", c)
		}
	}
	if p.Has("doormatrix", "sentry-x") {
		t.Error("one peer's proposal answered for another; the slug is what " +
			"attributes it, and a peer must not be able to grant vocabulary " +
			"to a different product")
	}
	if !p.Has(" sentry ", " sentry-x ") {
		t.Error("surrounding space defeated the lookup")
	}
}

func TestApprovingOrDismissingDropsTheProposal(t *testing.T) {
	p := NewProposals()
	p.Note("sentry", "sentry-x", incident.SeverityHigh, "x", tp0)
	p.Forget("sentry", "sentry-x")

	if p.Has("sentry", "sentry-x") {
		t.Error("still proposed after being forgotten")
	}
	if got := p.For("sentry"); len(got) != 0 {
		t.Errorf("still listed: %+v", got)
	}
}

// UNPAIRING TAKES THE PENDING QUESTIONS WITH IT.
//
// Otherwise an unpaired product goes on asking the operator for vocabulary --
// and a DIFFERENT installation of that product, pairing later under the same
// slug, inherits the first one's queue.
func TestUnpairingClearsEverythingForThatPeer(t *testing.T) {
	p := NewProposals()
	p.Note("sentry", "sentry-x", incident.SeverityHigh, "x", tp0)
	p.Note("sentry", "not-prefixed", incident.SeverityHigh, "x", tp0)
	p.Note("doormatrix", "doormatrix-y", incident.SeverityHigh, "x", tp0)

	p.ForgetPeer("sentry")

	if got := p.For("sentry"); len(got) != 0 {
		t.Errorf("sentry still has %+v", got)
	}
	if unusable, overflowed := p.Refused("sentry"); unusable != 0 || overflowed != 0 {
		t.Errorf("counts survived the unpair: %d unusable, %d overflowed", unusable, overflowed)
	}
	if got := p.For("doormatrix"); len(got) != 1 {
		t.Errorf("the other peer was cleared too: %+v", got)
	}
}

func TestTheListIsOrderedByWhatWasTriedMostRecently(t *testing.T) {
	p := NewProposals()
	p.Note("sentry", "sentry-old", incident.SeverityHigh, "x", tp0)
	p.Note("sentry", "sentry-new", incident.SeverityHigh, "x", tp0.Add(time.Hour))
	p.Note("sentry", "sentry-mid", incident.SeverityHigh, "x", tp0.Add(time.Minute))

	got := p.For("sentry")
	want := []string{"sentry-new", "sentry-mid", "sentry-old"}
	for i, w := range want {
		if got[i].Condition != w {
			t.Fatalf("order = %v, want %v",
				[]string{got[0].Condition, got[1].Condition, got[2].Condition}, want)
		}
	}
}

// Two proposals sharing a timestamp must not reorder between two reads. An
// unstable order under a list somebody is reading is how the wrong button gets
// pressed.
func TestTheOrderIsStableWhenTwoArrivedTogether(t *testing.T) {
	p := NewProposals()
	for _, c := range []string{"sentry-c", "sentry-a", "sentry-b"} {
		p.Note("sentry", c, incident.SeverityHigh, "x", tp0)
	}
	first := p.For("sentry")
	for i := 0; i < 20; i++ {
		got := p.For("sentry")
		for j := range got {
			if got[j].Condition != first[j].Condition {
				t.Fatalf("read %d differs: %v", i, got)
			}
		}
	}
}

func TestNothingIsRecordedWithoutAPeerOrACondition(t *testing.T) {
	p := NewProposals()
	p.Note("", "sentry-x", incident.SeverityHigh, "x", tp0)
	p.Note("sentry", "   ", incident.SeverityHigh, "x", tp0)
	if got := p.All(); len(got) != 0 {
		t.Errorf("recorded %+v", got)
	}
}
