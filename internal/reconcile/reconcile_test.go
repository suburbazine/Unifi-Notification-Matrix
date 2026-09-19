package reconcile

import (
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/rule"
)

var now = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) time.Time { return now.Add(-d) }

func rules(entities ...[]string) rule.Set {
	var s rule.Set
	for i, e := range entities {
		s = append(s, rule.Rule{Name: string(rune('a' + i)), Entities: e})
	}
	return s
}

func report(rs rule.Set, known []Entity) []Finding {
	return Report(Input{Rules: rs, Known: known, Enumerated: true, Now: now})
}

func only(t *testing.T, got []Finding) Finding {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("want exactly one finding, got %d: %+v", len(got), got)
	}
	return got[0]
}

// A FAILED ENUMERATION MUST CONCLUDE NOTHING.
//
// This is the guard the sibling product nearly shipped without, and the
// failure it prevents is not a wrong answer on a page -- it is every
// configured entity reported missing at once the first time a query fails.
func TestAFailedEnumerationConcludesNothing(t *testing.T) {
	rs := rules([]string{"front-gate"})
	if got := Report(Input{Rules: rs, Enumerated: false, Now: now,
		Known: []Entity{{Source: "access", ID: "other", LastSeen: now}}}); got != nil {
		t.Errorf("reported %d findings from a failed enumeration: %+v", len(got), got)
	}
}

// AN EMPTY RECORD IS NOT A CLAIM THAT THE SITE HAS NOTHING.
//
// A fresh install has seen nothing, and every rule in a configuration restored
// from backup would otherwise be reported as pointing at a device that does
// not exist -- on the one day the operator most needs the page to be quiet.
func TestAnEmptyRecordConcludesNothing(t *testing.T) {
	if got := report(rules([]string{"front-gate"}), nil); got != nil {
		t.Errorf("reported %d findings against an empty record: %+v", len(got), got)
	}
}

// The ordinary case: a rule pointing at something that spoke recently is not
// a finding, and a review list that includes it is a review list nobody reads.
func TestALiveReferenceIsNotAFinding(t *testing.T) {
	known := []Entity{{Source: "access", ID: "gate-1", Name: "Front Gate", LastSeen: ago(time.Hour)}}
	for _, ref := range []string{"gate-1", "Front Gate", "FRONT GATE", "  gate-1  "} {
		if got := report(rules([]string{ref}), known); got != nil {
			t.Errorf("%q was reported: %+v", ref, got)
		}
	}
}

// RE-ADOPTION, WHICH IS THE WHOLE POINT.
//
// The id in the rule still resolves -- the record is permanent, so the old row
// never goes away -- and resolving is exactly what makes this invisible today.
// What gives it away is the MAC turning up on a newer id.
func TestAnIDRuleBrokenByReAdoptionIsFoundByItsMAC(t *testing.T) {
	known := []Entity{
		{Source: "access", ID: "old-id", Name: "Front Gate", MAC: "AA:BB:CC:DD:EE:FF",
			FirstSeen: ago(200 * 24 * time.Hour), LastSeen: ago(6 * 24 * time.Hour)},
		{Source: "access", ID: "new-id", Name: "Front Gate", MAC: "aabbccddeeff",
			FirstSeen: ago(6 * 24 * time.Hour), LastSeen: ago(time.Minute)},
	}
	f := only(t, report(rules([]string{"old-id"}), known))
	if f.Status != StatusSuperseded {
		t.Fatalf("status = %q, want %q", f.Status, StatusSuperseded)
	}
	if len(f.Successors) != 1 || f.Successors[0].ID != "new-id" {
		t.Fatalf("successors = %+v, want new-id", f.Successors)
	}
	if f.Successors[0].On != "mac" {
		t.Errorf("matched on %q; the MAC is the identifier that survives both "+
			"a rename and a re-adoption and must be preferred", f.Successors[0].On)
	}
}

// The MAC is spelled differently by different sources. Two spellings of one
// address failing to match turns the evidence case back into the shrug case,
// silently.
func TestMACPunctuationDoesNotHideTheEvidence(t *testing.T) {
	for _, spelling := range []string{"aa-bb-cc-dd-ee-ff", "AABBCCDDEEFF", "aa:bb:cc:dd:ee:ff"} {
		known := []Entity{
			{Source: "access", ID: "old", Name: "A", MAC: "aa:bb:cc:dd:ee:ff", LastSeen: ago(48 * time.Hour)},
			{Source: "access", ID: "new", Name: "B", MAC: spelling, LastSeen: ago(time.Minute)},
		}
		f := only(t, report(rules([]string{"old"}), known))
		if f.Status != StatusSuperseded || len(f.Successors) == 0 || f.Successors[0].On != "mac" {
			t.Errorf("%q: status %q successors %+v", spelling, f.Status, f.Successors)
		}
	}
}

// WITHOUT A MAC, THE NAME IS THE FALLBACK -- and it is reported AS the weaker
// answer, because it is one.
func TestANewIDCarryingTheSameNameIsOfferedWhenThereIsNoMAC(t *testing.T) {
	known := []Entity{
		{Source: "access", ID: "old", Name: "Side Door", LastSeen: ago(30 * 24 * time.Hour)},
		{Source: "access", ID: "new", Name: "Side Door", LastSeen: ago(time.Minute)},
	}
	f := only(t, report(rules([]string{"old"}), known))
	if f.Status != StatusSuperseded {
		t.Fatalf("status = %q", f.Status)
	}
	if f.Successors[0].On != "name" {
		t.Errorf("on = %q, want name", f.Successors[0].On)
	}
}

// EVIDENCE OUTRANKS A HINT.
//
// Offering the name match first would invite somebody to take the weaker
// answer when the stronger one was right there.
func TestTheMACCandidateIsOfferedAboveTheNameCandidate(t *testing.T) {
	known := []Entity{
		{Source: "access", ID: "old", Name: "Gate", MAC: "aa:bb", LastSeen: ago(48 * time.Hour)},
		{Source: "access", ID: "by-name", Name: "Gate", LastSeen: ago(time.Minute)},
		{Source: "access", ID: "by-mac", Name: "Gate (rear)", MAC: "aa:bb", LastSeen: ago(time.Hour)},
	}
	f := only(t, report(rules([]string{"old"}), known))
	if len(f.Successors) != 2 {
		t.Fatalf("successors = %+v", f.Successors)
	}
	if f.Successors[0].ID != "by-mac" {
		t.Errorf("offered %q first; the MAC match is evidence and the name "+
			"match is a hint", f.Successors[0].ID)
	}
}

// A NAME-WRITTEN RULE SURVIVES A RE-ADOPTION, and must not be reported.
//
// The old row is six days quiet and the new row shares its name, so a
// reconciliation that judged by the oldest match would report the one case the
// identity table says is fine. This is the false positive that would teach an
// operator to ignore the list.
func TestANameRuleIsNotReportedWhenTheNameStillResolvesToSomethingLive(t *testing.T) {
	known := []Entity{
		{Source: "access", ID: "old-id", Name: "Front Gate", MAC: "aa:bb", LastSeen: ago(6 * 24 * time.Hour)},
		{Source: "access", ID: "new-id", Name: "Front Gate", MAC: "aa:bb", LastSeen: ago(time.Minute)},
	}
	if got := report(rules([]string{"Front Gate"}), known); got != nil {
		t.Errorf("reported a name reference that still resolves to a live "+
			"device: %+v", got)
	}
}

// A reference that resolves to nothing at all. A rename produces this, and so
// does a typo -- neither is an error and both are worth an eye.
func TestAReferenceMatchingNothingIsReportedAsUnknown(t *testing.T) {
	known := []Entity{{Source: "access", ID: "gate-1", Name: "Gate", LastSeen: now}}
	f := only(t, report(rules([]string{"frnot-gate"}), known))
	if f.Status != StatusUnknown {
		t.Fatalf("status = %q, want %q", f.Status, StatusUnknown)
	}
	if f.MatchedID != "" || f.MatchedName != "" {
		t.Errorf("an unknown reference resolved to %q/%q", f.MatchedID, f.MatchedName)
	}
	if len(f.Successors) != 0 {
		t.Errorf("offered a replacement for something that never existed: %+v", f.Successors)
	}
}

// QUIET, WITH NOTHING TAKING ITS PLACE, IS THE WEAK CASE and waits a long time.
func TestQuietWithNoReplacementWaitsForTheThreshold(t *testing.T) {
	known := []Entity{{Source: "access", ID: "gate-1", Name: "Gate", LastSeen: ago(20 * 24 * time.Hour)}}

	if got := report(rules([]string{"gate-1"}), known); got != nil {
		t.Errorf("twenty days of quiet was reported; a delivery door in a "+
			"building that takes monthly deliveries looks exactly like this: %+v", got)
	}

	known[0].LastSeen = ago(40 * 24 * time.Hour)
	f := only(t, report(rules([]string{"gate-1"}), known))
	if f.Status != StatusSilent {
		t.Errorf("status = %q, want %q", f.Status, StatusSilent)
	}
}

// The superseded case does NOT wait for the silence threshold, because it does
// not need to: the evidence is the pair, not the elapsed time.
func TestSupersededDoesNotWaitForTheSilenceThreshold(t *testing.T) {
	known := []Entity{
		{Source: "access", ID: "old", Name: "Gate", MAC: "aa:bb", LastSeen: ago(2 * time.Hour)},
		{Source: "access", ID: "new", Name: "Gate", MAC: "aa:bb", LastSeen: ago(time.Minute)},
	}
	f := only(t, report(rules([]string{"old"}), known))
	if f.Status != StatusSuperseded {
		t.Errorf("status = %q; two hours is not thirty days, and the pair is "+
			"the evidence rather than the elapsed time", f.Status)
	}
}

// A CANDIDATE THAT WENT QUIET FIRST IS NOT A SUCCESSOR.
//
// Without this, a rule pointing at the LIVE camera would be offered the dead
// one as its replacement -- which is not a missed detection, it is this
// feature actively breaking a working rule.
func TestSomethingQuieterThanTheReferenceIsNeverOfferedAsAReplacement(t *testing.T) {
	known := []Entity{
		{Source: "access", ID: "live", Name: "Gate", MAC: "aa:bb", LastSeen: ago(time.Minute)},
		{Source: "access", ID: "dead", Name: "Gate", MAC: "aa:bb", LastSeen: ago(90 * 24 * time.Hour)},
	}
	if got := report(rules([]string{"live"}), known); got != nil {
		t.Errorf("offered a replacement for a device that reported a minute "+
			"ago: %+v", got)
	}
}

// Two sources may each adopt hardware, and a MAC seen through a different
// source is a different device's record as far as adoption is concerned.
func TestASuccessorMustBeInTheSameSource(t *testing.T) {
	known := []Entity{
		{Source: "access", ID: "old", Name: "Gate", MAC: "aa:bb", LastSeen: ago(60 * 24 * time.Hour)},
		{Source: "protect", ID: "new", Name: "Gate", MAC: "aa:bb", LastSeen: ago(time.Minute)},
	}
	f := only(t, report(rules([]string{"old"}), known))
	if f.Status != StatusSilent {
		t.Errorf("status = %q, want %q: a cross-source match is not a "+
			"re-adoption", f.Status, StatusSilent)
	}
}

// A GLOB IS A CLASS MATCH, and rewriting one is not something this can do
// honestly -- but a class that currently contains nothing is still worth
// saying out loud.
func TestAPatternIsReportedWhenItMatchesNothingAndNeverRewritten(t *testing.T) {
	known := []Entity{{Source: "access", ID: "gate-1", Name: "Front Gate", LastSeen: now}}

	if got := report(rules([]string{"gate-*"}), known); got != nil {
		t.Errorf("a pattern that matches something was reported: %+v", got)
	}
	if got := report(rules([]string{"door-?"}), known); len(got) != 1 {
		t.Fatalf("a pattern matching nothing was not reported: %+v", got)
	}

	f := only(t, report(rules([]string{"camera-*"}), known))
	if f.Status != StatusUnknown || !f.Pattern {
		t.Fatalf("status %q pattern %v", f.Status, f.Pattern)
	}
	if len(f.Successors) != 0 {
		t.Errorf("offered to rewrite a glob: %+v", f.Successors)
	}
}

// "*" is "anything" and cannot be stale. An empty entry is not a reference.
func TestAnythingAndNothingAreNotReferences(t *testing.T) {
	known := []Entity{{Source: "access", ID: "gate-1", LastSeen: now}}
	if got := report(rules([]string{"*", "", "   "}), known); got != nil {
		t.Errorf("reported %+v", got)
	}
}

// The finding has to carry enough to find the rule again and to replace the
// reference EXACTLY as written, or the amendment cannot be applied safely.
func TestAFindingNamesItsRuleAndKeepsTheReferenceAsWritten(t *testing.T) {
	rs := rule.Set{
		{Name: "first", Entities: []string{"gate-1"}},
		{Name: "second", Entities: []string{"  Old-ID  "}},
	}
	known := []Entity{
		{Source: "access", ID: "gate-1", LastSeen: now},
		{Source: "access", ID: "Old-ID", Name: "Gate", MAC: "aa", LastSeen: ago(48 * time.Hour)},
		{Source: "access", ID: "new", Name: "Gate", MAC: "aa", LastSeen: now},
	}
	f := only(t, report(rs, known))
	if f.Rule != "second" || f.RuleIndex != 1 {
		t.Errorf("rule = %q index %d", f.Rule, f.RuleIndex)
	}
	if f.Reference != "Old-ID" {
		t.Errorf("reference = %q; it is trimmed for comparison but reported as "+
			"the operator wrote it", f.Reference)
	}
}
