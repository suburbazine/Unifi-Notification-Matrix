package link

import (
	"errors"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

func spec(name string) ConditionSpec {
	return ConditionSpec{Name: name, Meaning: "Something an operator can read.",
		Severity: incident.SeverityHigh}
}

func TestAWorkableManifestValidates(t *testing.T) {
	if err := sentry().Manifest.Validate("sentry"); err != nil {
		t.Fatalf("a workable manifest was refused: %v", err)
	}
}

// Approving eleven conditions is review; approving two hundred is
// rubber-stamping, and the review is the whole security value of the manifest.
func TestAnOversizedManifestIsRefused(t *testing.T) {
	m := Manifest{Capability: "access"}
	for i := 0; i <= MaxManifestConditions; i++ {
		m.Conditions = append(m.Conditions, spec("sentry-c"+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	if err := m.Validate("sentry"); !errors.Is(err, ErrManifestTooLarge) {
		t.Errorf("a manifest of %d conditions was accepted: %v", len(m.Conditions), err)
	}
}

// Dedup keys are namespaced by source already, but the rules editor offers ONE
// vocabulary to a human: a peer declaring "motion" there would be
// indistinguishable from this product's own condition.
func TestAConditionMustCarryThePeersPrefix(t *testing.T) {
	m := Manifest{Capability: "access", Conditions: []ConditionSpec{spec("motion")}}
	if err := m.Validate("sentry"); !errors.Is(err, ErrConditionPrefix) {
		t.Errorf("a condition without the peer's prefix was accepted: %v", err)
	}
}

func TestAManifestMustBeReviewable(t *testing.T) {
	noMeaning := Manifest{Capability: "access",
		Conditions: []ConditionSpec{{Name: "sentry-x", Severity: incident.SeverityHigh}}}
	if err := noMeaning.Validate("sentry"); !errors.Is(err, ErrNoMeaning) {
		t.Errorf("a condition with no meaning was accepted: %v", err)
	}

	badSev := Manifest{Capability: "access",
		Conditions: []ConditionSpec{{Name: "sentry-x", Meaning: "m", Severity: "urgent"}}}
	if err := badSev.Validate("sentry"); !errors.Is(err, ErrSeverity) {
		t.Errorf("a condition proposing an unknown severity was accepted: %v", err)
	}

	dup := Manifest{Capability: "access", Conditions: []ConditionSpec{spec("sentry-x"), spec("sentry-x")}}
	if err := dup.Validate("sentry"); !errors.Is(err, ErrConditionDup) {
		t.Errorf("a duplicated condition was accepted: %v", err)
	}

	none := Manifest{Capability: "access"}
	if err := none.Validate("sentry"); !errors.Is(err, ErrManifestEmpty) {
		t.Errorf("an empty manifest was accepted: %v", err)
	}

	noCap := Manifest{Conditions: []ConditionSpec{spec("sentry-x")}}
	if err := noCap.Validate("sentry"); !errors.Is(err, ErrNoCapability) {
		t.Errorf("a manifest claiming no capability was accepted: %v", err)
	}
}

// MOMENTARY IS A PROPOSAL, NOT A DECLARATION. The flag decides whether an
// incident that cleared before its first rung is still delivered, and getting
// it wrong on a high-volume condition floods the operator. A peer approved by
// somebody who has never seen the condition fire cannot know either.
func TestTheOperatorsOverrideBeatsThePeersProposal(t *testing.T) {
	p := sentry()
	if !p.IsMomentary("sentry-access-denied") {
		t.Fatal("the peer's proposal was not honoured with no override present")
	}

	state := false
	p.Overrides = map[string]Override{"sentry-access-denied": {Momentary: &state}}
	if p.IsMomentary("sentry-access-denied") {
		t.Error("the peer's proposal beat the operator's override")
	}

	// ...and the other direction, so an override can also promote.
	momentary := true
	p.Overrides = map[string]Override{"sentry-blocked-locally": {Momentary: &momentary}}
	if !p.IsMomentary("sentry-blocked-locally") {
		t.Error("an override promoting a state condition was ignored")
	}
}

// The override lives outside the manifest so it SURVIVES an amendment: a peer
// re-proposing momentary in its next release must not silently undo an
// operator who decided otherwise.
func TestAnOverrideSurvivesAManifestAmendment(t *testing.T) {
	p := sentry()
	state := false
	p.Overrides = map[string]Override{"sentry-access-denied": {Momentary: &state}}

	// The peer amends, re-proposing momentary for the same condition.
	amended := p.Manifest
	for i := range amended.Conditions {
		if amended.Conditions[i].Name == "sentry-access-denied" {
			amended.Conditions[i].Momentary = true
		}
	}
	p.Manifest = amended

	if p.IsMomentary("sentry-access-denied") {
		t.Error("an amendment silently reverted the operator's override")
	}
}

func TestClaimDemotingIsReadFromTheManifest(t *testing.T) {
	p := sentry()
	if !p.DemotesClaim("sentry-blocked-locally") {
		t.Error("a declared claim-demoting condition was not recognised")
	}
	if p.DemotesClaim("sentry-access-denied") {
		t.Error("an ordinary condition was treated as claim-demoting")
	}
	// Unknown conditions demote nothing: they are refused at the envelope, and
	// a name nobody approved must not be able to switch off our own source.
	if p.DemotesClaim("sentry-not-in-the-manifest") {
		t.Error("an unapproved condition was treated as claim-demoting")
	}
}
