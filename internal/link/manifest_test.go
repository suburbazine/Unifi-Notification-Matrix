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

	// A capability that names nothing this product runs would suppress nothing
	// and still be shown as SERVING it: coverage on the page, none in fact.
	bogus := Manifest{Capability: "rewards", Conditions: []ConditionSpec{spec("sentry-x")}}
	if err := bogus.Validate("sentry"); !errors.Is(err, ErrCapability) {
		t.Errorf("a capability naming no source this product has was accepted: %v", err)
	}
}

// A PEER THAT STANDS IN FOR NOTHING CAN STILL PAIR.
//
// The capability was required, which meant a product with no counterpart here
// -- a loyalty system, a backup agent -- could not pair at all, or could only
// by inventing a claim to a source that does not exist. Most peers are that
// kind: they add events, they displace nothing.
func TestAPeerWithNoCapabilityPairs(t *testing.T) {
	m := Manifest{Conditions: []ConditionSpec{{
		Name: "lsrewards-redemption-without-reward", Meaning: "A free item was " +
			"given at the till with no reward behind it.",
		Severity: "high", Momentary: true,
	}}}
	if err := m.Validate("lsrewards"); err != nil {
		t.Fatalf("a manifest that claims no capability was refused: %v -- a product "+
			"that stands in for none of this product's sources cannot pair at all", err)
	}

	p := NewPairer("aa:bb")
	p.NewKey = func() (string, []byte, error) { return "lnk_TEST", make([]byte, KeyBytes), nil }
	code, err := p.Offer()
	if err != nil {
		t.Fatal(err)
	}
	res, peer, err := p.Complete(PairRequest{
		Slug: "lsrewards", Fingerprint: "aabb", Nonce: "n1",
		Proof:    PairProof(code, "client", "lsrewards", "aabb", "n1"),
		Manifest: m,
	})
	if err != nil {
		t.Fatalf("pairing a capability-less peer failed: %v", err)
	}
	if res.Capability != "" || peer.Manifest.Capability != "" {
		t.Errorf("a peer that claimed nothing came out holding %q", res.Capability)
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
