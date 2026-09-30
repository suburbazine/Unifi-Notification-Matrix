package main

import (
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

// A MOMENTARY CONDITION CAN FOLD AFTER REVIEW.
//
// Whether a quickly-cleared arrival is delivered at all, and whether one
// arriving after an acknowledgement opens a new incident, are two decisions.
// They were one flag, so nobody could have the first without the second. The
// operator decided exactly that split for Sentry: a credential sweep after
// review is news, a single access denial after review is not.
func TestAMomentaryConditionCanFoldAfterReview(t *testing.T) {
	no, yes := false, true
	sentry := link.Peer{Slug: "sentry", LinkID: "lnk_S", Manifest: link.Manifest{
		Capability: "access",
		Conditions: []link.ConditionSpec{
			{Name: "sentry-access-denied", Meaning: "a door refused somebody",
				Severity: incident.SeverityHigh, Momentary: true, PerOccurrence: &no},
			{Name: "sentry-credential-sweep", Meaning: "one identity at many doors",
				Severity: incident.SeverityCritical, Momentary: true},
		}}}
	ev := func(c string) event.Event { return event.Event{Source: "sentry", Condition: c} }

	if occurrenceFor([]link.Peer{sentry}, ev("sentry-access-denied")) {
		t.Error("access-denied was declared per_occurrence false and still opens a new " +
			"incident after every acknowledgement")
	}
	if !occurrenceFor([]link.Peer{sentry}, ev("sentry-credential-sweep")) {
		t.Error("credential-sweep declared nothing and does not default to per-occurrence")
	}
	// Still momentary for delivery: the two decisions are separate.
	if !momentaryFor([]link.Peer{sentry}, "sentry-access-denied") {
		t.Error("opting out of per-occurrence also turned off momentary delivery; they " +
			"are separate decisions")
	}

	// The operator's override beats the declaration, both ways.
	sentry.Overrides = map[string]link.Override{
		"sentry-access-denied":    {PerOccurrence: &yes},
		"sentry-credential-sweep": {PerOccurrence: &no},
	}
	if !occurrenceFor([]link.Peer{sentry}, ev("sentry-access-denied")) ||
		occurrenceFor([]link.Peer{sentry}, ev("sentry-credential-sweep")) {
		t.Error("the operator's per_occurrence override did not beat the peer's declaration")
	}
}

// THE FLAG SURVIVES THE TRIP from a pairing into the configuration file and
// back out into the decision.
//
// Five places copy a condition field by field between the link and config
// types, and a new field is dropped silently by whichever one is forgotten --
// which is how the actor field once vanished between the envelope and the
// incident, validated past and read by nothing.
func TestPerOccurrenceSurvivesPairingIntoTheConfiguration(t *testing.T) {
	no := false
	cfg := &config.Config{}
	d := linkDeps{
		cfg:      func() *config.Config { return cfg },
		saveCfg:  func(c *config.Config) error { cfg = c; return nil },
		state:    newLinkState(nil),
		auditLog: &capturingLog{},
	}
	peer := link.Peer{Slug: "sentry", LinkID: "lnk_S", Manifest: link.Manifest{
		Capability: "access",
		Conditions: []link.ConditionSpec{{Name: "sentry-access-denied",
			Meaning: "a door refused somebody", Severity: incident.SeverityHigh,
			Momentary: true, PerOccurrence: &no}},
	}}
	if err := d.storePeer(peer, make([]byte, link.KeyBytes)); err != nil {
		t.Fatal(err)
	}

	peers, _ := config.BuildLinks(cfg)
	if len(peers) != 1 {
		t.Fatalf("paired peers after storing = %d", len(peers))
	}
	if peers[0].IsPerOccurrence("sentry-access-denied") {
		t.Error("per_occurrence false was declared at pairing and lost on the way into " +
			"the configuration or back out of it")
	}
	if got := manifestConditions(cfg.Links[0].Conditions); got[0].PerOccurrence == nil || *got[0].PerOccurrence {
		t.Error("manifestConditions drops per_occurrence, so the manifest validator and " +
			"any amendment see a different condition from the one approved")
	}

	// AND THE OPERATOR'S OVERRIDE, written into the file. At a site where the
	// peer paired before it declared anything, this is the ONLY way the
	// decision can be applied -- so it is the path that most needs to work.
	yes := true
	cfg.Links[0].Overrides = map[string]config.LinkOverride{
		"sentry-access-denied": {PerOccurrence: &yes},
	}
	peers, _ = config.BuildLinks(cfg)
	if !peers[0].IsPerOccurrence("sentry-access-denied") {
		t.Error("a per_occurrence override written in config.yaml did not reach the " +
			"decision; an operator at an already-paired site has no way to apply it")
	}
}
