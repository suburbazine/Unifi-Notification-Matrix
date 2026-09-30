package main

import (
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

func rewardsPeer(overrides map[string]link.Override) link.Peer {
	return link.Peer{
		Slug: "lsrewards", LinkID: "lnk_TEST",
		Manifest: link.Manifest{Conditions: []link.ConditionSpec{
			{Name: "lsrewards-redemption-without-reward", Meaning: "a free item with no reward",
				Severity: incident.SeverityHigh, Momentary: true},
			{Name: "lsrewards-backup-failing", Meaning: "backups are failing",
				Severity: incident.SeverityMedium, Momentary: false},
			{Name: "lsrewards-Decline-Spike", Meaning: "declines at the register",
				Severity: incident.SeverityMedium, Momentary: true},
		}},
		Overrides: overrides,
	}
}

// A PEER'S MOMENTARY PROPOSAL IS WHAT DECIDES.
//
// It was read by nothing. The scheduler classified with this product's own
// catalogue alone, so every peer condition behaved as state, and a one-shot
// event raised and cleared before the first tick was never delivered -- a
// free item handed out at the till, reported, accepted, and told to nobody.
// Sentry's link test fell through the same hole.
func TestAPeersMomentaryConditionIsTreatedAsMomentary(t *testing.T) {
	peers := []link.Peer{rewardsPeer(nil)}

	if !momentaryFor(peers, "lsrewards-redemption-without-reward") {
		t.Error("a condition the peer proposed as momentary is treated as state, so a " +
			"one-shot event cleared before the first scheduler tick is never delivered")
	}
	if momentaryFor(peers, "lsrewards-backup-failing") {
		t.Error("a condition the peer proposed as state is treated as momentary")
	}
	if momentaryFor(peers, "lsrewards-never-declared") {
		t.Error("a condition in no manifest was classified momentary")
	}

	// The native catalogue still answers for this product's own conditions.
	var native string
	for _, c := range event.Catalogue() {
		if event.IsMomentary(c.Name) {
			native = c.Name
			break
		}
	}
	if native == "" {
		t.Fatal("the native catalogue has no momentary condition to check against")
	}
	if !momentaryFor(peers, native) {
		t.Errorf("wiring in the peers lost this product's own momentary %q", native)
	}
}

// THE OPERATOR'S OVERRIDE BEATS THE PEER'S PROPOSAL, both ways. The flag
// decides whether a cleared incident is still delivered, and getting it wrong
// on a high-volume condition floods somebody; the peer proposes and the
// operator, who has seen it fire, decides.
func TestTheOperatorsOverrideBeatsThePeersProposal(t *testing.T) {
	no, yes := false, true
	peers := []link.Peer{rewardsPeer(map[string]link.Override{
		"lsrewards-redemption-without-reward": {Momentary: &no},
		"lsrewards-backup-failing":            {Momentary: &yes},
	})}

	if momentaryFor(peers, "lsrewards-redemption-without-reward") {
		t.Error("the operator overrode momentary to false and the peer's proposal won")
	}
	if !momentaryFor(peers, "lsrewards-backup-failing") {
		t.Error("the operator overrode momentary to true and the peer's proposal won")
	}
}

// The scheduler asks with the condition as a dedup key has it: lower-cased,
// "/" replaced. A manifest name with a capital after the slug must still be
// found, or its flag is silently ignored for exactly those conditions.
func TestAConditionIsFoundAsTheSchedulerSpellsIt(t *testing.T) {
	peers := []link.Peer{rewardsPeer(nil)}
	key := incident.Key("lsrewards", "wv01-register-1", "lsrewards-Decline-Spike")
	inc := incident.Incident{DedupKey: key}
	if !momentaryFor(peers, inc.Condition()) {
		t.Errorf("the scheduler asks about %q and the manifest says %q; the "+
			"classification was lost to the key's lower-casing", inc.Condition(),
			"lsrewards-Decline-Spike")
	}
}

// WHICH EVENTS KEEP EVERY ARRIVAL. A paired peer's momentary conditions -- a
// void, a free item -- and nothing native: motion arrives in bursts, and a new
// incident for every burst after an acknowledgement would page somebody all
// afternoon.
func TestOnlyAPeersMomentaryConditionsArePerOccurrence(t *testing.T) {
	peers := []link.Peer{rewardsPeer(nil)}
	ev := func(source, cond string) event.Event {
		return event.Event{Source: source, Condition: cond}
	}

	if !occurrenceFor(peers, ev("lsrewards", "lsrewards-redemption-without-reward")) {
		t.Error("a peer's momentary condition is not per-occurrence, so a second free " +
			"item at the same till is folded away and recorded nowhere")
	}
	if occurrenceFor(peers, ev("lsrewards", "lsrewards-backup-failing")) {
		t.Error("a peer's STATE condition was made per-occurrence: every repeat report " +
			"of a failing backup would be counted as a new fact")
	}

	var native string
	for _, c := range event.Catalogue() {
		if event.IsMomentary(c.Name) {
			native = c.Name
			break
		}
	}
	if occurrenceFor(peers, ev("protect", native)) {
		t.Errorf("native momentary %q became per-occurrence; motion bursts after an "+
			"acknowledgement would each open a new incident", native)
	}

	// Another peer sending a condition that happens to share the name is not
	// this peer's: the manifest that decides is the sender's own.
	if occurrenceFor(peers, ev("impostor", "lsrewards-redemption-without-reward")) {
		t.Error("a condition was classified by a manifest that does not belong to its sender")
	}

	// And the operator's override moves it, with the delivery flag, as one decision.
	no := false
	over := []link.Peer{rewardsPeer(map[string]link.Override{
		"lsrewards-redemption-without-reward": {Momentary: &no}})}
	if occurrenceFor(over, ev("lsrewards", "lsrewards-redemption-without-reward")) {
		t.Error("the operator overrode momentary to false and the condition is still per-occurrence")
	}
}
