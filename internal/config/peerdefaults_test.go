package config

import (
	"fmt"
	"os"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

func sentryLink(declared *bool, override *bool) Link {
	l := Link{Slug: "sentry", LinkID: "lnk_S", Capability: "access",
		Conditions: []LinkCondition{
			{Name: "sentry-access-denied", Meaning: "a door refused somebody",
				Severity: incident.SeverityHigh, Momentary: true, PerOccurrence: declared},
			{Name: "sentry-credential-sweep", Meaning: "one identity at many doors",
				Severity: incident.SeverityCritical, Momentary: true},
		}}
	if override != nil {
		l.Overrides = map[string]LinkOverride{"sentry-access-denied": {PerOccurrence: override}}
	}
	return l
}

// A SITE PAIRED ON AN OLDER SENTRY GETS THE OPERATOR'S DECISION ON ITS OWN.
//
// The manifest is stored at pairing, so a Sentry that could not yet declare
// per_occurrence left every such site re-alerting on access denials after
// review until somebody re-paired it or edited config.yaml by hand.
func TestAnOldSentryPairingGetsTheDecisionWrittenIn(t *testing.T) {
	c := &Config{Links: []Link{sentryLink(nil, nil)}}

	if !ApplyPeerDefaults(c) {
		t.Fatal("nothing was applied to a Sentry pairing that declares nothing")
	}
	o, ok := c.Links[0].Overrides["sentry-access-denied"]
	if !ok || o.PerOccurrence == nil || *o.PerOccurrence {
		t.Fatalf("override = %+v, want per_occurrence false written into the file", o)
	}
	if _, touched := c.Links[0].Overrides["sentry-credential-sweep"]; touched {
		t.Error("credential-sweep was given an override; the decision was that it re-alerts")
	}
	if ApplyPeerDefaults(c) {
		t.Error("applying twice changed something the second time; every start would rewrite the file")
	}

	// And it takes effect through the same path everything else does.
	peers, _ := BuildLinks(&Config{Links: []Link{withKey(c.Links[0])}})
	if len(peers) != 1 || peers[0].IsPerOccurrence("sentry-access-denied") {
		t.Error("the written default does not reach the decision")
	}
}

// NOTHING ALREADY DECIDED IS TOUCHED: the peer's own declaration (a pairing
// on 1.6.12 or later), or the operator's explicit choice either way.
func TestADefaultNeverOverridesADecision(t *testing.T) {
	yes := true
	for name, l := range map[string]Link{
		"the peer declared it":           sentryLink(&yes, nil),
		"the operator chose true":        sentryLink(nil, &yes),
		"another product with that name": {Slug: "lsprotect", Conditions: sentryLink(nil, nil).Conditions},
	} {
		c := &Config{Links: []Link{l}}
		if ApplyPeerDefaults(c) {
			t.Errorf("%s, and the default was written anyway", name)
		}
	}
}

// withKey gives a link the credential BuildLinks requires.
func withKey(l Link) Link {
	l.Key = "0123456789abcdef0123456789abcdef"
	return l
}

// AND AT START, which is the path an upgraded site actually takes: the file
// was written by an older build, from a pairing on an older Sentry, and the
// daemon opening it must write the decision in.
func TestStartingOnAnOldPairingWritesTheDecisionIntoTheFile(t *testing.T) {
	dir := t.TempDir()
	handWritten := fmt.Sprintf(`version: %d
web:
  listen: 127.0.0.1:8322
  link_listen: 127.0.0.1:8433
links:
  - slug: sentry
    link_id: lnk_S
    link_key: "0123456789abcdef0123456789abcdef"
    capability: access
    conditions:
      - name: sentry-access-denied
        meaning: a door refused somebody
        severity: high
        momentary: true
`, SchemaVersion)
	if err := os.WriteFile(Path(dir), []byte(handWritten), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if o := c.Links[0].Overrides["sentry-access-denied"]; o.PerOccurrence == nil || *o.PerOccurrence {
		t.Fatalf("the daemon started on an old Sentry pairing without applying the decision: %+v", o)
	}

	back, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if o := back.Links[0].Overrides["sentry-access-denied"]; o.PerOccurrence == nil || *o.PerOccurrence {
		t.Error("the decision was applied in memory and never written to config.yaml, " +
			"so nobody reading the file can see why access denials fold")
	}
}
