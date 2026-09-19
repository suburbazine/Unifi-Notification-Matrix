package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/web"
)

var amendAt = time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

// amendable is a configuration with one paired peer that already has an
// approved manifest, which is the state an amendment starts from.
func amendable() *config.Config {
	return &config.Config{Links: []config.Link{
		{Slug: "sentry", LinkID: "lnk_sentry", Key: secret.Secret("k"),
			Capability: "access",
			// SPARE CAPACITY ON PURPOSE. A slice that is exactly full makes
			// every append allocate, which hides an aliased write behind the
			// allocator -- so the bug would be invisible here and intermittent
			// in production, where a manifest grown by earlier amendments has
			// room left in it.
			Conditions: append(make([]config.LinkCondition, 0, 8), config.LinkCondition{
				Name: "sentry-door-forced", Meaning: "a door was forced",
				Severity: incident.SeverityCritical,
			}),
			Overrides: map[string]config.LinkOverride{
				"sentry-door-forced": {Momentary: boolPtr(true)},
			}},
		{Slug: "other", LinkID: "lnk_other", Key: secret.Secret("k")},
	}}
}

func boolPtr(b bool) *bool { return &b }

type amendHarness struct {
	d     linkDeps
	cur   *config.Config
	saved *config.Config
	log   *capturingLog
	saves int
	err   error
}

func newAmendHarness(t *testing.T) *amendHarness {
	t.Helper()
	h := &amendHarness{cur: amendable(), log: &capturingLog{}}
	h.d = linkDeps{
		cfg: func() *config.Config { return h.cur },
		saveCfg: func(c *config.Config) error {
			h.saves++
			if h.err != nil {
				return h.err
			}
			h.saved = c
			h.cur = c
			return nil
		},
		state:    newLinkState(nil),
		auditLog: h.log,
	}
	return h
}

// propose puts a condition in the state a peer's refused event would.
func (h *amendHarness) propose(slug, cond string, sev incident.Severity) {
	h.d.state.proposals.Note(slug, cond, sev, "the peer's own words", amendAt)
}

func (h *amendHarness) conditions(slug string) []config.LinkCondition {
	for _, l := range h.cur.Links {
		if l.Slug == slug {
			return l.Conditions
		}
	}
	return nil
}

// THE WHOLE POINT: a peer's new condition becomes approved vocabulary without
// anybody opening the configuration file.
func TestAProposedConditionBecomesPartOfTheApprovedManifest(t *testing.T) {
	h := newAmendHarness(t)
	h.propose("sentry", "sentry-door-missing", incident.SeverityHigh)

	err := h.d.approveCondition("sentry", web.ApprovedCondition{
		Condition: "sentry-door-missing",
		Meaning:   "a door the controller can no longer see",
		Severity:  "high",
		Momentary: false,
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	got := h.conditions("sentry")
	if len(got) != 2 {
		t.Fatalf("conditions = %+v", got)
	}
	added := got[1]
	if added.Name != "sentry-door-missing" || added.Severity != incident.SeverityHigh {
		t.Errorf("added = %+v", added)
	}
	if added.Meaning != "a door the controller can no longer see" {
		t.Errorf("meaning = %q", added.Meaning)
	}
	// And the question is no longer being asked.
	if h.d.state.proposals.Has("sentry", "sentry-door-missing") {
		t.Error("still listed as waiting for a decision after being approved")
	}
}

// ONLY WHAT THE PEER ACTUALLY ASKED FOR.
//
// The gate that keeps this from becoming a general "write the config with one
// POST": a session may approve a peer's request, not compose one for it.
func TestApprovingSomethingNeverProposedWritesNothing(t *testing.T) {
	h := newAmendHarness(t)
	h.propose("sentry", "sentry-door-missing", incident.SeverityHigh)

	for _, cond := range []string{"sentry-invented", "sentry-door-forced", ""} {
		err := h.d.approveCondition("sentry", web.ApprovedCondition{
			Condition: cond, Meaning: "whatever I like", Severity: "critical",
		})
		if !errors.Is(err, web.ErrNotProposed) {
			t.Errorf("%q gave %v, want ErrNotProposed", cond, err)
		}
	}
	if h.saves != 0 {
		t.Errorf("the configuration was saved %d times for conditions nobody "+
			"asked for", h.saves)
	}
}

// A peer cannot be granted another peer's vocabulary: the slug is what
// attributes a proposal, and matching on the condition alone would let one
// product's request widen a different product's manifest.
func TestOnePeersProposalCannotBeApprovedForAnother(t *testing.T) {
	h := newAmendHarness(t)
	h.propose("sentry", "sentry-door-missing", incident.SeverityHigh)

	err := h.d.approveCondition("other", web.ApprovedCondition{
		Condition: "sentry-door-missing", Meaning: "m", Severity: "high",
	})
	if !errors.Is(err, web.ErrNotProposed) {
		t.Errorf("err = %v, want ErrNotProposed", err)
	}
}

// THE SAME VALIDATOR PAIRING RUNS.
//
// An amendment that could produce a manifest pairing would have refused is an
// amendment that has found a way round the review.
func TestAnAmendmentMustSatisfyEverythingPairingWouldHave(t *testing.T) {
	h := newAmendHarness(t)
	// A name without the peer's prefix never reaches the list in the first
	// place, so the case to prove here is the one that CAN be proposed and
	// must still be refused on its way in.
	h.propose("sentry", "sentry-x", incident.SeverityHigh)

	for _, c := range []web.ApprovedCondition{
		{Condition: "sentry-x", Meaning: "m", Severity: "urgent"},
		{Condition: "sentry-x", Meaning: "m", Severity: ""},
		{Condition: "sentry-x", Meaning: "", Severity: "high"},
	} {
		err := h.d.approveCondition("sentry", c)
		if err == nil {
			t.Errorf("%+v was accepted", c)
		}
		if !errors.Is(err, config.ErrInvalid) {
			t.Errorf("%+v gave %v; an operator mistake must be reportable as "+
				"one rather than as an internal failure", c, err)
		}
	}

	// A BAD SEVERITY HAS TO SAY WHAT A GOOD ONE LOOKS LIKE. The manifest
	// validator refuses it too, but only names the value it disliked -- and
	// "sentry-x proposes urgent" leaves somebody guessing at the five words
	// that would have worked.
	err := h.d.approveCondition("sentry", web.ApprovedCondition{
		Condition: "sentry-x", Meaning: "m", Severity: "urgent",
	})
	if err == nil || !strings.Contains(err.Error(), "critical") {
		t.Errorf("a refused severity did not list the ones that work: %v", err)
	}
	if h.saves != 0 {
		t.Errorf("saved %d times despite refusing every amendment", h.saves)
	}
}

// THE OPERATOR'S OVERRIDES SURVIVE.
//
// They are decisions about conditions rather than about the manifest, and a
// peer shipping a new condition is not a reason to undo one.
func TestAnAmendmentLeavesTheOperatorsOverridesAlone(t *testing.T) {
	h := newAmendHarness(t)
	h.propose("sentry", "sentry-new", incident.SeverityLow)

	if err := h.d.approveCondition("sentry", web.ApprovedCondition{
		Condition: "sentry-new", Meaning: "m", Severity: "low",
	}); err != nil {
		t.Fatal(err)
	}
	for _, l := range h.cur.Links {
		if l.Slug != "sentry" {
			continue
		}
		o, ok := l.Overrides["sentry-door-forced"]
		if !ok || o.Momentary == nil || !*o.Momentary {
			t.Errorf("the override was lost: %+v", l.Overrides)
		}
	}
}

// AND EVERY OTHER PEER IS LEFT ALONE.
func TestAnAmendmentTouchesOnlyOnePeer(t *testing.T) {
	h := newAmendHarness(t)
	h.propose("sentry", "sentry-new", incident.SeverityLow)
	before := len(h.conditions("other"))

	if err := h.d.approveCondition("sentry", web.ApprovedCondition{
		Condition: "sentry-new", Meaning: "m", Severity: "low",
	}); err != nil {
		t.Fatal(err)
	}
	if got := len(h.conditions("other")); got != before {
		t.Errorf("the other peer's manifest went from %d to %d", before, got)
	}
	for _, l := range h.cur.Links {
		if l.Slug == "other" && l.LinkID != "lnk_other" {
			t.Error("the other peer's credential was rewritten")
		}
	}
}

// A REFUSED SAVE KEEPS THE QUESTION.
//
// Forgetting the proposal first would leave the peer going on being refused
// and the page having stopped mentioning it -- the operator would be left with
// no sign that anything was ever wrong.
func TestASaveThatFailsLeavesTheProposalStanding(t *testing.T) {
	h := newAmendHarness(t)
	h.propose("sentry", "sentry-new", incident.SeverityLow)
	h.err = errors.New("the disk is full")

	err := h.d.approveCondition("sentry", web.ApprovedCondition{
		Condition: "sentry-new", Meaning: "m", Severity: "low",
	})
	if err == nil {
		t.Fatal("a failed save was reported as a success")
	}
	if !h.d.state.proposals.Has("sentry", "sentry-new") {
		t.Error("the proposal was dropped by an amendment that did not happen")
	}
	if got := len(h.conditions("sentry")); got != 1 {
		t.Errorf("the running configuration gained a condition from a save "+
			"that failed: %d conditions", got)
	}
}

// TWO TABS, ONE APPROVAL.
//
// The second press arrives after the first has already written it. Adding the
// condition twice would produce a manifest the validator refuses, so this has
// to end as a no-op rather than as an error or a duplicate.
func TestApprovingTheSameConditionTwiceIsHarmless(t *testing.T) {
	h := newAmendHarness(t)
	h.propose("sentry", "sentry-new", incident.SeverityLow)
	c := web.ApprovedCondition{Condition: "sentry-new", Meaning: "m", Severity: "low"}

	if err := h.d.approveCondition("sentry", c); err != nil {
		t.Fatal(err)
	}
	// The second press: the proposal is gone, so it is refused as not
	// proposed rather than duplicating the entry.
	if err := h.d.approveCondition("sentry", c); !errors.Is(err, web.ErrNotProposed) {
		t.Errorf("second approval gave %v", err)
	}
	if got := len(h.conditions("sentry")); got != 2 {
		t.Errorf("conditions = %d, want 2", got)
	}

	// And the shape where the proposal is somehow still listed -- a peer that
	// re-sent between the two presses -- must also not duplicate it.
	h.propose("sentry", "sentry-new", incident.SeverityLow)
	if err := h.d.approveCondition("sentry", c); err != nil {
		t.Errorf("a re-proposed but already-approved condition gave %v", err)
	}
	if got := len(h.conditions("sentry")); got != 2 {
		t.Errorf("conditions = %d after a re-approval, want 2", got)
	}
	if h.d.state.proposals.Has("sentry", "sentry-new") {
		t.Error("still asking about something already in the manifest")
	}
}

func TestApprovingForAPeerThatIsNotPairedIsRefused(t *testing.T) {
	h := newAmendHarness(t)
	h.propose("ghost", "ghost-x", incident.SeverityLow)

	err := h.d.approveCondition("ghost", web.ApprovedCondition{
		Condition: "ghost-x", Meaning: "m", Severity: "low",
	})
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("err = %v, want a reportable one", err)
	}
	if h.saves != 0 {
		t.Errorf("saved %d times for a peer that is not paired", h.saves)
	}
}

// THE AMENDMENT IS AUDITED, with what changed and not with anything else.
func TestAnAmendmentIsRecorded(t *testing.T) {
	h := newAmendHarness(t)
	h.propose("sentry", "sentry-new", incident.SeverityLow)

	if err := h.d.approveCondition("sentry", web.ApprovedCondition{
		Condition: "sentry-new", Meaning: "m", Severity: "low",
	}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range h.log.entries {
		if e.Fields["condition"] == "sentry-new" && e.Fields["product"] == "sentry" {
			found = true
		}
	}
	if !found {
		t.Errorf("not recorded: %+v", h.log.entries)
	}
}

// A FAILED SAVE MUST NOT HAVE CHANGED THE RUNNING CONFIGURATION.
//
// cfg() hands out a pointer to the configuration this process is USING, so an
// amendment written through it and then not persisted would leave the daemon
// honouring a condition the file does not contain -- and the operator was told
// it failed.
func TestARefusedSaveDoesNotMutateTheLiveConfig(t *testing.T) {
	h := newAmendHarness(t)
	live := h.cur
	h.propose("sentry", "sentry-new", incident.SeverityLow)
	h.err = errors.New("refused")

	_ = h.d.approveCondition("sentry", web.ApprovedCondition{
		Condition: "sentry-new", Meaning: "m", Severity: "low",
	})

	for _, l := range live.Links {
		if l.Slug == "sentry" && len(l.Conditions) != 1 {
			t.Errorf("the live configuration now has %d conditions", len(l.Conditions))
		}
	}
}

// AN ALIASED APPEND WRITES INTO THE CONFIGURATION THIS PROCESS IS USING.
//
// `entry.Conditions = append(entry.Conditions, ...)` looks local and is not:
// while the slice has spare capacity, append writes into the SAME backing
// array the live config points at, before the save has been attempted. It is
// invisible whenever the slice happens to be exactly full, which is why a
// manifest with room in it is what this test builds.
func TestAmendingDoesNotWriteThroughTheLiveConfigsBackingArray(t *testing.T) {
	h := newAmendHarness(t)
	live := h.cur
	h.propose("sentry", "sentry-new", incident.SeverityLow)
	h.err = errors.New("refused")

	_ = h.d.approveCondition("sentry", web.ApprovedCondition{
		Condition: "sentry-new", Meaning: "m", Severity: "low",
	})

	for _, l := range live.Links {
		if l.Slug != "sentry" {
			continue
		}
		// Past the length, into the capacity the amendment should not have
		// touched.
		full := l.Conditions[:cap(l.Conditions)]
		for i, c := range full {
			if i < len(l.Conditions) {
				continue
			}
			if c.Name != "" {
				t.Errorf("the amendment wrote %q into the live config's "+
					"backing array at index %d, before the save was attempted",
					c.Name, i)
			}
		}
	}
}
