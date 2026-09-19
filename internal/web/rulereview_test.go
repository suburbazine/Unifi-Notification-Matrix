package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/reconcile"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/rule"
)

// reAdopted sets up the shape this whole feature exists for: a rule written
// with a device id, hardware re-adopted so the id changed, and one MAC
// connecting the two rows of the permanent record.
func reAdopted(h *harness) {
	now := time.Now()
	h.mu.Lock()
	h.cfg.Rules = rule.Set{
		{Name: "gate is critical", Entities: []string{"old-gate-id"},
			Severity: "critical"},
	}
	h.observed = []reconcile.Entity{
		{Source: "access", ID: "old-gate-id", Name: "Front Gate", MAC: "aa:bb:cc:dd:ee:ff",
			FirstSeen: now.Add(-200 * 24 * time.Hour), LastSeen: now.Add(-6 * 24 * time.Hour)},
		{Source: "access", ID: "new-gate-id", Name: "Front Gate", MAC: "aa:bb:cc:dd:ee:ff",
			FirstSeen: now.Add(-6 * 24 * time.Hour), LastSeen: now.Add(-time.Minute)},
	}
	h.mu.Unlock()
}

func review(t *testing.T, h *harness) RuleReview {
	t.Helper()
	resp, body := h.do("GET", "/api/rules/review", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("review: %d %s", resp.StatusCode, body)
	}
	var out RuleReview
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	return out
}

// THE REVIEW IS CONFIGURATION DETAIL. It quotes the operator's rules and names
// the site's doors, so it sits behind a session like the settings it reports
// on.
func TestTheRuleReviewIsGated(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	reAdopted(h)

	resp, _ := h.do("GET", "/api/rules/review", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("signed out GET = %d, want 401", resp.StatusCode)
	}
	resp, _ = h.do("POST", "/api/rules/repoint", map[string]any{
		"rule_index": 0, "rule": "gate is critical",
		"from": "old-gate-id", "to": "new-gate-id",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("signed out POST = %d, want 401", resp.StatusCode)
	}
}

// The whole feature, end to end: find the stale reference, offer the device
// that carries its MAC, and write the rule when the operator accepts.
func TestAReAdoptedDeviceIsFoundAndTheRuleCanBeRepointedAtIt(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	reAdopted(h)

	rev := review(t, h)
	if !rev.Available {
		t.Fatalf("review unavailable: %s", rev.Detail)
	}
	if len(rev.Findings) != 1 {
		t.Fatalf("findings = %+v", rev.Findings)
	}
	f := rev.Findings[0]
	if f.Status != string(reconcile.StatusSuperseded) {
		t.Errorf("status = %q", f.Status)
	}
	if len(f.Successors) != 1 || f.Successors[0].ID != "new-gate-id" {
		t.Fatalf("successors = %+v", f.Successors)
	}
	if f.Successors[0].On != "mac" {
		t.Errorf("on = %q, want mac", f.Successors[0].On)
	}

	resp, body := h.do("POST", "/api/rules/repoint", map[string]any{
		"rule_index": f.RuleIndex, "rule": f.Rule,
		"from": f.Reference, "to": "new-gate-id",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("repoint: %d %s", resp.StatusCode, body)
	}

	h.mu.Lock()
	got := h.cfg.Rules[0].Entities
	h.mu.Unlock()
	if len(got) != 1 || got[0] != "new-gate-id" {
		t.Fatalf("rule entities = %v, want the new id", got)
	}

	// And the review is quiet afterwards, because the reference now resolves
	// to something that reported a minute ago.
	if rev := review(t, h); len(rev.Findings) != 0 {
		t.Errorf("still reporting after the repoint: %+v", rev.Findings)
	}
}

// A REPOINT IS AUDITED, with what it changed and not with anything else.
func TestARepointIsRecorded(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	reAdopted(h)

	h.do("POST", "/api/rules/repoint", map[string]any{
		"rule_index": 0, "rule": "gate is critical",
		"from": "old-gate-id", "to": "new-gate-id",
	})
	if !h.log.has(audit.KindConfigChanged, "repointed a rule") {
		t.Errorf("not recorded; the audit summaries were %v", h.log.summaries())
	}
}

// ONLY A SUGGESTION THIS REVIEW IS MAKING MAY BE APPLIED.
//
// Without this, the endpoint is a second way to edit a rule -- one POST, any
// value, and none of the validation the settings form does. The narrowness is
// the security property, not a convenience.
func TestAnIDTheReviewIsNotOfferingIsRefused(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	reAdopted(h)

	for _, to := range []string{"something-else", "*", "new-gate-id-typo"} {
		resp, _ := h.do("POST", "/api/rules/repoint", map[string]any{
			"rule_index": 0, "rule": "gate is critical",
			"from": "old-gate-id", "to": to,
		})
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("to=%q gave %d, want 409", to, resp.StatusCode)
		}
	}
	h.mu.Lock()
	got := h.cfg.Rules[0].Entities[0]
	h.mu.Unlock()
	if got != "old-gate-id" {
		t.Errorf("the rule was changed anyway: %q", got)
	}
}

// AN EDIT MADE SOMEWHERE ELSE WINS.
//
// The operator who changed the rule in another tab meant that change.
// Applying a suggestion computed against the text it used to have would
// overwrite a deliberate edit with a guess.
func TestARuleEditedSinceThePageWasDrawnIsNotOverwritten(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	reAdopted(h)

	h.mu.Lock()
	h.cfg.Rules[0].Name = "renamed by somebody else"
	h.mu.Unlock()

	resp, _ := h.do("POST", "/api/rules/repoint", map[string]any{
		"rule_index": 0, "rule": "gate is critical",
		"from": "old-gate-id", "to": "new-gate-id",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

// A FAILED READ IS REPORTED AS A FAILED READ.
//
// Reported as zero findings it would be the most reassuring answer this
// endpoint can give, produced by the one case in which it knows nothing at
// all -- which is the failure mode this whole package was written to avoid.
func TestAFailedRecordReadSaysSoRatherThanReportingNothingWrong(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	reAdopted(h)
	h.mu.Lock()
	h.observedErr = errors.New("database is locked")
	h.mu.Unlock()

	rev := review(t, h)
	if rev.Available {
		t.Error("a failed read reported itself as a completed check")
	}
	if rev.Detail == "" {
		t.Error("no explanation of why the rules were not checked")
	}
	if len(rev.Findings) != 0 {
		t.Errorf("findings from a failed read: %+v", rev.Findings)
	}
	// The real error goes where somebody authorised can read it, and not into
	// the response.
	if !h.log.has(audit.KindService, "entity record") {
		t.Errorf("the read failure was not recorded: %v", h.log.summaries())
	}
	if strings.Contains(rev.Detail, "database is locked") {
		t.Error("the internal error reached the response body")
	}
}

// A repoint cannot be applied while the record cannot be read either, because
// nothing is being offered when nothing was checked.
func TestNoRepointIsAppliedWhileTheRecordCannotBeRead(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	reAdopted(h)
	h.mu.Lock()
	h.observedErr = errors.New("database is locked")
	h.mu.Unlock()

	resp, _ := h.do("POST", "/api/rules/repoint", map[string]any{
		"rule_index": 0, "rule": "gate is critical",
		"from": "old-gate-id", "to": "new-gate-id",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

// A BUILD WITH NO RECORD SAYS THE RULES WERE NOT CHECKED.
//
// "Nothing is wrong" and "nothing was checked" look identical on a screen and
// are opposite facts.
func TestABuildWithNoRecordSaysTheRulesWereNotChecked(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	h.srv.deps.ObservedEntities = nil

	rev := review(t, h)
	if rev.Available {
		t.Error("claimed to have checked the rules with nothing to check against")
	}
	if rev.Detail == "" {
		t.Error("said nothing about why")
	}
}

// The denominator. A review against four rows is a different claim from a
// review against four hundred, and a short list reads as reassurance without
// it.
func TestTheReviewSaysHowMuchItCheckedAgainst(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	reAdopted(h)

	if got := review(t, h).Known; got != 2 {
		t.Errorf("known = %d, want 2", got)
	}
}

// THE CHECK AND THE WRITE READ THE CONFIGURATION TWICE, and something may
// change in between.
//
// The offer is computed against one read and applied against another. A rule
// renamed, reordered or deleted in that gap would otherwise have a suggestion
// meant for a different rule written into it -- which is this feature breaking
// a rule rather than mending one. The hook changes the configuration between
// the two reads of a single request, which is the only way to make the guard
// fail.
func TestARuleThatChangesBetweenTheCheckAndTheWriteIsNotWritten(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	reAdopted(h)

	reads := 0
	h.mu.Lock()
	h.onConfigRead = func() { // called with h.mu held
		reads++
		if reads == 2 {
			h.cfg.Rules[0].Name = "somebody renamed it a microsecond ago"
		}
	}
	h.mu.Unlock()

	resp, _ := h.do("POST", "/api/rules/repoint", map[string]any{
		"rule_index": 0, "rule": "gate is critical",
		"from": "old-gate-id", "to": "new-gate-id",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	h.mu.Lock()
	got := h.cfg.Rules[0].Entities[0]
	h.mu.Unlock()
	if got != "old-gate-id" {
		t.Errorf("wrote %q into a rule that had changed underneath it", got)
	}
}

// A SUGGESTION BELONGS TO ONE REFERENCE, not to the rule that contains it.
//
// A rule may name several entities, and each gets its own finding. Applying
// the successor offered for one of them to a different one would repoint the
// wrong door -- with a perfectly valid-looking id, so nothing downstream would
// ever notice.
func TestASuggestionCannotBeAppliedToADifferentReferenceInTheSameRule(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	now := time.Now()
	h.mu.Lock()
	h.cfg.Rules = rule.Set{{Name: "two doors", Entities: []string{"old-a", "old-b"}}}
	h.observed = []reconcile.Entity{
		{Source: "access", ID: "old-a", Name: "Door A", MAC: "aa:aa", LastSeen: now.Add(-9 * 24 * time.Hour)},
		{Source: "access", ID: "new-a", Name: "Door A", MAC: "aa:aa", LastSeen: now.Add(-time.Minute)},
		{Source: "access", ID: "old-b", Name: "Door B", MAC: "bb:bb", LastSeen: now.Add(-9 * 24 * time.Hour)},
		{Source: "access", ID: "new-b", Name: "Door B", MAC: "bb:bb", LastSeen: now.Add(-time.Minute)},
	}
	h.mu.Unlock()

	if got := len(review(t, h).Findings); got != 2 {
		t.Fatalf("findings = %d, want one per reference", got)
	}

	// new-b is a real, currently-offered successor -- for old-b, not for old-a.
	resp, _ := h.do("POST", "/api/rules/repoint", map[string]any{
		"rule_index": 0, "rule": "two doors", "from": "old-a", "to": "new-b",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
	h.mu.Lock()
	got := h.cfg.Rules[0].Entities
	h.mu.Unlock()
	if got[0] != "old-a" || got[1] != "old-b" {
		t.Errorf("entities = %v; a suggestion meant for one door was written "+
			"into another", got)
	}
}

// TWO RULES MAY SHARE A NAME IN A RUNNING CONFIGURATION.
//
// Set.Validate refuses duplicate names, but a save only refuses problems it
// INTRODUCES -- so a configuration that already had two rules called the same
// thing keeps running with them. Matching the offer by name alone would then
// write the suggestion into whichever one came first, which is a coin toss
// between mending a rule and breaking one.
func TestTwoRulesSharingANameAreToldApartByPosition(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	now := time.Now()
	h.mu.Lock()
	h.cfg.Rules = rule.Set{
		{Name: "same name", Entities: []string{"old-a"}},
		{Name: "same name", Entities: []string{"old-b"}},
	}
	h.observed = []reconcile.Entity{
		{Source: "access", ID: "old-a", Name: "A", MAC: "aa", LastSeen: now.Add(-9 * 24 * time.Hour)},
		{Source: "access", ID: "new-a", Name: "A", MAC: "aa", LastSeen: now.Add(-time.Minute)},
		{Source: "access", ID: "old-b", Name: "B", MAC: "bb", LastSeen: now.Add(-9 * 24 * time.Hour)},
		{Source: "access", ID: "new-b", Name: "B", MAC: "bb", LastSeen: now.Add(-time.Minute)},
	}
	h.mu.Unlock()

	// The offer for rule 1 ("old-b" -> "new-b") aimed at rule 0.
	resp, _ := h.do("POST", "/api/rules/repoint", map[string]any{
		"rule_index": 0, "rule": "same name", "from": "old-b", "to": "new-b",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}

	// And the right one still applies.
	resp, body := h.do("POST", "/api/rules/repoint", map[string]any{
		"rule_index": 1, "rule": "same name", "from": "old-b", "to": "new-b",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the correct repoint was refused: %d %s", resp.StatusCode, body)
	}
	h.mu.Lock()
	a, b := h.cfg.Rules[0].Entities[0], h.cfg.Rules[1].Entities[0]
	h.mu.Unlock()
	if a != "old-a" || b != "new-b" {
		t.Errorf("rules = %q, %q", a, b)
	}
}

// A SAVE THAT FAILS MUST LEAVE THE RUNNING RULES ALONE.
//
// The daemon hands out a pointer to the configuration it is USING. Editing a
// rule through it and then failing to persist would leave this process running
// the change while the file on disk says otherwise -- and the operator was
// told it did not happen.
func TestARefusedSaveDoesNotChangeTheRunningRules(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	reAdopted(h)

	h.mu.Lock()
	h.saveErr = errors.New("the disk is full")
	before := h.cfg
	h.mu.Unlock()

	resp, _ := h.do("POST", "/api/rules/repoint", map[string]any{
		"rule_index": 0, "rule": "gate is critical",
		"from": "old-gate-id", "to": "new-gate-id",
	})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	if got := before.Rules[0].Entities[0]; got != "old-gate-id" {
		t.Errorf("the running configuration was changed by a save that "+
			"failed: %q", got)
	}
}

// The rule may have been deleted between the page being drawn and the button
// being pressed, and an index past the end of the list is the shape that takes.
func TestARuleThatHasBeenDeletedIsNotWrittenTo(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	reAdopted(h)

	for _, idx := range []int{-1, 1, 99} {
		resp, _ := h.do("POST", "/api/rules/repoint", map[string]any{
			"rule_index": idx, "rule": "gate is critical",
			"from": "old-gate-id", "to": "new-gate-id",
		})
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("rule_index %d gave %d, want 409", idx, resp.StatusCode)
		}
	}
}
