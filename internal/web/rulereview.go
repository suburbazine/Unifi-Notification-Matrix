package web

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/reconcile"
)

// The other direction.
//
// Every surface in this product reports on what arrived. This one reports on
// what was CONFIGURED and did not arrive -- the set nothing else can see,
// because a rule that never matches produces no event, no incident, no error
// and no entry anywhere. See internal/reconcile for why that gap is the one
// that let a gate stand open all night somewhere else.
//
// Session-gated, because it names the site's doors and cameras and quotes the
// operator's rules back at them. The public board says what is wrong; this
// says what is configured, and that is configuration detail.

// RuleReview is what the interface shows about rule references.
type RuleReview struct {
	// Available is false when the permanent record could not be read, or this
	// build has no record at all. NOT the same as "no findings", and the page
	// says so: "nothing is wrong" and "nothing was checked" look identical on
	// a screen and are opposite facts.
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`

	// Known is how many things the record holds. The denominator: a review
	// against four rows is a different claim from a review against four
	// hundred, and without it a short findings list reads as reassurance it
	// has not earned.
	Known int `json:"known"`

	Findings []RuleFinding `json:"findings"`
}

// RuleFinding is one rule reference worth an operator's attention.
type RuleFinding struct {
	Rule      string `json:"rule"`
	RuleIndex int    `json:"rule_index"`
	Reference string `json:"reference"`
	Status    string `json:"status"`
	Pattern   bool   `json:"pattern,omitempty"`

	Source      string     `json:"source,omitempty"`
	MatchedID   string     `json:"matched_id,omitempty"`
	MatchedName string     `json:"matched_name,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	QuietDays   int        `json:"quiet_days,omitempty"`

	Successors []RuleSuccessor `json:"successors,omitempty"`
}

// RuleSuccessor is a candidate to point the rule at instead.
type RuleSuccessor struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`

	// On is "mac" or "name". Sent rather than rendered into a sentence here,
	// because the page ranks by it: a MAC match is evidence and a name match
	// is a hint, and the button must not present them as the same offer.
	On string `json:"on"`

	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

// handleRuleReview reconciles the configured rules against the record.
func (s *Server) handleRuleReview(w http.ResponseWriter, r *http.Request) {
	rev, _ := s.ruleReview(r)
	writeJSON(w, http.StatusOK, rev)
}

// ruleReview builds the review and returns the findings alongside it.
//
// Both, because the apply path needs the findings themselves: a replacement is
// only allowed if this same reconciliation offered it, which means the offer
// and the check have to come from one function rather than from two that agree
// today.
func (s *Server) ruleReview(r *http.Request) (RuleReview, []reconcile.Finding) {
	if s.deps.ObservedEntities == nil {
		return RuleReview{Detail: "this build keeps no permanent record of what " +
			"this site has, so there is nothing to check the rules against"}, nil
	}
	known, err := s.deps.ObservedEntities(r.Context())
	if err != nil {
		// NOT a 500, and NOT an empty findings list either.
		//
		// A failed read has to report itself as a failed read. Reported as
		// zero findings it would be the most reassuring answer this endpoint
		// can give, produced by the one case where it knows nothing at all.
		s.record(r, audit.Entry{
			Kind: audit.KindService, Actor: "web",
			Summary: "web: reading the entity record for the rule review failed",
			Fields:  map[string]string{"error": err.Error()},
		})
		return RuleReview{Detail: "the record of what this site has could not be " +
			"read just now, so the rules were not checked against it"}, nil
	}

	cfg := s.deps.Config()
	if cfg == nil {
		return RuleReview{Detail: "the configuration is not readable just now"}, nil
	}
	findings := reconcile.Report(reconcile.Input{
		Rules:      cfg.Rules,
		Known:      known,
		Enumerated: true,
		Now:        s.now(),
	})

	rev := RuleReview{Available: true, Known: len(known), Findings: []RuleFinding{}}
	for _, f := range findings {
		rev.Findings = append(rev.Findings, viewFinding(f, s.now()))
	}
	return rev, findings
}

func viewFinding(f reconcile.Finding, now time.Time) RuleFinding {
	v := RuleFinding{
		Rule:        f.Rule,
		RuleIndex:   f.RuleIndex,
		Reference:   f.Reference,
		Status:      string(f.Status),
		Pattern:     f.Pattern,
		Source:      f.Source,
		MatchedID:   f.MatchedID,
		MatchedName: f.MatchedName,
	}
	if !f.LastSeen.IsZero() {
		t := f.LastSeen
		v.LastSeen = &t
		v.QuietDays = int(now.Sub(t) / (24 * time.Hour))
	}
	for _, sc := range f.Successors {
		e := RuleSuccessor{ID: sc.ID, Name: sc.Name, Kind: sc.Kind, On: sc.On}
		if !sc.FirstSeen.IsZero() {
			t := sc.FirstSeen
			e.FirstSeen = &t
		}
		if !sc.LastSeen.IsZero() {
			t := sc.LastSeen
			e.LastSeen = &t
		}
		v.Successors = append(v.Successors, e)
	}
	return v
}

// repointRequest asks for one rule reference to be replaced.
type repointRequest struct {
	RuleIndex int    `json:"rule_index"`
	Rule      string `json:"rule"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// handleRepointRule replaces one entity reference in one rule.
//
// # Why this is not a small settings save
//
// It is the narrowest write in this interface, and the narrowness is the
// point. The replacement must be one THIS reconciliation is offering, right
// now, for this exact reference -- not merely a plausible id, and not
// something the caller chose. Otherwise this would be a second way to edit
// rules, reachable by one POST, with weaker validation than the form that
// exists for editing rules.
//
// It also refuses when the rule has moved or the reference has changed since
// the page was drawn. An operator who edited the rule in another tab meant
// that edit; silently applying a suggestion computed against the old text
// would overwrite a deliberate change with a guess.
func (s *Server) handleRepointRule(w http.ResponseWriter, r *http.Request) {
	var req repointRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("that request could not be read"))
		return
	}
	req.From = strings.TrimSpace(req.From)
	req.To = strings.TrimSpace(req.To)
	if req.From == "" || req.To == "" {
		writeJSON(w, http.StatusBadRequest,
			errorBody("a replacement needs both what to replace and what to put there"))
		return
	}

	_, findings := s.ruleReview(r)
	if !s.offering(findings, req) {
		// Covers every stale case at once: the record now says the reference
		// is fine, the suggestion has changed, or it was never offered.
		writeJSON(w, http.StatusConflict, errorBody(
			"that suggestion is no longer being offered -- what this site has "+
				"seen has changed since this page was drawn. Reload and look again"))
		return
	}

	cur := s.deps.Config()
	if cur == nil || req.RuleIndex < 0 || req.RuleIndex >= len(cur.Rules) {
		writeJSON(w, http.StatusConflict, errorBody("that rule is no longer there"))
		return
	}
	next := *cur
	// Clone before editing. The daemon hands out a pointer to the
	// configuration it is USING, so writing through it and then failing to
	// persist would leave this process running a change the operator was told
	// did not happen. Shallow is enough: the entity list below is rebuilt
	// rather than written in place.
	next.Rules = slices.Clone(cur.Rules)
	target := &next.Rules[req.RuleIndex]
	if target.Name != req.Rule {
		writeJSON(w, http.StatusConflict, errorBody(
			"the rules have been edited since this page was drawn; reload and look again"))
		return
	}

	replaced := false
	ents := make([]string, len(target.Entities))
	copy(ents, target.Entities)
	for i, e := range ents {
		if strings.TrimSpace(e) == req.From {
			ents[i] = req.To
			replaced = true
			break
		}
	}
	if !replaced {
		writeJSON(w, http.StatusConflict, errorBody(
			"that rule no longer refers to "+req.From))
		return
	}
	target.Entities = ents

	if err := s.deps.SaveConfig(&next); err != nil {
		if errors.Is(err, config.ErrInvalid) {
			writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
			return
		}
		s.fail(w, r, "saving the repointed rule", err)
		return
	}

	s.record(r, audit.Entry{
		Kind:    audit.KindConfigChanged,
		Summary: "repointed a rule at a device that had been re-adopted",
		Fields: map[string]string{
			"rule": req.Rule, "from": req.From, "to": req.To,
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rule": req.Rule})
}

// offering reports whether this review is currently proposing this
// replacement for this reference.
//
// Deliberately NOT also matched on the rule. A successor is a fact about the
// reference -- reconcile.Report derives it from the record alone -- so the
// same reference in two rules is offered the same replacement, and comparing
// the rule here would be a check that can never fail. WHICH rule gets written
// is settled below, against the configuration itself, which is the only
// reading that can be stale.
func (s *Server) offering(findings []reconcile.Finding, req repointRequest) bool {
	for _, f := range findings {
		if strings.TrimSpace(f.Reference) != req.From {
			continue
		}
		for _, sc := range f.Successors {
			if sc.ID == req.To {
				return true
			}
		}
	}
	return false
}
