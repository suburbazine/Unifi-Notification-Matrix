package web

import (
	"errors"
	"net/http"
	"slices"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/rule"
)

// Silencing an alarm from the alarm.
//
// The operator is looking at a card that says a camera on a failing PoE port
// has gone offline for the ninth time this week. The rule that would stop it
// is four fields long, and every one of them is on the card already. Making
// somebody re-type them into Settings is how a silence gets written wrong --
// a typo in a condition does not fail, it simply never matches, and the card
// comes back tomorrow.
//
// So this writes the rule FROM the incident. Nothing about what the rule
// matches comes from the request: source, condition and entity are read out of
// the stored incident's dedup key, which is the one description of "this
// alarm" the product is certain of. A caller cannot widen it, because there is
// nowhere in the request to put a wider thing.
//
// # Why only this exact alarm
//
// "Every camera's motion" is a more useful silence and a more dangerous one,
// and it was considered and left out. The card shows ONE alarm, and the only
// judgement the operator can make from it is about that one. A rule wider
// than the card -- this condition from every device on the source -- silences
// alarms the card never showed, including, through the site's own severity
// rules, an alarm on some other door that is critical. The check below that
// refuses to silence a critical alarm can be made for the alarm on the card;
// it cannot be made for alarms that have not happened yet. A wider rule
// belongs in Settings, where the whole rule list is on screen when it is
// written.
//
// # Why not critical
//
// Quiet hours never apply to critical, and no control exists to make them.
// That is the product's stance: critical is the tier for the things that must
// wake somebody even when they have asked not to be woken. A permanent
// silence is a stronger thing than quiet hours, and this button offers it at
// the worst possible moment for the judgement -- at 3am, from the card of the
// alarm that is nagging. So the API refuses it, whatever the page shows: a
// critical alarm can still be silenced, by writing the rule in Settings with
// the rule list in front of you, which is the deliberate act the tier calls
// for.
//
// # The open incident
//
// A rule only affects events that have not arrived yet. Silencing the alarm
// and leaving the incident alerting would be half a feature -- and worse than
// half, because the engine ignores a matching event BEFORE it looks at whether
// the event clears anything, so the "camera is back" that would have resolved
// this incident will now be ignored too, and it would sit open for ever. The
// incident is closed here, with a reason that names the rule.
//
// # Reversibility
//
// The rule is an ordinary entry in the configured rule list, appended at the
// end, named after the alarm. It shows up in Settings > Rules like any other
// and is removed there like any other. The audit record carries the name, the
// incident and the three fields, so "why was I not paged about that camera"
// has an answer months later.

// silenceRuleFor builds the ignore rule that matches exactly this incident.
//
// Exactly: one source, one condition, one entity, no window, no severity. The
// name is the dedup key with a prefix, so two silences of the same alarm
// produce the same name -- which is how a repeat is detected -- and an
// operator grepping the audit file for the key finds the rule.
func silenceRuleFor(inc *incident.Incident) (rule.Rule, error) {
	src, ent, cond := inc.Source, inc.Entity(), inc.Condition()
	// Key writes "unknown" where a part was empty, and a rule for the literal
	// word "unknown" matches nothing -- it would be written, shown, audited,
	// and silence nothing. Refuse rather than promise.
	if src == "" || ent == "" || cond == "" || ent == "unknown" || cond == "unknown" {
		return rule.Rule{}, errors.New(
			"this alarm does not name a device and a condition, so a rule cannot " +
				"be written to match it; silence the condition from Settings > Rules instead")
	}
	return rule.Rule{
		Name:       "silence " + inc.DedupKey,
		Sources:    []string{src},
		Conditions: []string{cond},
		Entities:   []string{ent},
		Ignore:     true,
	}, nil
}

// sameSilence reports whether an existing rule IS the generated one: the same
// three fields, ignore, and nothing else. A rule that merely shares the name
// has been edited by hand since, and is not this silence.
func sameSilence(have, want rule.Rule) bool {
	return have.Ignore == want.Ignore &&
		have.Severity == "" && have.Elevate == 0 && have.Window == nil &&
		slices.Equal(have.Sources, want.Sources) &&
		slices.Equal(have.Conditions, want.Conditions) &&
		slices.Equal(have.Entities, want.Entities)
}

// handleSilenceIncident writes an ignore rule matching one incident, and
// closes the incident.
//
// Follows handleRepointRule: clone the configuration before editing, refuse
// on a conflict with 409, persist through deps.SaveConfig, record what was
// done. The rule is saved BEFORE the incident is closed, because the two
// failures are not symmetric: a rule saved and an incident left open is a
// visible half-result the operator can finish by hand, while an incident
// closed and a rule that failed validation is an alarm dismissed for nothing.
func (s *Server) handleSilenceIncident(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("no incident id"))
		return
	}
	inc, err := s.deps.Store.Get(r.Context(), id)
	if errors.Is(err, incident.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, errorBody("no such incident"))
		return
	}
	if err != nil {
		s.fail(w, r, "reading the incident", err)
		return
	}

	// THE API ENFORCES THIS, NOT THE PAGE. The page also does not offer the
	// button on a critical card, but a page is a courtesy and this is the
	// rule. See the head of this file for why.
	if inc.Severity == incident.SeverityCritical {
		writeJSON(w, http.StatusForbidden, errorBody(
			"a critical alarm cannot be silenced from here. Critical is the tier "+
				"that is never quietened automatically; if this one really should be, "+
				"write the rule in Settings > Rules, deliberately"))
		return
	}

	want, err := silenceRuleFor(inc)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}

	cur := s.deps.Config()
	if cur == nil {
		writeJSON(w, http.StatusConflict, errorBody("the configuration is not readable just now"))
		return
	}

	already := false
	for _, have := range cur.Rules {
		if have.Name != want.Name {
			continue
		}
		if !sameSilence(have, want) {
			// The name is taken by something that is no longer this silence.
			// Appending a second rule with the name would be refused by the
			// validator; overwriting the operator's edit would be worse.
			writeJSON(w, http.StatusConflict, errorBody(
				"a rule named \""+want.Name+"\" already exists and has been edited "+
					"since it was generated, so it was left alone. Look at it in "+
					"Settings > Rules"))
			return
		}
		already = true
		break
	}

	if !already {
		next := *cur
		// Clone before editing: the daemon hands out the configuration it is
		// USING, and a failed save must not leave it running a change the
		// operator was told did not happen.
		next.Rules = append(slices.Clone(cur.Rules), want)
		if err := s.deps.SaveConfig(&next); err != nil {
			if errors.Is(err, config.ErrInvalid) {
				writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
				return
			}
			s.fail(w, r, "saving the silence rule", err)
			return
		}
		s.record(r, audit.Entry{
			Kind:       audit.KindConfigChanged,
			IncidentID: inc.ID, DedupKey: inc.DedupKey, Severity: string(inc.Severity),
			Summary: "silenced an alarm from the incident board: added an ignore rule",
			Fields: map[string]string{
				"rule": want.Name, "source": want.Sources[0],
				"condition": want.Conditions[0], "entity": want.Entities[0],
			},
		})
	}

	reason := "silenced by rule \"" + want.Name + "\""
	if already {
		reason += " (already in place)"
	}
	closed, err := s.closeSilenced(r, id, reason)
	if err != nil {
		// The rule is saved and recorded; that is the part that cannot be
		// redone by hand. Say what is left rather than report a failure that
		// would send the operator to re-silence something already silent.
		s.record(r, audit.Entry{
			Kind: audit.KindService, Actor: "web",
			Summary: "web: closing a silenced incident failed",
			Fields:  map[string]string{"incident": id, "error": err.Error()},
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "rule": want.Name, "already": already, "closed": false,
			"detail": "the rule is saved, but this incident could not be closed; close it by hand",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "rule": want.Name, "already": already, "closed": closed,
	})
}

// closeSilenced closes the incident with the compare-and-swap retry the other
// incident writes use, and reports whether it did -- false when the incident
// was already terminal, which is not an error: a silence on a closed card is
// still a silence.
func (s *Server) closeSilenced(r *http.Request, id, reason string) (bool, error) {
	for attempt := 0; attempt < ackRetries; attempt++ {
		inc, err := s.deps.Store.Get(r.Context(), id)
		if err != nil {
			return false, err
		}
		if inc.Terminal() {
			return false, nil
		}
		expect := inc.UpdatedAt
		inc.Close(s.now(), reason)
		err = s.deps.Store.PutIfUnchanged(r.Context(), inc, expect)
		if errors.Is(err, incident.ErrConflict) {
			continue
		}
		if err != nil {
			return false, err
		}
		s.record(r, audit.Entry{
			Kind: audit.KindClosed, IncidentID: inc.ID, DedupKey: inc.DedupKey,
			Severity: string(inc.Severity),
			Summary:  "closed from the web UI",
			Fields:   map[string]string{"reason": reason},
		})
		return true, nil
	}
	return false, errors.New("the incident is being changed by something else")
}
