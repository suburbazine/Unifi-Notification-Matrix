package config

import (
	"slices"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Decisions the operator has made about a first-party peer's conditions,
// applied to sites that paired before the peer could declare them itself.
//
// WHY THIS IS A TABLE WITH A NAME IN IT. Nothing else in the link code knows
// any peer by name, and that is deliberate: the slug is data. This is the one
// exception, and it is narrow. The operator decided that a Sentry access
// denial arriving after an acknowledgement folds into the reviewed incident,
// and Sentry declares that itself from 1.6.12 -- but a site stores a peer's
// manifest at PAIRING, so every site paired on an earlier Sentry would keep
// re-alerting until somebody re-paired it or hand-edited config.yaml. The
// operator asked for it to apply on its own instead.
//
// Written INTO the file, as an ordinary override, rather than applied
// invisibly: the page and the file then say why a condition behaves as it
// does, and the operator can change it like any other override.
//
// Applied only where nothing has been said yet:
//   - the peer is paired and declares the condition;
//   - its stored manifest makes no per_occurrence declaration for it (a
//     pairing on 1.6.12 or later does, and that declaration then stands);
//   - the operator has made no per_occurrence override for it.
//
// So `per_occurrence: true`, set explicitly, is never touched -- that is how
// an operator opts out. Deleting the line is not: it is written again at the
// next start, because an absent line is indistinguishable from never having
// had one.
var firstPartyDefaults = map[string]map[string]LinkOverride{
	"sentry": {
		"sentry-access-denied": {PerOccurrence: boolPtr(false)},
	},
}

func boolPtr(b bool) *bool { return &b }

// firstPartyConditions are conditions a first-party peer sends that the
// operator has decided to accept -- behaviour included -- without an approval
// click at every site.
//
// SENTRY'S MONITORING-STOPPED. Sentry 1.6.16 raises it while it is running but
// watching nothing, and it is meant to hand Access straight back to this
// product's own ingest. But a site paired before 1.6.16 stores a manifest
// without it: the condition is refused, then offered for approval, and
// approving it from the card deliberately does NOT carry demotes_claim -- so
// a stopped Sentry kept the doors for the whole silence window, watched by
// nothing. The operator asked for it to work everywhere without a re-pair.
//
// Safe to accept unreviewed for one reason, and the reason is the whole
// justification: raising it can ONLY make this product take the doors back.
// It cannot silence, lower or suppress anything.
var firstPartyConditions = map[string][]LinkCondition{
	"sentry": {{
		Name: "sentry-monitoring-stopped",
		Meaning: "Sentry is running but no watch is active, so it is not watching " +
			"the doors; this product watches them itself until Sentry starts again.",
		Severity:     incident.SeverityMedium,
		Momentary:    false,
		DemotesClaim: true,
	}},
}

// ApplyPeerDefaults writes any first-party default that applies into c, and
// reports whether it changed anything.
func ApplyPeerDefaults(c *Config) bool {
	if c == nil {
		return false
	}
	changed := false
	for i := range c.Links {
		l := &c.Links[i]
		if applyFirstPartyConditions(l) {
			changed = true
		}
		defaults, ok := firstPartyDefaults[l.Slug]
		if !ok {
			continue
		}
		for cond, want := range defaults {
			declared := false
			for _, spec := range l.Conditions {
				if spec.Name != cond {
					continue
				}
				declared = true
				if spec.PerOccurrence != nil {
					declared = false // the peer said so itself; that stands
				}
			}
			if !declared || want.PerOccurrence == nil {
				continue
			}
			o := l.Overrides[cond]
			if o.PerOccurrence != nil {
				continue // the operator decided
			}
			if l.Overrides == nil {
				l.Overrides = map[string]LinkOverride{}
			}
			v := *want.PerOccurrence
			o.PerOccurrence = &v
			l.Overrides[cond] = o
			changed = true
		}
	}
	return changed
}

// applyFirstPartyConditions makes sure a first-party peer's accepted
// conditions are present and behave as decided.
//
// The condition list is REPLACED rather than written into. A Config is copied
// by value on every save, so its Links' condition slices are shared with the
// configuration the daemon is running; setting a field through them would
// change the running configuration before this one was saved -- or when it
// never is.
func applyFirstPartyConditions(l *Link) bool {
	want, ok := firstPartyConditions[l.Slug]
	if !ok {
		return false
	}
	conds := slices.Clone(l.Conditions)
	changed := false
	for _, w := range want {
		found := false
		for j := range conds {
			if conds[j].Name != w.Name {
				continue
			}
			found = true
			if w.DemotesClaim && !conds[j].DemotesClaim {
				conds[j].DemotesClaim = true
				changed = true
			}
		}
		if !found {
			conds = append(conds, w)
			changed = true
		}
	}
	if changed {
		l.Conditions = conds
	}
	return changed
}
