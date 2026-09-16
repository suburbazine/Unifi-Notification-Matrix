// Package rule turns events into incidents.
//
// This is the seam ARCHITECTURE.md §2 draws between "something happened" and
// "something is still true". A source reports facts; a rule decides whether a
// fact is worth waking somebody for, and how loudly.
package rule

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Rule matches events and adjusts what happens to them.
//
// Deliberately NOT a scripting language. ARCHITECTURE.md §1 puts the ceiling
// here: rules map events to severities and policies, and anything more
// expressive belongs in Home Assistant or Node-RED, which this product feeds
// by webhook rather than competes with. A config format that can express
// arbitrary logic is a config format nobody can audit at 3am.
type Rule struct {
	// Name identifies the rule in diagnostics and in the audit record. An
	// alert that arrived because of a rule must be able to say which one.
	Name string `json:"name"`

	// Match. An empty list matches anything; a non-empty one must contain the
	// event's value. Patterns accept a trailing "*" for prefix matching.
	Sources    []string `json:"sources,omitempty"`
	Conditions []string `json:"conditions,omitempty"`
	Entities   []string `json:"entities,omitempty"`

	// Severity overrides the source's proposal when set.
	//
	// The source knows what happened; the site knows how much it cares. A
	// doorbell ring is noise in a warehouse and worth knowing about in a
	// private house, and neither the source nor this product can decide that.
	Severity incident.Severity `json:"severity,omitempty"`

	// Ignore drops matching events entirely.
	Ignore bool `json:"ignore,omitempty"`
}

var (
	ErrNoName = errors.New("rule has no name")

	// ErrBlanketIgnore rejects an ignore rule that matches everything.
	ErrBlanketIgnore = errors.New(
		"an ignore rule must narrow what it silences by source, condition or entity")

	ErrBadSeverity = errors.New("rule names an unknown severity")

	// ErrDuplicateName rejects two rules sharing a name, which would make
	// the audit record ambiguous about which one silenced or escalated an
	// event.
	ErrDuplicateName = errors.New("rule name is used more than once")
)

// Validate refuses a rule that would silently disable the product.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return ErrNoName
	}
	if r.Severity != "" && !r.Severity.Valid() {
		return fmt.Errorf("%w: %q (want critical, high, medium, low or info)",
			ErrBadSeverity, r.Severity)
	}
	// AN IGNORE RULE MUST NARROW SOMETHING.
	//
	// Silencing a specific noisy condition is a legitimate operator need -- a
	// camera on a failing PoE port, a door sensor being replaced. Silencing
	// EVERYTHING is not a rule, it is an off switch that leaves the service
	// running and looking healthy, which is the worst way to have no
	// monitoring.
	if r.Ignore && len(r.Sources) == 0 && len(r.Conditions) == 0 && len(r.Entities) == 0 {
		return fmt.Errorf("%w (rule %q)", ErrBlanketIgnore, r.Name)
	}
	if r.Ignore && r.Severity != "" {
		return fmt.Errorf("rule %q both ignores events and sets a severity; "+
			"only one of those can be true", r.Name)
	}
	return nil
}

// Matches reports whether the rule applies to an event.
func (r Rule) Matches(e event.Event) bool {
	return matchAny(r.Sources, e.Source) &&
		matchAny(r.Conditions, e.Condition) &&
		(matchAny(r.Entities, e.Entity.ID) || matchAnyNonEmpty(r.Entities, e.Entity.Name))
}

// matchAny reports whether value matches any pattern, or the list is empty.
func matchAny(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	return matchAnyNonEmpty(patterns, value)
}

func matchAnyNonEmpty(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(value))
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		switch {
		case p == "":
			continue
		case p == "*":
			return true
		case strings.HasSuffix(p, "*"):
			if strings.HasPrefix(v, strings.TrimSuffix(p, "*")) {
				return true
			}
		default:
			// path.Match gives "?" and character classes on top of "*", which
			// is enough for camera names like "Door-?" without becoming a
			// language.
			if ok, err := path.Match(p, v); err == nil && ok {
				return true
			}
			if p == v {
				return true
			}
		}
	}
	return false
}

// Decision is what the rule set concluded about one event.
type Decision struct {
	// Ignore means no incident, by an explicit rule.
	Ignore bool

	// Severity is the effective severity after any override.
	Severity incident.Severity

	// MatchedBy names every rule that applied, for the audit record. An alert
	// that arrived because of a rule must be able to say which one, and an
	// alert that did NOT arrive is the harder question -- so the ignore path
	// records its rule too.
	MatchedBy []string
}

// Set is an ordered rule list.
//
// LAST MATCH WINS for severity, so a later, more specific rule can override an
// earlier broad one -- which is the order people write them in. An ignore by
// ANY rule wins outright, because a deliberate silence should not need to be
// the last word to take effect.
type Set []Rule

// Validate checks every rule, reporting all problems rather than the first.
//
// Joined with errors.Join rather than flattened into one string, so the
// sentinels survive: a caller asking errors.Is(err, ErrBlanketIgnore) gets a
// true answer. Flattening lost that, and a test caught it -- which is the
// whole argument for having sentinels rather than messages.
func (s Set) Validate() error {
	var errs []error
	seen := map[string]bool{}
	for i, r := range s {
		if err := r.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("rule %d: %w", i, err))
			continue
		}
		if seen[r.Name] {
			errs = append(errs, fmt.Errorf("%w: %q", ErrDuplicateName, r.Name))
		}
		seen[r.Name] = true
	}
	return errors.Join(errs...)
}

// Decide applies the set to an event.
func (s Set) Decide(e event.Event) Decision {
	d := Decision{Severity: e.Severity}
	if !d.Severity.Valid() {
		// A source that proposed nothing usable gets a floor rather than a
		// guess. "high" is deliberately not the floor: inventing urgency is as
		// wrong as inventing calm, and an unclassified event should be visible
		// without waking anyone.
		d.Severity = incident.SeverityMedium
	}
	for _, r := range s {
		if !r.Matches(e) {
			continue
		}
		d.MatchedBy = append(d.MatchedBy, r.Name)
		if r.Ignore {
			d.Ignore = true
			continue
		}
		if r.Severity != "" {
			d.Severity = r.Severity
		}
	}
	return d
}
