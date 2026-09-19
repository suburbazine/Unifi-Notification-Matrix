// Package reconcile compares what the rules point AT against what this site
// has actually been seen to have.
//
// # Why this exists
//
// Every loop in this product runs over what a source returned. Nothing ran
// over what the operator configured, and the gap between those two sets is
// invisible to everything built on the first one: a rule naming a door that no
// longer answers to that name is not an error, is not a warning, and does not
// appear anywhere. It simply never matches, for ever, and the board stays
// green because nothing is arriving to make it otherwise.
//
// The sibling product found this the hard way. A motor gate stood open all
// night with an obstruction in its path while a hundred and sixteen polls
// reported healthy, because the two ids its rules named had gone stale
// together six days earlier and nothing was reconciling the other direction.
//
// # The identity table, which is the whole reason a fix is possible
//
// A UniFi device id is generated AT ADOPTION TIME. So:
//
//	                      rename     re-adoption
//	rule written by name  breaks     survives
//	rule written by id    survives   breaks
//	MAC                   survives   survives
//
// The permanent entity record (store.ObservedEntity, schema v3) keeps the MAC.
// Re-adopting hardware therefore leaves TWO rows with one MAC between them:
// the identity that went quiet and the identity that took over. That pair is
// the evidence, and it is what lets this package do more than shrug.
//
// # What it deliberately does not do
//
// It raises nothing and alerts nobody. It answers a question an operator asks
// by opening a page. The sibling product nearly shipped the alerting version,
// and on the first failed enumeration it would have raised one condition per
// configured entity, all at once, in the middle of the night, about devices
// that were fine. Report(), not Raise().
package reconcile

import (
	"path"
	"sort"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/rule"
)

// Entity is one row of the permanent record.
//
// Mirrors store.ObservedEntity rather than importing it: this package decides
// things about rules and entities and has no business knowing there is a
// database.
type Entity struct {
	Source string
	ID     string
	Name   string
	Kind   string
	MAC    string

	FirstSeen time.Time
	LastSeen  time.Time
}

// Status is what reconciling one reference concluded.
type Status string

const (
	// StatusSuperseded is the confident one: the thing this rule names went
	// quiet, and something that is almost certainly the same physical device
	// is reporting under a different id. Re-adoption looks exactly like this.
	StatusSuperseded Status = "superseded"

	// StatusSilent is a reference that still resolves, to something that has
	// not been heard from in a long time, with nothing that looks like a
	// replacement. Much weaker: a side door nobody opens in a month is
	// indistinguishable from a door that has been unplugged.
	StatusSilent Status = "silent"

	// StatusUnknown is a reference that matches nothing this product has ever
	// recorded. A typo, a rename, or a rule written ahead of the hardware --
	// all three are worth an operator's eye and none of them is an error.
	StatusUnknown Status = "unknown"
)

// DefaultSilentAfter is how quiet a still-resolving reference has to be before
// it is worth mentioning, when nothing has taken its place.
//
// Deliberately long. The alternative -- a week, say -- would report every
// delivery door in a building that takes deliveries monthly, and a review list
// that is mostly wrong is a review list nobody opens twice. The superseded
// case does not wait for this at all, because it has real evidence.
const DefaultSilentAfter = 30 * 24 * time.Hour

// Successor is something that looks like the same device under a new identity.
type Successor struct {
	ID   string
	Name string
	Kind string

	// On is what connects it to the reference: "mac" or "name". The MAC is
	// the one identifier that survives both a rename and a re-adoption, so a
	// match on it is evidence and a match on the name is a strong hint.
	On string

	FirstSeen time.Time
	LastSeen  time.Time
}

// Finding is one rule reference worth an operator's attention.
//
// Reference is the string AS WRITTEN in the rule, because that is what they
// will look for in the file and what an amendment has to replace exactly.
type Finding struct {
	Rule      string
	RuleIndex int
	Reference string
	Status    Status

	// Source, MatchedID, MatchedName and LastSeen describe what the reference
	// currently resolves to. All empty for StatusUnknown, which resolves to
	// nothing -- and that emptiness is the finding.
	Source      string
	MatchedID   string
	MatchedName string
	LastSeen    time.Time

	// Successors are the candidates to point at instead, best first. Empty
	// unless Status is StatusSuperseded.
	Successors []Successor

	// Pattern is set when the reference contains a wildcard. A glob is a
	// deliberate class match, so nothing here will ever offer to rewrite one:
	// "door-*" matching nothing today is worth saying, and guessing what it
	// should have been is not.
	Pattern bool
}

// Input is everything a reconciliation needs, handed in.
type Input struct {
	Rules rule.Set
	Known []Entity

	// Enumerated is false when the record could not be read.
	//
	// THE GUARD THAT MATTERS. An empty list is not a claim that the site has
	// nothing; it is usually a claim that the reading failed. Concluding
	// "every rule points at something that does not exist" from a failed query
	// is how a diagnostic becomes the outage.
	Enumerated bool

	Now         time.Time
	SilentAfter time.Duration
}

// Report reconciles the rules against the record.
//
// Returns findings only: a reference that resolves to something that spoke
// this morning produces nothing, because the list is meant to be short enough
// that a non-empty one means something.
func Report(in Input) []Finding {
	// NOT ENUMERATED, OR NOTHING RECORDED: conclude nothing.
	//
	// Both are "we do not know", and the difference between "we do not know"
	// and "it is not there" is the entire distance between a useful review and
	// a page full of confident nonsense on a fresh install.
	if !in.Enumerated || len(in.Known) == 0 {
		return nil
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	silentAfter := in.SilentAfter
	if silentAfter <= 0 {
		silentAfter = DefaultSilentAfter
	}

	var out []Finding
	for i, r := range in.Rules {
		for _, ref := range r.Entities {
			f, ok := reconcileOne(ref, in.Known, now, silentAfter)
			if !ok {
				continue
			}
			f.Rule = r.Name
			f.RuleIndex = i
			out = append(out, f)
		}
	}
	return out
}

// reconcileOne decides about a single entity reference.
func reconcileOne(ref string, known []Entity, now time.Time,
	silentAfter time.Duration) (Finding, bool) {

	trimmed := strings.TrimSpace(ref)
	needle := strings.ToLower(trimmed)
	// An empty reference is not a reference, and "*" is "anything", which
	// cannot be stale.
	if needle == "" || needle == "*" {
		return Finding{}, false
	}

	if isPattern(needle) {
		for _, e := range known {
			if globMatches(needle, e.ID) || globMatches(needle, e.Name) {
				return Finding{}, false
			}
		}
		return Finding{Reference: trimmed, Status: StatusUnknown, Pattern: true}, true
	}

	matches := matching(needle, known)
	if len(matches) == 0 {
		return Finding{Reference: trimmed, Status: StatusUnknown}, true
	}

	// The most recently heard-from match is the one that decides. A name that
	// two rows share -- the old identity and the new one after a re-adoption
	// -- is a reference that still works, and calling it stale because the
	// older row is old would be wrong about the one case the record exists to
	// get right.
	best := matches[0]
	for _, e := range matches[1:] {
		if e.LastSeen.After(best.LastSeen) {
			best = e
		}
	}

	f := Finding{
		Reference:   trimmed,
		Source:      best.Source,
		MatchedID:   best.ID,
		MatchedName: best.Name,
		LastSeen:    best.LastSeen,
	}

	if succ := successors(best, known); len(succ) > 0 {
		f.Status = StatusSuperseded
		f.Successors = succ
		return f, true
	}
	if now.Sub(best.LastSeen) >= silentAfter {
		f.Status = StatusSilent
		return f, true
	}
	return Finding{}, false
}

// matching returns every recorded entity a plain reference resolves to.
//
// Both the id and the name, because rule.Matches tries both and an operator
// may have written either.
func matching(needle string, known []Entity) []Entity {
	var out []Entity
	for _, e := range known {
		if strings.ToLower(strings.TrimSpace(e.ID)) == needle ||
			strings.ToLower(strings.TrimSpace(e.Name)) == needle {
			out = append(out, e)
		}
	}
	return out
}

// successors finds identities that look like the same physical thing.
//
// Two requirements, and both are about not inventing a story:
//
//   - the candidate must be a DIFFERENT id in the SAME source, because a
//     device is only ever superseded within the source that adopted it;
//   - it must have been heard from after the reference went quiet. Without
//     that this would offer to repoint a live rule at a second camera that
//     merely shares a name, which is a worse outcome than saying nothing.
func successors(ref Entity, known []Entity) []Successor {
	var out []Successor
	mac := normaliseMAC(ref.MAC)
	name := strings.ToLower(strings.TrimSpace(ref.Name))

	for _, e := range known {
		if e.Source != ref.Source || e.ID == ref.ID || strings.TrimSpace(e.ID) == "" {
			continue
		}
		if !e.LastSeen.After(ref.LastSeen) {
			continue
		}
		on := ""
		switch {
		case mac != "" && normaliseMAC(e.MAC) == mac:
			on = "mac"
		case name != "" && strings.ToLower(strings.TrimSpace(e.Name)) == name:
			on = "name"
		default:
			continue
		}
		out = append(out, Successor{
			ID: e.ID, Name: e.Name, Kind: e.Kind, On: on,
			FirstSeen: e.FirstSeen, LastSeen: e.LastSeen,
		})
	}

	// MAC first, then most recently seen. The MAC survives both a rename and a
	// re-adoption and the name survives only one of them, so a MAC match is
	// evidence and a name match is a hint -- and offering the hint above the
	// evidence would invite somebody to take the weaker answer.
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].On == "mac") != (out[j].On == "mac") {
			return out[i].On == "mac"
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// normaliseMAC compares MACs by their bytes rather than their punctuation.
//
// Sources spell them differently -- colons, hyphens, upper case, none at all
// -- and two spellings of one address failing to match would silently turn the
// evidence case back into the shrug case.
func normaliseMAC(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return b.String()
}

// isPattern reports whether a reference is a class match rather than a name.
//
// The same three metacharacters rule.matchAnyNonEmpty honours, so this agrees
// with what actually matches at runtime rather than with a simpler idea of it.
func isPattern(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// globMatches applies a reference the way the rule engine does, trailing "*"
// included.
func globMatches(pattern, value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		if strings.HasPrefix(v, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	ok, err := path.Match(pattern, v)
	return err == nil && ok
}
