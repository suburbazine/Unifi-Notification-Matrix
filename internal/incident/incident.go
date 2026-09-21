// Package incident models the unit this product is actually about.
//
// A notification is a message that was sent. An incident is a condition that
// is still true. Only the second can be nagged about, and only the second can
// be acknowledged -- so the incident, not the notification, is the thing that
// gets stored, scheduled and closed.
package incident

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Severity selects the escalation policy. The vocabulary is fixed: a rule
// picks one of these, and a policy is defined for each.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// State is the lifecycle position. It is DERIVED, never stored -- see State().
type State string

const (
	StateOpen         State = "open"
	StateAlerting     State = "alerting"
	StateAcknowledged State = "acknowledged"
	StateResolved     State = "resolved"
	StateClosed       State = "closed"
)

// Incident is a condition that was observed and has not yet been dealt with.
//
// Note what is NOT here: a `state` field. State is computed from the
// timestamps below, which makes the central invariant structural rather than
// a rule someone has to remember.
type Incident struct {
	ID       string
	DedupKey string // source + entity + condition; see Key
	Severity Severity
	Source   string // "protect", "access", "network", "inbound", "internal"
	Title    string
	Detail   string

	OpenedAt time.Time

	// Delivery. FirstAlertAt is set once; LastAlertAt advances on every
	// SUCCESSFUL delivery. A failed delivery advances neither -- if every
	// channel failed, the incident has not been alerted.
	FirstAlertAt *time.Time
	LastAlertAt  *time.Time
	AlertCount   int
	Stage        int // index into the policy's stage ladder

	// The two orthogonal facts. Acknowledged means a PERSON responded;
	// Resolved means the CONDITION ended. They are independent and both
	// matter, which is why they are two nullable timestamps rather than one
	// status enum.
	AckedAt    *time.Time
	AckVia     string // the channel the ack arrived through, not a user
	ResolvedAt *time.Time

	ClosedAt    *time.Time
	CloseReason string

	// PredecessorID links a recurrence back to the incident it repeats. A
	// condition that clears and returns is a NEW incident -- see Recur.
	PredecessorID string

	// LastDeliveryError is the most recent failure across all channels, kept
	// so the operator can see why an incident is not being delivered without
	// reading logs.
	LastDeliveryError string

	UpdatedAt time.Time
}

// Key builds a dedup key. Dedup is not an optimisation, it is correctness: a
// camera flapping on a bad PoE port emits fifty events a minute and that is
// ONE incident, which re-alerts on its own schedule rather than the event
// rate.
//
// The same logical condition arriving by two different routes -- a WebSocket
// event and an Alarm Manager webhook for the same camera going offline -- must
// produce the same key, which is why the key is built from what the condition
// IS and never from how it arrived.
func Key(source, entity, condition string) string {
	clean := func(s string) string {
		s = strings.TrimSpace(strings.ToLower(s))
		s = strings.ReplaceAll(s, "/", "_")
		if s == "" {
			s = "unknown"
		}
		return s
	}
	return fmt.Sprintf("%s/%s/%s", clean(source), clean(entity), clean(condition))
}

// Condition is the condition this incident is about, read back out of the
// dedup key.
//
// Safe by construction rather than by parsing luck: Key cleans each of its
// three parts and replaces any "/" inside them, so a key is always exactly
// three slash-separated segments. Pinned by a round-trip test, because the day
// that stops being true this returns something plausible and wrong.
func (i *Incident) Condition() string {
	parts := strings.Split(i.DedupKey, "/")
	if len(parts) != 3 {
		return ""
	}
	return parts[2]
}

// Entity is the entity this incident is about, read back out of the dedup
// key -- the middle segment, safe to parse for the same reason Condition is.
//
// What comes back is the key's CLEANED form: lower-cased, with any "/" the id
// held turned into "_", and "unknown" where the source supplied no id at all.
// That is the right thing for a rule to match on -- rule matching is
// case-insensitive -- but a caller that needs to know whether there was an
// entity at all must treat "unknown" as "none", because a rule written for the
// literal word "unknown" matches nothing.
func (i *Incident) Entity() string {
	parts := strings.Split(i.DedupKey, "/")
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}

// State computes the lifecycle position from the timestamps.
//
// This is a function rather than a field on purpose. The product's central
// claim is that "a person responded" and "the condition ended" are orthogonal
// and must not collapse into one flag -- a door acked but still standing open
// is an open obligation, and a door that closed itself at 3am with nobody
// acking is something the morning shift needs to see. Storing a single state
// enum would let those two facts drift apart from the state that claims to
// summarise them. Deriving it makes that unrepresentable.
func (i *Incident) State() State {
	switch {
	case i.ClosedAt != nil:
		return StateClosed
	case i.AckedAt != nil && i.ResolvedAt != nil:
		// Both facts are true: a person saw it AND the condition ended. There
		// is nothing left to do and nothing left to show.
		return StateClosed
	case i.AckedAt != nil:
		return StateAcknowledged
	case i.ResolvedAt != nil:
		return StateResolved
	case i.FirstAlertAt != nil:
		return StateAlerting
	default:
		return StateOpen
	}
}

// Acknowledged and Resolved are exposed separately because the UI must be able
// to show an acknowledged-but-unresolved incident as the open obligation it is.
func (i *Incident) Acknowledged() bool { return i.AckedAt != nil }
func (i *Incident) Resolved() bool     { return i.ResolvedAt != nil }

// Terminal reports whether the incident will never alert again.
func (i *Incident) Terminal() bool { return i.State() == StateClosed }

// ShouldReAlert reports whether this incident is still nagging. Only an
// incident that has been delivered and has had no human response re-alerts.
func (i *Incident) ShouldReAlert() bool { return i.State() == StateAlerting }

var (
	// ErrClosed is returned when something tries to mutate a closed incident.
	// A closed incident is terminal: a recurrence is a new incident (Recur),
	// never a revival, because reviving would make an old acknowledgement
	// apply to an event the acknowledger never saw.
	ErrClosed = errors.New("incident is closed")
)

// touch advances UpdatedAt, and never moves it backwards.
//
// Monotonicity is not tidiness here, it is what the store's compare-and-swap
// is built on. The scheduler captures `now` at the start of a tick, spends
// real time delivering, and only then records the alert -- so an
// acknowledgement landing mid-delivery is stamped LATER than the `now` the
// alert write carries. A plain assignment would then move UpdatedAt backwards
// over the ack, which both misorders the history view and hands the next
// reader an expect value that has already been superseded.
func (i *Incident) touch(at time.Time) {
	if at.After(i.UpdatedAt) {
		i.UpdatedAt = at
	}
}

// Open creates an incident in the Open state.
func Open(id, dedupKey string, sev Severity, source, title, detail string, now time.Time) *Incident {
	return &Incident{
		ID:        id,
		DedupKey:  dedupKey,
		Severity:  sev,
		Source:    source,
		Title:     title,
		Detail:    detail,
		OpenedAt:  now,
		UpdatedAt: now,
	}
}

// RecordAlert notes a SUCCESSFUL delivery.
//
// Call this only when at least one channel accepted the alert. A failed
// delivery must not advance LastAlertAt: if every channel failed, the incident
// has not been alerted, and the scheduler must try again sooner rather than
// treating the failure as a completed nag.
func (i *Incident) RecordAlert(at time.Time, stage int) error {
	if i.Terminal() {
		return ErrClosed
	}
	if i.FirstAlertAt == nil {
		t := at
		i.FirstAlertAt = &t
	}
	t := at
	i.LastAlertAt = &t
	i.AlertCount++
	if stage > i.Stage {
		i.Stage = stage
	}
	i.LastDeliveryError = ""
	i.touch(at)
	return nil
}

// RecordDeliveryFailure records that every channel failed. Deliberately does
// NOT touch LastAlertAt -- see RecordAlert.
func (i *Incident) RecordDeliveryFailure(at time.Time, err string) {
	i.LastDeliveryError = err
	i.touch(at)
}

// Acknowledge records that a person responded, through the named channel.
//
// Attribution is to the CHANNEL, not to a user: an ack arriving from a tap on
// an ntfy action button carries no identity, and the audit record must say
// what is actually known rather than invent a name.
//
// Idempotent. Two taps on the same notification is not an error, and the first
// acknowledgement is the one that counts.
func (i *Incident) Acknowledge(at time.Time, via string) error {
	if i.Terminal() {
		return ErrClosed
	}
	if i.AckedAt != nil {
		return nil
	}
	t := at
	i.AckedAt = &t
	i.AckVia = via
	i.touch(at)
	return nil
}

// Resolve records that the source reported the condition cleared.
//
// Idempotent, for the same reason ingest is: the same clear can arrive over
// both a push channel and a reconciliation sweep.
func (i *Incident) Resolve(at time.Time) error {
	if i.Terminal() {
		return ErrClosed
	}
	if i.ResolvedAt != nil {
		return nil
	}
	t := at
	i.ResolvedAt = &t
	i.touch(at)
	return nil
}

// Close terminates the incident explicitly -- an operator dismissing it, or a
// policy giving up. Acknowledged-and-resolved incidents are already Closed by
// derivation and do not need this.
func (i *Incident) Close(at time.Time, reason string) {
	if i.ClosedAt != nil {
		return
	}
	t := at
	i.ClosedAt = &t
	i.CloseReason = reason
	i.touch(at)
}

// Recur builds the successor for a condition that cleared and came back.
//
// A recurrence is a NEW incident linked to its predecessor, never a revival of
// the old one. Reviving would carry the old acknowledgement forward, making it
// apply to an event the acknowledger never saw -- which is precisely the
// silence this product exists to prevent.
func (i *Incident) Recur(newID string, now time.Time) *Incident {
	n := Open(newID, i.DedupKey, i.Severity, i.Source, i.Title, i.Detail, now)
	n.PredecessorID = i.ID
	return n
}
