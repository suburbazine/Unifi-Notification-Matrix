package link

import (
	"errors"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

var now = time.Date(2026, 9, 18, 2, 42, 19, 0, time.UTC)

func sentry() Peer {
	return Peer{
		Slug: "sentry",
		Manifest: Manifest{
			Capability: "access",
			Conditions: []ConditionSpec{
				{Name: "sentry-credential-sweep", Meaning: "One identity refused at several doors.",
					Severity: incident.SeverityCritical, Momentary: true},
				{Name: "sentry-access-denied", Meaning: "A credential was refused during a watch.",
					Severity: incident.SeverityHigh, Momentary: true},
				{Name: "sentry-door-enforced", Meaning: "A door was found unlocked and locked again.",
					Severity: incident.SeverityHigh, Momentary: true},
				{Name: "sentry-blocked-locally", Meaning: "The machine is refusing outbound connections.",
					Severity: incident.SeverityCritical, DemotesClaim: true},
			},
		},
	}
}

func sweep() Envelope {
	return Envelope{
		LinkVersion: Version,
		Product:     "sentry",
		SiteID:      "site-1",
		EventID:     "3f2b1c-uuid",
		SentAt:      now,
		State:       StateRaised,
		Condition:   "sentry-credential-sweep",
		Severity:    "critical",
		Title:       "Credential sweep: refused at 16 doors",
		Entity:      Party{Kind: "identity", ID: "d540df0c", Name: "A Person"},
	}
}

func TestAWellFormedEnvelopeIsAccepted(t *testing.T) {
	if err := sweep().Validate(sentry()); err != nil {
		t.Fatalf("a valid envelope was refused: %v", err)
	}
}

// THE SWEEP, which is the reason the whole channel exists. One identity refused
// at sixteen doors is ONE incident, because the peer sets the entity to the
// actor and the key is computed from it. Under door-scoped keying the same
// real event became sixteen separate incidents that each nagged.
func TestASweepIsOneActorScopedIncident(t *testing.T) {
	p, e := sentry(), sweep()
	first := e.Event(p, now)

	// A second envelope for the same actor and condition, differing only in
	// the doors it names, must land on the same incident.
	e.EventID = "another-uuid"
	e.Context = map[string]any{"doors": 16}
	second := e.Event(p, now)

	if first.DedupKey() != second.DedupKey() {
		t.Errorf("two envelopes for one actor produced %q and %q", first.DedupKey(), second.DedupKey())
	}
	if want := "sentry/d540df0c/sentry-credential-sweep"; first.DedupKey() != want {
		t.Errorf("DedupKey() = %q, want %q -- peer slug, actor, condition", first.DedupKey(), want)
	}
}

// The sender's key is a tripwire, not an input. A disagreement is a mapping bug
// on one side or the other, and it must be loud rather than become two
// incidents that never merge.
func TestASenderKeyThatDisagreesIsRefused(t *testing.T) {
	e := sweep()
	e.DedupKey = "sentry:credential-sweep:d540df0c" // the peer's own format
	if err := e.Validate(sentry()); !errors.Is(err, ErrDedupKey) {
		t.Errorf("a disagreeing dedup_key was accepted: %v", err)
	}

	e.DedupKey = "sentry/d540df0c/sentry-credential-sweep"
	if err := e.Validate(sentry()); err != nil {
		t.Errorf("an agreeing dedup_key was refused: %v", err)
	}
}

// A condition outside the approved manifest is refused rather than bucketed.
// A silent catch-all would recreate the open vocabulary a closed one exists to
// prevent, and would hide the peer's mapping bugs while doing it.
func TestAnUnapprovedConditionIsRefused(t *testing.T) {
	e := sweep()
	e.Condition = "sentry-something-new"
	if err := e.Validate(sentry()); !errors.Is(err, ErrCondition) {
		t.Errorf("a condition outside the manifest was accepted: %v", err)
	}
}

// Validated, never coerced: a coerced severity is a silent downgrade of exactly
// the cascade the peer is trying to express.
func TestAnUnknownSeverityIsRefusedNotCoerced(t *testing.T) {
	e := sweep()
	e.Severity = "urgent"
	if err := e.Validate(sentry()); !errors.Is(err, ErrSeverity) {
		t.Errorf("an unknown severity was accepted: %v", err)
	}
}

// The cap exists because critical never gives up and quiet hours never apply
// to it, which is a lot of power to hand across a network boundary. Uncapped
// by default: the cascade is the point.
func TestTheSeverityCapAppliesWhenSet(t *testing.T) {
	p := sentry()
	if got := sweep().Event(p, now).Severity; got != incident.SeverityCritical {
		t.Errorf("uncapped severity = %q, want critical", got)
	}
	p.MaxSeverity = incident.SeverityHigh
	if got := sweep().Event(p, now).Severity; got != incident.SeverityHigh {
		t.Errorf("capped severity = %q, want high", got)
	}
	// A cap never RAISES anything.
	e := sweep()
	e.Severity = "low"
	if got := e.Event(p, now).Severity; got != incident.SeverityLow {
		t.Errorf("capped a low event up to %q", got)
	}
}

func TestStateBecomesClears(t *testing.T) {
	e := sweep()
	if e.Event(sentry(), now).Clears {
		t.Error("a raised envelope claims to clear")
	}
	e.State = StateCleared
	if !e.Event(sentry(), now).Clears {
		t.Error("a cleared envelope does not clear")
	}
	e.State = "resolved"
	if err := e.Validate(sentry()); !errors.Is(err, ErrState) {
		t.Errorf("an unknown state was accepted: %v", err)
	}
}

// occurred_at is an observation; sent_at is an arrival. An alert presenting an
// arrival as an observation sends somebody scrubbing to the wrong point in the
// footage, so the distinction travels with the event.
func TestOccurredAtIsAnObservationAndSentAtIsAnArrival(t *testing.T) {
	e := sweep()
	got := e.Event(sentry(), now)
	if !got.AtIsArrivalTime || !got.At.Equal(e.SentAt) {
		t.Errorf("with no occurred_at: At=%v arrival=%v, want sent_at and arrival", got.At, got.AtIsArrivalTime)
	}

	seen := now.Add(-90 * time.Second)
	e.OccurredAt = &seen
	got = e.Event(sentry(), now)
	if got.AtIsArrivalTime || !got.At.Equal(seen) {
		t.Errorf("with occurred_at: At=%v arrival=%v, want the controller's time", got.At, got.AtIsArrivalTime)
	}
}

// An envelope naming another product must not be accepted on this peer's
// credentials -- and nothing may be keyed on the literal string "sentry",
// because this channel is meant to carry more than one product.
func TestAnEnvelopeFromAnotherProductIsRefused(t *testing.T) {
	e := sweep()
	e.Product = "doormatrix"
	if err := e.Validate(sentry()); !errors.Is(err, ErrWrongPeer) {
		t.Errorf("an envelope from another product was accepted: %v", err)
	}

	// ...and the same envelope against a doormatrix peer keys under its slug.
	dm := Peer{Slug: "doormatrix", Manifest: sentry().Manifest}
	if err := e.Validate(dm); err != nil {
		t.Fatalf("a doormatrix envelope was refused by a doormatrix peer: %v", err)
	}
	if got := e.Event(dm, now).DedupKey(); got != "doormatrix/d540df0c/sentry-credential-sweep" {
		t.Errorf("DedupKey() = %q, want it keyed under the peer's own slug", got)
	}
}

func TestRequiredFieldsAreRefusedWhenEmpty(t *testing.T) {
	for _, drop := range []func(*Envelope){
		func(e *Envelope) { e.EventID = "" },
		func(e *Envelope) { e.SiteID = "" },
		func(e *Envelope) { e.Condition = "" },
		func(e *Envelope) { e.Title = "" },
		func(e *Envelope) { e.Entity.ID = "" },
	} {
		e := sweep()
		drop(&e)
		if err := e.Validate(sentry()); err == nil {
			t.Errorf("an envelope missing a required field was accepted: %+v", e)
		}
	}
	e := sweep()
	e.SentAt = time.Time{}
	if err := e.Validate(sentry()); !errors.Is(err, ErrNoTimestamp) {
		t.Errorf("an envelope with no sent_at was accepted: %v", err)
	}
	e = sweep()
	e.LinkVersion = 2
	if err := e.Validate(sentry()); !errors.Is(err, ErrVersion) {
		t.Errorf("a future envelope version was accepted: %v", err)
	}
}

// Context is rendered into the body, and the order must not move between two
// deliveries of the same event -- a body that reorders itself reads as a
// different event.
func TestContextRendersDeterministically(t *testing.T) {
	e := sweep()
	e.Detail = "Refused at 16 doors."
	e.Context = map[string]any{"method": "REMOTE_UNLOCK_USER", "doors": 16, "window_minutes": 5}

	first := e.Event(sentry(), now).Detail
	for i := 0; i < 20; i++ {
		if got := e.Event(sentry(), now).Detail; got != first {
			t.Fatalf("the rendered body moved between runs:\n%q\n%q", first, got)
		}
	}
	if first == e.Detail {
		t.Error("the context was not rendered into the body at all")
	}
}
