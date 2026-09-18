// Package link receives events from a paired first-party product.
//
// It exists because internal/inbound cannot carry this traffic, and the reason
// is worth stating rather than rediscovering. Inbound hooks attach meaning to
// the URL because UniFi's Alarm Manager payloads are undocumented and vary by
// firmware, so the body cannot be trusted to say what happened. A paired peer
// is the opposite case: a cooperative sender that knows exactly what it means.
// Two hook properties make them the wrong fit:
//
//   - A hook's severity is fixed per URL. A peer's severity is per event: the
//     same door denial is high alone and critical once it is one of sixteen by
//     the same identity in a minute. Pinning severity to a URL cannot express
//     that, and the cascade is the main thing worth sending.
//   - Meaning attaches to the URL, so full coverage costs one hook, token and
//     bearer per condition.
//
// So Link carries meaning, severity and lifecycle in a typed envelope on one
// endpoint. What it does NOT do is trust any of it blindly: the dedup key is
// computed here rather than accepted, the condition must be one the operator
// approved for this peer, and an unknown severity is refused rather than
// coerced into something plausible.
package link

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Version is the envelope this build speaks.
const Version = 1

// States an envelope may report.
const (
	StateRaised  = "raised"
	StateCleared = "cleared"
)

// Party is an entity or an actor named by the peer.
type Party struct {
	// Kind is "door", "identity" or "site". Identity is what makes a
	// credential sweep one incident instead of sixteen: the peer sets the
	// entity to the ACTOR, so the dedup key computed from it is actor-scoped
	// across every door involved.
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Envelope is one event from a paired peer.
type Envelope struct {
	LinkVersion    int    `json:"link_version"`
	Product        string `json:"product"`
	ProductVersion string `json:"product_version,omitempty"`
	SiteID         string `json:"site_id"`

	// EventID is the idempotency key. A redelivery of the same EventID must be
	// a no-op so the peer can retry safely.
	EventID string `json:"event_id"`

	// SentAt is when the peer emitted this. OccurredAt is the controller's own
	// time where the peer knows it, which for denials genuinely lags.
	SentAt     time.Time  `json:"sent_at"`
	OccurredAt *time.Time `json:"occurred_at,omitempty"`

	State string `json:"state"`

	// DedupKey is a TRIPWIRE, not an input. We compute the key ourselves and
	// refuse the envelope if the peer's disagrees, which turns a mapping bug on
	// either side into a loud refusal rather than two incidents that never
	// merge.
	DedupKey string `json:"dedup_key,omitempty"`

	Condition string `json:"condition"`
	Severity  string `json:"severity"`

	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`

	Entity Party  `json:"entity"`
	Actor  *Party `json:"actor,omitempty"`

	// Context is rendered into the incident body, not stored typed. If it ever
	// needs to be queryable that is a store migration and a conversation.
	Context map[string]any `json:"context,omitempty"`
}

// Peer is what the operator approved at pairing.
type Peer struct {
	// Slug names the product and becomes the event's source, so it is also the
	// first segment of every dedup key this peer produces. Never hardcoded:
	// this channel is meant to carry more than one product.
	Slug string

	// Conditions is the manifest the operator approved. A condition outside it
	// is refused rather than bucketed, because a silent catch-all recreates the
	// open vocabulary that a closed one exists to prevent -- and hides the
	// peer's mapping bugs while it does so.
	Conditions map[string]bool

	// MaxSeverity optionally caps what this peer may claim. Empty means
	// uncapped, which is the default: the cascade is the point. It exists
	// because critical never gives up and quiet hours never apply to it, and
	// that is a lot of power to hand across a network boundary.
	MaxSeverity incident.Severity
}

var (
	ErrVersion     = errors.New("link: unsupported envelope version")
	ErrState       = errors.New("link: state must be raised or cleared")
	ErrCondition   = errors.New("link: condition is not in this peer's approved manifest")
	ErrSeverity    = errors.New("link: unknown severity")
	ErrDedupKey    = errors.New("link: the sender's dedup_key disagrees with the computed one")
	ErrMissing     = errors.New("link: required field is empty")
	ErrWrongPeer   = errors.New("link: envelope names a different product")
	ErrNoTimestamp = errors.New("link: sent_at is required")
)

// Validate checks an envelope against what the operator approved for this peer.
//
// Every refusal is a 400 rather than a silent repair. A coerced severity is a
// downgrade of exactly the cascade the peer is trying to express, and a
// silently accepted unknown condition becomes part of a STORED dedup key that
// nothing will ever merge with.
func (e Envelope) Validate(p Peer) error {
	if e.LinkVersion != Version {
		return fmt.Errorf("%w: %d (this build speaks %d)", ErrVersion, e.LinkVersion, Version)
	}
	if strings.TrimSpace(e.Product) == "" || !strings.EqualFold(e.Product, p.Slug) {
		return fmt.Errorf("%w: %q, paired peer is %q", ErrWrongPeer, e.Product, p.Slug)
	}
	for field, v := range map[string]string{
		"event_id":  e.EventID,
		"site_id":   e.SiteID,
		"condition": e.Condition,
		"title":     e.Title,
		"entity.id": e.Entity.ID,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%w: %s", ErrMissing, field)
		}
	}
	if e.SentAt.IsZero() {
		return ErrNoTimestamp
	}
	switch e.State {
	case StateRaised, StateCleared:
	default:
		return fmt.Errorf("%w: %q", ErrState, e.State)
	}
	if !p.Conditions[e.Condition] {
		return fmt.Errorf("%w: %q", ErrCondition, e.Condition)
	}
	sev := incident.Severity(e.Severity)
	if !sev.Valid() {
		return fmt.Errorf("%w: %q (want critical, high, medium, low or info)", ErrSeverity, e.Severity)
	}
	if want := e.dedupKeyFor(p); e.DedupKey != "" && e.DedupKey != want {
		return fmt.Errorf("%w: sender says %q, computed %q", ErrDedupKey, e.DedupKey, want)
	}
	return nil
}

// dedupKeyFor is the key this envelope produces, computed here rather than
// taken from the sender.
func (e Envelope) dedupKeyFor(p Peer) string {
	return incident.Key(p.Slug, e.Entity.ID, e.Condition)
}

// Event converts a validated envelope into an event this product's engine can
// decide on. Validate first; this assumes it passed.
func (e Envelope) Event(p Peer, receivedAt time.Time) event.Event {
	at := e.SentAt
	arrival := true
	if e.OccurredAt != nil && !e.OccurredAt.IsZero() {
		// The peer knows when the controller saw it, which for a denial lags
		// the moment the peer emitted. Treat that as the observation and say
		// so, because an alert presenting an arrival time as an observation
		// sends somebody scrubbing to the wrong point in the footage.
		at = *e.OccurredAt
		arrival = false
	}

	sev := incident.Severity(e.Severity)
	if p.MaxSeverity != "" && severityRank(sev) > severityRank(p.MaxSeverity) {
		sev = p.MaxSeverity
	}

	return event.Event{
		ID:     e.EventID,
		Source: p.Slug,
		Kind:   e.Condition,
		Entity: event.Entity{
			ID:   e.Entity.ID,
			Name: strings.TrimSpace(firstNonEmpty(e.Entity.Name, e.Entity.ID)),
			Kind: e.Entity.Kind,
		},
		Condition:       e.Condition,
		Clears:          e.State == StateCleared,
		At:              at,
		ReceivedAt:      receivedAt,
		AtIsArrivalTime: arrival,
		Severity:        sev,
		Title:           e.Title,
		Detail:          e.detailWithContext(),
	}
}

// detailWithContext renders the peer's context into the body.
//
// Deterministically ordered, because an incident body that reorders itself
// between two deliveries of the same event reads as two different events.
func (e Envelope) detailWithContext() string {
	if len(e.Context) == 0 {
		return e.Detail
	}
	keys := make([]string, 0, len(e.Context))
	for k := range e.Context {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString(e.Detail)
	for _, k := range keys {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s: %v", k, e.Context[k])
	}
	return b.String()
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func severityRank(s incident.Severity) int {
	switch s {
	case incident.SeverityCritical:
		return 5
	case incident.SeverityHigh:
		return 4
	case incident.SeverityMedium:
		return 3
	case incident.SeverityLow:
		return 2
	case incident.SeverityInfo:
		return 1
	}
	return 0
}
