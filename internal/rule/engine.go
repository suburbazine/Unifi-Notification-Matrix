package rule

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Outcome is what the engine did with an event.
type Outcome string

const (
	// OutcomeOpened created a new incident.
	OutcomeOpened Outcome = "opened"

	// OutcomeUpdated folded the event into an incident that was already open.
	// This is the storm case: fifty flaps become one incident.
	OutcomeUpdated Outcome = "updated"

	// OutcomeRecurred created a new incident linked to a closed predecessor.
	OutcomeRecurred Outcome = "recurred"

	// OutcomeResolved marked the condition as ended.
	OutcomeResolved Outcome = "resolved"

	// OutcomeIgnored matched an explicit ignore rule.
	OutcomeIgnored Outcome = "ignored"

	// OutcomeNoop is a clear for a condition that was not open. Not an error:
	// a reconciliation sweep reports everything it finds healthy, most of
	// which was never a problem.
	OutcomeNoop Outcome = "noop"
)

// Result describes what happened, for the audit record and diagnostics.
type Result struct {
	Outcome  Outcome
	Incident *incident.Incident
	Decision Decision
}

// Engine applies rules to events and maintains incidents.
//
// Safe for concurrent use: several sources emit at once, and two events for
// the same condition arriving together is the ordinary case, not an edge one.
type Engine struct {
	store incident.Store
	now   func() time.Time
	newID func() string

	mu    sync.RWMutex
	rules Set

	// onDecision records what the engine concluded. Set via WithAuditHook.
	onDecision func(Result, event.Event)

	// loc is the site's zone, for rule windows. The daemon commonly runs on a
	// server whose clock is UTC while the site it watches is not, so a window
	// evaluated in the host's zone is active at the wrong hours.
	loc *time.Location
}

// Option configures an Engine.
type Option func(*Engine)

// WithClock injects a clock so tests need not sleep.
//
// Must be safe for concurrent use: several sources emit at once and Handle
// does not serialise them.
func WithClock(f func() time.Time) Option { return func(e *Engine) { e.now = f } }

// WithAuditHook records every decision, including the ones that silenced an
// event.
//
// Ignores are audited as deliberately as alerts. "Why was I not paged" is the
// harder question and it is unanswerable unless the silences are written down.
func WithAuditHook(f func(Result, event.Event)) Option {
	return func(e *Engine) { e.onDecision = f }
}

// WithIDs injects the incident id generator.
//
// Must be safe for concurrent use -- Handle calls it from whatever goroutine
// the event arrived on. The default (randomID) is, because crypto/rand is; a
// test that substituted a bare counter tripped the race detector, which is how
// this requirement came to be written down.
func WithIDs(f func() string) Option { return func(e *Engine) { e.newID = f } }

// New builds an engine.
func New(store incident.Store, rules Set, opts ...Option) (*Engine, error) {
	if store == nil {
		return nil, errors.New("rule: engine needs a store")
	}
	if err := rules.Validate(); err != nil {
		return nil, fmt.Errorf("rule: %w", err)
	}
	e := &Engine{store: store, rules: rules, now: time.Now, newID: randomID, loc: time.Local}
	for _, o := range opts {
		o(e)
	}
	return e, nil
}

// WithLocation sets the zone that rule windows are evaluated in. Production
// passes the site's configured zone; the default is the host's own clock.
func WithLocation(loc *time.Location) Option {
	return func(e *Engine) {
		if loc != nil {
			e.loc = loc
		}
	}
}

// SetRules replaces the rule set, for a config reload.
func (e *Engine) SetRules(rules Set) error {
	if err := rules.Validate(); err != nil {
		return fmt.Errorf("rule: %w", err)
	}
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
	return nil
}

func (e *Engine) ruleSet() Set {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules
}

// createAttempts bounds the retry when two events race to open the same
// incident.
//
// The store enforces at-most-one live incident per dedup key in its schema, so
// the loser of a race gets ErrActiveExists rather than a duplicate. Retrying
// re-reads and folds into the winner, which is exactly what should happen: a
// flapping camera seen by two goroutines is still one problem.
const createAttempts = 3

// Handle applies the rules to an event and updates the store.
func (e *Engine) Handle(ctx context.Context, ev event.Event) (Result, error) {
	res, err := e.handle(ctx, ev)
	if err == nil && e.onDecision != nil {
		e.onDecision(res, ev)
	}
	return res, err
}

func (e *Engine) handle(ctx context.Context, ev event.Event) (Result, error) {
	d := e.ruleSet().DecideIn(ev, e.loc)
	if d.Ignore {
		return Result{Outcome: OutcomeIgnored, Decision: d}, nil
	}

	key := ev.DedupKey()
	now := e.now()

	// A CLEAR never opens anything. "The camera is back" is not news unless we
	// were worried about it, and opening an incident to say something is fine
	// is how a product teaches people to ignore it.
	if ev.Clears {
		return e.resolve(ctx, key, d, now)
	}

	for attempt := 0; attempt < createAttempts; attempt++ {
		open, err := e.store.OpenByDedupKey(ctx, key)
		switch {
		case err == nil:
			// A RESOLVED incident that nobody ever acknowledged is not
			// something to fold into. It is still non-terminal, so it is what
			// this lookup finds, but the scheduler will never alert on it
			// again -- Policy.NextDue refuses anything Resolved.
			//
			// So folding the new event in buried it completely: door forced at
			// 03:00, door closes at 03:05 having woken nobody, door forced
			// again at 03:30 -- and the second forcing joined a corpse. No
			// alert, then or ever, for either one.
			//
			// Closing it here makes the next pass through this loop find
			// nothing live and open a fresh incident linked to this one as its
			// predecessor, which is what a condition that cleared and came
			// back has always been meant to produce.
			if open.Resolved() && !open.Acknowledged() {
				open.Close(now, "the condition returned before anybody acknowledged it")
				if err := e.store.Put(ctx, open); err != nil {
					return Result{}, err
				}
				continue
			}

			// Already live: fold in. Deliberately does NOT re-alert or reset
			// the escalation ladder -- a camera flapping fifty times a minute
			// is one incident nagging on its own schedule, not fifty alerts.
			if err := e.update(ctx, open, ev, d, now); err != nil {
				return Result{}, err
			}
			return Result{Outcome: OutcomeUpdated, Incident: open, Decision: d}, nil

		case errors.Is(err, incident.ErrNotFound):
			// Nothing live. Link to a closed predecessor if there is one.
			res, err := e.open(ctx, key, ev, d, now)
			if errors.Is(err, incident.ErrActiveExists) {
				// Lost the race with a concurrent event for the same
				// condition. Re-read and fold into the winner: a flapping
				// camera seen by two goroutines is still one problem.
				continue
			}
			if err != nil {
				return Result{}, err
			}
			return res, nil

		default:
			return Result{}, fmt.Errorf("rule: looking up %s: %w", key, err)
		}
	}
	return Result{}, fmt.Errorf("rule: %s changed under every attempt to open it", key)
}

func (e *Engine) open(ctx context.Context, key string, ev event.Event, d Decision, now time.Time) (Result, error) {
	title, detail := render(ev, d)

	// A condition that cleared and came back is a NEW incident linked to its
	// predecessor, never a revival. Reviving would carry the old
	// acknowledgement onto an event the acknowledger never saw.
	prev, err := e.store.LatestByDedupKey(ctx, key)
	outcome := OutcomeOpened
	var inc *incident.Incident
	switch {
	case err == nil && prev.Terminal():
		inc = prev.Recur(e.newID(), now)
		inc.Severity = d.Severity
		inc.Title, inc.Detail = title, detail
		outcome = OutcomeRecurred
	case err == nil || errors.Is(err, incident.ErrNotFound):
		inc = incident.Open(e.newID(), key, d.Severity, ev.Source, title, detail, now)
	default:
		return Result{}, fmt.Errorf("rule: looking up the history of %s: %w", key, err)
	}

	if err := e.store.Put(ctx, inc); err != nil {
		return Result{}, err
	}
	return Result{Outcome: outcome, Incident: inc, Decision: d}, nil
}

// update folds a repeat event into a live incident.
func (e *Engine) update(ctx context.Context, inc *incident.Incident, ev event.Event, d Decision, now time.Time) error {
	changed := false

	// Severity can only go UP on a live incident. A later, milder event must
	// not quietly downgrade an alarm that is already escalating -- a smoke
	// sensor reporting a routine test after reporting smoke does not make the
	// smoke less urgent.
	if severityRank(d.Severity) > severityRank(inc.Severity) {
		inc.Severity = d.Severity
		changed = true
	}
	if t, _ := render(ev, d); t != "" && inc.Title == "" {
		inc.Title = t
		changed = true
	}
	if !changed {
		return nil
	}
	inc.UpdatedAt = now
	return e.store.Put(ctx, inc)
}

func (e *Engine) resolve(ctx context.Context, key string, d Decision, now time.Time) (Result, error) {
	open, err := e.store.OpenByDedupKey(ctx, key)
	if errors.Is(err, incident.ErrNotFound) {
		return Result{Outcome: OutcomeNoop, Decision: d}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("rule: looking up %s: %w", key, err)
	}
	if err := open.Resolve(now); err != nil {
		// Terminal already. Nothing to do and nothing wrong.
		return Result{Outcome: OutcomeNoop, Incident: open, Decision: d}, nil
	}
	if err := e.store.Put(ctx, open); err != nil {
		return Result{}, err
	}
	return Result{Outcome: OutcomeResolved, Incident: open, Decision: d}, nil
}

// RaiseInternal opens an incident about the product itself.
//
// This is how a crash, or a source that has gone silent, becomes something
// that escalates rather than a line in a log nobody reads (ARCHITECTURE.md §9
// and §9a). It bypasses the rule set on purpose: an operator ignore rule aimed
// at a noisy camera must not be able to silence the product reporting its own
// failure.
func (e *Engine) RaiseInternal(ctx context.Context, condition string, sev incident.Severity, title, detail string) (Result, error) {
	return e.RaiseInternalFor(ctx, selfEntity(), condition, sev, title, detail)
}

// selfEntity is the product itself, for internal incidents about the whole
// service rather than about one part of it.
func selfEntity() event.Entity {
	return event.Entity{ID: "notifymatrix", Name: "NotifyMatrix", Kind: "service"}
}

// RaiseInternalFor opens an internal incident against a named part of the
// product.
//
// The entity matters because internal faults are not all the same fault. A
// deadman firing for the Protect source and one firing for Access are two
// problems with two fixes, and collapsing them into one incident -- which is
// what a fixed entity does, through the dedup key -- means the second one is
// absorbed as an update to the first and nobody is ever told about it.
func (e *Engine) RaiseInternalFor(ctx context.Context, ent event.Entity, condition string, sev incident.Severity, title, detail string) (Result, error) {
	ev := event.Event{
		Source:     "internal",
		Kind:       condition,
		Entity:     ent,
		Condition:  condition,
		Severity:   sev,
		Title:      title,
		Detail:     detail,
		At:         e.now(),
		ReceivedAt: e.now(),
	}
	d := Decision{Severity: sev, MatchedBy: []string{"internal"}}
	key := ev.DedupKey()

	if open, err := e.store.OpenByDedupKey(ctx, key); err == nil {
		return Result{Outcome: OutcomeUpdated, Incident: open, Decision: d}, nil
	} else if !errors.Is(err, incident.ErrNotFound) {
		return Result{}, err
	}
	return e.open(ctx, key, ev, d, e.now())
}

// ResolveInternalFor closes an internal incident when the fault it described
// has stopped.
//
// Symmetric with RaiseInternalFor and not optional: a deadman that can raise
// but never resolve leaves a source that recovered nagging forever, and the
// operator learns to ignore the one message that means the product itself is
// broken.
func (e *Engine) ResolveInternalFor(ctx context.Context, ent event.Entity, condition string) (Result, error) {
	key := incident.Key("internal", ent.ID, condition)
	return e.resolve(ctx, key, Decision{MatchedBy: []string{"internal"}}, e.now())
}

// render builds the alert text.
func render(ev event.Event, d Decision) (title, detail string) {
	title = ev.Title
	if title == "" {
		name := ev.Entity.Name
		if name == "" {
			name = ev.Entity.ID
		}
		if name == "" {
			name = ev.Source
		}
		title = fmt.Sprintf("%s: %s", name, humanise(ev.Condition))
	}

	var b strings.Builder
	if ev.Detail != "" {
		b.WriteString(ev.Detail)
	}
	if ev.Entity.Name != "" || ev.Entity.ID != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s: %s", strings.Title(ev.Entity.Kind), coalesce(ev.Entity.Name, ev.Entity.ID))
	}
	if !ev.At.IsZero() {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		// "received" rather than "at" when the source supplied no time of its
		// own. An arrival time presented as an observation time sends somebody
		// scrubbing footage to a moment that means nothing.
		word := "At"
		if ev.AtIsArrivalTime {
			word = "Received"
		}
		fmt.Fprintf(&b, "%s: %s", word, ev.At.UTC().Format(time.RFC3339))
	}
	if len(d.MatchedBy) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Rule: %s", strings.Join(d.MatchedBy, ", "))
	}
	return title, b.String()
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func humanise(condition string) string {
	return strings.ReplaceAll(condition, "-", " ")
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

// randomID is the default incident id: random rather than sequential.
//
// A sequential id leaks how many incidents a site has had, and incident ids
// travel in acknowledgement URLs that reach phones and mail servers.
func randomID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Cannot happen on any supported platform, and a panic here is
		// preferable to a predictable id in an ack URL.
		panic("rule: no randomness available for incident ids: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
