package rule

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
)

var t0 = time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

// Tested against the REAL store, not a fake. The dedup guarantee this engine
// leans on lives in the schema's partial unique index, and a fake would be
// asserting my own assumption back at me.
func newEngine(t *testing.T, rules Set) (*Engine, *store.SQLite, *time.Time) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "incidents.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	clk := t0
	var n int
	e, err := New(db, rules,
		WithClock(func() time.Time { return clk }),
		WithIDs(func() string { n++; return fmt.Sprintf("i%d", n) }))
	if err != nil {
		t.Fatal(err)
	}
	return e, db, &clk
}

func offline(entity string) event.Event {
	return event.Event{
		Source:    "protect",
		Kind:      "deviceUpdate",
		Entity:    event.Entity{ID: entity, Name: "Front Door Cam", Kind: "camera"},
		Condition: event.ConditionOffline,
		Severity:  incident.SeverityHigh,
		At:        t0,
	}
}

// THE STORM CASE. A camera on a failing PoE port emits fifty events a minute.
// That is ONE incident, which re-alerts on its own schedule -- otherwise the
// first genuine alarm storm teaches the operator to ignore the product.
func TestAnEventStormCollapsesToOneIncident(t *testing.T) {
	e, db, _ := newEngine(t, nil)
	ctx := context.Background()

	first, err := e.Handle(ctx, offline("cam-1"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != OutcomeOpened {
		t.Fatalf("first event = %s, want opened", first.Outcome)
	}

	for i := 0; i < 49; i++ {
		r, err := e.Handle(ctx, offline("cam-1"))
		if err != nil {
			t.Fatal(err)
		}
		if r.Outcome != OutcomeUpdated {
			t.Fatalf("event %d = %s, want updated", i+2, r.Outcome)
		}
	}

	active, err := db.Active(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("50 events produced %d incidents, want 1", len(active))
	}
	// Folding an event in must NOT re-alert or reset the ladder.
	if active[0].AlertCount != 0 || active[0].LastAlertAt != nil {
		t.Error("folding events in advanced the escalation ladder")
	}
}

// Two goroutines racing to open the same condition must still produce one
// incident: the store refuses the loser and the engine folds into the winner.
func TestConcurrentEventsForOneConditionProduceOneIncident(t *testing.T) {
	e, db, _ := newEngine(t, nil)
	ctx := context.Background()

	const n = 12
	var wg sync.WaitGroup
	outcomes := make([]Outcome, n)
	errs := make([]error, n)
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			r, err := e.Handle(ctx, offline("cam-race"))
			outcomes[i], errs[i] = r.Outcome, err
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	active, err := db.Active(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("%d concurrent events produced %d incidents, want 1", n, len(active))
	}
	opened := 0
	for _, o := range outcomes {
		if o == OutcomeOpened {
			opened++
		}
	}
	if opened != 1 {
		t.Errorf("%d goroutines reported opening it, want exactly 1", opened)
	}
}

// A clear resolves; it never opens anything. Opening an incident to announce
// that something is fine is how a product teaches people to ignore it.
func TestAClearResolvesAndNeverOpens(t *testing.T) {
	e, db, _ := newEngine(t, nil)
	ctx := context.Background()

	clear := offline("cam-1")
	clear.Clears = true

	r, err := e.Handle(ctx, clear)
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != OutcomeNoop {
		t.Fatalf("a clear with nothing open = %s, want noop", r.Outcome)
	}
	if active, _ := db.Active(ctx); len(active) != 0 {
		t.Fatal("a clear opened an incident")
	}

	if _, err := e.Handle(ctx, offline("cam-1")); err != nil {
		t.Fatal(err)
	}
	r, err = e.Handle(ctx, clear)
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != OutcomeResolved {
		t.Fatalf("a clear on a live incident = %s, want resolved", r.Outcome)
	}
	if !r.Incident.Resolved() {
		t.Error("the incident was not marked resolved")
	}
}

// A condition that cleared and came back is a NEW incident linked to its
// predecessor. Reviving would carry an old acknowledgement onto an event the
// acknowledger never saw.
func TestARecurrenceIsANewIncidentLinkedToItsPredecessor(t *testing.T) {
	e, db, clk := newEngine(t, nil)
	ctx := context.Background()

	first, err := e.Handle(ctx, offline("cam-1"))
	if err != nil {
		t.Fatal(err)
	}
	// Acknowledge and resolve it, which makes it terminal.
	inc := first.Incident
	if err := inc.Acknowledge(t0.Add(time.Minute), "ntfy"); err != nil {
		t.Fatal(err)
	}
	if err := inc.Resolve(t0.Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := db.Put(ctx, inc); err != nil {
		t.Fatal(err)
	}
	if !inc.Terminal() {
		t.Fatal("test precondition: the first incident should be terminal")
	}

	*clk = t0.Add(time.Hour)
	again, err := e.Handle(ctx, offline("cam-1"))
	if err != nil {
		t.Fatal(err)
	}
	if again.Outcome != OutcomeRecurred {
		t.Fatalf("outcome = %s, want recurred", again.Outcome)
	}
	if again.Incident.ID == inc.ID {
		t.Fatal("the closed incident was revived instead of a new one opened")
	}
	if again.Incident.PredecessorID != inc.ID {
		t.Errorf("PredecessorID = %q, want %q", again.Incident.PredecessorID, inc.ID)
	}
	if again.Incident.Acknowledged() {
		t.Fatal("the recurrence inherited the predecessor's acknowledgement, so " +
			"an old ack now applies to an event nobody saw")
	}
}

// Severity may rise on a live incident and must never fall: a smoke sensor
// reporting a routine test after reporting smoke does not make the smoke less
// urgent.
func TestSeverityRisesButNeverFallsOnALiveIncident(t *testing.T) {
	e, _, _ := newEngine(t, nil)
	ctx := context.Background()

	low := offline("cam-1")
	low.Severity = incident.SeverityLow
	if _, err := e.Handle(ctx, low); err != nil {
		t.Fatal(err)
	}

	high := offline("cam-1")
	high.Severity = incident.SeverityCritical
	r, err := e.Handle(ctx, high)
	if err != nil {
		t.Fatal(err)
	}
	if r.Incident.Severity != incident.SeverityCritical {
		t.Errorf("severity = %s, want it raised to critical", r.Incident.Severity)
	}

	back := offline("cam-1")
	back.Severity = incident.SeverityInfo
	r, err = e.Handle(ctx, back)
	if err != nil {
		t.Fatal(err)
	}
	if r.Incident.Severity != incident.SeverityCritical {
		t.Errorf("severity = %s; a milder later event downgraded a live alarm",
			r.Incident.Severity)
	}
}

func TestAnIgnoreRuleDropsTheEvent(t *testing.T) {
	e, db, _ := newEngine(t, Set{{
		Name:     "flapping camera in the car park",
		Entities: []string{"cam-flappy"},
		Ignore:   true,
	}})
	ctx := context.Background()

	r, err := e.Handle(ctx, offline("cam-flappy"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != OutcomeIgnored {
		t.Fatalf("outcome = %s, want ignored", r.Outcome)
	}
	if active, _ := db.Active(ctx); len(active) != 0 {
		t.Error("an ignored event still opened an incident")
	}
	// The rule that silenced it must be named: "why was I not paged" is the
	// harder question, and it is unanswerable if ignores are anonymous.
	if len(r.Decision.MatchedBy) == 0 {
		t.Error("the ignore did not record which rule was responsible")
	}

	// A different camera is unaffected.
	other, err := e.Handle(ctx, offline("cam-1"))
	if err != nil {
		t.Fatal(err)
	}
	if other.Outcome != OutcomeOpened {
		t.Errorf("an unrelated camera was also silenced: %s", other.Outcome)
	}
}

// An operator ignore rule aimed at a noisy camera must not be able to silence
// the product reporting its own failure.
func TestRaiseInternalBypassesIgnoreRules(t *testing.T) {
	e, db, _ := newEngine(t, Set{{
		Name:       "silence everything from internal",
		Sources:    []string{"internal"},
		Conditions: []string{"*"},
		Ignore:     true,
	}})
	ctx := context.Background()

	r, err := e.RaiseInternal(ctx, event.ConditionUncleanShutdown,
		incident.SeverityHigh, "notifymatrix crashed", "the previous run died")
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != OutcomeOpened {
		t.Fatalf("outcome = %s, want opened despite the ignore rule", r.Outcome)
	}
	if active, _ := db.Active(ctx); len(active) != 1 {
		t.Fatal("an ignore rule silenced the product reporting its own crash")
	}
}

// Raising the same internal condition twice while it is still open must not
// stack up duplicates -- a crash loop restarting every five seconds would
// otherwise produce an incident per restart.
func TestRaiseInternalIsIdempotentWhileOpen(t *testing.T) {
	e, db, _ := newEngine(t, nil)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := e.RaiseInternal(ctx, event.ConditionUncleanShutdown,
			incident.SeverityHigh, "crashed", "again"); err != nil {
			t.Fatal(err)
		}
	}
	active, _ := db.Active(ctx)
	if len(active) != 1 {
		t.Fatalf("five crash reports produced %d incidents, want 1", len(active))
	}
}

// The same real-world problem reported by two different routes must collapse
// to one incident -- that is what the dedup key is for.
func TestTheSameConditionFromTwoRoutesIsOneIncident(t *testing.T) {
	e, db, _ := newEngine(t, nil)
	ctx := context.Background()

	viaSocket := offline("cam-1")
	viaWebhook := offline("cam-1")
	viaWebhook.Kind = "alarmManagerWebhook"
	viaWebhook.Entity.MAC = "aa:bb:cc:dd:ee:ff"
	viaWebhook.AtIsArrivalTime = true

	if _, err := e.Handle(ctx, viaSocket); err != nil {
		t.Fatal(err)
	}
	r, err := e.Handle(ctx, viaWebhook)
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != OutcomeUpdated {
		t.Fatalf("the webhook route = %s, want updated -- the same problem "+
			"arriving twice is one incident", r.Outcome)
	}
	if active, _ := db.Active(ctx); len(active) != 1 {
		t.Fatal("two routes produced two incidents for one problem")
	}
}

// An arrival time presented as an observation time sends somebody scrubbing
// footage to a moment that means nothing.
func TestAnArrivalTimeIsLabelledAsReceived(t *testing.T) {
	e, _, _ := newEngine(t, nil)
	ctx := context.Background()

	ev := offline("cam-1")
	ev.AtIsArrivalTime = true
	r, err := e.Handle(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Incident.Detail, "Received:") {
		t.Errorf("detail presents an arrival time as an observation time:\n%s",
			r.Incident.Detail)
	}

	ev2 := offline("cam-2")
	r2, err := e.Handle(ctx, ev2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r2.Incident.Detail, "At:") {
		t.Errorf("a real observation time was not labelled 'At':\n%s", r2.Incident.Detail)
	}
}

func TestIncidentIDsAreNotSequential(t *testing.T) {
	// Ids travel in acknowledgement URLs that reach phones and mail servers; a
	// sequential one leaks how many incidents a site has had.
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id := randomID()
		if seen[id] {
			t.Fatalf("duplicate id after %d draws: %s", i, id)
		}
		if len(id) < 16 {
			t.Fatalf("id %q is too short to be unguessable", id)
		}
		seen[id] = true
	}
}

func TestEngineRefusesABadRuleSet(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := New(db, Set{{Name: "blanket", Ignore: true}}); !errors.Is(err, ErrBlanketIgnore) {
		t.Fatalf("New with a blanket ignore = %v, want ErrBlanketIgnore", err)
	}
}
