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

func occurrenceEngine(t *testing.T, st incident.Store) (*Engine, *time.Time) {
	t.Helper()
	clk := t0
	var idMu sync.Mutex
	var n int
	e, err := New(st, nil,
		WithClock(func() time.Time { return clk }),
		WithIDs(func() string {
			idMu.Lock()
			defer idMu.Unlock()
			n++
			return fmt.Sprintf("i%d", n)
		}),
		// Per-occurrence: the peer's sale events. Nothing native.
		WithOccurrences(func(ev event.Event) bool { return ev.Source == "lsprotect" }))
	if err != nil {
		t.Fatal(err)
	}
	return e, &clk
}

func realStore(t *testing.T) *store.SQLite {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "incidents.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func voided(register, detail string) event.Event {
	return event.Event{
		Source: "lsprotect", Kind: "lsprotect-sale-voided",
		Entity:    event.Entity{ID: register, Name: "Register 1", Kind: "register"},
		Condition: "lsprotect-sale-voided", Severity: incident.SeverityMedium,
		Title: "Sale voided at Register 1", Detail: detail, At: t0,
	}
}

// A SECOND VOID AT THE SAME TILL WAS RECORDED NOWHERE.
//
// Folding a repeat into a live incident kept the first arrival's detail and
// discarded the rest, which is right for "the door is still open" and wrong
// for a second void: the incident said one sale was voided, and the second
// $340 existed in no record anyone could read.
func TestEveryOccurrenceIsKeptInFull(t *testing.T) {
	db := realStore(t)
	e, clk := occurrenceEngine(t, db)
	ctx := context.Background()

	for i, d := range []string{"invoice 1001, $12", "invoice 1002, $340", "invoice 1003, $8"} {
		*clk = t0.Add(time.Duration(i) * time.Minute)
		if _, err := e.Handle(ctx, voided("wv01-register-1", d)); err != nil {
			t.Fatal(err)
		}
	}

	inc, err := db.OpenByDedupKey(ctx, incident.Key("lsprotect", "wv01-register-1", "lsprotect-sale-voided"))
	if err != nil {
		t.Fatal(err)
	}
	if inc.Occurrences != 3 {
		t.Errorf("occurrences = %d, want 3 -- repeats were folded and not counted", inc.Occurrences)
	}
	if !strings.Contains(inc.Detail, "1003") {
		t.Errorf("the incident's detail is %q; an alert built from it describes an "+
			"earlier void, not the latest", inc.Detail)
	}

	got, err := db.Occurrences(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("stored %d occurrences, want 3", len(got))
	}
	want := []string{"1003", "1002", "1001"}
	for i, o := range got {
		if !strings.Contains(o.Detail, want[i]) || o.Seq != 3-i {
			t.Errorf("occurrence %d = seq %d %q, want seq %d with %s", i, o.Seq, o.Detail, 3-i, want[i])
		}
	}
}

// AN ACKNOWLEDGEMENT IS A REVIEW OF WHAT HAD ARRIVED WHEN IT WAS GIVEN.
//
// A void after a manager has looked at the earlier ones is something they
// have not seen. Folded silently into an incident marked as dealt with, it
// would never be delivered at all.
func TestAnOccurrenceAfterAnAcknowledgementAlertsAgain(t *testing.T) {
	db := realStore(t)
	e, clk := occurrenceEngine(t, db)
	ctx := context.Background()

	if _, err := e.Handle(ctx, voided("wv01-register-1", "invoice 1001")); err != nil {
		t.Fatal(err)
	}
	key := incident.Key("lsprotect", "wv01-register-1", "lsprotect-sale-voided")
	first, err := db.OpenByDedupKey(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	*clk = t0.Add(time.Minute)
	if err := first.Acknowledge(*clk, "ntfy"); err != nil {
		t.Fatal(err)
	}
	if err := db.Put(ctx, first); err != nil {
		t.Fatal(err)
	}

	*clk = t0.Add(10 * time.Minute)
	res, err := e.Handle(ctx, voided("wv01-register-1", "invoice 1002"))
	if err != nil {
		t.Fatal(err)
	}

	next, err := db.OpenByDedupKey(ctx, key)
	if err != nil {
		t.Fatalf("no live incident after a void that arrived after the acknowledgement: %v "+
			"-- it was folded into one marked as reviewed and will never be delivered", err)
	}
	if next.ID == first.ID || next.Acknowledged() {
		t.Fatalf("the new void is sitting in the acknowledged incident %s; nobody will "+
			"be told about it", first.ID)
	}
	if next.PredecessorID != first.ID {
		t.Errorf("the new incident does not link back to the one reviewed before it")
	}
	if res.Outcome != OutcomeRecurred {
		t.Errorf("outcome = %s, want recurred", res.Outcome)
	}

	old, err := db.Get(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !old.Terminal() || old.AckVia != "ntfy" {
		t.Errorf("the reviewed incident is %s acked via %q; its acknowledgement must "+
			"stay on the record exactly as it was given", old.State(), old.AckVia)
	}
}

// NOTHING CHANGES FOR A CONDITION THAT IS STATE. "Still offline", reported
// again, is not a new fact; counting it would page somebody every poll.
func TestAStateConditionIsNotCountedOrReopened(t *testing.T) {
	db := realStore(t)
	e, clk := occurrenceEngine(t, db)
	ctx := context.Background()

	if _, err := e.Handle(ctx, offline("cam-1")); err != nil {
		t.Fatal(err)
	}
	key := incident.Key("protect", "cam-1", event.ConditionOffline)
	inc, err := db.OpenByDedupKey(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	*clk = t0.Add(time.Minute)
	if err := inc.Acknowledge(*clk, "email"); err != nil {
		t.Fatal(err)
	}
	if err := db.Put(ctx, inc); err != nil {
		t.Fatal(err)
	}

	*clk = t0.Add(5 * time.Minute)
	if _, err := e.Handle(ctx, offline("cam-1")); err != nil {
		t.Fatal(err)
	}
	still, err := db.OpenByDedupKey(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if still.ID != inc.ID || !still.Acknowledged() {
		t.Error("a camera still offline, reported again, reopened an acknowledged incident")
	}
	if still.Occurrences != 1 {
		t.Errorf("a repeated state report was counted as occurrence %d", still.Occurrences)
	}
	if got, _ := db.Occurrences(ctx, inc.ID); len(got) != 0 {
		t.Errorf("a state condition's repeats were stored as %d occurrences", len(got))
	}
}

// racyStore acknowledges the incident the moment the engine tries to write
// its fold -- the race a plain write would lose.
type racyStore struct {
	*store.SQLite
	at    time.Time
	fired bool
}

func (r *racyStore) PutIfUnchanged(ctx context.Context, inc *incident.Incident, expect time.Time) error {
	if !r.fired {
		r.fired = true
		cur, err := r.SQLite.Get(ctx, inc.ID)
		if err != nil {
			return err
		}
		if err := cur.Acknowledge(r.at, "voice"); err != nil {
			return err
		}
		if err := r.SQLite.Put(ctx, cur); err != nil {
			return err
		}
	}
	return r.SQLite.PutIfUnchanged(ctx, inc, expect)
}

// A MANAGER ACKNOWLEDGING WHILE AN OCCURRENCE IS BEING FOLDED.
//
// The old fold wrote only when a severity rose; this one writes on every
// arrival, so the window between reading an incident and writing it back is
// hit constantly on a busy till. A plain write in that window erases the
// acknowledgement -- the one write this product must never lose.
func TestAnAcknowledgementLandingMidFoldIsNotErased(t *testing.T) {
	db := realStore(t)
	racy := &racyStore{SQLite: db, fired: true} // quiet while the incident opens
	e, clk := occurrenceEngine(t, racy)
	ctx := context.Background()

	if _, err := e.Handle(ctx, voided("wv01-register-1", "invoice 1001")); err != nil {
		t.Fatal(err)
	}
	key := incident.Key("lsprotect", "wv01-register-1", "lsprotect-sale-voided")
	first, err := db.OpenByDedupKey(ctx, key)
	if err != nil {
		t.Fatal(err)
	}

	racy.fired, racy.at = false, t0.Add(30*time.Second)
	*clk = t0.Add(time.Minute)
	if _, err := e.Handle(ctx, voided("wv01-register-1", "invoice 1002")); err != nil && !errors.Is(err, incident.ErrConflict) {
		t.Fatal(err)
	}

	old, err := db.Get(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !old.Acknowledged() || old.AckVia != "voice" {
		t.Fatalf("the acknowledgement given while the second void was being folded was "+
			"ERASED (acked=%v via %q)", old.Acknowledged(), old.AckVia)
	}
	next, err := db.OpenByDedupKey(ctx, key)
	if err != nil || next.ID == first.ID {
		t.Errorf("the void that raced the acknowledgement was not given its own "+
			"incident, so nobody is told about it (err %v)", err)
	}
}
