package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// THE COUNT IS NEVER CAPPED; THE DETAIL IS.
//
// A register that voids dozens of sales in a day must keep an exact total and
// the most recent ones in full -- and must not grow the database without
// bound doing it. Both halves are pinned: pruning that never happens is a
// slow leak, and pruning that takes the newest instead of the oldest keeps a
// morning nobody cares about and discards the afternoon.
func TestOccurrencesAreBoundedAndKeepTheNewest(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "incidents.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	t0 := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)

	const keep = 5
	for seq := 1; seq <= 12; seq++ {
		if err := s.AddOccurrence(ctx, "inc-1", incident.Occurrence{
			Seq: seq, At: t0.Add(time.Duration(seq) * time.Minute),
			Severity: incident.SeverityMedium, Title: "void", Detail: "sale " + string(rune('A'+seq)),
		}, keep); err != nil {
			t.Fatal(err)
		}
	}
	// Another incident's occurrences are not this one's to prune.
	if err := s.AddOccurrence(ctx, "inc-2", incident.Occurrence{Seq: 1, At: t0,
		Severity: incident.SeverityLow, Title: "other", Detail: "x"}, keep); err != nil {
		t.Fatal(err)
	}

	got, err := s.Occurrences(ctx, "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != keep {
		t.Fatalf("kept %d occurrences, want the most recent %d -- the table is not bounded", len(got), keep)
	}
	if got[0].Seq != 12 || got[len(got)-1].Seq != 8 {
		t.Errorf("kept seq %d..%d, want 12..8, newest first -- pruning dropped the "+
			"wrong end", got[0].Seq, got[len(got)-1].Seq)
	}
	if !got[0].At.Equal(t0.Add(12*time.Minute)) || got[0].Severity != incident.SeverityMedium {
		t.Errorf("occurrence round-tripped as %+v", got[0])
	}

	other, err := s.Occurrences(ctx, "inc-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 1 {
		t.Errorf("pruning one incident's occurrences touched another's: %d left", len(other))
	}
}

// The count on the incident survives the round trip -- it is the half that is
// never capped, so it has to be the half that is stored reliably.
func TestTheOccurrenceCountIsStoredWithTheIncident(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "incidents.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)

	inc := incident.Open("inc-1", "lsprotect/wv01-register-1/lsprotect-sale-voided",
		incident.SeverityMedium, "lsprotect", "Sale voided", "first", now)
	if inc.Occurrences != 1 {
		t.Fatalf("a new incident has %d occurrences, want 1", inc.Occurrences)
	}
	// Stored FIRST, so the writes below go through the update paths -- an
	// insert-only test cannot tell whether an update carries the count.
	if err := s.Put(ctx, inc); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 140; i++ {
		if _, err := inc.Occur(now.Add(time.Minute), incident.SeverityMedium, "Sale voided", "again"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Put(ctx, inc); err != nil {
		t.Fatal(err)
	}
	back, err := s.Get(ctx, "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if back.Occurrences != 141 {
		t.Errorf("occurrences = %d after a round trip, want 141 -- the total is "+
			"the half that must never be capped", back.Occurrences)
	}

	// And through the compare-and-swap path the scheduler writes with.
	expect := back.UpdatedAt
	if _, err := back.Occur(now.Add(2*time.Minute), incident.SeverityMedium, "Sale voided", "once more"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutIfUnchanged(ctx, back, expect); err != nil {
		t.Fatal(err)
	}
	again, err := s.Get(ctx, "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if again.Occurrences != 142 {
		t.Errorf("occurrences = %d after a compare-and-swap write, want 142", again.Occurrences)
	}
}
