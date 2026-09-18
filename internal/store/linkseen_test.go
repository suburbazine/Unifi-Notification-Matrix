package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

var seenAt = time.Date(2026, 9, 18, 6, 0, 0, 0, time.UTC)

func TestAnEventIdIsSeenOnlyOnce(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	first, err := s.SeenEvent(ctx, "lnk_a", "evt-1", seenAt, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if first {
		t.Error("a brand new event id was reported as already seen")
	}

	again, err := s.SeenEvent(ctx, "lnk_a", "evt-1", seenAt.Add(time.Second), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !again {
		t.Error("a repeated event id was not recognised; the alarm would be raised twice")
	}
}

// Scoped by link. Two peers choosing the same event id is legitimate, and one
// peer must never be able to suppress another's events by guessing them.
func TestEventIdsDoNotCollideAcrossLinks(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if _, err := s.SeenEvent(ctx, "lnk_a", "shared", seenAt, time.Hour); err != nil {
		t.Fatal(err)
	}
	seen, err := s.SeenEvent(ctx, "lnk_b", "shared", seenAt, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Error("one peer's event id suppressed another peer's event")
	}
}

// THE REASON THIS IS ON DISK RATHER THAN IN MEMORY.
//
// A restart during an alarm is exactly when a peer is retrying, so the record
// has to outlive the process. In memory it would be lost precisely when it
// matters and the alarm would be raised a second time.
func TestAnEventIdSurvivesARestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "incidents.db")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SeenEvent(ctx, "lnk_a", "evt-1", seenAt, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })

	seen, err := again.SeenEvent(ctx, "lnk_a", "evt-1", seenAt.Add(time.Minute), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Error("the event id did not survive a restart; a retry across one would double-raise")
	}
}

// Past its window an id is forgotten, so the table cannot grow for ever and a
// genuinely new event reusing an old id is not wrongly suppressed.
func TestAnEventIdExpires(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if _, err := s.SeenEvent(ctx, "lnk_a", "evt-1", seenAt, time.Hour); err != nil {
		t.Fatal(err)
	}
	seen, err := s.SeenEvent(ctx, "lnk_a", "evt-1", seenAt.Add(2*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Error("an id well past its window still suppressed an event")
	}
}

// A retry must not extend the window: letting it would let a peer keep one id
// alive indefinitely by repeating it.
func TestARetryDoesNotExtendTheWindow(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if _, err := s.SeenEvent(ctx, "lnk_a", "evt-1", seenAt, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Repeated at 45 minutes: still inside the window, so still a duplicate.
	if seen, _ := s.SeenEvent(ctx, "lnk_a", "evt-1", seenAt.Add(45*time.Minute), time.Hour); !seen {
		t.Fatal("the id was forgotten early")
	}
	// At 70 minutes it must be gone, measured from the FIRST sighting.
	if seen, _ := s.SeenEvent(ctx, "lnk_a", "evt-1", seenAt.Add(70*time.Minute), time.Hour); seen {
		t.Error("a retry extended the window; an id could be kept alive for ever")
	}
}

// Forgetting is what stops a failed ingest from turning the peer's retry into
// a duplicate of an incident that never existed.
func TestForgettingAnEventIdLetsItBeAcceptedAgain(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if _, err := s.SeenEvent(ctx, "lnk_a", "evt-1", seenAt, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetEvent(ctx, "lnk_a", "evt-1"); err != nil {
		t.Fatal(err)
	}
	if seen, _ := s.SeenEvent(ctx, "lnk_a", "evt-1", seenAt.Add(time.Second), time.Hour); seen {
		t.Error("a forgotten id was still treated as seen")
	}
}

// A bounded table that prunes beats one that grows. The oldest ids go first,
// because they are the ones a retry can no longer be referring to.
func TestThePerLinkTableIsBounded(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	// Filled by direct insert rather than through SeenEvent: the trim is one
	// DELETE and driving it through four thousand transactions made this the
	// slowest test in the package for no extra coverage.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxSeenPerLink+49; i++ {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO link_seen_events (link_id, event_id, seen_at) VALUES (?, ?, ?)`,
			"lnk_a", fmt.Sprintf("evt-%05d", i),
			seenAt.Add(time.Duration(i)*time.Millisecond).UTC().Format(timeLayout)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// One real call to trigger the trim, and it is the newest id.
	last := fmt.Sprintf("evt-%05d", MaxSeenPerLink+49)
	if _, err := s.SeenEvent(ctx, "lnk_a", last,
		seenAt.Add(time.Duration(MaxSeenPerLink+49)*time.Millisecond), time.Hour); err != nil {
		t.Fatal(err)
	}

	var rows int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM link_seen_events WHERE link_id = ?`, "lnk_a").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows > MaxSeenPerLink {
		t.Errorf("%d rows kept, want at most %d", rows, MaxSeenPerLink)
	}
	// The most recent id is still there, which is the one a retry would name.
	if seen, _ := s.SeenEvent(ctx, "lnk_a", last, seenAt.Add(time.Minute), time.Hour); !seen {
		t.Error("pruning dropped the most recent id rather than the oldest")
	}
}
