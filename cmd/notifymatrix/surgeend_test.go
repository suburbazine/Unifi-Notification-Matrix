package main

import (
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/surge"
)

// The whole path against the real database: count events, cross a boundary,
// find a row, and have it judged.
//
// The unit tests either side of this use a fake store, so nothing else proves
// that what the recorder writes is what the baseline later reads -- which is
// the join two of tonight's bugs lived in.
func TestActivityReachesTheDatabaseAndIsJudged(t *testing.T) {
	db, err := store.Open(t.TempDir() + "/incidents.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Date(2026, 9, 22, 3, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	// A fortnight of quiet weekday history, so the baseline is earned and a
	// burst has something to be unusual against.
	for d := 1; d <= 20; d++ {
		day := now.AddDate(0, 0, -d).Truncate(24 * time.Hour)
		for i := 0; i < 144; i++ {
			if err := db.PutBucket(surge.Bucket{
				Start: day.Add(time.Duration(i) * surge.Width), Events: 3, Devices: 2,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Built twenty minutes ago, because a daemon with nine minutes of uptime
	// has nothing honest to say: its trailing ten minutes includes time
	// nobody was watching. Freezing the clock at construction would test the
	// silence rather than the sentence.
	start := now
	now = start.Add(-20 * time.Minute)
	a := newSiteActivity(
		surge.NewRecorder(db, clock, nil),
		surge.NewReporter(db, time.UTC, clock, nil),
		db.FlagBucket,
	)
	now = start

	// Nine devices dropping inside one bucket: the shape this exists for.
	for i := 0; i < 14; i++ {
		a.observe(event.Event{
			Source: "protect", Condition: "offline",
			Entity: event.Entity{ID: string(rune('a' + i%9))}, At: now,
		})
	}

	// The alert that fires while it is happening says so.
	note := a.note(now)
	if note == "" {
		t.Fatal("no note while nine devices were dropping")
	}
	if want := "Site unusually busy"; note[:len(want)] != want {
		t.Errorf("note = %q, want it to lead with the verdict", note)
	}

	// Cross the boundary, then judge what closed.
	now = now.Add(surge.Width + time.Minute)
	a.rec.Tick()
	a.judge(now.Add(-surge.Width - time.Minute).Truncate(surge.Width))

	got, err := db.Buckets(now.Add(-2*surge.Width), now)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, b := range got {
		if b.Events == 14 && b.Devices == 9 {
			found = true
			if b.Flagged != surge.Busy {
				t.Errorf("the bucket was stored unflagged: %+v", b)
			}
		}
	}
	if !found {
		t.Errorf("the burst never reached the database: %+v", got)
	}
}
