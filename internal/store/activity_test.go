package store

import (
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/surge"
)

func openTemp(t *testing.T) *SQLite {
	t.Helper()
	db, err := Open(t.TempDir() + "/incidents.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

var b0 = time.Date(2026, 9, 22, 3, 0, 0, 0, time.UTC)

func TestABucketSurvivesARoundTrip(t *testing.T) {
	db := openTemp(t)
	want := surge.Bucket{Start: b0, Events: 14, Devices: 9, Degraded: true, Flagged: surge.Busy}
	if err := db.PutBucket(want); err != nil {
		t.Fatal(err)
	}

	got, err := db.Buckets(b0.Add(-time.Hour), b0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("read %d buckets, want 1", len(got))
	}
	if got[0] != want {
		t.Errorf("read %+v, want %+v", got[0], want)
	}
}

// A daemon restarting inside a bucket must not leave two rows for one span:
// the baseline would then count that ten minutes twice, with the smaller
// fraction dragging it down.
func TestOneSpanIsOneRow(t *testing.T) {
	db := openTemp(t)
	if err := db.PutBucket(surge.Bucket{Start: b0, Events: 2, Devices: 1}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutBucket(surge.Bucket{Start: b0, Events: 14, Devices: 9}); err != nil {
		t.Fatal(err)
	}

	got, _ := db.Buckets(b0.Add(-time.Hour), b0.Add(time.Hour))
	if len(got) != 1 {
		t.Fatalf("read %d rows for one span", len(got))
	}
	if got[0].Events != 14 {
		t.Errorf("kept %d events; the later write saw more of the span", got[0].Events)
	}
}

// BOUNDED BY CONSTRUCTION. Pruning happens on the write, so retention cannot
// drift because a sweeper was never scheduled.
func TestOldBucketsArePrunedOnWrite(t *testing.T) {
	db := openTemp(t)
	old := b0.Add(-surge.Retention - time.Hour)
	if err := db.PutBucket(surge.Bucket{Start: old, Events: 1, Devices: 1}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutBucket(surge.Bucket{Start: b0, Events: 1, Devices: 1}); err != nil {
		t.Fatal(err)
	}

	got, _ := db.Buckets(old.Add(-time.Hour), b0.Add(time.Hour))
	for _, b := range got {
		if b.Start.Equal(old) {
			t.Error("a bucket past the retention window survived a later write")
		}
	}
}

// The verdict is written after the fact, because judging it needs the baseline
// that this row has just joined.
func TestABucketCanBeFlaggedAfterTheFact(t *testing.T) {
	db := openTemp(t)
	if err := db.PutBucket(surge.Bucket{Start: b0, Events: 200, Devices: 25}); err != nil {
		t.Fatal(err)
	}
	if err := db.FlagBucket(b0, surge.Busy); err != nil {
		t.Fatal(err)
	}

	got, _ := db.Buckets(b0.Add(-time.Hour), b0.Add(time.Hour))
	if len(got) != 1 || got[0].Flagged != surge.Busy {
		t.Errorf("flagged = %+v, want busy", got)
	}
}
