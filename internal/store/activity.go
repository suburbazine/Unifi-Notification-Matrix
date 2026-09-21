package store

import (
	"context"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/surge"
)

// Site activity, ten minutes at a time.
//
// Kept here rather than in the audit log, where the same events are already
// written down in another form: that file rotates by size, so a busy site
// would quietly lose the history a baseline is computed from -- and the loss
// would be invisible, because the baseline would simply be computed from less
// and go on sounding confident.

// PutBucket writes one completed bucket and prunes anything past the window
// the baseline looks back over.
//
// Pruning HERE rather than on a timer: the write is the only moment this table
// is certainly being touched, so retention cannot drift because a sweeper was
// never scheduled or died quietly. It costs one DELETE per ten minutes.
func (s *SQLite) PutBucket(b surge.Bucket) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// INSERT OR REPLACE, because a bucket is identified by its span: a daemon
	// restarting inside one must not be able to leave two rows for the same
	// ten minutes, and the later write is the one that saw more of it.
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO activity_buckets (start, events, devices, degraded, flagged)
		 VALUES (?, ?, ?, ?, ?)`,
		b.Start.UTC().Unix(), b.Events, b.Devices, boolToInt(b.Degraded), int(b.Flagged),
	); err != nil {
		return err
	}

	cutoff := b.Start.UTC().Add(-surge.Retention).Unix()
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM activity_buckets WHERE start < ?`, cutoff)
	return err
}

// Buckets returns every bucket in [from, to), oldest first.
func (s *SQLite) Buckets(from, to time.Time) ([]surge.Bucket, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT start, events, devices, degraded, flagged
		   FROM activity_buckets
		  WHERE start >= ? AND start < ?
		  ORDER BY start`,
		from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []surge.Bucket
	for rows.Next() {
		var (
			start, events, devices int64
			degraded, flagged      int64
		)
		if err := rows.Scan(&start, &events, &devices, &degraded, &flagged); err != nil {
			return nil, err
		}
		out = append(out, surge.Bucket{
			Start:    time.Unix(start, 0).UTC(),
			Events:   int(events),
			Devices:  int(devices),
			Degraded: degraded != 0,
			Flagged:  surge.Verdict(flagged),
		})
	}
	return out, rows.Err()
}

// FlagBucket records what a bucket was judged to be, after the fact.
//
// Separate from PutBucket because the judgement needs the baseline, and the
// baseline is computed from the table this row has just gone into. Writing the
// verdict in a second statement keeps that ordering honest instead of hiding a
// read inside a write.
func (s *SQLite) FlagBucket(start time.Time, v surge.Verdict) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx,
		`UPDATE activity_buckets SET flagged = ? WHERE start = ?`,
		int(v), start.UTC().Unix())
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
