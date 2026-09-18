package store

import (
	"context"
	"fmt"
	"time"
)

// MaxSeenPerLink bounds how many event ids one link may hold.
//
// A bounded table that prunes beats one that grows: the peer's own retry
// window is seconds, so anything beyond a few thousand is either a very busy
// site or something wrong, and neither should be able to grow this file
// without limit. Pruned oldest-first, because the oldest ids are the ones a
// retry can no longer be referring to.
const MaxSeenPerLink = 4096

// SeenEvent records that an event id has already been accepted, and reports
// whether it had been seen before.
//
// The peer retries with the SAME event id after a timeout, so an event this
// product accepted but whose reply never arrived must not raise a second
// incident. Returning "seen before" lets the caller answer the retry with the
// same success it would have sent the first time.
//
// Scoped by link id: two peers choosing the same event id is legitimate, and
// one peer must never be able to suppress another's events by guessing them.
func (s *SQLite) SeenEvent(ctx context.Context, linkID, eventID string, now time.Time, ttl time.Duration) (bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store: link seen: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Expire first, so an id whose retry window has long passed does not keep
	// a slot for ever and does not wrongly suppress a genuinely new event that
	// happens to reuse the id.
	if ttl > 0 {
		cutoff := now.Add(-ttl).UTC().Format(timeLayout)
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM link_seen_events WHERE seen_at < ?`, cutoff); err != nil {
			return false, fmt.Errorf("store: link seen prune: %w", err)
		}
	}

	var found int
	err = tx.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM link_seen_events WHERE link_id = ? AND event_id = ?`,
		linkID, eventID).Scan(&found)
	if err != nil {
		return false, fmt.Errorf("store: link seen lookup: %w", err)
	}
	if found > 0 {
		// Deliberately NOT refreshing seen_at. The window is measured from
		// when the event was first accepted; letting a retry extend it would
		// let a peer keep an id alive indefinitely.
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("store: link seen commit: %w", err)
		}
		return true, nil
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO link_seen_events (link_id, event_id, seen_at) VALUES (?, ?, ?)`,
		linkID, eventID, now.UTC().Format(timeLayout)); err != nil {
		return false, fmt.Errorf("store: link seen insert: %w", err)
	}

	// Keep the per-link table bounded, oldest first.
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM link_seen_events
		WHERE link_id = ? AND rowid NOT IN (
			SELECT rowid FROM link_seen_events
			WHERE link_id = ?
			ORDER BY seen_at DESC, rowid DESC
			LIMIT ?
		)`, linkID, linkID, MaxSeenPerLink); err != nil {
		return false, fmt.Errorf("store: link seen trim: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store: link seen commit: %w", err)
	}
	return false, nil
}

// ForgetEvent releases an idempotency record.
//
// Used when an event was recorded as seen and then failed to become an
// incident: without this, the peer's retry would be answered as a duplicate of
// something that never existed, and the alarm would be lost by both ends
// agreeing it had already been handled.
func (s *SQLite) ForgetEvent(ctx context.Context, linkID, eventID string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM link_seen_events WHERE link_id = ? AND event_id = ?`,
		linkID, eventID); err != nil {
		return fmt.Errorf("store: link forget: %w", err)
	}
	return nil
}
