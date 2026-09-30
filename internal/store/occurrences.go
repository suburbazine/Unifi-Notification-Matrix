package store

import (
	"context"
	"fmt"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// AddOccurrence stores one arrival of a per-occurrence condition and drops
// anything older than the most recent keep.
//
// Pruned HERE rather than on a timer, for the reason activity buckets are: the
// write is the only moment this table is certainly being touched, so retention
// cannot drift because a sweeper was never scheduled. Incidents are never
// deleted, so there is no other path by which an incident's occurrences could
// be orphaned.
//
// INSERT OR REPLACE on (incident_id, seq) because an arrival is identified by
// its number: a retry of the same write must not leave two rows claiming to be
// the fifty-seventh.
func (s *SQLite) AddOccurrence(ctx context.Context, incidentID string, o incident.Occurrence, keep int) error {
	if incidentID == "" || o.Seq < 1 {
		return fmt.Errorf("store: an occurrence needs an incident and a sequence number")
	}
	if keep < 1 {
		keep = incident.MaxOccurrences
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO incident_occurrences (incident_id, seq, at, severity, title, detail)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		incidentID, o.Seq, encTime(o.At), string(o.Severity), o.Title, o.Detail,
	); err != nil {
		return fmt.Errorf("store: occurrence %d of %s: %w", o.Seq, incidentID, err)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM incident_occurrences WHERE incident_id = ? AND seq <= ?`,
		incidentID, o.Seq-keep,
	); err != nil {
		return fmt.Errorf("store: pruning occurrences of %s: %w", incidentID, err)
	}
	return nil
}

// Occurrences returns an incident's stored occurrences, newest first.
func (s *SQLite) Occurrences(ctx context.Context, incidentID string) ([]incident.Occurrence, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, at, severity, title, detail
		   FROM incident_occurrences
		  WHERE incident_id = ?
		  ORDER BY seq DESC`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []incident.Occurrence
	for rows.Next() {
		var (
			o       incident.Occurrence
			at, sev string
		)
		if err := rows.Scan(&o.Seq, &at, &sev, &o.Title, &o.Detail); err != nil {
			return nil, err
		}
		t, err := decTime(at)
		if err != nil {
			return nil, err
		}
		o.At, o.Severity = t, incident.Severity(sev)
		out = append(out, o)
	}
	return out, rows.Err()
}
