package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ObservedEntity is one thing this product has seen an event about, and when.
//
// FirstSeen is what makes this a record rather than a cache. "This camera has
// been here since March and stopped reporting on Tuesday" is a different
// sentence from "there is no camera by that name", and only the first one
// tells an operator whether something was lost or never existed.
type ObservedEntity struct {
	Source    string
	ID        string
	Name      string
	Kind      string
	MAC       string
	FirstSeen time.Time
	LastSeen  time.Time
}

// NoteEntity records that something was seen, creating the row on first sight
// and touching it afterwards.
//
// The name, kind and MAC are updated ONLY when the incoming event carries
// them. A source that knows a device by MAC alone -- the Alarm Manager webhook
// path -- must not blank the name another route established, and an event
// missing a field is a gap in that event rather than news about the device.
func (s *SQLite) NoteEntity(ctx context.Context, e ObservedEntity) error {
	if strings.TrimSpace(e.Source) == "" || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	if e.LastSeen.IsZero() {
		e.LastSeen = time.Now().UTC()
	}
	if e.FirstSeen.IsZero() {
		e.FirstSeen = e.LastSeen
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// COALESCE(NULLIF(excluded.x, ''), observed_entities.x) keeps what is
	// already known when the new event says nothing. first_seen is never
	// touched on conflict: it is the one column whose whole value is that it
	// does not move.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO observed_entities (source, id, name, kind, mac, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source, id) DO UPDATE SET
			name      = COALESCE(NULLIF(excluded.name, ''), observed_entities.name),
			kind      = COALESCE(NULLIF(excluded.kind, ''), observed_entities.kind),
			mac       = COALESCE(NULLIF(excluded.mac,  ''), observed_entities.mac),
			last_seen = excluded.last_seen`,
		e.Source, e.ID, e.Name, e.Kind, e.MAC,
		e.FirstSeen.UTC().Format(time.RFC3339Nano),
		e.LastSeen.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("store: recording an observed entity: %w", err)
	}
	return nil
}

// ObservedEntities returns everything ever seen, most recently seen first.
//
// Everything, with no limit: the caller that wants the twenty most recent for
// a picker can take them, and the caller asking what a site had before the
// power went out needs all of them. A cap here would decide that question for
// both of them, in favour of the one that matters less.
func (s *SQLite) ObservedEntities(ctx context.Context) ([]ObservedEntity, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT source, id, name, kind, mac, first_seen, last_seen
		FROM observed_entities
		ORDER BY last_seen DESC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: reading observed entities: %w", err)
	}
	defer rows.Close()
	return scanEntities(rows)
}

// EntitiesWithMAC returns everything ever seen carrying this MAC.
//
// The lookup the re-adoption case needs. A UniFi device id is generated at
// adoption, so re-adopting hardware produces a new id for the same physical
// thing; the MAC is what connects the two, and more than one row coming back
// is the evidence -- the old id and the new one, same hardware.
func (s *SQLite) EntitiesWithMAC(ctx context.Context, mac string) ([]ObservedEntity, error) {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT source, id, name, kind, mac, first_seen, last_seen
		FROM observed_entities
		WHERE mac = ?
		ORDER BY last_seen DESC`, mac)
	if err != nil {
		return nil, fmt.Errorf("store: reading entities by MAC: %w", err)
	}
	defer rows.Close()
	return scanEntities(rows)
}

func scanEntities(rows *sql.Rows) ([]ObservedEntity, error) {
	var out []ObservedEntity
	for rows.Next() {
		var e ObservedEntity
		var first, last string
		if err := rows.Scan(&e.Source, &e.ID, &e.Name, &e.Kind, &e.MAC, &first, &last); err != nil {
			return nil, fmt.Errorf("store: reading an observed entity: %w", err)
		}
		e.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
		e.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
		out = append(out, e)
	}
	return out, rows.Err()
}
