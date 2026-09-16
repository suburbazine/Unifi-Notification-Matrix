// Package store is the durable home of incidents.
//
// Durability is not a feature of this product, it is the product. The daemon
// must survive a crash, a service restart and a power cut with the alarm still
// alarming -- and restarts are most likely during exactly the power and
// network events that generate alarms. Everything unusual in this package
// follows from that one sentence: the synchronous setting, the partial unique
// index, and the refusal to use INSERT OR REPLACE.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"modernc.org/sqlite"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// ErrActiveExists means an incident is already open for that dedup key.
//
// This is the correct and expected answer to the second of two racing
// ingests, not a bug: the flapping camera opened its incident on the first
// one. The caller re-reads with OpenByDedupKey and updates that incident
// instead of creating a second.
var ErrActiveExists = errors.New("an active incident already exists for this dedup key")

// SQLite extended result codes we act on. Declared here rather than imported
// from modernc.org/sqlite/lib so that the dependency surface stays at the
// driver, and matched as typed codes rather than by string-matching an error
// message, which changes between driver versions without warning.
const (
	sqliteConstraintUnique = 2067 // SQLITE_CONSTRAINT_UNIQUE
	sqliteBusy             = 5    // SQLITE_BUSY, the PRIMARY code; see isBusy
)

// openBusyRetryFor bounds how long Open waits out a database another process
// is holding. Bounded, because a start that hangs forever is as silent as one
// that fails -- it just takes longer to notice.
const openBusyRetryFor = 5 * time.Second

// timeLayout is RFC 3339 in UTC with a FIXED nine-digit fractional second.
//
// Not time.RFC3339Nano, which strips trailing zeros from the fraction. That
// makes stored timestamps non-sortable as text: "…:05Z" sorts AFTER
// "…:05.5Z" because 'Z' > '.', so ORDER BY updated_at would silently
// interleave half the history view. Fixed width makes byte order and time
// order the same thing.
const timeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// nonTerminal is the SQL spelling of incident.Incident.Terminal() inverted:
// closed explicitly, or acknowledged AND resolved, is terminal.
//
// State is derived, never stored -- there is deliberately no state column to
// drift out of step with the timestamps. The one duplication that remains is
// this predicate, which also appears literally in the migration that creates
// the partial unique index (migrations are frozen history and cannot
// reference a Go constant). TestDerivedTerminalMatchesIncidentPackage walks
// every combination of the three timestamps and fails if the two spellings
// ever disagree with the Go definition.
const nonTerminal = `closed_at IS NULL AND (acked_at IS NULL OR resolved_at IS NULL)`

const incidentColumns = `id, dedup_key, severity, source, title, detail, opened_at,
	first_alert_at, last_alert_at, alert_count, stage,
	acked_at, ack_via, resolved_at, closed_at, close_reason,
	predecessor_id, last_delivery_error, updated_at`

// SQLite is an incident.Store backed by an on-disk SQLite database.
//
// Safe for concurrent use: ingest, the escalation scheduler and the web UI all
// touch it at once.
type SQLite struct {
	db   *sql.DB
	path string

	// writeMu serialises writers in Go rather than letting them collide in
	// SQLite and unwind through the busy handler. SQLite allows exactly one
	// writer regardless; taking the turn here means an event storm -- fifty
	// offline/online flaps a minute from one bad PoE port -- queues instead of
	// generating SQLITE_BUSY retries. Uniqueness is still enforced by the
	// index, not by this mutex: two processes sharing the database file do not
	// share this lock, and the schema has to hold anyway.
	writeMu sync.Mutex

	closeOnce sync.Once
}

var _ incident.Store = (*SQLite)(nil)

// Open opens (creating if necessary) the incident database at path and brings
// its schema up to date.
func Open(path string) (*SQLite, error) {
	if path == "" {
		return nil, errors.New("store: empty database path")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: create database directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}

	// More than one connection so the UI's reads are not stuck behind a write
	// (that is what WAL buys); a small ceiling because every open connection
	// is a WAL reader holding back checkpointing.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Both steps are retried while SQLite reports the file busy. The first
	// connection to a brand-new database converts it from the default rollback
	// journal to WAL, and PRAGMA journal_mode answers SQLITE_BUSY IMMEDIATELY
	// when another connection holds the write lock -- it does not consult
	// busy_timeout the way an ordinary statement does. The window is small and
	// its shape is ordinary: a service restart overlapping its predecessor, an
	// operator with a sqlite3 session open, a second daemon during an upgrade.
	// Losing it means the daemon does not start, and a security product that
	// does not start is silence.
	if err := retryBusy(ctx, func() error { return db.PingContext(ctx) }); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// Safe to retry: applyMigration re-reads user_version inside its own
	// transaction, so a migration that another process committed in the
	// meantime is a no-op rather than a duplicate CREATE TABLE.
	if err := retryBusy(ctx, func() error { return migrate(ctx, db) }); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLite{db: db, path: path}, nil
}

// retryBusy runs fn, retrying while SQLite says the database is busy, until
// openBusyRetryFor has elapsed or ctx is done. Any other error is returned at
// once: waiting out a real fault only delays the diagnosis.
func retryBusy(ctx context.Context, fn func() error) error {
	deadline := time.Now().Add(openBusyRetryFor)
	delay := 25 * time.Millisecond
	for {
		err := fn()
		if err == nil || !isBusy(err) || !time.Now().Before(deadline) {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
		if delay < time.Second {
			delay *= 2
		}
	}
}

// dsn builds the connection string.
//
// The PRAGMAs go in the DSN rather than being executed once after opening
// because synchronous and busy_timeout are PER CONNECTION. Running them once
// against a pool configures exactly one connection and silently leaves the
// rest at the defaults -- a bug a single-threaded test never sees and
// production always does.
//
// What each one trades:
//
//	journal_mode=WAL  Readers do not block the writer. The web UI reads the
//	                  live board while ingest writes; without WAL the board
//	                  stalls during an event storm, which is when someone is
//	                  most likely to be looking at it.
//
//	synchronous=FULL  fsync the WAL at every commit. NORMAL is the usual WAL
//	                  recommendation and does survive a process crash, but it
//	                  does NOT survive power loss: the WAL is only fsynced at
//	                  checkpoint, so the most recent commits can vanish. The
//	                  commits we would lose are precisely the incident that
//	                  opened seconds before the power went out -- the single
//	                  case this product exists for. The price is one fsync per
//	                  commit, and this workload commits a handful of times per
//	                  incident rather than thousands per second, so the price
//	                  is invisible.
//
//	busy_timeout      Wait rather than fail when another process (an operator
//	                  running sqlite3 against the file, a second daemon during
//	                  an upgrade) holds the write lock.
//
// _txlock=immediate takes the write lock when a transaction begins instead of
// on its first write, so a read-then-write transaction cannot deadlock against
// another one by trying to upgrade.
func dsn(path string) string {
	q := url.Values{
		"_pragma": []string{
			"busy_timeout(10000)",
			"journal_mode(WAL)",
			"synchronous(FULL)",
			"foreign_keys(ON)",
		},
		"_txlock": []string{"immediate"},
	}
	return path + "?" + q.Encode()
}

// Put writes the incident, creating or replacing it wholesale.
func (s *SQLite) Put(ctx context.Context, inc *incident.Incident) error {
	if inc == nil {
		return errors.New("store: put nil incident")
	}
	if inc.ID == "" {
		return errors.New("store: incident has no id")
	}
	// An empty dedup key is not "no key", it is ONE key shared by every
	// incident that omits it -- and the partial unique index would then permit
	// exactly one active incident in the entire product, silently swallowing
	// every other alarm. Refuse it here where it is diagnosable.
	if inc.DedupKey == "" {
		return fmt.Errorf("store: incident %s has no dedup key", inc.ID)
	}
	// A zero OpenedAt makes every escalation stage due in the year 1, so the
	// incident pages forever at the tick rate. Refuse rather than store it.
	if inc.OpenedAt.IsZero() {
		return fmt.Errorf("store: incident %s has no opened_at", inc.ID)
	}

	const q = `
INSERT INTO incidents (` + incidentColumns + `)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
	dedup_key           = excluded.dedup_key,
	severity            = excluded.severity,
	source              = excluded.source,
	title               = excluded.title,
	detail              = excluded.detail,
	opened_at           = excluded.opened_at,
	first_alert_at      = excluded.first_alert_at,
	last_alert_at       = excluded.last_alert_at,
	alert_count         = excluded.alert_count,
	stage               = excluded.stage,
	acked_at            = excluded.acked_at,
	ack_via             = excluded.ack_via,
	resolved_at         = excluded.resolved_at,
	closed_at           = excluded.closed_at,
	close_reason        = excluded.close_reason,
	predecessor_id      = excluded.predecessor_id,
	last_delivery_error = excluded.last_delivery_error,
	updated_at          = excluded.updated_at`

	// ON CONFLICT(id), never INSERT OR REPLACE. OR REPLACE resolves a conflict
	// on ANY uniqueness constraint by deleting the conflicting row -- so a
	// second goroutine inserting a different id with the same dedup key would
	// not fail, it would silently DELETE the live incident the first goroutine
	// just opened, taking a real alarm with it. Naming the id conflict
	// explicitly means same-id rewrites are absorbed and dedup-key collisions
	// surface as the error they are.
	s.writeMu.Lock()
	_, err := s.db.ExecContext(ctx, q,
		inc.ID, inc.DedupKey, string(inc.Severity), inc.Source, inc.Title, inc.Detail,
		encTime(inc.OpenedAt),
		encTimePtr(inc.FirstAlertAt), encTimePtr(inc.LastAlertAt),
		inc.AlertCount, inc.Stage,
		encTimePtr(inc.AckedAt), inc.AckVia, encTimePtr(inc.ResolvedAt),
		encTimePtr(inc.ClosedAt), inc.CloseReason,
		inc.PredecessorID, inc.LastDeliveryError,
		encTime(inc.UpdatedAt),
	)
	s.writeMu.Unlock()

	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("store: put %s (%s): %w", inc.ID, inc.DedupKey, ErrActiveExists)
		}
		return fmt.Errorf("store: put %s: %w", inc.ID, err)
	}
	return nil
}

// PutIfUnchanged writes only if the stored row's updated_at still equals
// expect, and returns incident.ErrConflict otherwise.
//
// The compare and the write are ONE statement -- the comparison is the UPDATE's
// own WHERE clause, evaluated by SQLite while it holds the write lock. Reading
// updated_at first and then writing would reintroduce, inside the store, the
// very gap the method exists to close.
//
// Note the deliberate absence of an INSERT path: this cannot create a row. A
// caller that reached here believing it was updating an incident which has
// since been deleted should be told so, not silently handed a fresh incident
// with a resurrected acknowledgement on it.
func (s *SQLite) PutIfUnchanged(ctx context.Context, inc *incident.Incident, expect time.Time) error {
	if inc == nil {
		return errors.New("store: put nil incident")
	}
	if inc.ID == "" {
		return errors.New("store: incident has no id")
	}
	if inc.DedupKey == "" {
		return fmt.Errorf("store: incident %s has no dedup key", inc.ID)
	}
	if inc.OpenedAt.IsZero() {
		return fmt.Errorf("store: incident %s has no opened_at", inc.ID)
	}

	const q = `
UPDATE incidents SET
	dedup_key           = ?,
	severity            = ?,
	source              = ?,
	title               = ?,
	detail              = ?,
	opened_at           = ?,
	first_alert_at      = ?,
	last_alert_at       = ?,
	alert_count         = ?,
	stage               = ?,
	acked_at            = ?,
	ack_via             = ?,
	resolved_at         = ?,
	closed_at           = ?,
	close_reason        = ?,
	predecessor_id      = ?,
	last_delivery_error = ?,
	updated_at          = ?
WHERE id = ? AND updated_at = ?`

	s.writeMu.Lock()
	res, err := s.db.ExecContext(ctx, q,
		inc.DedupKey, string(inc.Severity), inc.Source, inc.Title, inc.Detail,
		encTime(inc.OpenedAt),
		encTimePtr(inc.FirstAlertAt), encTimePtr(inc.LastAlertAt),
		inc.AlertCount, inc.Stage,
		encTimePtr(inc.AckedAt), inc.AckVia, encTimePtr(inc.ResolvedAt),
		encTimePtr(inc.ClosedAt), inc.CloseReason,
		inc.PredecessorID, inc.LastDeliveryError,
		encTime(inc.UpdatedAt),
		inc.ID, encTime(expect),
	)
	s.writeMu.Unlock()

	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("store: put %s (%s): %w", inc.ID, inc.DedupKey, ErrActiveExists)
		}
		return fmt.Errorf("store: put %s: %w", inc.ID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: put %s: %w", inc.ID, err)
	}
	if n == 1 {
		return nil
	}

	// Nothing matched. Distinguish "somebody else wrote it" from "it is gone",
	// because the two want different handling: the caller retries the first and
	// must not retry the second.
	var exists int
	switch err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM incidents WHERE id = ?`, inc.ID).Scan(&exists); {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("store: put %s: %w", inc.ID, incident.ErrNotFound)
	case err != nil:
		return fmt.Errorf("store: put %s: %w", inc.ID, err)
	default:
		return fmt.Errorf("store: put %s: %w", inc.ID, incident.ErrConflict)
	}
}

// Get returns one incident by id, or incident.ErrNotFound.
func (s *SQLite) Get(ctx context.Context, id string) (*incident.Incident, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+incidentColumns+` FROM incidents WHERE id = ?`, id)
	inc, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: get %s: %w", id, incident.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: get %s: %w", id, err)
	}
	return inc, nil
}

// OpenByDedupKey returns the non-terminal incident for this key, or
// incident.ErrNotFound.
//
// At most one can exist: the partial unique index in the schema guarantees it,
// which is the only guarantee worth having. A Go-side check is a
// read-then-write race by construction -- two goroutines ingesting the same
// flapping camera both find nothing and both insert -- and the loser of that
// race is a duplicate alarm that has to be acknowledged twice.
func (s *SQLite) OpenByDedupKey(ctx context.Context, key string) (*incident.Incident, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+incidentColumns+` FROM incidents WHERE dedup_key = ? AND `+nonTerminal, key)
	inc, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: open incident for %s: %w", key, incident.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: open incident for %s: %w", key, err)
	}
	return inc, nil
}

// Active returns every non-terminal incident, oldest first, which is the order
// the escalation scheduler and the live board both want.
func (s *SQLite) Active(ctx context.Context) ([]*incident.Incident, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+incidentColumns+` FROM incidents WHERE `+nonTerminal+` ORDER BY opened_at ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: active: %w", err)
	}
	out, err := scanAll(rows)
	if err != nil {
		return nil, fmt.Errorf("store: active: %w", err)
	}
	return out, nil
}

// Recent returns incidents by most recently updated, terminal ones included.
// A limit of zero or less means no limit.
func (s *SQLite) Recent(ctx context.Context, limit int) ([]*incident.Incident, error) {
	if limit <= 0 {
		limit = -1 // SQLite: a negative LIMIT is no limit.
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+incidentColumns+` FROM incidents ORDER BY updated_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: recent: %w", err)
	}
	out, err := scanAll(rows)
	if err != nil {
		return nil, fmt.Errorf("store: recent: %w", err)
	}
	return out, nil
}

// Close releases the database. Idempotent, because shutdown paths converge.
func (s *SQLite) Close() error {
	var err error
	s.closeOnce.Do(func() {
		// Fold the WAL back into the main file so a copy of the .db taken by
		// a backup script after a clean shutdown is complete on its own. This
		// is best-effort: a failure here loses nothing, because the WAL is
		// already durable and is replayed on the next open.
		_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		err = s.db.Close()
	})
	return err
}

// Path reports the database file, for diagnostics ("it is installed and
// nothing happens" usually ends with someone looking at the wrong file).
func (s *SQLite) Path() string { return s.path }

type rowScanner interface {
	Scan(dest ...any) error
}

func scanIncident(sc rowScanner) (*incident.Incident, error) {
	var (
		inc                                            incident.Incident
		severity                                       string
		openedAt, updatedAt                            string
		firstAlert, lastAlert, acked, resolved, closed sql.NullString
	)
	err := sc.Scan(
		&inc.ID, &inc.DedupKey, &severity, &inc.Source, &inc.Title, &inc.Detail,
		&openedAt, &firstAlert, &lastAlert, &inc.AlertCount, &inc.Stage,
		&acked, &inc.AckVia, &resolved, &closed, &inc.CloseReason,
		&inc.PredecessorID, &inc.LastDeliveryError, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	inc.Severity = incident.Severity(severity)

	for _, f := range []struct {
		raw string
		dst *time.Time
	}{{openedAt, &inc.OpenedAt}, {updatedAt, &inc.UpdatedAt}} {
		t, err := decTime(f.raw)
		if err != nil {
			return nil, err
		}
		*f.dst = t
	}
	for _, f := range []struct {
		raw sql.NullString
		dst **time.Time
	}{
		{firstAlert, &inc.FirstAlertAt},
		{lastAlert, &inc.LastAlertAt},
		{acked, &inc.AckedAt},
		{resolved, &inc.ResolvedAt},
		{closed, &inc.ClosedAt},
	} {
		p, err := decTimePtr(f.raw)
		if err != nil {
			return nil, err
		}
		*f.dst = p
	}
	return &inc, nil
}

func scanAll(rows *sql.Rows) ([]*incident.Incident, error) {
	defer rows.Close()
	var out []*incident.Incident
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

func encTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// encTimePtr maps nil to SQL NULL and nothing else to SQL NULL.
//
// A nil timestamp that comes back as a zero time.Time is the worst bug
// available in this package: a nil AckedAt read back as zero makes
// Incident.State() report every incident acknowledged, and the product goes
// silent while claiming a human responded. NULL is the only representation of
// "not set", and a zero time.Time is stored as the year 1 rather than being
// quietly folded into NULL -- if a caller stores a zero time it is a bug in
// the caller, and it must be visible as one.
func encTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return encTime(*t)
}

func decTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("unparseable timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

func decTimePtr(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid {
		return nil, nil
	}
	t, err := decTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// isUniqueViolation reports whether err is a UNIQUE constraint failure.
//
// There is exactly one unique index in the schema -- the one active incident
// per dedup key -- so a unique violation can only mean that. Matched on the
// extended result code rather than on the message text, because the message
// is not a contract.
func isUniqueViolation(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code() == sqliteConstraintUnique
}

// isBusy reports whether err is SQLITE_BUSY in any of its forms.
//
// Masked to the primary result code rather than compared whole: the driver
// enables extended result codes, so the same condition arrives as plain
// SQLITE_BUSY (5), SQLITE_BUSY_RECOVERY (261), SQLITE_BUSY_SNAPSHOT (517) or
// SQLITE_BUSY_TIMEOUT (773) depending on where it was raised. Matched on the
// code, never on the message text, for the same reason as isUniqueViolation.
func isBusy(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqliteBusy
}
