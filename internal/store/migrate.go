package store

import (
	"context"
	"database/sql"
	"fmt"
)

// migration is one step of the schema's history.
type migration struct {
	version int
	stmts   []string
}

// migrations is APPEND-ONLY history. An entry that has shipped is never
// edited.
//
// This matters more than it usually does. The text below is what already ran
// on every installed database; editing it changes only what a FRESH install
// gets, so the two diverge with no error anywhere. For the partial unique
// index in particular, the divergence would show up as duplicate active
// incidents on upgraded installs and nowhere else -- an alarm that has to be
// acknowledged twice, discovered by an operator at 3am rather than by a test.
//
// Schema versioning exists from the first release because a product that
// stores alarm state cannot ask an operator to delete their database to
// upgrade: the thing it would delete is the alarm that is currently ringing.
var migrations = []migration{
	{
		version: 1,
		stmts: []string{
			// STRICT so a type mismatch is an error at write time rather than
			// a surprise at read time. Timestamps are TEXT in a fixed-width
			// RFC 3339 UTC layout (see timeLayout): sortable as bytes, exact
			// on round trip, and readable by an operator with the sqlite3 CLI,
			// which matters for a product whose support story is "look at the
			// state yourself".
			`CREATE TABLE incidents (
				id                  TEXT    PRIMARY KEY,
				dedup_key           TEXT    NOT NULL,
				severity            TEXT    NOT NULL,
				source              TEXT    NOT NULL,
				title               TEXT    NOT NULL,
				detail              TEXT    NOT NULL,
				opened_at           TEXT    NOT NULL,
				first_alert_at      TEXT,
				last_alert_at       TEXT,
				alert_count         INTEGER NOT NULL DEFAULT 0,
				stage               INTEGER NOT NULL DEFAULT 0,
				acked_at            TEXT,
				ack_via             TEXT    NOT NULL DEFAULT '',
				resolved_at         TEXT,
				closed_at           TEXT,
				close_reason        TEXT    NOT NULL DEFAULT '',
				predecessor_id      TEXT    NOT NULL DEFAULT '',
				last_delivery_error TEXT    NOT NULL DEFAULT '',
				updated_at          TEXT    NOT NULL
			) STRICT`,

			// The invariant that makes an event storm collapse into one
			// incident, enforced by the SCHEMA rather than by Go.
			//
			// The WHERE clause is the inverse of incident.Incident.Terminal():
			// closed explicitly, or acknowledged AND resolved. A terminal
			// incident drops out of the index, which is what frees the key for
			// a recurrence -- and a recurrence is a new incident, never a
			// revival, so the key must become free.
			//
			// There is NO state column. State is derived from these
			// timestamps in Go and must stay derived; a stored copy is a
			// second source of truth that can disagree with the timestamps
			// that produced it, and the disagreement would decide whether an
			// alarm keeps ringing.
			`CREATE UNIQUE INDEX incidents_one_active_per_dedup_key
				ON incidents (dedup_key)
				WHERE closed_at IS NULL AND (acked_at IS NULL OR resolved_at IS NULL)`,

			// The history view's ordering, and the scheduler's scan.
			`CREATE INDEX incidents_updated_at ON incidents (updated_at DESC, id DESC)`,
			`CREATE INDEX incidents_active_opened_at
				ON incidents (opened_at)
				WHERE closed_at IS NULL AND (acked_at IS NULL OR resolved_at IS NULL)`,
		},
	},
	{
		version: 2,
		stmts: []string{
			// Idempotency for the peer link.
			//
			// A peer retries on a timeout with the SAME event id, so a reply
			// this product sent but the peer never received must not raise the
			// alarm twice. In memory would be enough for a retry seconds
			// later; it is NOT enough across a restart, and a restart during
			// an alarm is exactly when a peer is retrying -- so this is
			// durable for the same reason the incidents themselves are.
			//
			// Scoped by link: two peers choosing the same id is legitimate,
			// and one peer must never be able to suppress another's events by
			// guessing them.
			`CREATE TABLE link_seen_events (
				link_id  TEXT NOT NULL,
				event_id TEXT NOT NULL,
				seen_at  TEXT NOT NULL,
				PRIMARY KEY (link_id, event_id)
			) STRICT`,

			// Pruning scans by age, so it is indexed by age.
			`CREATE INDEX link_seen_events_seen_at ON link_seen_events (seen_at)`,
		},
	},
	{
		version: 3,
		stmts: []string{
			// EVERY THING THIS PRODUCT HAS EVER SEEN AN EVENT ABOUT, kept for
			// good.
			//
			// This was a map in memory, capped at 500, evicting the least
			// recently seen. Both of those were wrong for the question it
			// turns out to answer.
			//
			// Not in memory, because the useful question is asked after a
			// restart: a site loses power, comes back, and the operator needs
			// to know WHAT IT HAD -- not what answered afterwards. An
			// in-memory registry is empty at exactly that moment.
			//
			// Not evicted by recency, because the least recently seen entity
			// after a lightning strike is the camera that was destroyed. The
			// eviction policy discarded precisely the rows the record exists
			// to preserve.
			//
			// Unbounded is safe here, and that was checked rather than
			// assumed: every source keys entities on adopted hardware or on a
			// configured hook -- Protect cameras and sensors, Access doors,
			// adopted Network devices, and "hook/<name>" for the inbound
			// receiver, which is per HOOK and not per client. Nothing emits an
			// entity per DHCP lease. A row is roughly 200 bytes, so twenty
			// thousand of them is four megabytes.
			//
			// Keyed on (source, id) and NOT on the name, unlike the map it
			// replaces: there, renaming a camera created a second entry and
			// the picker offered both. A rename updates this row in place.
			`CREATE TABLE observed_entities (
				source     TEXT NOT NULL,
				id         TEXT NOT NULL,
				name       TEXT NOT NULL DEFAULT '',
				kind       TEXT NOT NULL DEFAULT '',
				mac        TEXT NOT NULL DEFAULT '',
				first_seen TEXT NOT NULL,
				last_seen  TEXT NOT NULL,
				PRIMARY KEY (source, id)
			) STRICT`,

			// The rules editor wants them newest-first.
			`CREATE INDEX observed_entities_last_seen ON observed_entities (last_seen)`,

			// THE MAC IS WHAT SURVIVES A RE-ADOPTION, and it is indexed
			// because that is the lookup the reconciliation needs: a device
			// whose id changed but whose hardware did not. A UniFi device id
			// is generated AT ADOPTION TIME, so re-adopting a hub recreates
			// every door or camera under it as a new entity -- a routine
			// maintenance action that silently detaches every rule naming one
			// by id. The name survives that and breaks on a rename; the id
			// survives a rename and breaks on this. Only the MAC survives
			// both.
			`CREATE INDEX observed_entities_mac ON observed_entities (mac) WHERE mac <> ''`,
		},
	},
}

func latestVersion() int {
	if len(migrations) == 0 {
		return 0
	}
	return migrations[len(migrations)-1].version
}

// migrate brings the database up to latestVersion.
//
// The version lives in PRAGMA user_version rather than in a table of its own:
// it is transactional, it costs no schema, and it is visible to an operator
// running `sqlite3 incidents.db 'pragma user_version'` without knowing
// anything about our table layout.
// migrate brings the schema up to date, and reports where it put the snapshot
// it takes first. snapshotErr is returned separately from the migration's own
// error because a snapshot that could not be written must NOT stop the daemon:
// see MigrationSnapshot.
func migrate(ctx context.Context, db *sql.DB, path string) (snapshot string, snapshotErr error, err error) {
	var current int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&current); err != nil {
		return "", nil, fmt.Errorf("store: read schema version: %w", err)
	}

	// Refuse a database written by a newer build rather than operating on it.
	// A downgrade that "mostly works" writes rows the newer build will then
	// misread, and the rows in question are live alarms. Failing to start is
	// loud; corrupting incident state is not.
	if latest := latestVersion(); current > latest {
		return "", nil, fmt.Errorf(
			"store: database schema is version %d but this build understands at most %d; "+
				"it was written by a newer version of notifymatrix", current, latest)
	}

	// Nothing to do, so nothing to snapshot. The common case by far: this runs
	// on every start, and almost every start is not an upgrade.
	if current >= latestVersion() {
		return "", nil, nil
	}

	// BEFORE the first migration, because after it the old schema is gone.
	// A failure here is carried out rather than returned as the function's
	// error: the upgrade still proceeds, and the operator is told.
	snapshot, snapshotErr = snapshotBeforeMigrating(ctx, db, path, current)

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return snapshot, snapshotErr, err
		}
	}
	return snapshot, snapshotErr, nil
}

// applyMigration runs one migration and its version bump in a single
// transaction, so an interrupted upgrade leaves the database at the old
// version rather than half-way between two.
func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin migration %d: %w", m.version, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	// Re-read the version INSIDE the transaction. The check in migrate() runs
	// outside it, so two processes opening the same file at once -- a service
	// restart overlapping its predecessor, or a second daemon during an
	// upgrade -- both read version 0 and both decide to apply migration 1. The
	// loser then dies on "table incidents already exists" and the daemon does
	// not start at all, which for this product is silence.
	//
	// The transaction is BEGIN IMMEDIATE (_txlock=immediate in the DSN), so it
	// already holds the write lock by the time this read happens: whoever gets
	// here second sees the winner's committed version and does nothing.
	var applied int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&applied); err != nil {
		return fmt.Errorf("store: migration %d re-read schema version: %w", m.version, err)
	}
	if applied >= m.version {
		return nil
	}

	for i, stmt := range m.stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: migration %d statement %d: %w", m.version, i, err)
		}
	}
	// PRAGMA user_version does not accept a bound parameter; the value is an
	// int from a constant table in this file, never from input.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, m.version)); err != nil {
		return fmt.Errorf("store: migration %d set version: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit migration %d: %w", m.version, err)
	}
	return nil
}
