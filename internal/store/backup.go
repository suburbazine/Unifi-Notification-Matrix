package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
)

// A MIGRATION IS A ONE-WAY DOOR, so this takes a copy of the key before
// walking through it.
//
// migrate() refuses a database whose schema is newer than the build reading
// it, deliberately: a downgrade that "mostly works" writes rows the newer
// build then misreads, and those rows are live alarms. The cost of that
// correctness is that upgrading is irreversible -- once 0.1.8 raised the
// schema to 2, 0.1.7 would not start again, and the only way back was a backup
// nobody had been told to take.
//
// Which is a thing to find out BEFORE the upgrade, not after. So the snapshot
// is taken here rather than in the updater: this is the only code that knows a
// migration is about to happen, and it covers every route in -- the in-app
// updater, a replaced binary, a package manager, an operator running the new
// version by hand.

// backupSuffix names a snapshot after the schema version it can be restored
// INTO, not after the product version that wrote it.
//
// The schema number is the fact that matters: "incidents.db.v1.bak" tells a
// reader exactly which builds can open it, and stays true however many product
// releases shared that schema. It is also deterministic, so an upgrade
// attempted twice reuses one name instead of accumulating files.
func backupSuffix(schema int) string { return fmt.Sprintf(".v%d.bak", schema) }

// backupPathFor is where the snapshot of a database at this schema goes.
func backupPathFor(path string, schema int) string {
	return path + backupSuffix(schema)
}

// snapshotBeforeMigrating copies the database as it stands, returning the path
// written, or "" when no copy was needed.
//
// VACUUM INTO rather than a file copy. The database runs in WAL mode, so the
// bytes on disk are not the database: recent commits live in the -wal sidecar
// until a checkpoint, and copying the main file alone yields a snapshot
// missing whatever was written most recently -- which, for this product, is
// the alarm that is currently ringing. VACUUM INTO asks SQLite for a
// consistent, self-contained copy with the WAL already folded in, so the
// result is one file that needs no sidecars to open.
//
// It briefly needs room for a second copy of the database. That is the honest
// cost and there is no way around it; a snapshot that is not a full copy is
// not a snapshot.
func snapshotBeforeMigrating(ctx context.Context, db *sql.DB, path string, from int) (string, error) {
	// A brand-new database has nothing to go back to. Version 0 means the
	// first migration is about to create the schema, not change it, and
	// writing an empty file called a backup would be worse than writing
	// nothing: somebody would one day restore it.
	if from <= 0 {
		return "", nil
	}
	if path == "" {
		return "", errors.New("store: no database path, so no snapshot can be taken")
	}

	dest := backupPathFor(path, from)

	// An existing snapshot is KEPT rather than refreshed. If it is here, a
	// previous attempt at this same upgrade already took it, and that copy is
	// the older and therefore more faithful record of the state before any of
	// this started. VACUUM INTO refuses a target that exists, so this check is
	// what turns that refusal into intended behaviour instead of an error.
	switch info, err := os.Stat(dest); {
	case err == nil && info.Mode().IsRegular():
		return dest, nil
	case err == nil:
		// Something is there and it is not a file -- a directory, a device,
		// a symlink to either. Checking the MODE rather than mere existence
		// matters: treating any entry as "already snapshotted" would report a
		// path an operator could not restore from and would never open to
		// find out. Found by a test that put a directory here.
		return "", fmt.Errorf("store: %s exists and is not a file, so no snapshot "+
			"can be written there", dest)
	case !errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("store: checking for an existing snapshot at %s: %w", dest, err)
	}

	// Quoted as a SQL string literal: VACUUM INTO takes a literal, not a bound
	// parameter, in every SQLite version that has it. Single quotes are the
	// only character that needs escaping in one.
	literal := "'" + strings.ReplaceAll(dest, "'", "''") + "'"
	if _, err := db.ExecContext(ctx, "VACUUM INTO "+literal); err != nil {
		// Leave nothing half-written behind. A truncated file with a plausible
		// name is the worst artefact this function could produce.
		_ = os.Remove(dest)
		return "", fmt.Errorf("store: snapshotting the database to %s: %w", dest, err)
	}
	return dest, nil
}

// MigrationSnapshot reports what happened to the pre-upgrade snapshot on the
// most recent Open: the path written, and any error that stopped one being
// written.
//
// BOTH ARE REPORTED AND NEITHER STOPS THE DAEMON. A failed snapshot costs the
// operator a convenient way back; refusing to start costs them the thing the
// product exists to do. For a product whose cardinal failure is silence, that
// is not a close decision -- but it is only defensible if the failure is said
// out loud, which is what this exists for.
func (s *SQLite) MigrationSnapshot() (path string, err error) {
	return s.snapshotPath, s.snapshotErr
}
