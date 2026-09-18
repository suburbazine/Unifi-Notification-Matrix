package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// openAt builds a database stopped at a given schema version, the way a build
// that only knew about that many migrations would have left it.
func openAt(t *testing.T, path string, upto int) {
	t.Helper()
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for _, m := range migrations {
		if m.version > upto {
			break
		}
		if err := applyMigration(ctx, db, m); err != nil {
			t.Fatal(err)
		}
	}
	var got int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != upto {
		t.Fatalf("fixture is at schema %d, wanted %d", got, upto)
	}
}

func schemaOf(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v int
	if err := db.QueryRowContext(context.Background(), `PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// THE SNAPSHOT HAS TO BE A DATABASE AN OLDER BUILD CAN OPEN.
//
// A file of the right size with the right name proves nothing. This is the
// test that would have been worth having before 0.1.8 shipped: it opens the
// snapshot, checks it is still at the OLD schema, and reads back a row written
// before the upgrade.
func TestTheSnapshotIsAWorkingDatabaseAtTheOldSchema(t *testing.T) {
	if latestVersion() < 2 {
		t.Skip("needs at least two migrations to have an upgrade to snapshot")
	}
	path := filepath.Join(t.TempDir(), "incidents.db")
	openAt(t, path, 1)

	// Something recognisable, written by the OLD build before the upgrade.
	func() {
		db, err := sql.Open("sqlite", dsn(path))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec(`INSERT INTO incidents
			(id, dedup_key, severity, source, title, detail, opened_at, updated_at)
			VALUES ('before1','protect/e/c','high','protect','Before the upgrade','','2026-09-18T00:00:00Z','2026-09-18T00:00:00Z')`); err != nil {
			t.Fatalf("writing the pre-upgrade row: %v", err)
		}
	}()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	snap, snapErr := s.MigrationSnapshot()
	if snapErr != nil {
		t.Fatalf("the snapshot failed: %v", snapErr)
	}
	if snap == "" {
		t.Fatal("an upgrade took no snapshot, so there is no way back from it")
	}
	if _, err := os.Stat(snap); err != nil {
		t.Fatalf("the snapshot path does not exist: %v", err)
	}

	// The live database moved on.
	if got := schemaOf(t, path); got != latestVersion() {
		t.Errorf("live database is at schema %d, want %d", got, latestVersion())
	}

	// The snapshot did not. This is the whole point: an older build checks
	// user_version and refuses anything above what it knows.
	if got := schemaOf(t, snap); got != 1 {
		t.Errorf("snapshot is at schema %d, want 1 -- a build that understands "+
			"only schema 1 would refuse to open it, which makes it useless as "+
			"the thing you roll back to", got)
	}

	// And it carries the data, not just the shape.
	db, err := sql.Open("sqlite", dsn(snap))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var title string
	if err := db.QueryRow(`SELECT title FROM incidents WHERE id = 'before1'`).Scan(&title); err != nil {
		t.Fatalf("the pre-upgrade row is not in the snapshot: %v", err)
	}
	if title != "Before the upgrade" {
		t.Errorf("title = %q", title)
	}
}

// A FRESH INSTALL TAKES NO SNAPSHOT.
//
// There is nothing to go back to, and an empty file named like a backup is
// worse than no file: somebody restores it one day.
func TestAFreshDatabaseIsNotSnapshotted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	snap, snapErr := s.MigrationSnapshot()
	if snapErr != nil {
		t.Errorf("a fresh install reported a snapshot error: %v", snapErr)
	}
	if snap != "" {
		t.Errorf("a fresh install wrote a snapshot at %q", snap)
	}
	matches, _ := filepath.Glob(path + "*.bak")
	if len(matches) != 0 {
		t.Errorf("a fresh install left backup files: %v", matches)
	}
}

// AN ORDINARY START TAKES NO SNAPSHOT EITHER. This runs on every boot, and a
// copy of the database on each one would fill a disk to no purpose.
func TestStartingWithNothingToMigrateTakesNoSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if snap, _ := second.MigrationSnapshot(); snap != "" {
		t.Errorf("a start with no migration to run wrote a snapshot at %q", snap)
	}
}

// AN EXISTING SNAPSHOT IS KEPT, NOT REFRESHED.
//
// If it is there, a previous attempt at this same upgrade took it, and that
// copy is older and therefore a more faithful record of the state before any
// of this began. Overwriting it with the state after a half-finished attempt
// would quietly destroy the thing being preserved.
func TestAnExistingSnapshotIsNotOverwritten(t *testing.T) {
	if latestVersion() < 2 {
		t.Skip("needs at least two migrations")
	}
	path := filepath.Join(t.TempDir(), "incidents.db")
	openAt(t, path, 1)

	dest := backupPathFor(path, 1)
	if err := os.WriteFile(dest, []byte("an older snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "an older snapshot" {
		t.Error("the earlier snapshot was overwritten by this attempt; the copy " +
			"that predates the whole upgrade is the one worth keeping")
	}
	if snap, _ := s.MigrationSnapshot(); snap != dest {
		t.Errorf("reported %q, want the existing snapshot at %q", snap, dest)
	}
}

// A SNAPSHOT THAT CANNOT BE WRITTEN MUST NOT STOP THE DAEMON.
//
// The trade, stated: a failed snapshot costs the operator a convenient way
// back. Refusing to start costs them the thing the product exists to do, and
// for this product silence is the cardinal failure. So the upgrade proceeds
// and the failure is reported -- which is only defensible because it IS
// reported, which is what this test pins.
func TestAFailedSnapshotDoesNotStopTheUpgrade(t *testing.T) {
	if latestVersion() < 2 {
		t.Skip("needs at least two migrations")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "incidents.db")
	openAt(t, path, 1)

	// A directory where the snapshot file needs to go: SQLite cannot write it,
	// and this works the same on every platform.
	if err := os.Mkdir(backupPathFor(path, 1), 0o700); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("a failed snapshot stopped the daemon starting: %v", err)
	}
	defer s.Close()

	snap, snapErr := s.MigrationSnapshot()
	if snapErr == nil {
		t.Fatal("the snapshot could not have succeeded, and no error was reported; " +
			"an operator would believe they had a way back")
	}
	if snap != "" {
		t.Errorf("a failed snapshot reported a path: %q", snap)
	}

	// And the upgrade still happened.
	if got := schemaOf(t, path); got != latestVersion() {
		t.Errorf("schema is %d, want %d: the upgrade did not proceed", got, latestVersion())
	}
}

// The snapshot is named for the schema it restores INTO, so a reader can tell
// which builds can open it without opening it.
func TestTheSnapshotIsNamedForTheSchemaItRestores(t *testing.T) {
	if got := backupPathFor("/data/incidents.db", 1); got != "/data/incidents.db.v1.bak" {
		t.Errorf("backupPathFor = %q", got)
	}
	if got := backupPathFor("/data/incidents.db", 7); got != "/data/incidents.db.v7.bak" {
		t.Errorf("backupPathFor = %q", got)
	}
}

// A path containing a quote cannot break out of the VACUUM INTO literal.
// SQLite takes a literal there rather than a bound parameter, so the escaping
// is hand-rolled and worth a test.
func TestAQuoteInThePathDoesNotBreakTheSnapshot(t *testing.T) {
	if latestVersion() < 2 {
		t.Skip("needs at least two migrations")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "o'brien.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Skipf("this platform will not take a quote in a filename: %v", err)
	}
	os.Remove(path)

	openAt(t, path, 1)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	snap, snapErr := s.MigrationSnapshot()
	if snapErr != nil {
		t.Fatalf("a quoted path failed to snapshot: %v", snapErr)
	}
	if _, err := os.Stat(snap); err != nil {
		t.Fatalf("no snapshot at %q: %v", snap, err)
	}
	if got := schemaOf(t, snap); got != 1 {
		t.Errorf("snapshot is at schema %d, want 1", got)
	}
}

func TestSnapshotOfAnEmptyPathIsAnError(t *testing.T) {
	if _, err := snapshotBeforeMigrating(context.Background(), nil, "", 1); err == nil {
		t.Error("an empty path reported success")
	}
}

// THE SNAPSHOT MUST INCLUDE WHAT IS STILL IN THE WAL.
//
// This database runs in WAL mode, so the bytes in incidents.db are not the
// database: commits live in the -wal sidecar until a checkpoint folds them in.
// A plain file copy of the main file therefore yields a snapshot missing
// whatever was written most recently -- which, for this product, is the alarm
// that is currently ringing.
//
// Written because the first version of these tests did NOT catch that:
// replacing VACUUM INTO with os.ReadFile/os.WriteFile left every one of them
// green. Their pre-upgrade row was written by a connection that was then
// closed, and closing checkpoints the WAL, so the row had already moved into
// the main file and a naive copy found it. The comment in backup.go claimed
// something no test demonstrated.
//
// Here the writer stays OPEN with autocheckpoint off, so the row is provably
// still in the sidecar when the snapshot is taken.
func TestTheSnapshotIncludesCommitsStillInTheWAL(t *testing.T) {
	if latestVersion() < 2 {
		t.Skip("needs at least two migrations")
	}
	path := filepath.Join(t.TempDir(), "incidents.db")
	openAt(t, path, 1)

	writer, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	// One connection, so the PRAGMA and the INSERT are certain to share it.
	writer.SetMaxOpenConns(1)
	if _, err := writer.Exec(`PRAGMA wal_autocheckpoint = 0`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`INSERT INTO incidents
		(id, dedup_key, severity, source, title, detail, opened_at, updated_at)
		VALUES ('inwal','protect/e/c','critical','protect','Still in the WAL','','2026-09-18T00:00:00Z','2026-09-18T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	// The row has to be in the sidecar for this test to mean anything.
	fi, statErr := os.Stat(path + "-wal")
	if statErr != nil || fi.Size() == 0 {
		t.Skipf("no populated -wal sidecar here (%v), so this test cannot tell "+
			"a real snapshot from a plain file copy", statErr)
	}

	// The writer is still open, so nothing has checkpointed.
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, snapErr := s.MigrationSnapshot()
	if snapErr != nil {
		t.Fatalf("snapshot failed: %v", snapErr)
	}
	if snap == "" {
		t.Fatal("no snapshot taken")
	}

	db, err := sql.Open("sqlite", dsn(snap))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var title string
	if err := db.QueryRow(`SELECT title FROM incidents WHERE id = 'inwal'`).Scan(&title); err != nil {
		t.Fatalf("a commit that was still in the WAL is missing from the snapshot: %v\n"+
			"A copy of the main database file alone is not a snapshot of this "+
			"database; that is what VACUUM INTO is for.", err)
	}
	if title != "Still in the WAL" {
		t.Errorf("title = %q", title)
	}
}
