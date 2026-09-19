package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openStore(t *testing.T) *SQLite {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "incidents.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// THE RECORD SURVIVES A RESTART, which is the whole point of moving it out of
// memory. The question it answers -- "what did this site have?" -- is asked
// after the power comes back, and an in-memory registry is empty exactly then.
func TestWhatWasSeenSurvivesAReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "incidents.db")
	ctx := context.Background()

	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	if err := first.NoteEntity(ctx, ObservedEntity{
		Source: "protect", ID: "cam-1", Name: "Front Gate", Kind: "camera",
		MAC: "aa:bb:cc:dd:ee:01", FirstSeen: when, LastSeen: when,
	}); err != nil {
		t.Fatal(err)
	}
	first.Close()

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()

	got, err := again.ObservedEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("after a restart the record holds %d entities, want 1; the "+
			"operator asking what they had before the outage gets nothing", len(got))
	}
	if got[0].Name != "Front Gate" || got[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("entity = %+v", got[0])
	}
	if !got[0].FirstSeen.Equal(when) {
		t.Errorf("first_seen = %v, want %v -- without it, 'lost' and 'never "+
			"existed' read the same", got[0].FirstSeen, when)
	}
}

// FIRST SEEN NEVER MOVES. It is the one column whose entire value is that it
// does not: "here since March, stopped on Tuesday" versus "there is no such
// camera" are different sentences and only one of them describes a loss.
func TestFirstSeenIsNotOverwrittenBySeeingItAgain(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	march := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	sept := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)

	for _, at := range []time.Time{march, sept} {
		if err := s.NoteEntity(ctx, ObservedEntity{
			Source: "protect", ID: "cam-1", Name: "Front Gate", FirstSeen: at, LastSeen: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.ObservedEntities(ctx)
	if len(got) != 1 {
		t.Fatalf("seeing one camera twice made %d rows", len(got))
	}
	if !got[0].FirstSeen.Equal(march) {
		t.Errorf("first_seen = %v, want the March sighting", got[0].FirstSeen)
	}
	if !got[0].LastSeen.Equal(sept) {
		t.Errorf("last_seen = %v, want the September sighting", got[0].LastSeen)
	}
}

// A RENAME UPDATES THE ROW rather than creating a second one. The map this
// replaces keyed on {source, id, name}, so renaming a camera produced two
// entries and the rules picker offered both.
func TestARenameUpdatesTheSameRow(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	note := func(name string) {
		if err := s.NoteEntity(ctx, ObservedEntity{
			Source: "protect", ID: "cam-1", Name: name, LastSeen: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	note("Front Gate")
	note("Yard Camera")

	got, _ := s.ObservedEntities(ctx)
	if len(got) != 1 {
		t.Fatalf("a rename produced %d rows, want 1: %+v", len(got), got)
	}
	if got[0].Name != "Yard Camera" {
		t.Errorf("name = %q, want the current one", got[0].Name)
	}
}

// AN EVENT THAT KNOWS LESS MUST NOT ERASE WHAT IS KNOWN.
//
// The two Protect ingest paths identify devices differently -- the WebSocket
// carries an id, the Alarm Manager webhook a bare MAC -- so an event arriving
// by the thinner route is a gap in that event, not news that the camera lost
// its name.
func TestASparseEventDoesNotBlankWhatIsAlreadyKnown(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	if err := s.NoteEntity(ctx, ObservedEntity{
		Source: "protect", ID: "cam-1", Name: "Front Gate", Kind: "camera",
		MAC: "aa:bb:cc:dd:ee:01", LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.NoteEntity(ctx, ObservedEntity{
		Source: "protect", ID: "cam-1", LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ObservedEntities(ctx)
	if got[0].Name != "Front Gate" || got[0].Kind != "camera" || got[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("a sparse event erased what was known: %+v", got[0])
	}
}

// THE MAC IS WHAT CONNECTS A RE-ADOPTED DEVICE TO ITS OLD SELF.
//
// A UniFi device id is generated at adoption, so re-adopting a hub recreates
// every camera or door under it with a new id. Two rows sharing a MAC is the
// evidence that the new thing is the old thing.
func TestTheSameHardwareUnderTwoIdsIsFoundByItsMAC(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	const mac = "aa:bb:cc:dd:ee:01"

	for _, id := range []string{"old-id", "new-id"} {
		if err := s.NoteEntity(ctx, ObservedEntity{
			Source: "protect", ID: id, Name: "Front Gate", Kind: "camera",
			MAC: mac, LastSeen: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.EntitiesWithMAC(ctx, mac)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("looking up the MAC found %d rows, want both ids; without both "+
			"there is no evidence the re-adopted device is the old one", len(got))
	}
	if none, err := s.EntitiesWithMAC(ctx, ""); err != nil || len(none) != 0 {
		t.Errorf("an empty MAC matched %d rows; every device without one would "+
			"look like the same device", len(none))
	}
}
