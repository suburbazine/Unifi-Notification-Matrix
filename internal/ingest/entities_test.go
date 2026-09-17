package ingest

import (
	"fmt"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
)

// The entity field of a rule is the one no fixed list can supply: camera and
// door names belong to the site, not to this build. The only honest
// suggestions are the things events have actually been about.
func TestObservedEntitiesAreOfferedMostRecentFirst(t *testing.T) {
	now := t0
	s := &Supervisor{deps: Deps{Now: func() time.Time { return now }}}

	s.noteEntity("protect", event.Entity{ID: "cam-1", Name: "Front Door Cam", Kind: "camera"})
	now = t0.Add(time.Minute)
	s.noteEntity("access", event.Entity{ID: "door-3", Name: "Server Room", Kind: "door"})

	got := s.KnownEntities()
	if len(got) != 2 {
		t.Fatalf("%d entities, want 2", len(got))
	}
	if got[0].Name != "Server Room" {
		t.Errorf("first = %q, want the most recently seen", got[0].Name)
	}
	// BOTH halves reach the editor: a rule matches on id or name, and they
	// answer different needs -- the name is what a person recognises, the id
	// is what survives somebody renaming a camera.
	if got[0].ID != "door-3" || got[0].Source != "access" {
		t.Errorf("entity lost its id or source: %+v", got[0])
	}
}

// Seeing the same thing again is not a second thing.
func TestSeeingAnEntityAgainDoesNotDuplicateIt(t *testing.T) {
	now := t0
	s := &Supervisor{deps: Deps{Now: func() time.Time { return now }}}
	for i := 0; i < 50; i++ {
		now = t0.Add(time.Duration(i) * time.Second)
		s.noteEntity("protect", event.Entity{ID: "cam-1", Name: "Front Door Cam"})
	}
	if got := s.KnownEntities(); len(got) != 1 {
		t.Fatalf("%d entities after 50 sightings of one camera", len(got))
	}
}

// BOUNDED. This is fed by arriving events and nothing else prunes it, so a
// site with many transient clients would otherwise grow it without limit --
// a memory leak dressed up as a convenience.
func TestObservedEntitiesAreBounded(t *testing.T) {
	now := t0
	s := &Supervisor{deps: Deps{Now: func() time.Time { return now }}}
	for i := 0; i < maxKnownEntities+120; i++ {
		now = t0.Add(time.Duration(i) * time.Second)
		s.noteEntity("protect", event.Entity{
			ID:   fmt.Sprintf("dev-%d", i),
			Name: fmt.Sprintf("Device %d", i),
		})
	}
	got := s.KnownEntities()
	if len(got) > maxKnownEntities {
		t.Fatalf("%d entities retained, cap is %d", len(got), maxKnownEntities)
	}
	// The ones kept are the recent ones, which is what somebody writing a rule
	// is most likely to be looking for.
	if got[0].ID != fmt.Sprintf("dev-%d", maxKnownEntities+119) {
		t.Errorf("newest retained is %q, want the most recent sighting", got[0].ID)
	}
}

// An event about nothing in particular must not create a blank suggestion.
func TestAnEventWithNoEntityIsNotRemembered(t *testing.T) {
	s := &Supervisor{deps: Deps{Now: func() time.Time { return t0 }}}
	s.noteEntity("protect", event.Entity{})
	if got := s.KnownEntities(); len(got) != 0 {
		t.Errorf("a blank entity was remembered: %+v", got)
	}
}
