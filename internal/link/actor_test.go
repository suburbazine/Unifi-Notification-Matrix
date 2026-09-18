package link

import (
	"testing"
	"time"
)

// THE ACTOR IS THE WHO, AND IT WAS BEING DROPPED.
//
// It sat in the envelope, documented and validated past, and nothing read it.
// On a door denial the entity is the DOOR and the actor is the person, so an
// alert without it says a door refused somebody and does not say who -- which
// is most of what the operator got out of bed for.
func TestTheActorReachesTheIncidentBody(t *testing.T) {
	p := sentry()
	e := sweep()
	e.Condition = "sentry-access-denied"
	e.Detail = "refused at 03:14"
	e.Entity = Party{Kind: "door", ID: "block-2-door", Name: "Block 2"}
	e.Actor = &Party{Kind: "identity", ID: "d540df0c", Name: "R. Okafor"}
	e.Context = nil

	got := e.Event(p, time.Now()).Detail
	const want = "refused at 03:14\nIdentity: R. Okafor (d540df0c)"
	if got != want {
		t.Errorf("detail =\n%q\nwant\n%q", got, want)
	}
}

// ...AND IS LEFT OUT WHEN IT IS THE SAME PARTY AS THE ENTITY.
//
// That is how a peer scopes a cascade to one identity: entity IS the actor, so
// the incident is already titled after them. Repeating it underneath is noise,
// and noise in an alert body is what stops people reading alert bodies.
func TestAnActorThatIsTheEntityIsNotRepeated(t *testing.T) {
	p := sentry()
	e := sweep()
	e.Detail = "sixteen doors in a minute"
	e.Entity = Party{Kind: "identity", ID: "d540df0c", Name: "R. Okafor"}
	e.Actor = &Party{Kind: "identity", ID: "d540df0c", Name: "R. Okafor"}
	e.Context = nil

	if got := e.Event(p, time.Now()).Detail; got != "sixteen doors in a minute" {
		t.Errorf("detail = %q, want the detail alone", got)
	}
}

// The ordering is fixed: detail, then who, then context. An incident body that
// reorders itself between two deliveries of the same event reads as two
// different events.
func TestTheBodyOrdersDetailThenActorThenContext(t *testing.T) {
	p := sentry()
	e := sweep()
	e.Condition = "sentry-access-denied"
	e.Detail = "refused"
	e.Entity = Party{Kind: "door", ID: "block-2-door"}
	e.Actor = &Party{Kind: "identity", ID: "d540df0c"}
	e.Context = map[string]any{"zulu": 1, "alpha": 2}

	const want = "refused\nIdentity: d540df0c\nalpha: 2\nzulu: 1"
	if got := e.Event(p, time.Now()).Detail; got != want {
		t.Errorf("detail =\n%q\nwant\n%q", got, want)
	}
}

func TestNoActorChangesNothing(t *testing.T) {
	p := sentry()
	e := sweep()
	e.Detail = "plain"
	e.Actor = nil
	e.Context = nil
	if got := e.Event(p, time.Now()).Detail; got != "plain" {
		t.Errorf("detail = %q", got)
	}
}
