package incident

import (
	"context"
	"errors"
)

// ErrNotFound is returned by Store lookups that match nothing.
var ErrNotFound = errors.New("incident not found")

// Store is the durable home of incidents.
//
// This interface exists because durability is not negotiable here: the store
// must survive a process restart, a crash, and a reboot with the alarm still
// alarming. Service restarts are most likely during exactly the power and
// network events that generate alarms, so an in-memory store with periodic
// flush is not a simpler version of this -- it is a broken one.
//
// Implementations must be safe for concurrent use: ingest, the escalation
// scheduler and the web UI all touch it at once.
type Store interface {
	// Put writes the incident, creating or replacing it wholesale.
	Put(ctx context.Context, inc *Incident) error

	// Get returns one incident by id, or ErrNotFound.
	Get(ctx context.Context, id string) (*Incident, error)

	// OpenByDedupKey returns the NON-TERMINAL incident for this key, or
	// ErrNotFound.
	//
	// At most one may exist at a time -- that is what makes an event storm
	// collapse into one incident -- and the implementation must enforce it
	// rather than trusting callers, because two goroutines ingesting the same
	// flapping camera will otherwise both find nothing and both create one.
	OpenByDedupKey(ctx context.Context, key string) (*Incident, error)

	// Active returns every non-terminal incident. Used by the scheduler to
	// rebuild its schedule at start, and by the UI for the live board.
	Active(ctx context.Context) ([]*Incident, error)

	// Recent returns incidents by most recently updated, terminal ones
	// included, for the history view.
	Recent(ctx context.Context, limit int) ([]*Incident, error)

	Close() error
}
