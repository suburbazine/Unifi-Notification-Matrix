package incident

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by Store lookups that match nothing.
var ErrNotFound = errors.New("incident not found")

// ErrConflict means the stored incident changed since the caller read it, so
// the write was refused rather than applied on top of somebody else's change.
var ErrConflict = errors.New("incident changed concurrently")

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
	//
	// Use it to CREATE, and to write from a path that owns the incident
	// outright. For read-modify-write from a concurrent path, use
	// PutIfUnchanged: Put is last-write-wins, and the write most likely to be
	// lost here is an acknowledgement.
	Put(ctx context.Context, inc *Incident) error

	// PutIfUnchanged writes only if the stored row's UpdatedAt still equals
	// expect, and returns ErrConflict otherwise.
	//
	// This exists for one specific race, and it is the race that matters most
	// in this product. The escalation scheduler reads an incident, spends real
	// time delivering it through channels that talk to the network, and then
	// writes back the fact that it alerted. An acknowledgement arriving during
	// that window — which is precisely when it arrives, because the alert that
	// prompted it has just gone out — would be overwritten by the write that
	// follows.
	//
	// Losing an ack is not a cosmetic failure. The operator taps the button,
	// watches the alert keep arriving, and concludes the product does not
	// work. That it fails "safe" by continuing to nag is no comfort: a
	// watchdog nobody trusts gets muted, and a muted watchdog is the failure
	// this product exists to prevent, arriving by a longer road.
	PutIfUnchanged(ctx context.Context, inc *Incident, expect time.Time) error

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
