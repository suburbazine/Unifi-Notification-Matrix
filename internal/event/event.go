// Package event is the normalised shape every source produces.
//
// Sources differ wildly in what they can tell us -- Protect pushes typed events
// over a WebSocket, Access requires polling a log, Network only sends an
// undocumented webhook with no timestamp at all. This package is where those
// differences stop. Everything downstream of here sees one shape.
package event

import (
	"context"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Entity is the thing an event happened to.
//
// ID and MAC are both present because the two Protect ingest paths identify
// devices differently -- the WebSocket carries a Protect device id, the Alarm
// Manager webhook carries a bare MAC. A source that knows only one fills only
// one, and resolution to a stable identity happens in the source, before the
// event is emitted, so that nothing downstream has to care which route it
// arrived by.
type Entity struct {
	ID   string // stable identifier within the source
	Name string // human name, for the alert text
	Kind string // "camera", "sensor", "door", "device", "nvr", "site"
	MAC  string // when the source identified it that way
}

// Event is something a source observed.
//
// Immutable once emitted. If a source needs to correct an event, it emits
// another one.
type Event struct {
	// ID is the source's own identifier where it has one. Used to suppress
	// re-processing the same event when it arrives twice.
	ID string

	Source string // "protect", "access", "network", "inbound", "internal"
	Kind   string // the source's own type name, e.g. "sensorAlarm"

	Entity Entity

	// Condition is the normalised thing that is true, and it is what the dedup
	// key is built from: "offline", "forced-open", "smoke", "wan-down". Two
	// sources reporting the same condition about the same entity must use the
	// same string, or the same real-world problem becomes two incidents.
	Condition string

	// Clears inverts the event: this says the condition has ENDED rather than
	// begun. A camera coming back online and a camera going offline are the
	// same Condition with different Clears.
	Clears bool

	// At is when it happened; ReceivedAt is when we saw it.
	At         time.Time
	ReceivedAt time.Time

	// AtIsArrivalTime marks an event whose At we stamped ourselves because the
	// source did not supply one.
	//
	// This is not a detail. Protect's Alarm Manager webhook carries a real
	// controller timestamp; Network's carries none at all, and the Access log
	// mixes seconds and milliseconds. An alert that presents an arrival time as
	// though it were an observation time will send someone scrubbing to the
	// wrong point in the footage, so the flag travels with the event and the
	// alert text says "received" rather than "at".
	AtIsArrivalTime bool

	// Severity is the source's PROPOSAL. Rules may override it; a source knows
	// what happened, not how much this particular site cares.
	Severity incident.Severity

	Title  string
	Detail string

	// Snapshot is an optional JPEG for channels that can attach one.
	Snapshot []byte

	// Raw is the original payload, kept for the audit record. Never rendered
	// into an alert: it can contain credential-bearing URLs.
	Raw map[string]any
}

// DedupKey is what collapses the same condition arriving by different routes
// into one incident.
func (e Event) DedupKey() string {
	return incident.Key(e.Source, e.Entity.ID, e.Condition)
}

// Sink receives events from a source. Implementations must not block: a source
// stalled on delivery stops reading its socket, and a Protect socket that stops
// being read silently misses events it can never recover (there is no resume
// cursor).
type Sink interface {
	Emit(Event)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(Event)

func (f SinkFunc) Emit(e Event) { f(e) }

// Source is an ingest path. Run blocks until ctx is cancelled and is expected
// to reconnect internally rather than returning on transient failure.
type Source interface {
	// Name is the source identifier used in dedup keys and diagnostics.
	Name() string

	// Run ingests until ctx is done. Returning a non-nil error means the source
	// cannot work at all with this configuration -- a bad API key, not a
	// dropped connection.
	Run(ctx context.Context, out Sink) error

	// Liveness is how long this source may be OUT OF CONTACT before the
	// deadman treats it as a fault. Zero disables the deadman for it.
	Liveness() time.Duration
}

// Contactable is an optional interface a Source may implement to report the
// last time it was in contact with its console, as distinct from the last time
// it had something to report.
//
// THE TWO ARE NOT THE SAME, and conflating them is how a working installation
// pages its operator every half hour. The deadman originally measured emitted
// EVENTS, so a Protect source holding a healthy websocket over a quiet evening
// -- no motion, no detections, no device changing state -- looked exactly like
// one whose socket had died, and after thirty minutes it was reported as dead.
// A dead source and a quiet site looking identical is the confusion this
// product exists to remove; measuring the wrong thing recreated it, pointed
// the other way.
//
// A source that implements this reports the last frame, poll or sweep that
// actually reached its console. Nothing arriving THERE is a real fault;
// nothing worth emitting is a quiet night.
type Contactable interface {
	LastContact() time.Time
}
