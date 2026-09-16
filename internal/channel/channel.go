// Package channel delivers alerts to humans.
//
// A channel is stateless: it formats and sends, and reports what happened. It
// knows nothing about incidents, escalation or UniFi -- everything it needs is
// in the Alert it is handed.
package channel

import (
	"context"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Alert is one delivery. Everything a channel needs, and nothing it does not.
type Alert struct {
	IncidentID string
	Severity   incident.Severity

	Title  string
	Body   string
	Entity string // human name of the thing, for tags and subjects

	// AckURL acknowledges this one incident and nothing else. It carries its
	// own authority (an HMAC scoped to the incident), so channels may embed it
	// in an unauthenticated context -- an ntfy action button, a link in an
	// email -- which is the point: nobody is signing into a web UI at 3am.
	AckURL string

	// OpenedAt is when the condition was first observed; At is the observation
	// time of the event that triggered this particular alert.
	OpenedAt time.Time
	At       time.Time

	// AtIsArrivalTime says the timestamp is when WE received it, not when it
	// happened, because the source supplied no time of its own. Channels must
	// word the alert accordingly -- "received 03:14" rather than "at 03:14" --
	// so nobody scrubs footage to a time that means nothing.
	AtIsArrivalTime bool

	// Stage is the escalation rung, and Repeat counts how many times this
	// incident has already been alerted. A channel may use these to say "3rd
	// reminder", which is often the difference between a notification that gets
	// read and one that gets swiped away.
	Stage  int
	Repeat int

	// Snapshot is an optional JPEG. Channels that cannot attach one ignore it.
	Snapshot []byte
}

// IsRepeat reports whether this is a re-alert rather than the first delivery.
func (a Alert) IsRepeat() bool { return a.Repeat > 0 }

// Channel sends an alert. Implementations must respect ctx and must not retry
// beyond their own bounded policy -- the escalation ladder above them is what
// provides persistence, so a channel that retries for minutes is duplicating a
// job that is already being done better elsewhere.
type Channel interface {
	// Name is the identifier used in policy stage lists and diagnostics.
	Name() string

	// Send delivers, or returns why it could not.
	Send(ctx context.Context, a Alert) error

	// Test sends a harmless message proving the configuration works. Wired to
	// the "send test" button, and to the scheduled self-test.
	Test(ctx context.Context) error
}
