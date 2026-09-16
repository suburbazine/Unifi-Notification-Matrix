// Package audit is the append-only record of what this product did.
//
// Not a log. A log is for debugging and gets rotated away; this answers "who
// silenced that alarm, and when" months later, which is the question that
// matters after an incident that mattered.
package audit

import (
	"context"
	"strings"
	"time"
)

// Kind classifies an entry. Fixed vocabulary: an audit record whose categories
// drift is one nobody can search.
type Kind string

const (
	// KindEvent is a source observation that reached the rule engine.
	KindEvent Kind = "event"

	// KindIncidentOpened, KindIncidentUpdated and KindIncidentRecurred track
	// the lifecycle.
	KindIncidentOpened   Kind = "incident.opened"
	KindIncidentUpdated  Kind = "incident.updated"
	KindIncidentRecurred Kind = "incident.recurred"

	// KindIncidentIgnored records an event a rule silenced. THE MOST
	// IMPORTANT KIND. "Why was I not paged" is the hard question, and it is
	// unanswerable unless the silences are recorded as deliberately as the
	// alerts.
	KindIncidentIgnored Kind = "incident.ignored"

	KindAlertSent   Kind = "alert.sent"
	KindAlertFailed Kind = "alert.failed"
	KindAlertHeld   Kind = "alert.held" // quiet hours

	KindAcknowledged Kind = "incident.acknowledged"
	KindResolved     Kind = "incident.resolved"
	KindClosed       Kind = "incident.closed"

	// KindConfigChanged records a settings write, with WHAT changed but never
	// the values -- a config diff would put credentials in the audit file.
	KindConfigChanged Kind = "config.changed"

	// KindAuth covers sign-in attempts, successful and not.
	KindAuth Kind = "auth"

	// KindService covers start, clean stop and crash detection.
	KindService Kind = "service"
)

// Entry is one immutable record.
type Entry struct {
	At   time.Time `json:"at"`
	Kind Kind      `json:"kind"`

	// Actor is who or what caused this, as precisely as is actually known:
	// "ntfy" for an acknowledgement that arrived through an ntfy link,
	// "web" for the local UI, "system" for the product itself. Never a
	// username, because there are no user accounts -- claiming more than is
	// known is the failure this field exists to avoid.
	Actor string `json:"actor,omitempty"`

	IncidentID string `json:"incident_id,omitempty"`
	DedupKey   string `json:"dedup_key,omitempty"`
	Severity   string `json:"severity,omitempty"`

	// Summary is one human-readable line.
	Summary string `json:"summary"`

	// Fields carries structured detail. MUST NOT contain secrets: this file
	// is plain text, is meant to be read and grepped by an operator, and may
	// well be pasted into a support ticket.
	Fields map[string]string `json:"fields,omitempty"`
}

// Log is the append-only sink.
//
// Append must never block the caller for long and must never fail the
// operation it is recording: an alert that was delivered but could not be
// written to the audit file is still an alert that was delivered, and
// discarding it would be the worse error. Implementations report write
// failures out of band.
type Log interface {
	Append(ctx context.Context, e Entry) error

	// Recent returns the most recent entries, newest first.
	Recent(ctx context.Context, limit int) ([]Entry, error)

	Close() error
}

// Nop is a Log that discards. Used where auditing is genuinely not wanted,
// such as in tests of other packages.
type Nop struct{}

func (Nop) Append(context.Context, Entry) error          { return nil }
func (Nop) Recent(context.Context, int) ([]Entry, error) { return nil, nil }
func (Nop) Close() error                                 { return nil }

// scrub removes anything that must not be written to a plain-text file that
// an operator will grep and may paste into a support ticket.
//
// Belt and braces. Callers are not supposed to put credentials in Fields, and
// secret.Secret already renders as <redacted> if one is formatted in by
// accident. This is the third line: a field NAMED like a credential has its
// value replaced regardless of what it actually holds, because the cost of
// over-redacting an audit field is nil and the cost of under-redacting one is
// a console API key sitting in a text file forever.
func (e *Entry) scrub() {
	const cap = 2000
	if len(e.Summary) > cap {
		e.Summary = e.Summary[:cap] + "…"
	}
	if len(e.Fields) == 0 {
		return
	}
	for k, v := range e.Fields {
		if looksSecret(k) {
			if v != "" {
				e.Fields[k] = "<redacted>"
			}
			continue
		}
		if len(v) > cap {
			e.Fields[k] = v[:cap] + "…"
		}
	}
}

// secretish are substrings that mark a field name as carrying a credential.
//
// Matched on the NAME, not the value: guessing from a value means deciding
// whether a given string "looks like" a key, which is exactly the judgement
// that fails on the one key that does not look like one.
var secretish = []string{
	"key", "token", "secret", "password", "passwd", "pass",
	"credential", "auth", "cookie", "session", "signature", "bearer",
}

func looksSecret(name string) bool {
	n := strings.ToLower(name)
	for _, s := range secretish {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}
