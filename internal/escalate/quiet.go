package escalate

import (
	"errors"
	"fmt"
	"time"
)

// QuietHours is a window during which lower-severity alerts are held.
//
// It can never apply to critical: Policy.Validate refuses a critical policy
// with RespectQuietHours set, so the config cannot express "mute the alarm".
// That refusal is the important half of this feature — a quiet-hours control
// that reached the top severity would be a mute button with a friendly name.
type QuietHours struct {
	Enabled bool `json:"enabled"`

	// Start and End are "HH:MM" in 24-hour form. A window may wrap midnight:
	// Start "22:00", End "07:00" is the ordinary case and the one that is
	// easiest to get wrong.
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`

	// Zone is an IANA name ("Europe/London"). Empty means the host's local
	// time.
	//
	// This is stored explicitly rather than assumed, because the daemon
	// commonly runs on a server whose clock is UTC while the site it is
	// watching is not. Quiet hours derived from the wrong zone are silent at
	// the wrong times, and nobody notices until an alert they wanted did not
	// arrive.
	Zone string `json:"zone,omitempty"`
}

var (
	ErrBadQuietTime = errors.New("quiet hours: time must be HH:MM in 24-hour form")
	ErrBadQuietZone = errors.New("quiet hours: unknown time zone")
	ErrEmptyWindow  = errors.New("quiet hours: start and end are the same, which is not a window")
)

// Validate checks the window can be interpreted at all. Called at config load,
// so a typo is a startup refusal rather than a surprise at 2am.
func (q QuietHours) Validate() error {
	if !q.Enabled {
		return nil
	}
	s, err := parseHM(q.Start)
	if err != nil {
		return fmt.Errorf("%w: start %q", ErrBadQuietTime, q.Start)
	}
	e, err := parseHM(q.End)
	if err != nil {
		return fmt.Errorf("%w: end %q", ErrBadQuietTime, q.End)
	}
	if s == e {
		// Ambiguous between "no window" and "all day", and the two are
		// opposites. Refuse rather than pick one.
		return fmt.Errorf("%w (%s)", ErrEmptyWindow, q.Start)
	}
	if _, err := q.location(); err != nil {
		return fmt.Errorf("%w: %q", ErrBadQuietZone, q.Zone)
	}
	return nil
}

func (q QuietHours) location() (*time.Location, error) {
	if q.Zone == "" {
		return time.Local, nil
	}
	return time.LoadLocation(q.Zone)
}

// Contains reports whether t falls inside the window.
//
// Start is inclusive and End is exclusive, so back-to-back windows neither
// overlap nor leave a one-minute gap.
func (q QuietHours) Contains(t time.Time) bool {
	if !q.Enabled {
		return false
	}
	s, err := parseHM(q.Start)
	if err != nil {
		return false
	}
	e, err := parseHM(q.End)
	if err != nil || s == e {
		return false
	}
	loc, err := q.location()
	if err != nil {
		// An unloadable zone must not silently become "quiet everywhere",
		// which would mute every non-critical alert. Validate catches this at
		// startup; if it is somehow reached here, fail toward alerting.
		return false
	}
	lt := t.In(loc)
	m := lt.Hour()*60 + lt.Minute()

	if s < e {
		return m >= s && m < e
	}
	// Wraps midnight: 22:00-07:00 means "at or after 22:00, OR before 07:00".
	return m >= s || m < e
}

// NextEnd returns when the current quiet window ends, for a held incident.
// Meaningful only when Contains(t) is true.
func (q QuietHours) NextEnd(t time.Time) time.Time {
	loc, err := q.location()
	if err != nil {
		return t
	}
	e, err := parseHM(q.End)
	if err != nil {
		return t
	}
	lt := t.In(loc)
	end := time.Date(lt.Year(), lt.Month(), lt.Day(), e/60, e%60, 0, 0, loc)
	if !end.After(lt) {
		end = end.AddDate(0, 0, 1)
	}
	return end
}

// parseHM returns minutes since midnight.
func parseHM(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, err
	}
	return t.Hour()*60 + t.Minute(), nil
}
