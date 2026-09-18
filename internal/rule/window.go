package rule

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Window is a daily span of clock time in the site's own zone.
//
// It exists because a rule could say WHAT to escalate and never WHEN. A denial
// at 3am and one at 2pm are the same event to this product and very different
// events to a building, and the only way to express that was to have whatever
// sent the event decide the severity for us -- which puts a judgement about
// the site inside a product that cannot see the site.
//
// Deliberately a clock window and not a calendar. Holidays, term dates and
// per-door schedules belong to whatever system already owns them; this is the
// smallest thing that answers "out of hours".
type Window struct {
	// Start and End are "HH:MM" in 24-hour form. A window may wrap midnight:
	// "21:30" to "06:00" is the ordinary case and the one easiest to get
	// wrong.
	Start string `json:"start"`
	End   string `json:"end"`
}

var (
	ErrBadWindowTime = errors.New("rule window: time must be HH:MM in 24-hour form")
	ErrEmptyWindow   = errors.New("rule window: start and end are the same instant, which matches nothing")
)

// Validate refuses a window that cannot be read.
//
// A malformed window must fail at startup, where somebody is watching. Treated
// as "never matches" it would silently disable the rule built on it, which is
// the failure this product dislikes most: configured, plausible, inert.
func (w Window) Validate() error {
	s, err := parseHHMM(w.Start)
	if err != nil {
		return fmt.Errorf("%w: start %q", ErrBadWindowTime, w.Start)
	}
	e, err := parseHHMM(w.End)
	if err != nil {
		return fmt.Errorf("%w: end %q", ErrBadWindowTime, w.End)
	}
	if s == e {
		return ErrEmptyWindow
	}
	return nil
}

// Contains reports whether t falls inside the window. t is used in whatever
// location it carries, so the caller converts to the site's zone first.
//
// Half-open: the start minute is inside, the end minute is not. Without that,
// two adjacent windows both claim the boundary minute.
func (w Window) Contains(t time.Time) bool {
	s, err := parseHHMM(w.Start)
	if err != nil {
		return false
	}
	e, err := parseHHMM(w.End)
	if err != nil {
		return false
	}
	m := t.Hour()*60 + t.Minute()
	if s <= e {
		return m >= s && m < e
	}
	// Wraps midnight: inside means after the start OR before the end.
	return m >= s || m < e
}

func parseHHMM(v string) (int, error) {
	parts := strings.Split(strings.TrimSpace(v), ":")
	if len(parts) != 2 {
		return 0, ErrBadWindowTime
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, ErrBadWindowTime
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, ErrBadWindowTime
	}
	return h*60 + m, nil
}
