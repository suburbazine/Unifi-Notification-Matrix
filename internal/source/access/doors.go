// Package access is the UniFi Access ingest path.
//
// It has THREE inputs, not one, and that is forced by what Access actually
// exposes rather than by taste:
//
//   - The notifications WebSocket carries lock state and `remain_unlock` and
//     nothing else. No door position, no tamper, no offline, no battery. It is
//     a lock-state accelerator, not an alarm surface, and a product that
//     treated it as one would report a door as healthy while it stood open.
//   - The system log carries the denials and the admin activity, and it is the
//     only confirmed source for either. It lags by up to three and a half
//     minutes, which is the binding constraint on this whole package.
//   - Door position has to be POLLED, because Access has no held-open concept
//     at all -- it is an open feature request, not a payload we are failing to
//     parse.
//
// So the two alarms an access-control system most obviously owes you, door
// forced and door held, do not exist on any surface. This file derives them.
package access

import (
	"sort"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
)

// LockState is a door's lock, as Access reports it.
//
// Unknown is a real value and is never collapsed into locked: deriving a
// forced entry from a lock state we could not read would be raising a
// critical alarm on no evidence.
type LockState string

const (
	LockUnknown  LockState = ""
	LockLocked   LockState = "locked"
	LockUnlocked LockState = "unlocked"
)

// PositionState is the door position sensor (DPS).
//
// Four values, and the fourth is the one that matters. The console spells shut
// as "close", not "closed", and it spells "there is no sensor on this door" as
// "none" -- which is NOT the same as shut and must never be read as it. A
// measurement across 28 doors on one console found 26 reporting "none": on
// that site, held-open and forced-entry are underivable for all but two doors,
// and a product that quietly treated "none" as closed would show 26 reassuring
// green rows for doors it cannot see at all.
type PositionState string

const (
	PositionUnknown PositionState = ""
	PositionOpen    PositionState = "open"
	PositionClosed  PositionState = "close"
	PositionNone    PositionState = "none"
)

// derivable reports whether this door's position can be reasoned about.
func (p PositionState) derivable() bool {
	return p == PositionOpen || p == PositionClosed
}

// doorState is what this source last believed about one door.
type doorState struct {
	id   string
	name string

	lock     LockState
	position PositionState

	// lastUnlockedAt is the last moment the lock was seen unlocked, from
	// EITHER input. It is the whole basis of forced-entry suppression -- see
	// evaluate.
	lastUnlockedAt time.Time

	// openedAt is when the door was last seen to become open.
	openedAt time.Time

	// firstSeen guards the cold start. Until a door has been observed with the
	// door SHUT at least once, we do not know whether it was opened before or
	// after it was locked, and the difference between those two is the
	// difference between an alarm and somebody going to work.
	settled bool

	heldRaised   bool
	forcedRaised bool

	// remainUnlocked is Access's scheduled-or-manual "stay unlocked" mode.
	//
	// One bit, not two. It was briefly tracked alongside a separate
	// "already raised" flag, which made the change test redundant with the
	// raise test -- two guards for one decision, so neither could be shown to
	// matter. Mutation testing found it: deleting the outer guard changed
	// nothing observable.
	remainUnlocked bool
}

// doors is this source's memory of every door it has seen.
type doors struct {
	mu sync.Mutex
	by map[string]*doorState

	// heldAfter is how long a door may stand open before it is an incident.
	heldAfter time.Duration

	// unlockGrace is how recently the lock must have been unlocked for an
	// opening to count as authorised. See evaluate.
	unlockGrace time.Duration
}

func newDoors(heldAfter, unlockGrace time.Duration) *doors {
	return &doors{by: map[string]*doorState{}, heldAfter: heldAfter, unlockGrace: unlockGrace}
}

// transition is a derived condition change worth emitting.
type transition struct {
	door      doorState
	condition string
	clears    bool
	detail    string
}

// observeLock records a lock state, typically from the notifications socket.
//
// Separated from the poll because it has to be FAST. The whole forced-entry
// derivation turns on knowing whether a door was unlocked shortly before it
// opened, and a lock that unlocks and relocks between two polls is invisible
// to polling -- which would turn every ordinary entry through a
// quick-relocking door into a critical alarm.
func (d *doors) observeLock(id, name string, lock LockState, remainUnlocked bool, now time.Time) []transition {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.getLocked(id, name)

	if lock != LockUnknown {
		st.lock = lock
		if lock == LockUnlocked {
			st.lastUnlockedAt = now
		}
	}

	// The socket pushes full state syncs on a timer, so an arriving frame is
	// not a change. Emitting on arrival would re-raise the same incident every
	// few seconds, forever.
	var out []transition
	if remainUnlocked != st.remainUnlocked {
		st.remainUnlocked = remainUnlocked
		t := transition{door: *st, condition: event.ConditionDoorUnlocked,
			detail: "the door is set to remain unlocked"}
		if !remainUnlocked {
			t.clears = true
			t.detail = "the door is no longer set to remain unlocked"
		}
		out = append(out, t)
	}
	return out
}

// observePosition records a door position reading from the poll.
func (d *doors) observePosition(id, name string, lock LockState, position PositionState, now time.Time) []transition {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.getLocked(id, name)

	// The poll also carries lock state. It is FRESH but not FAST, so it fills
	// in a door the socket has never mentioned without overwriting the socket's
	// finer-grained history of when the lock was last open.
	if lock != LockUnknown {
		st.lock = lock
		if lock == LockUnlocked {
			st.lastUnlockedAt = now
		}
	}

	prev := st.position
	if position != PositionUnknown {
		st.position = position
	}
	return d.evaluateLocked(st, prev, now)
}

// evaluateLocked derives the two conditions Access does not report.
//
// FORCED ENTRY is decided at the moment the door BECOMES open, never from the
// state afterwards, and that ordering is the entire design:
//
//	normal entry:  unlock -> open  -> relock  (while still open)
//	forced entry:  locked -> open
//
// Both end in "locked and open", so a rule that looks at the current pair
// raises a critical alarm every time somebody holds a door on a lock that
// relocks quickly. Only the transition tells them apart.
//
// Polling alone cannot see that ordering either -- a lock that opens and
// relocks between two reads looks exactly like it was never unlocked -- so the
// test is not "is it locked now" but "was it unlocked recently", with
// unlockGrace as the window and the socket supplying the timestamps.
//
// THIS IS DERIVED AND UNVERIFIED AGAINST HARDWARE. Access computes its own
// "Unauthorized Opening" internally and does not expose it as a distinct
// machine-readable value (SOURCES.md section 2), so this approximates a
// console-side decision rather than reading one. It is biased toward
// reporting: a false page costs an operator a minute, and a door that was
// forced at 3am and never reported costs what this product exists to prevent.
func (d *doors) evaluateLocked(st *doorState, prev PositionState, now time.Time) []transition {
	var out []transition

	if !st.position.derivable() {
		// "none" (no sensor fitted, the common case) or unreadable. Nothing
		// below is derivable, and claiming otherwise would put a permanently
		// green door on the board beside ones that are genuinely watched.
		return nil
	}

	if st.position == PositionClosed {
		// A shut door is the only state from which we can safely start
		// reasoning: we now know any later opening happened after this moment.
		st.settled = true
		st.openedAt = time.Time{}

		if st.forcedRaised {
			st.forcedRaised = false
			out = append(out, transition{door: *st, condition: event.ConditionDoorForced,
				clears: true, detail: "the door is shut again"})
		}
		if st.heldRaised {
			st.heldRaised = false
			out = append(out, transition{door: *st, condition: event.ConditionDoorHeld,
				clears: true, detail: "the door is shut again"})
		}
		return out
	}

	// The door is open.
	if prev != PositionOpen {
		st.openedAt = now

		authorised := !st.lastUnlockedAt.IsZero() && now.Sub(st.lastUnlockedAt) <= d.unlockGrace
		switch {
		case !st.settled:
			// Cold start: the door was already open when this source first
			// looked at it, so the ordering that decides forced-versus-normal
			// is not knowable. Not raised as forced. The held-open timer below
			// still runs, so a door standing open across a restart is still
			// reported -- as what it observably is, rather than as a guess
			// about how it got that way.
		case st.lock == LockLocked && !authorised:
			st.forcedRaised = true
			out = append(out, transition{door: *st, condition: event.ConditionDoorForced,
				detail: "the door opened while locked, with no unlock in the last " +
					d.unlockGrace.String()})
		}
	}

	if !st.heldRaised && !st.openedAt.IsZero() && now.Sub(st.openedAt) >= d.heldAfter {
		st.heldRaised = true
		out = append(out, transition{door: *st, condition: event.ConditionDoorHeld,
			detail: "the door has stood open for " + d.heldAfter.String()})
	}
	return out
}

// tick re-evaluates every door against the clock alone.
//
// Held-open is the reason this exists: a door that opens and then reports
// nothing further would otherwise only be noticed on the next poll that
// happened to carry a changed field. The condition is a DURATION, so something
// has to look at the clock.
func (d *doors) tick(now time.Time) []transition {
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []transition
	for _, id := range d.idsLocked() {
		st := d.by[id]
		if st.position != PositionOpen || st.heldRaised || st.openedAt.IsZero() {
			continue
		}
		if now.Sub(st.openedAt) >= d.heldAfter {
			st.heldRaised = true
			out = append(out, transition{door: *st, condition: event.ConditionDoorHeld,
				detail: "the door has stood open for " + d.heldAfter.String()})
		}
	}
	return out
}

// forget drops doors the console no longer lists.
//
// A door removed from the console with an open incident against it keeps that
// incident: the incident belongs to the operator, not to the console's current
// inventory, and silently resolving it because a device disappeared is the
// failure this product exists to avoid. Only the local memory is dropped.
func (d *doors) forget(present map[string]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, st := range d.by {
		if present[id] {
			continue
		}
		if st.forcedRaised || st.heldRaised || st.remainUnlocked {
			continue
		}
		delete(d.by, id)
	}
}

func (d *doors) getLocked(id, name string) *doorState {
	st, ok := d.by[id]
	if !ok {
		st = &doorState{id: id}
		d.by[id] = st
	}
	if name != "" {
		// A name arriving empty does not erase one we already have: the
		// notifications socket carries an id and often no name at all, and a
		// nameless door in an alert is a door nobody can go and look at.
		st.name = name
	}
	return st
}

func (d *doors) idsLocked() []string {
	out := make([]string, 0, len(d.by))
	for id := range d.by {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// count is how many doors this source knows about, for Health.
func (d *doors) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.by)
}

// snapshot is the door list for diagnostics, sorted for stable output.
func (d *doors) snapshot() []doorState {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]doorState, 0, len(d.by))
	for _, id := range d.idsLocked() {
		out = append(out, *d.by[id])
	}
	return out
}

// nameOf returns the display name this source knows for a door.
//
// The log's own target display_name is often the short name while the door
// list carries the composite one the operator sees in the Access app. Matching
// the app matters more than matching the log: an alert naming a door
// differently from the console is an alert somebody has to translate at 3am.
func (d *doors) nameOf(id, fallback string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if st, ok := d.by[id]; ok && st.name != "" {
		return st.name
	}
	return fallback
}
