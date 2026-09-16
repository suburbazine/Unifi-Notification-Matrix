package network

import (
	"sort"
	"sync"
	"time"
)

// deviceState is what this source last believed about one device.
type deviceState struct {
	id    string
	name  string
	model string
	mac   string
	site  string

	state State

	// offlineSince is when the device was first seen down. Kept so a flapping
	// PoE port does not produce an incident per flap -- see observe.
	offlineSince time.Time

	// raised is whether an offline incident is currently open for it.
	raised bool
}

// devices is this source's memory of every device it has seen.
//
// The memory is the whole mechanism: the Network Integration API has no events
// at all, so the only way to tell a device that WENT down from one that is
// merely still down is to remember what it was last time.
type devices struct {
	mu sync.Mutex
	by map[string]*deviceState

	// downFor is how long a device must be seen down before it is an incident.
	//
	// Not zero, and that is the point. A poll landing during a firmware reboot,
	// a switch that bounces a port, or one dropped API response would otherwise
	// each raise and then resolve an incident -- and an operator who is paged
	// three times for a device that was never really down learns to ignore the
	// fourth.
	downFor time.Duration
}

func newDevices(downFor time.Duration) *devices {
	return &devices{by: map[string]*deviceState{}, downFor: downFor}
}

// transition is a reachability change worth emitting.
type transition struct {
	device deviceState
	clears bool
	detail string
}

// observe folds one poll's worth of devices in and returns what changed.
//
// `seen` is every device the console listed. A device MISSING from the list is
// not treated as down: the console omitting a device is a statement about the
// console's inventory, not about the device's power, and forgetting it is
// handled separately by forget.
func (d *devices) observe(site string, seen []device, now time.Time) []transition {
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []transition
	for _, dev := range seen {
		if dev.ID == "" {
			continue
		}
		st, ok := d.by[dev.ID]
		if !ok {
			st = &deviceState{id: dev.ID}
			d.by[dev.ID] = st
		}
		// Identity fields arriving empty do not erase what we already know: a
		// nameless device in an alert is a device nobody can go and look at.
		if n := dev.label(); n != "" {
			st.name = n
		}
		if dev.Model != "" {
			st.model = dev.Model
		}
		if m := dev.mac(); m != "" {
			st.mac = m
		}
		if site != "" {
			st.site = site
		}

		next, _ := classifyState(dev.State)
		out = append(out, d.applyLocked(st, next, now)...)
	}
	return out
}

// applyLocked moves one device to a new state and reports the consequence.
func (d *devices) applyLocked(st *deviceState, next State, now time.Time) []transition {
	prev := st.state

	switch next {
	case StateUnknown, StateTransitional:
		// Neither up nor down. The state is recorded so Health can report it,
		// but an incident is neither raised nor cleared: a device being
		// adopted is not an outage, and a state nobody recognises is not
		// evidence of anything at all.
		st.state = next
		return nil

	case StateOnline:
		st.state = StateOnline
		st.offlineSince = time.Time{}
		if st.raised {
			st.raised = false
			return []transition{{device: *st, clears: true,
				detail: "the device is reachable again"}}
		}
		return nil

	case StateOffline:
		st.state = StateOffline
		if st.offlineSince.IsZero() {
			st.offlineSince = now
		}
		if !st.raised && now.Sub(st.offlineSince) >= d.downFor {
			st.raised = true
			return []transition{{device: *st,
				detail: "the console has reported this device down for " +
					d.downFor.String()}}
		}
		_ = prev
		return nil
	}
	return nil
}

// tick re-checks the clock alone, so a device that went down and has reported
// nothing further still crosses the threshold.
func (d *devices) tick(now time.Time) []transition {
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []transition
	for _, id := range d.idsLocked() {
		st := d.by[id]
		if st.state != StateOffline || st.raised || st.offlineSince.IsZero() {
			continue
		}
		if now.Sub(st.offlineSince) >= d.downFor {
			st.raised = true
			out = append(out, transition{device: *st,
				detail: "the console has reported this device down for " + d.downFor.String()})
		}
	}
	return out
}

// forget drops devices the console no longer lists.
//
// A device with an open incident keeps it. The incident belongs to the
// operator, and a switch that was reported down and then vanished from the
// inventory is MORE worrying than one that is merely down -- resolving it
// because the console stopped mentioning it would erase exactly the case worth
// looking at.
func (d *devices) forget(present map[string]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, st := range d.by {
		if present[id] || st.raised {
			continue
		}
		delete(d.by, id)
	}
}

func (d *devices) idsLocked() []string {
	out := make([]string, 0, len(d.by))
	for id := range d.by {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (d *devices) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.by)
}

// countsByState is for Health: how many devices this source can actually say
// something about, and how many it cannot.
func (d *devices) countsByState() map[State]int {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[State]int{}
	for _, st := range d.by {
		out[st.state]++
	}
	return out
}
