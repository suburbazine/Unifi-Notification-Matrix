package protect

import (
	"strings"
	"sync"
	"time"
)

// DeviceState is one device as either channel or the REST sweep describes it.
//
// State is the connection enum, or "" for "we do not know". Empty is a real
// value here and is never collapsed into CONNECTED: reporting a camera as
// online because a field was unreadable is reporting security on no evidence.
type DeviceState struct {
	ID    string
	Name  string
	Kind  string // "camera", "sensor", "nvr", "device"
	MAC   string
	State string
}

type deviceInfo struct {
	DeviceState
	// updatedAt is when this record last changed from a live stream frame. The
	// reconciliation sweep uses it to avoid overwriting a fresher streamed
	// state with an older REST read -- see registry.applySweep.
	updatedAt time.Time
}

// registry is the source's memory of what each device was last seen doing.
//
// It exists because there is no resume cursor on either socket: the only way
// to tell a state that CHANGED from a state that was merely re-read is to
// remember the previous one ourselves. It also carries the MAC->id map that
// makes an Alarm Manager webhook (bare MAC, no device id) actionable.
type registry struct {
	mu    sync.Mutex
	byID  map[string]*deviceInfo
	byMAC map[string]string
}

func newRegistry() *registry {
	return &registry{byID: map[string]*deviceInfo{}, byMAC: map[string]string{}}
}

// normaliseMAC strips the separator so that "AA:BB:CC" and "aabbcc" -- both of
// which appear across UniFi surfaces -- resolve to the same device.
func normaliseMAC(mac string) string {
	r := strings.NewReplacer(":", "", "-", "", ".", "", " ", "")
	return strings.ToLower(r.Replace(strings.TrimSpace(mac)))
}

// observe records a device seen on a stream frame and returns the previous
// state, so the caller can decide whether anything actually changed.
//
// Fields arriving empty do not erase what we already know: a devices-channel
// update carrying only `state` must not blank the name we learned from the
// sweep, or every subsequent alert loses the human name of the camera.
func (r *registry) observe(d DeviceState, at time.Time) (prev string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mergeLocked(d, at, true)
}

func (r *registry) mergeLocked(d DeviceState, at time.Time, fromStream bool) (prev string) {
	if d.ID == "" {
		return ""
	}
	info, ok := r.byID[d.ID]
	if !ok {
		info = &deviceInfo{DeviceState: DeviceState{ID: d.ID}}
		r.byID[d.ID] = info
	}
	prev = info.State

	if d.Name != "" {
		info.Name = d.Name
	}
	if d.Kind != "" {
		info.Kind = d.Kind
	}
	if d.MAC != "" {
		info.MAC = d.MAC
		r.byMAC[normaliseMAC(d.MAC)] = d.ID
	}
	if s := normaliseState(d.State); s != "" {
		info.State = s
		if fromStream {
			info.updatedAt = at
		}
	}
	return prev
}

// applySweep merges a REST reconciliation result and returns the transitions
// worth emitting.
//
// A device whose state was updated from the live stream AFTER the sweep began
// is skipped. Without that, a camera that dropped while the sweep was in
// flight gets its fresh DISCONNECTED overwritten by the older CONNECTED the
// REST read started with, and the outage is erased by the very mechanism that
// exists to catch outages.
func (r *registry) applySweep(devices []DeviceState, startedAt, at time.Time) []transition {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []transition
	for _, d := range devices {
		if d.ID == "" {
			continue
		}
		if info, ok := r.byID[d.ID]; ok && info.updatedAt.After(startedAt) {
			// Fresher stream data wins; still refresh identity fields.
			r.mergeLocked(DeviceState{ID: d.ID, Name: d.Name, Kind: d.Kind, MAC: d.MAC}, at, false)
			continue
		}
		prev := r.mergeLocked(d, at, false)
		if normaliseState(d.State) == "" {
			// No state on this record -- /v1/nvrs carries none at all. Identity
			// updated, nothing claimed about health.
			continue
		}
		if cond, clears, emit := classifyState(prev, d.State); emit {
			out = append(out, transition{
				Device:    r.byID[d.ID].DeviceState,
				Condition: cond,
				Clears:    clears,
				Previous:  prev,
			})
		}
	}
	return out
}

// transition is a state change the sweep found that the stream did not tell us
// about -- which, with no resume cursor, is the entire point of sweeping.
type transition struct {
	Device    DeviceState
	Condition string
	Clears    bool
	Previous  string
}

func (r *registry) lookup(id string) (DeviceState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	info, ok := r.byID[id]
	if !ok {
		return DeviceState{}, false
	}
	return info.DeviceState, true
}

// ResolveMAC maps a bare MAC to the device this source knows by id.
//
// Protect's Alarm Manager webhook identifies devices by MAC and nothing else,
// so without this map a disk-failure alarm names a string the operator cannot
// act on. The map is populated by the reconciliation sweep, which is another
// reason the sweep is not optional.
func (s *Source) ResolveMAC(mac string) (DeviceState, bool) {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	id, ok := s.reg.byMAC[normaliseMAC(mac)]
	if !ok {
		return DeviceState{}, false
	}
	info, ok := s.reg.byID[id]
	if !ok {
		return DeviceState{}, false
	}
	return info.DeviceState, true
}
