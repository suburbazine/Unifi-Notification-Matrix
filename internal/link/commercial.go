package link

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// COMMERCIAL USE IS GRANTED BY A PARTNER, NOT CHECKED HERE.
//
// This product carries no licence of its own to verify. Its paired partners
// are commercial products -- Lightspeed Rewards, LSProtect -- and their Pro
// tiers include permission to use this one commercially. A partner says so on
// the link, in the signed body of every heartbeat, ping and event, and in its
// pairing request:
//
//	"commercial_permission": true
//
// Absent, or false, means it grants none: a partner whose Pro tier lapses
// stops granting it at its next heartbeat, with nothing for this end to
// expire. The field is inside the signed body because the body is what the
// HMAC covers -- a header would let anything on the path add it.
//
// What this product does with it is one thing: while at least one partner is
// paired and none of them grants permission, it REJECTS partner events (see
// Rejecting). Heartbeats are still taken, because they carry the permission
// and the silence alarm, and pairing is still possible, because pairing a Pro
// partner is how the rejection ends.

// FieldCommercialPermission is the wire name of the signal.
const FieldCommercialPermission = "commercial_permission"

// DefaultPermissionGrace is how long after start a paired partner that has
// not said anything yet is given the benefit of the doubt.
//
// Without it, every restart would reject partner events until each partner's
// next heartbeat -- up to five minutes at the default rate -- even at a site
// whose Pro partner has granted permission all along. Longer than the slowest
// heartbeat this product ever asks for; a partner that has not spoken by then
// counts as granting nothing.
const DefaultPermissionGrace = 10 * time.Minute

// permission is one partner's latest word.
type permission struct {
	granted bool
	at      time.Time
}

// Permissions is what each paired partner last said about commercial use.
// In memory: every partner repeats it on every heartbeat.
type Permissions struct {
	mu      sync.Mutex
	started time.Time
	grace   time.Duration
	bySlug  map[string]permission
}

// NewPermissions starts an empty record at the moment the product started.
func NewPermissions(started time.Time, grace time.Duration) *Permissions {
	return &Permissions{started: started, grace: grace, bySlug: map[string]permission{}}
}

// Note records what a partner just said. Called only for authenticated
// requests: an unauthenticated caller must not be able to grant permission on
// a partner's behalf, or revoke it.
func (p *Permissions) Note(slug string, granted bool, now time.Time) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if p == nil || slug == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bySlug[slug] = permission{granted: granted, at: now}
}

// PermissionState is one partner's standing, for the page.
type PermissionState string

const (
	PermissionGranted    PermissionState = "granted"
	PermissionNotGranted PermissionState = "not granted"
	PermissionNotHeard   PermissionState = "not heard yet"
)

// State reports one partner's standing.
func (p *Permissions) State(slug string) PermissionState {
	if p == nil {
		return PermissionNotHeard
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	got, ok := p.bySlug[strings.ToLower(strings.TrimSpace(slug))]
	switch {
	case !ok:
		return PermissionNotHeard
	case got.granted:
		return PermissionGranted
	default:
		return PermissionNotGranted
	}
}

// Rejecting reports whether partner events are to be refused: at least one
// partner is paired, and none of them grants commercial use.
//
// A partner not heard from since start counts as granting it until the grace
// runs out, and as granting nothing after.
func (p *Permissions) Rejecting(slugs []string, now time.Time) bool {
	if len(slugs) == 0 {
		return false
	}
	if p == nil {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	inGrace := now.Sub(p.started) < p.grace
	for _, s := range slugs {
		got, ok := p.bySlug[strings.ToLower(strings.TrimSpace(s))]
		if ok && got.granted {
			return false
		}
		if !ok && inGrace {
			return false
		}
	}
	return true
}

// commercialSignal reads the permission out of a heartbeat or ping body.
//
// Lenient on purpose: a partner that sends no body, or a body without the
// field, has granted nothing -- which is the same answer as a body that says
// false, and a malformed heartbeat is still proof of life.
func commercialSignal(body []byte) bool {
	var b struct {
		Commercial bool `json:"commercial_permission"`
	}
	if len(body) == 0 || json.Unmarshal(body, &b) != nil {
		return false
	}
	return b.Commercial
}
