package link

import (
	"sort"
	"sync"
	"time"
)

// DefaultResumeAfter is how long a peer must look healthy before it takes its
// capability back.
//
// Hysteresis on the RESUME side only. Handing authority back the instant a
// flapping console recovers would flip which product is watching the doors on
// every poll, and each flip is a moment where both or neither are raising.
// Losing the claim is immediate by design: the cost of resuming our own ingest
// a few seconds early is a duplicate incident, and the cost of resuming it
// late is nobody watching.
const DefaultResumeAfter = 2 * time.Minute

// Claim is one peer's hold on a capability.
//
// A capability has at most one claimant. While the claim is HELD this product
// stops raising from its own source for that capability; while it is DEMOTED
// the native source resumes. The peer does not decide this -- it is derived
// from what the peer reports about itself.
//
// TWO WAYS TO LOSE IT, and the second is the one that was missing:
//
//   - The peer goes quiet. Its heartbeat lapses past the silence it promised,
//     and the ordinary deadman answer applies.
//   - The peer is ALIVE AND BLIND. It heartbeats perfectly -- the link runs
//     over loopback or the LAN, not through the console it watches -- while
//     reporting a condition that means it cannot serve what it claimed. The
//     OS refusing its outbound sockets is the real example, and it happened on
//     a real install. Keying suppression on liveness alone leaves this product
//     silent through exactly that, with every surface reading healthy.
type Claim struct {
	// Capability is what is claimed, named after the source it displaces.
	Capability string

	// ResumeAfter is the hysteresis. Zero means DefaultResumeAfter.
	ResumeAfter time.Duration

	mu sync.Mutex

	// demoting is the set of currently-raised conditions that demote the
	// claim, kept as a set because two can be true at once and the claim only
	// recovers when the last of them clears.
	demoting map[string]bool

	lastBeat     time.Time
	healthySince time.Time
}

// NewClaim returns a claim that is not yet held: a peer holds nothing until it
// has been heard from.
func NewClaim(capability string, resumeAfter time.Duration) *Claim {
	return &Claim{
		Capability:  capability,
		ResumeAfter: resumeAfter,
		demoting:    map[string]bool{},
	}
}

func (c *Claim) resumeAfter() time.Duration {
	if c.ResumeAfter > 0 {
		return c.ResumeAfter
	}
	return DefaultResumeAfter
}

// Heartbeat records contact from the peer.
func (c *Claim) Heartbeat(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastBeat = now
	c.markHealthy(now)
}

// Observe records a condition edge from the peer.
//
// Only conditions the operator approved as claim-demoting move the claim;
// everything else is an ordinary incident and changes nothing here. Called for
// both edges, because a demotion that never cleared would be permanent.
func (c *Claim) Observe(condition string, demotes, cleared bool, now time.Time) {
	if !demotes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cleared {
		delete(c.demoting, condition)
		c.markHealthy(now)
		return
	}
	c.demoting[condition] = true
	// Losing the claim resets the clock: recovery is measured from the moment
	// the last problem cleared, not from the first time we heard anything.
	c.healthySince = time.Time{}
}

// markHealthy starts the recovery clock if nothing is currently demoting.
// Caller holds the lock.
func (c *Claim) markHealthy(now time.Time) {
	if len(c.demoting) == 0 && c.healthySince.IsZero() {
		c.healthySince = now
	}
}

// Held reports whether the peer currently holds its capability, and why not
// when it does not. The reason is for the operator: "monitoring authority
// changed hands" is invisible at the time by definition, because the whole
// point is that everything looks healthy.
func (c *Claim) Held(now time.Time, silentAfter time.Duration) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lastBeat.IsZero() {
		return false, "not heard from yet"
	}
	if silentAfter > 0 && now.Sub(c.lastBeat) > silentAfter {
		return false, "silent for " + now.Sub(c.lastBeat).Round(time.Second).String()
	}
	if len(c.demoting) > 0 {
		names := make([]string, 0, len(c.demoting))
		for n := range c.demoting {
			names = append(names, n)
		}
		sort.Strings(names)
		return false, "reporting " + joinNames(names)
	}
	if c.healthySince.IsZero() {
		return false, "waiting to recover"
	}
	if wait := c.resumeAfter() - now.Sub(c.healthySince); wait > 0 {
		return false, "recovering, " + wait.Round(time.Second).String() + " to go"
	}
	return true, ""
}

func joinNames(names []string) string {
	switch len(names) {
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	}
	out := ""
	for i, n := range names[:len(names)-1] {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out + " and " + names[len(names)-1]
}
