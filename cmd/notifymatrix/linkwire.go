package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/web"
)

// linkState is everything the peer link needs that outlives one request.
type linkState struct {
	mu     sync.RWMutex
	claims map[string]*link.Claim // capability -> claim

	// receipts is the operator-facing record of what a peer did, including
	// every refusal. The wire answer is always a bare 404, so this is the only
	// place a misconfigured peer is distinguishable from one that never calls.
	receipts []link.Receipt

	// addr is where the listener actually bound, empty until it has.
	addr string
}

// peerSilentAfter is how long a peer may go without contact before this
// product takes the capability back.
//
// Three missed heartbeats at the five-minute interval the peers agreed, so a
// single missed beat over a slow minute does not hand authority back and
// forth. Losing a capability is not a disaster -- our own source resumes and
// the worst case is a duplicate incident -- but flapping it is.
const peerSilentAfter = 16 * time.Minute

// maxReceipts bounds the record. The same trade as every other bounded table
// here: an endpoint reachable from outside must not be able to grow memory.
const maxReceipts = 200

// shownReceipts is how many reach the interface. Enough to cover a pairing
// attempt and the run of refusals that follow a misconfiguration, short enough
// that the page stays a page.
const shownReceipts = 25

func newLinkState(peers []link.Peer) *linkState {
	s := &linkState{claims: map[string]*link.Claim{}}
	for _, p := range peers {
		if cap := strings.TrimSpace(p.Manifest.Capability); cap != "" {
			s.claims[cap] = link.NewClaim(cap, 0)
		}
	}
	return s
}

// claimFor returns the claim a peer's capability is tracked under.
func (s *linkState) claimFor(peers []link.Peer, slug string) *link.Claim {
	for _, p := range peers {
		if p.Slug != slug {
			continue
		}
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.claims[p.Manifest.Capability]
	}
	return nil
}

// holds reports whether a peer currently holds a capability, and why not.
func (s *linkState) holds(capability string, now time.Time, silentAfter time.Duration) (bool, string) {
	s.mu.RLock()
	c := s.claims[capability]
	s.mu.RUnlock()
	if c == nil {
		return false, ""
	}
	return c.Held(now, silentAfter)
}

// setAddress records the address the link listener actually bound.
//
// The configuration may say "auto", in which case the configured value is not
// an address at all and the bound one is the only true answer -- for the page,
// which tells the operator what to hand the peer, and for the product hello,
// which advertises the port.
func (s *linkState) setAddress(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addr = addr
}

func (s *linkState) address() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addr
}

func (s *linkState) record(r link.Receipt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts = append(s.receipts, r)
	if len(s.receipts) > maxReceipts {
		s.receipts = s.receipts[len(s.receipts)-maxReceipts:]
	}
}

// Receipts returns a copy for the interface.
func (s *linkState) Receipts() []link.Receipt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]link.Receipt, len(s.receipts))
	copy(out, s.receipts)
	return out
}

// suppressedByPeer reports whether an event from one of this product's own
// sources should be held back because a peer is serving that capability.
//
// THIS IS THE ONLY BEHAVIOUR CHANGE PAIRING MAKES to existing ingest, and it is
// deliberately at the RAISE boundary rather than at the source. The source
// keeps polling, so the console-contact deadman keeps working and entity
// discovery keeps populating the rules editor; only the raising stops. That
// also makes it reversible in one place the moment the peer stops being able
// to serve.
func (s *linkState) suppressedByPeer(ev event.Event, now time.Time, silentAfter time.Duration) bool {
	held, _ := s.holds(ev.Source, now, silentAfter)
	return held
}

// linkCertificate returns the certificate for the link listener, minting and
// saving one on first use.
//
// KEPT once minted. The peer pins this exact certificate at pairing, so a new
// one on every start would mean a peer that pairs once and never connects
// again.
func linkCertificate(cfg *config.Config, save func(*config.Config) error) (certPEM, keyPEM []byte, err error) {
	if cfg.Web.LinkTLSCert != "" && !cfg.Web.LinkTLSKey.IsZero() {
		return []byte(cfg.Web.LinkTLSCert), []byte(cfg.Web.LinkTLSKey.Reveal()), nil
	}

	certPEM, keyPEM, err = link.MintCertificate(time.Now())
	if err != nil {
		return nil, nil, err
	}
	next := *cfg
	next.Web.LinkTLSCert = string(certPEM)
	next.Web.LinkTLSKey = secret.Secret(keyPEM)
	if err := save(&next); err != nil {
		// Refused rather than run with a certificate that will not survive a
		// restart: a peer would pin it, this product would present a different
		// one next time, and the peer would refuse to connect with no way to
		// tell why beyond "the certificate changed".
		return nil, nil, fmt.Errorf("link: storing the certificate: %w", err)
	}
	*cfg = next
	return certPEM, keyPEM, nil
}

// linkDeps assembles what the receiver needs from the running daemon.
type linkDeps struct {
	cfg       func() *config.Config
	saveCfg   func(*config.Config) error
	state     *linkState
	db        *store.SQLite
	delivery  *config.Delivery
	handle    func(context.Context, event.Event) error
	auditLog  audit.Log
	pairer    *link.Pairer
	version   string
	silentFor time.Duration
}

func (d linkDeps) build() link.Deps {
	peers := func() []link.Peer {
		p, _ := config.BuildLinks(d.cfg())
		return p
	}
	return link.Deps{
		Peers: peers,
		Credentials: func() []link.Credential {
			_, c := config.BuildLinks(d.cfg())
			return c
		},
		Ingest: d.handle,
		Seen: func(ctx context.Context, linkID, eventID string, now time.Time, ttl time.Duration) (bool, error) {
			return d.db.SeenEvent(ctx, linkID, eventID, now, ttl)
		},
		Forget: func(ctx context.Context, linkID, eventID string) error {
			return d.db.ForgetEvent(ctx, linkID, eventID)
		},
		Channels: func() []link.ChannelState {
			var out []link.ChannelState
			for _, st := range d.delivery.Stats() {
				out = append(out, link.ChannelState{
					Name: st.Channel, Enabled: true,
					ConsecutiveFails: st.ConsecutiveFails,
					BackingOffUntil:  st.BackingOffUntil,
				})
			}
			return out
		},
		Claim:   func(slug string) *link.Claim { return d.state.claimFor(peers(), slug) },
		Pairer:  d.pairer,
		Version: d.version,
		OnPaired: func(_ context.Context, p link.Peer, key []byte) error {
			return d.storePeer(p, key)
		},
		Record: func(r link.Receipt) {
			d.state.record(r)
			// Refusals reach the audit record as well as the receipt: a peer
			// being turned away is a fact about the product's own behaviour,
			// and the audit log is where those live.
			if !r.Accepted {
				_ = d.auditLog.Append(context.Background(), audit.Entry{
					Kind: audit.KindService, Actor: "link",
					Summary: "refused a link request",
					Fields:  map[string]string{"route": r.Route, "reason": r.Reason},
				})
			}
		},
	}
}

// storePeer persists a newly paired peer.
func (d linkDeps) storePeer(p link.Peer, key []byte) error {
	cur := d.cfg()
	next := *cur

	conds := make([]config.LinkCondition, 0, len(p.Manifest.Conditions))
	for _, c := range p.Manifest.Conditions {
		conds = append(conds, config.LinkCondition{
			Name: c.Name, Meaning: c.Meaning, Severity: c.Severity,
			Momentary: c.Momentary, DemotesClaim: c.DemotesClaim,
		})
	}
	entry := config.Link{
		Slug: p.Slug, LinkID: p.LinkID, Key: secret.Secret(key),
		Capability: p.Manifest.Capability, Conditions: conds,
	}

	// One entry per product. Re-pairing REPLACES the credential and the
	// manifest, and deliberately keeps nothing of the old key: rotation here
	// is re-pairing, so a stale credential left behind would be a second way in
	// that nobody remembers granting.
	replaced := false
	for i, existing := range next.Links {
		if strings.EqualFold(existing.Slug, p.Slug) {
			// The operator's overrides survive: they are decisions about
			// conditions, not about the credential.
			entry.Overrides = existing.Overrides
			entry.MaxSeverity = existing.MaxSeverity
			next.Links[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		next.Links = append(next.Links, entry)
	}

	if err := d.saveCfg(&next); err != nil {
		return err
	}

	// The claim map was built from the config AT START, so a peer that pairs
	// while this process is running has no claim to hold and its takeover
	// would silently never happen -- alive, heartbeating, and not actually
	// serving the capability it just claimed.
	d.state.adopt(p.Manifest.Capability)

	_ = d.auditLog.Append(context.Background(), audit.Entry{
		Kind: audit.KindService, Actor: "link", Summary: "paired a peer",
		Fields: map[string]string{
			"product": p.Slug, "link_id": p.LinkID,
			"capability": p.Manifest.Capability,
			"conditions": fmt.Sprint(len(conds)),
		},
	})
	fmt.Fprintf(os.Stderr, "link: paired %s (%s), claiming %q\n",
		p.Slug, p.LinkID, p.Manifest.Capability)
	return nil
}

// view renders pairing state for the interface.
//
// The per-peer "holding" line is the surface for "who is watching the doors
// right now", which is otherwise invisible: a peer can be alive, heartbeating
// and unable to see a single door, and in that state every other indicator on
// the page reads healthy.
func (s *linkState) view(cfg func() *config.Config, p *link.Pairer, now time.Time,
	startedAt time.Time) web.LinkPairing {
	c := cfg()
	out := web.LinkPairing{
		Available: p != nil,
		Address:   strings.TrimSpace(c.Web.LinkListen),
		Peers:     []web.LinkPeerView{},
	}
	// What the listener BOUND beats what the file asked for. They differ
	// whenever the file says "auto", and the operator is being told what to
	// type into another machine.
	if a := s.address(); a != "" {
		out.Address = a
	}
	if p != nil {
		out.Fingerprint = p.Fingerprint
		if code, left := p.Offered(); code != "" {
			out.Code = link.FormatCode(code)
			out.ExpiresSeconds = int(left / time.Second)
		}
	}
	for _, l := range c.Links {
		v := web.LinkPeerView{
			Product: l.Slug, LinkID: l.LinkID,
			Capability: l.Capability, Conditions: len(l.Conditions),
		}
		if l.Capability != "" {
			v.Holding, v.Why = s.holds(l.Capability, now, peerSilentAfter)
		}
		out.Peers = append(out.Peers, v)
	}

	// Newest first, and bounded again here rather than trusted: the operator
	// wants the refusal that just happened, not the first of two hundred.
	if !startedAt.IsZero() && now.After(startedAt) {
		out.SinceSeconds = int(now.Sub(startedAt) / time.Second)
	}
	rs := s.Receipts()
	out.Receipts = []web.LinkReceiptView{}
	for i := len(rs) - 1; i >= 0 && len(out.Receipts) < shownReceipts; i-- {
		out.Receipts = append(out.Receipts, web.LinkReceiptView{
			At: rs[i].At, LinkID: rs[i].LinkID, Route: rs[i].Route,
			Accepted: rs[i].Accepted, Duplicate: rs[i].Duplicate,
			Cause: string(rs[i].Cause), Reason: rs[i].Reason,
		})
	}
	return out
}

// release drops a capability's claim.
//
// Called when a peer is forgotten. Without it a peer that has just been
// unpaired keeps its capability HELD until the next restart, and this
// product's own source stays suppressed on behalf of something that can no
// longer reach it -- the exact state the claim exists to prevent, arriving
// through the door marked "revoke".
func (s *linkState) release(capability string) {
	if capability == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.claims, capability)
}

// adopt starts tracking a capability claimed by a peer that paired while this
// process was running.
//
// newLinkState builds the map from the config as it was AT START, so without
// this a freshly paired peer's claim would be nil until a restart: it could
// send events and heartbeat, and the capability it claimed would never be
// held. The peer would look entirely healthy and the takeover would silently
// not happen.
func (s *linkState) adopt(capability string) {
	if capability == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claims[capability] == nil {
		s.claims[capability] = link.NewClaim(capability, 0)
	}
}

// forgetPeer removes a peer from a configuration, returning the new
// configuration and the capability that peer was claiming.
func forgetPeer(cur *config.Config, slug string) (next *config.Config, capability string, found bool) {
	n := *cur
	n.Links = nil
	for _, l := range cur.Links {
		if strings.EqualFold(l.Slug, slug) {
			capability = l.Capability
			found = true
			continue
		}
		n.Links = append(n.Links, l)
	}
	return &n, capability, found
}
