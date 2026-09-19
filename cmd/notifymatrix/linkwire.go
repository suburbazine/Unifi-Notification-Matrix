package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
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

	// proposals are conditions paired peers have tried to send that their
	// approved manifest does not contain. Bounded and in memory, like the
	// receipts: a proposal is a prompt to look rather than a record, and the
	// peer re-sends within minutes.
	proposals *link.Proposals
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
	s := &linkState{claims: map[string]*link.Claim{}, proposals: link.NewProposals()}
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

// maxReceiptField bounds each string a receipt retains.
//
// Three of them come straight off the wire from a caller who has not
// authenticated: LinkID is the raw X-Link-Id header, Route is the raw URL
// path, and Reason quotes the offending value back. The ring holds two hundred
// receipts, so without a clamp a stranger choosing megabyte-long headers
// decides how much memory this daemon holds -- and holds it in the one
// structure that survives until the next restart.
//
// Long enough that nothing real is cut: a link id is a short token, a route is
// a fixed string from a list of five, and a reason worth reading is a
// sentence. The audit copy was already capped at 2000 bytes by scrub(); this
// is the ring catching up with it.
const maxReceiptField = 256

func clipReceiptField(v string) string {
	if len(v) <= maxReceiptField {
		return v
	}
	// Cut on a rune boundary so the page never renders a broken character.
	cut := maxReceiptField
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "..."
}

func (s *linkState) record(r link.Receipt) {
	r.LinkID = clipReceiptField(r.LinkID)
	r.Route = clipReceiptField(r.Route)
	r.Reason = clipReceiptField(r.Reason)

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
		Claim: func(slug string) *link.Claim { return d.state.claimFor(peers(), slug) },
		Propose: func(slug, condition string, sev incident.Severity, title string, now time.Time) {
			d.state.proposals.Note(slug, condition, sev, title, now)
		},
		Pairer:  d.pairer,
		Version: d.version,
		OnPaired: func(_ context.Context, p link.Peer, key []byte) error {
			return d.storePeer(p, key)
		},
		Record: func(r link.Receipt) {
			d.state.record(r)
			// AUDITED ONLY ONCE A REAL PEER IS BEHIND IT.
			//
			// This used to append EVERY refusal, and the link port refuses a
			// lot of things nobody authenticated for: no such route, wrong
			// method, unsigned, malformed headers, bad signature, clock skew,
			// and every pairing failure. All of them are reachable by anybody
			// who can open the port, and each one was a durable append with an
			// fsync -- one synchronous disk flush per stranger's packet.
			//
			// Worse than the cost: audit.jsonl rotates. Filling it with
			// refusals evicts the record of WHO ACKNOWLEDGED WHAT, which is
			// the thing the audit log exists for. An unauthenticated caller
			// could erase it by knocking.
			//
			// internal/inbound settled this the same way and does not audit
			// its rejections at all. The refusals still reach the operator in
			// full, through the bounded in-memory receipts on a page that
			// already needs a password -- which is where they were always the
			// most use.
			if !r.Accepted && auditedCause[r.Cause] {
				_ = d.auditLog.Append(context.Background(), audit.Entry{
					Kind: audit.KindService, Actor: "link",
					Summary: "refused a link request",
					Fields:  map[string]string{"route": r.Route, "reason": r.Reason},
				})
			}
		},
	}
}

// auditedCause is the set of refusals worth a durable record.
//
// The rule is ONE LINE: a refusal is audited only if reaching it required
// authentication, or a successful pairing. Everything else on this port is
// reachable by anybody and therefore cannot be allowed to write to disk.
//
// What survives the rule is what an operator would actually go looking for
// later: a paired peer sending something it did not declare, being rate
// limited, or hitting a storage failure. Those are facts about a product the
// operator granted a credential to, and they are rare by construction.
//
// Everything absent is still on the receipts page with its reason. Nothing is
// hidden; it simply is not written to a file a stranger can make rotate.
var auditedCause = map[link.Cause]bool{
	// After authentication.
	link.CauseRateLimited:         true,
	link.CauseNoPeer:              true,
	link.CauseMalformedEnvelope:   true,
	link.CauseInvalidEnvelope:     true,
	link.CauseEnvelopeVersion:     true,
	link.CauseUndeclaredCondition: true,
	link.CauseStore:               true,
	link.CauseIngest:              true,
	// After a pairing proof was accepted: the peer got in and this product
	// then failed to keep it, which leaves the two ends disagreeing about
	// whether a credential exists. That is worth a durable line.
	link.CausePairStore: true,
}

// storePeer persists a newly paired peer.
func (d linkDeps) storePeer(p link.Peer, key []byte) error {
	cur := d.cfg()
	next := *cur
	// CLONED BEFORE ANYTHING IS WRITTEN INTO IT.
	//
	// `next := *cur` is a shallow copy, so next.Links and cur.Links share a
	// backing array -- and the re-pair branch below assigns straight into it.
	// Two consequences, both silent: a concurrent Credentials() reader races
	// on the element, and a save that FAILS leaves this process running the
	// new credential while the operator is told the pairing did not happen,
	// with the old key already gone until a restart.
	//
	// Intermittent by construction, because the append branch allocates a new
	// array whenever the slice is exactly full -- so it is invisible in any
	// test whose fixture happens to have no spare capacity.
	next.Links = slices.Clone(cur.Links)

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
	//
	// WHICH MEANS A PAIRING CAN REVOKE ONE, and that has to be said out loud.
	// The slug is the PRODUCT, not the installation, and pairing carries no
	// site identifier -- so a second install of the same product is
	// indistinguishable here from the first one rotating its key. Both land on
	// this branch, and the earlier credential stops working immediately.
	//
	// Right for a rotation, a trap for anybody with two sites: the action reads
	// as "add a product" and is sometimes "replace a working one". It cannot be
	// told apart without a field this exchange does not carry, so what is left
	// is to never let it happen quietly.
	replaced := ""
	for i, existing := range next.Links {
		if strings.EqualFold(existing.Slug, p.Slug) {
			// The operator's overrides survive: they are decisions about
			// conditions, not about the credential.
			entry.Overrides = existing.Overrides
			entry.MaxSeverity = existing.MaxSeverity
			replaced = existing.LinkID
			next.Links[i] = entry
			break
		}
	}
	if replaced == "" {
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

	summary := "paired a peer"
	fields := map[string]string{
		"product": p.Slug, "link_id": p.LinkID,
		"capability": p.Manifest.Capability,
		"conditions": fmt.Sprint(len(conds)),
	}
	if replaced != "" {
		// Recorded as a REVOCATION as well as a pairing, because that is the
		// half nobody asked for and the half that breaks something.
		summary = "paired a peer, revoking its previous credential"
		fields["revoked_link_id"] = replaced
	}
	_ = d.auditLog.Append(context.Background(), audit.Entry{
		Kind: audit.KindService, Actor: "link", Summary: summary, Fields: fields,
	})

	fmt.Fprintf(os.Stderr, "link: paired %s (%s), claiming %q\n",
		p.Slug, p.LinkID, p.Manifest.Capability)
	if replaced != "" {
		fmt.Fprintf(os.Stderr, "link: this REPLACED an earlier pairing of %s (%s), "+
			"which can no longer send. If that was a different installation of %s "+
			"rather than the same one re-pairing, it has just been cut off\n",
			p.Slug, replaced, p.Slug)
	}
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
	// Proposals, with what was refused from the SAME peer carried on every
	// row of it: a page showing four and silently discarding ninety is telling
	// the operator their peer sends four things it does not declare.
	out.Proposals = []web.LinkProposalView{}
	for _, pr := range s.proposals.All() {
		unusable, overflowed := s.proposals.Refused(pr.Slug)
		out.Proposals = append(out.Proposals, web.LinkProposalView{
			Product: pr.Slug, Condition: pr.Condition,
			Severity: string(pr.Severity), Title: pr.Title,
			Count: pr.Count, First: pr.First, Last: pr.Last,
			Unusable: unusable, Overflowed: overflowed,
		})
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

// approveCondition adds one PROPOSED condition to a peer's approved manifest.
//
// The narrow write. Three things have to hold, and each one closes a way this
// could otherwise become a general "edit the config with one POST":
//
//   - the condition must be one this peer has ACTUALLY BEEN REFUSED FOR. An
//     operator may approve what a peer asked for, not whatever arrives in a
//     request body, and without this the endpoint would let a session grant a
//     peer vocabulary the peer never wanted;
//   - the resulting manifest must pass link.Manifest.Validate, the same check
//     pairing runs -- so the slug prefix, the severity, the meaning and the
//     size limit all still hold for an amendment;
//   - the save must succeed before the proposal is forgotten, or a refused
//     write would lose the prompt and the operator would be left with a peer
//     that goes on being refused and a page that has stopped mentioning it.
//
// The operator's OVERRIDES are untouched. They are decisions about conditions
// rather than about the manifest, and an amendment is not a reason to undo one.
func (d linkDeps) approveCondition(slug string, c web.ApprovedCondition) error {
	cond := strings.TrimSpace(c.Condition)
	if !d.state.proposals.Has(slug, cond) {
		return web.ErrNotProposed
	}

	sev := incident.Severity(strings.TrimSpace(c.Severity))
	if !sev.Valid() {
		return fmt.Errorf("%w: %q is not a severity (want critical, high, "+
			"medium, low or info)", config.ErrInvalid, c.Severity)
	}

	cur := d.cfg()
	next := *cur
	next.Links = slices.Clone(cur.Links)

	at := -1
	for i, l := range next.Links {
		if strings.EqualFold(l.Slug, slug) {
			at = i
			break
		}
	}
	if at < 0 {
		return fmt.Errorf("%w: no peer named %q is paired here", config.ErrInvalid, slug)
	}

	entry := next.Links[at]
	for _, existing := range entry.Conditions {
		if existing.Name == cond {
			// Already approved, which is the shape a second browser tab takes.
			// Forget the proposal rather than adding a duplicate the manifest
			// validator would then refuse.
			d.state.proposals.Forget(slug, cond)
			return nil
		}
	}
	entry.Conditions = append(slices.Clone(entry.Conditions), config.LinkCondition{
		Name: cond, Meaning: strings.TrimSpace(c.Meaning), Severity: sev,
		Momentary: c.Momentary,
		// DemotesClaim is deliberately NOT settable here. It means "alive, but
		// cannot serve what I claimed", so raising it hands a capability back
		// to this product's own source -- a decision that belongs with the
		// whole manifest at pairing, where the peer declares which of its
		// conditions mean that, rather than with one row in a form.
	})

	// The same validator pairing runs. An amendment that could produce a
	// manifest pairing would have refused is an amendment that has found a way
	// round the review.
	if err := (link.Manifest{
		Capability: entry.Capability,
		Conditions: manifestConditions(entry.Conditions),
	}).Validate(entry.Slug); err != nil {
		return fmt.Errorf("%w: %s", config.ErrInvalid, err.Error())
	}

	next.Links[at] = entry
	if err := d.saveCfg(&next); err != nil {
		return err
	}
	d.state.proposals.Forget(slug, cond)

	_ = d.auditLog.Append(context.Background(), audit.Entry{
		Kind: audit.KindConfigChanged, Actor: "web",
		Summary: "approved a new condition for a paired peer",
		Fields: map[string]string{
			"product": slug, "condition": cond, "severity": string(sev),
			"conditions": fmt.Sprint(len(entry.Conditions)),
		},
	})
	return nil
}

// manifestConditions converts stored conditions into what the validator takes.
func manifestConditions(in []config.LinkCondition) []link.ConditionSpec {
	out := make([]link.ConditionSpec, 0, len(in))
	for _, c := range in {
		out = append(out, link.ConditionSpec{
			Name: c.Name, Meaning: c.Meaning, Severity: c.Severity,
			Momentary: c.Momentary, DemotesClaim: c.DemotesClaim,
		})
	}
	return out
}
