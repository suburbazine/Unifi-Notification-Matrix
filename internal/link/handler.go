package link

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
)

// PathPrefix is where the receiver is mounted. Everything under it that is not
// a route below is a 404, and so is every failure.
const PathPrefix = "/link/"

// Routes served. Anything else under the prefix does not exist.
const (
	RoutePair      = "/link/pair"
	RouteEvents    = "/link/v1/events"
	RouteHeartbeat = "/link/v1/heartbeat"
	RoutePing      = "/link/v1/ping"
)

// knownRoute reports whether a path is one this receiver serves at all.
//
// RouteHello is in here even though it is the only GET: "exists but not with
// that verb" and "does not exist" are different facts, and the receipt is the
// one place that difference is allowed to survive.
func knownRoute(path string) bool {
	switch path {
	case RoutePair, RouteEvents, RouteHeartbeat, RoutePing, RouteHello:
		return true
	}
	return false
}

// MaxEventBytes caps an event body. Generous for a typed envelope and far
// short of anything that could exhaust memory on the operator's machine.
const MaxEventBytes = 16 << 10

// MaxPairBytes caps a pairing request. Smaller than an event: it carries a
// code, a proof and a manifest, and a manifest big enough to need more than
// this is one no operator was going to read anyway.
const MaxPairBytes = 4 << 10

// DefaultSeenFor is how long an accepted event id suppresses a retry of
// itself. The peer's worst case in flight is seconds; an hour is free and
// survives an argument about clock skew.
const DefaultSeenFor = time.Hour

// Deps are what the receiver needs from the rest of the product. Injected as
// functions so this package depends on no concrete store, engine or channel.
type Deps struct {
	// Peers returns the paired peers, and Credentials their shared secrets.
	// Read fresh on every request so an unpair takes effect immediately
	// rather than at the next restart.
	Peers       func() []Peer
	Credentials func() []Credential

	// Ingest hands a validated event to the rule engine.
	Ingest func(context.Context, event.Event) error

	// Seen records an event id and reports whether it had been seen before.
	// Durable, because a peer retrying across a restart must not double-raise.
	Seen func(ctx context.Context, linkID, eventID string, now time.Time, ttl time.Duration) (bool, error)

	// Channels reports current delivery health for the reply.
	Channels func() []ChannelState

	// Claim returns the capability claim for a peer, or nil if it holds none.
	Claim func(slug string) *Claim

	// Pairer offers and completes pairings. Nil means this build cannot pair,
	// and /link/pair is then a 404 like anything else that does not exist.
	Pairer *Pairer

	// Version is what /link/hello reports, so a peer can refuse a protocol it
	// does not speak. Empty is fine; it is reported as empty rather than
	// guessed at.
	Version string

	// OnPaired persists a newly paired peer and its key. An error here fails
	// the pairing: a peer that stored a credential this product did not would
	// authenticate against nothing for ever after.
	OnPaired func(ctx context.Context, p Peer, key []byte) error

	// Forget releases an idempotency record for an event that was accepted
	// and then failed to become an incident. Without it, a retry of an event
	// this product dropped would be answered as a duplicate of an incident
	// that never existed.
	Forget func(ctx context.Context, linkID, eventID string) error

	// Record notes what happened for the operator-facing receipt. Never
	// returned to the caller: the wire answer is always the same.
	Record func(Receipt)

	Now      func() time.Time
	SeenFor  time.Duration
	Verifier *Verifier
}

// Receipt is one thing that happened on a link, for the session-gated UI.
//
// Every failure answers a bare 404 on the wire, so this is the ONLY place an
// operator can find out that a peer is being refused and why. Without it a
// misconfigured peer is indistinguishable from a peer that never calls.
type Receipt struct {
	At        time.Time
	LinkID    string
	Route     string
	Accepted  bool
	Duplicate bool

	// Cause is why, as a countable label; Reason is why, as a sentence with
	// the specifics in it. Both, because a wall of refusals needs to be
	// counted by kind AND read one at a time.
	Cause  Cause
	Reason string
}

// Receiver serves the link routes.
type Receiver struct {
	deps    Deps
	limiter *limiter
}

// NewReceiver builds the handler.
func NewReceiver(d Deps) *Receiver {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.SeenFor == 0 {
		d.SeenFor = DefaultSeenFor
	}
	if d.Verifier == nil {
		d.Verifier = NewVerifier()
	}
	return &Receiver{deps: d, limiter: newLimiter()}
}

// reply is the bounded response a peer parses.
type reply struct {
	Accepted  bool   `json:"accepted"`
	Duplicate bool   `json:"duplicate,omitempty"`
	Delivery  string `json:"delivery"`

	// ServerTime lets a peer log clock skew. It never adjusts its own clock
	// from it, and this product never asks it to.
	ServerTime string `json:"server_time"`
}

func (rc *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := rc.deps.Now()

	// THE ANSWER TO EVERY FAILURE IS THE SAME, and it is a bare 404.
	//
	// internal/inbound settled this: an endpoint that distinguishes "wrong
	// key" from "no such route" tells an attacker which half to keep working
	// on, and one that says "unauthorised" confirms something is listening
	// here at all. The reason goes to the receipt, where a signed-in operator
	// can read it, and never onto the wire.
	deny := func(linkID string, cause Cause, reason string) {
		rc.record(Receipt{At: now, LinkID: linkID, Route: r.URL.Path,
			Cause: cause, Reason: reason})
		http.NotFound(w, r)
	}

	// THE ROUTE IS CHECKED BEFORE THE METHOD, which changes nothing on the
	// wire -- both answer the same bare 404 -- and everything in the receipt.
	// The other way round, a GET for a path that does not exist was recorded
	// as "method GET", so an operator reading a scanner's sweep was told the
	// verb was wrong about a route that was never there.
	if !knownRoute(r.URL.Path) {
		deny("", CauseNoRoute, "no such route")
		return
	}

	// GET is allowed for exactly one route, and only for as long as the
	// operator has a pairing window open.
	if r.Method == http.MethodGet && r.URL.Path == RouteHello {
		rc.hello(w, r, now, deny)
		return
	}
	if r.Method != http.MethodPost {
		deny("", CauseMethod, "method "+r.Method)
		return
	}
	switch r.URL.Path {
	case RouteEvents, RouteHeartbeat, RoutePing:
	case RouteHello:
		// Reached only by a POST: the GET above has already handled it. The
		// route exists, so saying "no such route" here would be the same
		// inaccuracy the ordering above was changed to fix.
		deny("", CauseMethod, "identify is a GET")
		return
	case RoutePair:
		// PAIRING IS NOT HMAC-AUTHENTICATED, because there is no key yet --
		// that is what it exists to establish. It authenticates on the code
		// proof instead, which binds this product's certificate fingerprint,
		// and it is bounded, single-use and short-lived to make up for being
		// the one route a stranger can reach.
		rc.pair(w, r, now, deny)
		return
	default:
		deny("", CauseNoRoute, "no such route")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxEventBytes+1))
	if err != nil {
		deny("", CauseBodyUnreadable, "unreadable body")
		return
	}
	if len(body) > MaxEventBytes {
		deny(r.Header.Get(HeaderLinkID), CauseBodyTooLarge, "body over the limit")
		return
	}

	creds := rc.credentials()
	cred, err := rc.deps.Verifier.Verify(creds, Request{
		Method: r.Method, Path: r.URL.Path,
		LinkID:        r.Header.Get(HeaderLinkID),
		Timestamp:     r.Header.Get(HeaderTimestamp),
		Nonce:         r.Header.Get(HeaderNonce),
		Authorization: r.Header.Get("Authorization"),
		Body:          body,
	})
	if err != nil {
		given := r.Header.Get(HeaderLinkID)
		deny(given, verifyCause(creds, given, err), err.Error())
		return
	}

	// AFTER authentication, never before: see limiter. A limit keyed on the
	// header would let anybody who can reach the port exhaust a real peer's
	// allowance and silence the doors from outside.
	if !rc.limiter.allow(cred.LinkID, now, PerPeerRate, RateWindow) {
		deny(cred.LinkID, CauseRateLimited, ErrRateLimited.Error())
		return
	}

	peer, ok := rc.peer(cred.LinkID)
	if !ok {
		// Authenticated against a credential with no peer behind it. Should be
		// impossible; treated as a failure rather than assumed away.
		deny(cred.LinkID, CauseNoPeer, "no peer for this link")
		return
	}

	switch r.URL.Path {
	case RoutePing:
		rc.ok(w, now, reply{Accepted: true})
	case RouteHeartbeat:
		if c := rc.claim(peer.Slug); c != nil {
			c.Heartbeat(now)
		}
		rc.record(Receipt{At: now, LinkID: cred.LinkID, Route: r.URL.Path, Accepted: true})
		rc.ok(w, now, reply{Accepted: true})
	case RouteEvents:
		rc.events(w, r, cred, peer, body, now, deny)
	}
}

func (rc *Receiver) events(w http.ResponseWriter, r *http.Request, cred Credential,
	peer Peer, body []byte, now time.Time, deny func(string, Cause, string)) {

	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		deny(cred.LinkID, CauseMalformedEnvelope, "malformed envelope")
		return
	}
	if err := env.Validate(peer); err != nil {
		// A version mismatch is somebody's upgrade; everything else here is a
		// peer claiming something it did not declare. Labelled apart because
		// the operator does a different thing about each.
		cause := CauseInvalidEnvelope
		if errors.Is(err, ErrVersion) {
			cause = CauseEnvelopeVersion
		}
		deny(cred.LinkID, cause, err.Error())
		return
	}

	// IDEMPOTENCY BEFORE INGEST. The peer retries with the same event id after
	// a timeout, so an event accepted here whose reply never arrived must not
	// raise the alarm twice. Answered with the same success the first attempt
	// would have had, because a retry that gets an error would be retried
	// again.
	if rc.deps.Seen != nil {
		seen, err := rc.deps.Seen(r.Context(), cred.LinkID, env.EventID, now, rc.deps.SeenFor)
		if err != nil {
			deny(cred.LinkID, CauseStore, "recording the event id: "+err.Error())
			return
		}
		if seen {
			rc.record(Receipt{At: now, LinkID: cred.LinkID, Route: r.URL.Path,
				Accepted: true, Duplicate: true})
			rc.ok(w, now, reply{Accepted: true, Duplicate: true})
			return
		}
	}

	// A claim-demoting condition moves the peer's capability claim whichever
	// way its edge points. Done before ingest so the demotion is in effect for
	// anything that follows it, and done for BOTH edges, since a demotion that
	// never cleared would be permanent.
	if c := rc.claim(peer.Slug); c != nil {
		c.Heartbeat(now)
		c.Observe(env.Condition, peer.DemotesClaim(env.Condition), env.State == StateCleared, now)
	}

	if rc.deps.Ingest != nil {
		if err := rc.deps.Ingest(r.Context(), env.Event(peer, now)); err != nil {
			// The event was genuine and we failed to take it. Refused so the
			// peer retries rather than assuming it landed -- with the same
			// event id, which the idempotency record above now holds. It is
			// released so the retry is not answered as a duplicate of an
			// event that never became an incident.
			rc.forget(r.Context(), cred.LinkID, env.EventID)
			deny(cred.LinkID, CauseIngest, "ingest: "+err.Error())
			return
		}
	}

	rc.record(Receipt{At: now, LinkID: cred.LinkID, Route: r.URL.Path, Accepted: true})
	rc.ok(w, now, reply{Accepted: true})
}

// ok writes the bounded reply, filling in the delivery status.
func (rc *Receiver) ok(w http.ResponseWriter, now time.Time, body reply) {
	body.Delivery = DeliveryOK
	if rc.deps.Channels != nil {
		body.Delivery = DeliveryStatus(rc.deps.Channels(), now)
	}
	body.ServerTime = now.UTC().Format(time.RFC3339)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func (rc *Receiver) credentials() []Credential {
	if rc.deps.Credentials == nil {
		return nil
	}
	return rc.deps.Credentials()
}

func (rc *Receiver) peer(linkID string) (Peer, bool) {
	if rc.deps.Peers == nil {
		return Peer{}, false
	}
	for _, p := range rc.deps.Peers() {
		if strings.EqualFold(p.LinkID, linkID) {
			return p, true
		}
	}
	return Peer{}, false
}

func (rc *Receiver) claim(slug string) *Claim {
	if rc.deps.Claim == nil {
		return nil
	}
	return rc.deps.Claim(slug)
}

func (rc *Receiver) record(r Receipt) {
	if rc.deps.Record != nil {
		rc.deps.Record(r)
	}
}

// forget releases an idempotency record for an event that was not ingested.
func (rc *Receiver) forget(ctx context.Context, linkID, eventID string) {
	if rc.deps.Forget == nil {
		return
	}
	_ = rc.deps.Forget(ctx, linkID, eventID)
}

// pair completes a pairing exchange.
//
// Answers a bare 404 on every failure like every other route, for the same
// reason: a caller that can tell "no pairing in progress" from "wrong code"
// learns when an operator is standing at the screen. The operator's receipt
// carries the real reason, and the fingerprint mismatch in particular needs to
// reach them -- it means something is terminating TLS in between, which is a
// completely different problem from a mistyped code.
func (rc *Receiver) pair(w http.ResponseWriter, r *http.Request, now time.Time,
	deny func(string, Cause, string)) {
	if rc.deps.Pairer == nil {
		deny("", CausePairUnavailable, "this build cannot pair")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxPairBytes+1))
	if err != nil || len(body) > MaxPairBytes {
		deny("", CausePairBody, "pairing body unreadable or over the limit")
		return
	}

	var req PairRequest
	if err := json.Unmarshal(body, &req); err != nil {
		deny("", CausePairBody, "malformed pairing request")
		return
	}

	res, peer, err := rc.deps.Pairer.Complete(req)
	if err != nil {
		deny("", pairCause(err), "pairing: "+err.Error())
		return
	}

	if rc.deps.OnPaired != nil {
		key, err := base64.StdEncoding.DecodeString(res.Key)
		if err != nil {
			deny("", CausePairStore, "pairing: encoding the key: "+err.Error())
			return
		}
		if err := rc.deps.OnPaired(r.Context(), peer, key); err != nil {
			// The peer must NOT be told it paired. A peer holding a credential
			// this product failed to store would authenticate against nothing
			// for ever, and the operator would see a peer that pairs and never
			// arrives.
			deny("", CausePairStore, "pairing: storing the peer: "+err.Error())
			return
		}
	}

	rc.record(Receipt{At: now, LinkID: res.LinkID, Route: r.URL.Path, Accepted: true})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}
