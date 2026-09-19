package ack

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Handler serves the acknowledgement endpoint.
//
// ONE ROUTE, ONE VERB. It acknowledges and it renders a page. It cannot read
// other incidents, list anything, or reach any other surface -- so a leaked
// link silences exactly one alarm and grants nothing else. That is the whole
// security model, and it only holds if this stays small.
type Handler struct {
	store incident.Store

	// signer is an interface only so a test can count the verifications.
	//
	// The property being counted is not cosmetic: the miss path and the hit
	// path must do the SAME cryptographic work, or "no such incident" answers
	// measurably faster than "wrong token" and the single error class leaks
	// through the clock. There is no way to observe that from outside, and a
	// wall-clock assertion on a shared machine is a flake generator.
	signer verifier
	now    func() time.Time

	// limiter bounds how often one source may be answered at all.
	//
	// THIS ROUTE IS THE ONE THAT FACES THE INTERNET. Everything else in this
	// product is reachable only from the LAN; an acknowledgement has to be
	// tappable from a phone on mobile data at 3am, so the port is forwarded,
	// and it will be found by scanners within days and fuzzed indefinitely.
	//
	// A limiter here can be far tighter than one on an API, because the
	// legitimate traffic is unusually well understood: a human opens ONE link
	// and taps it once, which is two requests, minutes apart. Nothing
	// legitimate arrives in a burst.
	limiter *limiter

	// OnAck is called after a successful acknowledgement, for the audit
	// record. Optional.
	OnAck func(inc *incident.Incident, via string)
}

// New builds a Handler.
func New(store incident.Store, signer *Signer, opts ...Option) (*Handler, error) {
	if store == nil {
		return nil, errors.New("ack: needs a store")
	}
	if signer == nil {
		return nil, ErrNoSecret
	}
	h := &Handler{
		store: store, signer: signer, now: time.Now,
		limiter: newLimiter(DefaultBurst, DefaultRefill),
	}
	for _, o := range opts {
		o(h)
	}
	return h, nil
}

// verifier is what the handler needs from a Signer.
type verifier interface {
	Verify(inc *incident.Incident, token string) error
}

// Option configures a Handler.
type Option func(*Handler)

// WithClock injects a clock so tests need not sleep. Must be safe for
// concurrent use.
func WithClock(f func() time.Time) Option { return func(h *Handler) { h.now = f } }

// WithAuditHook records successful acknowledgements.
func WithAuditHook(f func(*incident.Incident, string)) Option {
	return func(h *Handler) { h.OnAck = f }
}

// WithRateLimit replaces the per-source limit. A burst of zero or less removes
// it entirely, which is only ever right behind something else already doing
// the limiting.
func WithRateLimit(burst int, refill time.Duration) Option {
	return func(h *Handler) {
		if burst <= 0 {
			h.limiter = nil
			return
		}
		h.limiter = newLimiter(burst, refill)
	}
}

// ackRetries bounds the compare-and-swap retry.
const ackRetries = 3

// ServeHTTP handles /ack/{id}/{token}.
//
// ==========================================================================
// GET DOES NOT ACKNOWLEDGE. THIS IS THE MOST IMPORTANT LINE IN THE PACKAGE.
// ==========================================================================
//
// Corporate mail security scanners fetch every link in every message to check
// where it goes. Link-preview generators in chat apps do the same. If GET
// acknowledged, an alarm would be silenced automatically, seconds after it was
// raised, by a machine -- and the product would look like it was working
// perfectly while nobody had seen anything.
//
// That failure is silent, indistinguishable from a human acknowledging, and it
// would happen to EVERY alert that went out by email. It is the single worst
// bug this package could have.
//
// So GET renders a confirmation page with a button, and the POST behind that
// button performs the acknowledgement. The cost is one extra tap at 3am. The
// alternative is an alarm system that scanners switch off.
//
// ntfy action buttons can issue a POST directly, so the push path keeps its
// one-tap behaviour; it is email that pays the extra tap, and email is exactly
// where the scanners are.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Never cached, never stored: the URL is a credential and an intermediary
	// holding a copy of the response is holding a copy of it.
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")

	// SHAPE FIRST, AND IT COSTS NOTHING.
	//
	// A token is always exactly TokenChars long, so almost everything an
	// internet-facing port receives can be refused here: no allocation, no
	// HMAC, and above all no database read. Before this, every path with
	// three segments made this listener query SQLite -- which shares a
	// connection pool and a write lock with the escalation engine, so a
	// stranger could make the machine work and the work landed on the part of
	// the product that has to keep running.
	id, token, ok := parsePath(r.URL.Path)
	if !ok {
		h.render(w, http.StatusNotFound, pageInvalid, nil)
		return
	}

	// THEN the rate limit, and still before the store. After the shape check
	// on purpose, so a fuzzer is refused by the cheaper path and never grows
	// the limiter table.
	if h.limiter != nil && !h.limiter.allow(sourceOf(r), h.now()) {
		w.Header().Set("Retry-After", "10")
		h.render(w, http.StatusTooManyRequests, pageInvalid, nil)
		return
	}

	via := sanitiseVia(r.URL.Query().Get("via"))

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.confirm(w, r, id, token, via)
	case http.MethodPost:
		h.acknowledge(w, r, id, token, via)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		h.render(w, http.StatusMethodNotAllowed, pageInvalid, nil)
	}
}

// confirm renders the "are you sure" page. It changes nothing.
func (h *Handler) confirm(w http.ResponseWriter, r *http.Request, id, token, via string) {
	inc, err := h.lookup(r.Context(), id, token)
	if err != nil {
		// Same page, same status, whether the incident does not exist or the
		// token is wrong. Anything else lets a stranger enumerate incident ids.
		h.render(w, http.StatusNotFound, pageInvalid, nil)
		return
	}
	if inc.Acknowledged() {
		h.render(w, http.StatusOK, pageAlready, inc)
		return
	}
	h.render(w, http.StatusOK, pageConfirm, &confirmData{
		Incident: inc,
		Action:   fmt.Sprintf("/ack/%s/%s", id, token),
		Via:      via,
	})
}

func (h *Handler) acknowledge(w http.ResponseWriter, r *http.Request, id, token, via string) {
	ctx := r.Context()

	for attempt := 0; attempt < ackRetries; attempt++ {
		inc, err := h.lookup(ctx, id, token)
		if err != nil {
			h.render(w, http.StatusNotFound, pageInvalid, nil)
			return
		}
		// Idempotent. Two taps is not an error, and the person who tapped
		// twice should see it worked, not an error page that makes them think
		// it did not.
		if inc.Acknowledged() {
			h.render(w, http.StatusOK, pageAlready, inc)
			return
		}

		expect := inc.UpdatedAt
		if err := inc.Acknowledge(h.now(), via); err != nil {
			// Terminal already -- resolved and closed while the page was open.
			h.render(w, http.StatusOK, pageAlready, inc)
			return
		}

		// Compare-and-swap for the same reason the scheduler uses one: the
		// escalation loop may be writing this incident RIGHT NOW, having just
		// delivered the very alert being acknowledged. A last-write-wins Put
		// here is how an acknowledgement gets erased by the alert that
		// prompted it.
		err = h.store.PutIfUnchanged(ctx, inc, expect)
		switch {
		case err == nil:
			if h.OnAck != nil {
				h.OnAck(inc, via)
			}
			h.render(w, http.StatusOK, pageDone, inc)
			return
		case errors.Is(err, incident.ErrConflict):
			continue // somebody wrote; re-read and decide again
		case errors.Is(err, incident.ErrNotFound):
			h.render(w, http.StatusNotFound, pageInvalid, nil)
			return
		default:
			h.render(w, http.StatusInternalServerError, pageError, nil)
			return
		}
	}
	h.render(w, http.StatusConflict, pageError, nil)
}

// lookup finds and authorises an incident. The error is deliberately the same
// for every failure -- see ErrBadToken.
func (h *Handler) lookup(ctx context.Context, id, token string) (*incident.Incident, error) {
	inc, err := h.store.Get(ctx, id)
	if err != nil {
		// BURN THE SAME HMAC A HIT WOULD HAVE COST.
		//
		// One error, one status, one page -- and, before this, two measurably
		// different times. Skipping the verification on the miss path made
		// "no such incident" answer about 1.7us faster than "wrong token",
		// which is the enumeration the single error class exists to prevent,
		// arriving through the clock instead of through the body.
		_ = h.signer.Verify(&incident.Incident{ID: id, OpenedAt: h.now()}, token)
		return nil, ErrBadToken
	}
	if err := h.signer.Verify(inc, token); err != nil {
		return nil, ErrBadToken
	}
	return inc, nil
}

// TokenChars is how long a minted token always is.
//
// Derived from tokenBytes rather than written down twice, and the assertion
// below fails to COMPILE if the two ever disagree -- a length check that has
// quietly stopped matching the minter refuses every real link.
const TokenChars = 22

var _ = [1]struct{}{}[base64.RawURLEncoding.EncodedLen(tokenBytes)-TokenChars]

// maxIDChars bounds the incident id.
//
// Real ids are 24 hex characters. The bound is generous rather than exact so
// demo data and hand-made ids in tests keep working, and tight enough that
// nothing arbitrarily long is ever handed to the database as a parameter.
const maxIDChars = 64

// parsePath splits /ack/{id}/{token}, refusing anything that could not be a
// link this product minted.
//
// This check is the entire cost of a hostile request. Everything it rejects is
// rejected without an allocation, without an HMAC and without touching the
// store, which is what makes an exposed port survivable.
func parsePath(p string) (id, token string, ok bool) {
	p = strings.TrimPrefix(p, "/")
	parts := strings.Split(p, "/")
	if len(parts) != 3 || parts[0] != "ack" || !wellFormed(parts[1], parts[2]) {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// wellFormed reports whether these could be a real id and token.
//
// The length is checked first and is NOT a secret: every minted token is
// exactly TokenChars long, so refusing a different length reveals nothing that
// looking at any real link would not.
func wellFormed(id, token string) bool {
	if len(token) != TokenChars || len(id) == 0 || len(id) > maxIDChars {
		return false
	}
	for i := 0; i < len(token); i++ {
		if !isBase64URLByte(token[i]) {
			return false
		}
	}
	for i := 0; i < len(id); i++ {
		// Printable ASCII with no separator. An id is generated by this
		// product and never contains anything else.
		if c := id[i]; c < 0x21 || c > 0x7e || c == '/' {
			return false
		}
	}
	return true
}

func isBase64URLByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '_':
		return true
	}
	return false
}

// sourceOf is what the limiter counts by: the peer address without its port.
//
// DELIBERATELY NOT X-Forwarded-For. On a port reachable from the internet that
// header is written by whoever is calling, so keying on it would hand every
// caller a private allowance and turn the limit off. An operator who puts a
// reverse proxy in front of this should limit at the proxy, where the real
// address is known.
func sourceOf(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// sanitiseVia bounds the advisory channel hint.
//
// It comes from the query string, so it is attacker-controlled: length-capped
// and restricted to a safe alphabet before it ever reaches the audit record.
// It is rendered through html/template, so this is defence in depth rather
// than the only escaping.
func sanitiseVia(v string) string {
	if len(v) > 24 {
		v = v[:24]
	}
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

type confirmData struct {
	Incident *incident.Incident
	Action   string
	Via      string
}

func (h *Handler) render(w http.ResponseWriter, status int, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = t.Execute(w, data)
}
