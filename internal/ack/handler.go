package ack

import (
	"context"
	"errors"
	"fmt"
	"html/template"
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
	store  incident.Store
	signer *Signer
	now    func() time.Time

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
	h := &Handler{store: store, signer: signer, now: time.Now}
	for _, o := range opts {
		o(h)
	}
	return h, nil
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

	id, token, ok := parsePath(r.URL.Path)
	if !ok {
		h.render(w, http.StatusNotFound, pageInvalid, nil)
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
		return nil, ErrBadToken
	}
	if err := h.signer.Verify(inc, token); err != nil {
		return nil, ErrBadToken
	}
	return inc, nil
}

// parsePath splits /ack/{id}/{token}.
func parsePath(p string) (id, token string, ok bool) {
	p = strings.TrimPrefix(p, "/")
	parts := strings.Split(p, "/")
	if len(parts) != 3 || parts[0] != "ack" || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
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
