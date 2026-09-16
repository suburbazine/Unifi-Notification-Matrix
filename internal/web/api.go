package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// maxBody bounds a request body. Nothing this API accepts is large, and an
// unbounded decode on a LAN-reachable endpoint is a memory bomb one device
// away.
const maxBody = 1 << 20

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func errorBody(msg string) map[string]any { return map[string]any{"error": msg} }

func readJSON(r *http.Request, into any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	if err := dec.Decode(into); err != nil {
		return err
	}
	return nil
}

// record appends to the audit log, and never fails the operation it is
// recording. Package audit says so explicitly: an action that happened but
// could not be written down is still an action that happened.
func (s *Server) record(r *http.Request, e audit.Entry) {
	if e.At.IsZero() {
		e.At = s.now()
	}
	if e.Actor == "" {
		e.Actor = "web"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	_ = s.deps.Audit.Append(ctx, e)
}

// fail is the response to an error the operator can do nothing about.
//
// The message is generic on purpose -- an internal error string can name paths,
// hosts and library internals -- and the real one goes to the audit log, where
// it is reachable by somebody who is already authorised to read it.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, doing string, err error) {
	s.record(r, audit.Entry{
		Kind:    audit.KindService,
		Summary: "web: " + doing + " failed",
		Fields:  map[string]string{"error": err.Error()},
	})
	writeJSON(w, http.StatusInternalServerError,
		errorBody("something went wrong here; the audit log has the detail"))
}

// ---------------------------------------------------------------------------
// Wire shapes
//
// These exist so that nothing which could hold a secret is ever within reach of
// a response body. They are hand-written rather than derived for exactly that
// reason: a struct that mirrors the config by embedding it would gain a secret
// field the day somebody adds one to the config.
// ---------------------------------------------------------------------------

type incidentView struct {
	ID       string `json:"id"`
	DedupKey string `json:"dedup_key"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`

	State        string `json:"state"`
	Acknowledged bool   `json:"acknowledged"`
	Resolved     bool   `json:"resolved"`

	OpenedAt   time.Time  `json:"opened_at"`
	AgeSeconds int64      `json:"age_seconds"`
	AlertCount int        `json:"alert_count"`
	Stage      int        `json:"stage"`
	LastAlert  *time.Time `json:"last_alert_at,omitempty"`
	AckedAt    *time.Time `json:"acked_at,omitempty"`
	AckVia     string     `json:"ack_via,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`

	CloseReason       string    `json:"close_reason,omitempty"`
	PredecessorID     string    `json:"predecessor_id,omitempty"`
	LastDeliveryError string    `json:"last_delivery_error,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (s *Server) viewOf(inc *incident.Incident) incidentView {
	return incidentView{
		ID:                inc.ID,
		DedupKey:          inc.DedupKey,
		Severity:          string(inc.Severity),
		Source:            inc.Source,
		Title:             inc.Title,
		Detail:            inc.Detail,
		State:             string(inc.State()),
		Acknowledged:      inc.Acknowledged(),
		Resolved:          inc.Resolved(),
		OpenedAt:          inc.OpenedAt,
		AgeSeconds:        int64(s.now().Sub(inc.OpenedAt) / time.Second),
		AlertCount:        inc.AlertCount,
		Stage:             inc.Stage,
		LastAlert:         inc.LastAlertAt,
		AckedAt:           inc.AckedAt,
		AckVia:            inc.AckVia,
		ResolvedAt:        inc.ResolvedAt,
		ClosedAt:          inc.ClosedAt,
		CloseReason:       inc.CloseReason,
		PredecessorID:     inc.PredecessorID,
		LastDeliveryError: inc.LastDeliveryError,
		UpdatedAt:         inc.UpdatedAt,
	}
}

type healthView struct {
	StartedAt     *time.Time         `json:"started_at,omitempty"`
	UptimeSeconds int64              `json:"uptime_seconds"`
	Sources       []sourceHealthView `json:"sources"`
	Channels      []ChannelHealth    `json:"channels"`
	Service       ServiceHealth      `json:"service"`
}

type sourceHealthView struct {
	Name                  string     `json:"name"`
	LastSeen              *time.Time `json:"last_seen,omitempty"`
	AgeSeconds            int64      `json:"age_seconds,omitempty"`
	ExpectedWithinSeconds int64      `json:"expected_within_seconds,omitempty"`
	Silent                bool       `json:"silent"`
	Detail                string     `json:"detail,omitempty"`
}

func (s *Server) healthView(h Health) healthView {
	now := s.now()
	out := healthView{
		Channels: h.Channels,
		Service:  h.Service,
		Sources:  []sourceHealthView{},
	}
	if out.Channels == nil {
		out.Channels = []ChannelHealth{}
	}
	if !h.StartedAt.IsZero() {
		t := h.StartedAt
		out.StartedAt = &t
		out.UptimeSeconds = int64(now.Sub(t) / time.Second)
	}
	for _, src := range h.Sources {
		v := sourceHealthView{
			Name:                  src.Name,
			ExpectedWithinSeconds: int64(src.ExpectedWithin / time.Second),
			Silent:                src.Silent,
			Detail:                src.Detail,
		}
		if !src.LastSeen.IsZero() {
			t := src.LastSeen
			v.LastSeen = &t
			v.AgeSeconds = int64(now.Sub(t) / time.Second)
		}
		out.Sources = append(out.Sources, v)
	}
	return out
}

// ---------------------------------------------------------------------------
// Public endpoints
// ---------------------------------------------------------------------------

// handleStatus is the wall-display surface: counts, health, and whether this
// browser happens to be signed in. No configuration detail, so no session
// needed.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	active, err := s.deps.Store.Active(r.Context())
	if err != nil {
		s.fail(w, r, "reading open incidents", err)
		return
	}

	counts := map[string]int{
		"open": 0, "alerting": 0, "acknowledged": 0, "resolved": 0,
		"unacknowledged": 0, "failing_delivery": 0,
	}
	for _, inc := range active {
		counts["open"]++
		counts[string(inc.State())]++
		if !inc.Acknowledged() {
			counts["unacknowledged"]++
		}
		if inc.LastDeliveryError != "" {
			counts["failing_delivery"]++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":             s.deps.Version,
		"now":                 s.now(),
		"authenticated":       s.authenticated(r),
		"setup_required":      s.deps.PasswordHash() == "",
		"min_password_length": MinPasswordLength,
		"incidents":           counts,
		"health":              s.healthView(s.deps.Health()),
	})
}

// handleIncidents lists the board. Public: the whole reason for the public
// half of this interface is a screen on a wall showing what is wrong.
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	active, err := s.deps.Store.Active(r.Context())
	if err != nil {
		s.fail(w, r, "reading open incidents", err)
		return
	}
	// Newest first. An operator scanning the board wants what just happened.
	sort.SliceStable(active, func(i, j int) bool {
		return active[i].OpenedAt.After(active[j].OpenedAt)
	})

	recent, err := s.deps.Store.Recent(r.Context(), limit)
	if err != nil {
		s.fail(w, r, "reading recent incidents", err)
		return
	}

	seen := map[string]bool{}
	out := make([]incidentView, 0, len(active)+len(recent))
	for _, inc := range active {
		seen[inc.ID] = true
		out = append(out, s.viewOf(inc))
	}
	for _, inc := range recent {
		if seen[inc.ID] || !inc.Terminal() {
			continue
		}
		seen[inc.ID] = true
		out = append(out, s.viewOf(inc))
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": out})
}

// ---------------------------------------------------------------------------
// Authenticated endpoints
// ---------------------------------------------------------------------------

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	entries, err := s.deps.Audit.Recent(r.Context(), limit)
	if err != nil {
		s.fail(w, r, "reading the audit log", err)
		return
	}
	if entries == nil {
		entries = []audit.Entry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// ackRetries bounds the compare-and-swap retry. The race is real: the
// escalation scheduler reads an incident, spends seconds delivering it, and
// writes back afterwards -- and an acknowledgement arrives precisely then,
// because the alert that prompted it has just gone out.
const ackRetries = 3

type closeRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	s.mutate(w, r, "acknowledge", func(inc *incident.Incident, now time.Time) error {
		return inc.Acknowledge(now, "web")
	}, func(inc *incident.Incident) audit.Entry {
		return audit.Entry{
			Kind: audit.KindAcknowledged, IncidentID: inc.ID, DedupKey: inc.DedupKey,
			Severity: string(inc.Severity),
			Summary:  "acknowledged from the web UI",
		}
	})
}

func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	var req closeRequest
	// A body is optional here; a missing or unreadable one simply means no
	// reason was given, which is not worth refusing a close over.
	_ = readJSON(r, &req)
	reason := req.Reason
	if reason == "" {
		reason = "closed from the web UI"
	}
	if len([]rune(reason)) > 200 {
		reason = string([]rune(reason)[:200])
	}

	s.mutate(w, r, "close", func(inc *incident.Incident, now time.Time) error {
		inc.Close(now, reason)
		return nil
	}, func(inc *incident.Incident) audit.Entry {
		return audit.Entry{
			Kind: audit.KindClosed, IncidentID: inc.ID, DedupKey: inc.DedupKey,
			Severity: string(inc.Severity),
			Summary:  "closed from the web UI",
			Fields:   map[string]string{"reason": reason},
		}
	})
}

// mutate is the read-modify-write both incident actions share, including the
// compare-and-swap retry that keeps an acknowledgement from being overwritten
// by an alert write that started before it.
func (s *Server) mutate(
	w http.ResponseWriter, r *http.Request, what string,
	apply func(*incident.Incident, time.Time) error,
	entry func(*incident.Incident) audit.Entry,
) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("no incident id"))
		return
	}

	for attempt := 0; attempt < ackRetries; attempt++ {
		inc, err := s.deps.Store.Get(r.Context(), id)
		if errors.Is(err, incident.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errorBody("no such incident"))
			return
		}
		if err != nil {
			s.fail(w, r, "reading the incident", err)
			return
		}

		expect := inc.UpdatedAt
		if err := apply(inc, s.now()); err != nil {
			if errors.Is(err, incident.ErrClosed) {
				writeJSON(w, http.StatusConflict, errorBody("that incident is already closed"))
				return
			}
			s.fail(w, r, what, err)
			return
		}

		err = s.deps.Store.PutIfUnchanged(r.Context(), inc, expect)
		if errors.Is(err, incident.ErrConflict) {
			continue // somebody else wrote it; read again and reapply
		}
		if err != nil {
			s.fail(w, r, "saving the incident", err)
			return
		}
		s.record(r, entry(inc))
		writeJSON(w, http.StatusOK, map[string]any{"incident": s.viewOf(inc)})
		return
	}

	// Losing the race three times means something is writing this incident
	// continuously. Say so rather than reporting a success that did not happen.
	writeJSON(w, http.StatusConflict,
		errorBody("that incident is being changed by something else; try again"))
}
