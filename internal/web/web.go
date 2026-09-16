// Package web is the local operator interface.
//
// # The access model, which is the part that matters
//
// STATUS IS PUBLIC. CHANGES REQUIRE A PASSWORD.
//
// That split is deliberate and was asked for: a wall display in a plant room
// showing the incident board must not need somebody to sign into it, and the
// board is useless if it logs out overnight. So the incident list, the health
// surface and the page itself are readable by anyone who can reach the listen
// address -- which is 127.0.0.1 unless the operator widened it -- while every
// write, and every read that carries configuration detail, needs a session.
//
// # Secrets never leave this process
//
// A secret.Secret must never reach a response body. The settings surface sends
// "set" / "not set" booleans instead, and the structs it serialises do not have
// a field capable of holding a secret. That is the guard: not the redacting
// String() on the type (which is a backstop for logs, not a design), but the
// absence of anywhere for the value to sit. There is a test that asserts on raw
// response bytes with a canary value, because this is the kind of rule that
// gets broken by an innocent refactor.
//
// # Nothing is fetched from the internet
//
// The CSS and the JavaScript are embedded in the binary and served from it. No
// CDN, no framework, no webfont. This runs on a LAN that may have no route out
// at all, and an operator page that has to fetch something before it works is a
// page that fails exactly when the network is the problem.
//
// This package does NOT serve /ack/. The acknowledgement route carries its own
// authority, is reachable without a session, and is mounted separately by the
// daemon -- see internal/ack. Keeping it out of here is what keeps its blast
// radius to one incident.
package web

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/setup"
)

//go:embed assets
var assetFS embed.FS

// Deps is everything the server needs, handed in rather than reached for.
//
// The point of the function-valued fields is that this package owns no state
// that outlives a request except sessions: the config is whatever the daemon
// currently holds, and saving it is the daemon's job. This package never writes
// a config file, which means it can never write a half-formed one.
type Deps struct {
	Store incident.Store
	Audit audit.Log

	// Config returns the configuration as it currently stands. Treat the
	// result as read-only.
	Config func() *config.Config

	// SaveConfig persists a new configuration. A validation error it returns
	// is SHOWN to the operator -- that is the whole point of validating -- so
	// implementations should return config.Problems (or anything matching
	// errors.Is(err, config.ErrInvalid)) for operator mistakes, and an
	// ordinary error for genuine failures, which are reported generically.
	SaveConfig func(*config.Config) error

	// Health reports the "why is nothing happening" surface.
	Health func() Health

	// PasswordHash returns the stored password hash, "" when none is set.
	PasswordHash func() string

	// SetPasswordHash persists a new hash.
	SetPasswordHash func(string) error

	// TestChannel sends one channel's proof-of-configuration message and
	// reports what happened. Optional: a build that does not supply it simply
	// has no test button.
	TestChannel func(ctx context.Context, name string) error

	// Checklist reports what is still needed to make this installation work.
	//
	// Optional: a build that does not supply it simply has no setup panel. The
	// daemon assembles it, because most of the answer -- whether a webhook has
	// ever fired, whether a source is running -- lives in the running process
	// rather than in the configuration file.
	Checklist func() setup.Input

	// ControlService starts, stops or restarts the supervised service.
	//
	// Optional: a build without it has no restart button and says so rather
	// than offering one that cannot work. It matters because channels,
	// policies and rules are built once at start, so every configuration
	// change needs a restart -- and until now the only way to do it was a
	// terminal, which is the thing this page exists to avoid.
	ControlService func(ServiceAction) error

	// UpdateState, CheckUpdate and ApplyUpdate are the in-app updater.
	//
	// All optional and all three together: a build with none of them shows no
	// update panel rather than a set of buttons that cannot work.
	UpdateState func() UpdateState
	CheckUpdate func(context.Context) (UpdateState, error)
	ApplyUpdate func(ctx context.Context, version string) error

	// Demo, when set, is shown on every screen as a banner.
	//
	// A demo serves fabricated security alarms. Somebody arriving at a tab
	// somebody else left open has to be able to tell, without reading anything
	// else, that what they are looking at did not happen -- and the API says
	// so too, so a screenshot is not the only thing carrying the warning.
	Demo string

	// Version is shown in the header. Optional.
	Version string
}

// Health is the diagnostic surface: per-source liveness, per-channel queue
// state, and whether the service will come back by itself. Plain data, built by
// the daemon each time it is asked.
type Health struct {
	StartedAt time.Time `json:"started_at"`

	Sources  []SourceHealth  `json:"sources"`
	Channels []ChannelHealth `json:"channels"`
	Service  ServiceHealth   `json:"service"`
}

// SourceHealth is one ingest path.
//
// Silent is reported by the daemon rather than derived here from LastSeen and
// ExpectedWithin, because only the daemon knows the difference between "has not
// reported" and "is not running at all", and guessing would put a reassuring
// word on a source that has stopped.
type SourceHealth struct {
	Name string `json:"name"`

	// LastSeen is zero when the source has never reported.
	LastSeen time.Time `json:"last_seen"`

	// ExpectedWithin is the declared liveness interval. Zero means the source
	// makes no promise.
	ExpectedWithin time.Duration `json:"expected_within"`

	Silent bool   `json:"silent"`
	Detail string `json:"detail,omitempty"`
}

// ChannelHealth mirrors channel.Stats plus whether the channel is switched on.
// Converted by the daemon rather than imported here, so this package does not
// depend on the delivery side at all.
type ChannelHealth struct {
	Name      string    `json:"name"`
	Enabled   bool      `json:"enabled"`
	Depth     int       `json:"depth"`
	Pending   int       `json:"pending"`
	Dropped   int       `json:"dropped"`
	InFlight  bool      `json:"in_flight"`
	LastError string    `json:"last_error,omitempty"`
	LastSent  time.Time `json:"last_sent"`

	// ConsecutiveFails and BackingOffUntil report the failure backoff.
	//
	// A channel that is being held back is not being attempted, and a channel
	// that is not being attempted must not look like one that is fine. This
	// product's whole argument is against states that read as healthy and are
	// not.
	ConsecutiveFails int       `json:"consecutive_fails,omitempty"`
	BackingOffUntil  time.Time `json:"backing_off_until,omitempty"`
}

// ServiceHealth answers "will this come back on its own".
type ServiceHealth struct {
	State string `json:"state"`

	// RestartsAfterCrash is reported separately from StartType because they are
	// different mechanisms and only one of them is on by default: installing a
	// service with automatic start covers reboot and logout but NOT a crash.
	RestartsAfterCrash bool `json:"restarts_after_crash"`

	StartType string `json:"start_type,omitempty"`
	PID       int    `json:"pid,omitempty"`

	// UncleanPreviousExit means the last run did not shut down cleanly.
	UncleanPreviousExit bool `json:"unclean_previous_exit,omitempty"`

	Detail string `json:"detail,omitempty"`
}

// Server is the operator interface.
type Server struct {
	deps Deps

	auth *authState
	page *template.Template
	fsys fs.FS

	// now is injected so tests need not sleep.
	now func() time.Time
}

// New builds a Server.
//
// On a first run -- no password hash stored -- it mints a ONE-TIME setup token.
// There is no "no password means everyone is authenticated" path, because that
// is a product that ships wide open and relies on the operator to close it.
func New(d Deps) (*Server, error) {
	switch {
	case d.Store == nil:
		return nil, errors.New("web: needs an incident store")
	case d.Config == nil:
		return nil, errors.New("web: needs a config accessor")
	case d.SaveConfig == nil:
		return nil, errors.New("web: needs a way to save the config")
	case d.Health == nil:
		return nil, errors.New("web: needs a health reporter")
	case d.PasswordHash == nil || d.SetPasswordHash == nil:
		return nil, errors.New("web: needs somewhere to keep the password hash")
	}
	if d.Audit == nil {
		d.Audit = audit.Nop{}
	}
	if d.Version == "" {
		d.Version = "dev"
	}

	sub, err := fs.Sub(assetFS, "assets")
	if err != nil {
		return nil, err
	}
	page, err := template.ParseFS(sub, "index.html")
	if err != nil {
		return nil, err
	}

	s := &Server{deps: d, fsys: sub, page: page, now: time.Now}
	s.auth = newAuthState(s.now)
	if d.PasswordHash() == "" {
		tok, err := newToken()
		if err != nil {
			return nil, err
		}
		s.auth.setupToken = tok
	}
	return s, nil
}

// SetupToken is the one-time token that authorises setting the FIRST password.
// Empty once a password exists.
//
// The daemon prints it to stdout at start. That is the point: possession of the
// machine's console is the only authority on a fresh install, and anything
// weaker -- an open window, a default password -- is a product that ships
// unlocked.
func (s *Server) SetupToken() string {
	if s.deps.PasswordHash() != "" {
		return ""
	}
	return s.auth.token()
}

// Handler returns the mux, wrapped so every response carries the security
// headers. Mount it wherever; /ack/ is not served here and must be mounted
// separately.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public. A wall display needs no login, and a status page that logs out
	// overnight is a status page nobody looks at.
	mux.HandleFunc("GET /{$}", s.handlePage)
	mux.HandleFunc("GET /static/{file}", s.handleAsset)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/incidents", s.handleIncidents)
	mux.HandleFunc("GET /api/checklist", s.handleChecklist)

	// Authentication itself.
	mux.HandleFunc("POST /api/session", s.handleSignIn)
	mux.HandleFunc("POST /api/signout", s.handleSignOut)
	mux.HandleFunc("POST /api/setup", s.handleSetup)

	// Authenticated: every write, and every read carrying configuration
	// detail.
	mux.Handle("GET /api/settings", s.requireAuth(http.HandlerFunc(s.handleGetSettings)))
	mux.Handle("POST /api/settings", s.requireAuth(http.HandlerFunc(s.handleSaveSettings)))
	mux.Handle("GET /api/audit", s.requireAuth(http.HandlerFunc(s.handleAudit)))
	mux.Handle("POST /api/password", s.requireAuth(http.HandlerFunc(s.handleChangePassword)))
	mux.Handle("POST /api/channels/{name}/test", s.requireAuth(http.HandlerFunc(s.handleTestChannel)))
	mux.Handle("POST /api/incidents/{id}/ack", s.requireAuth(http.HandlerFunc(s.handleAck)))
	mux.Handle("POST /api/incidents/{id}/close", s.requireAuth(http.HandlerFunc(s.handleClose)))
	mux.Handle("POST /api/service", s.requireAuth(http.HandlerFunc(s.handleServiceAction)))
	mux.Handle("GET /api/update", s.requireAuth(http.HandlerFunc(s.handleUpdateState)))
	mux.Handle("POST /api/update/check", s.requireAuth(http.HandlerFunc(s.handleUpdateCheck)))
	mux.Handle("POST /api/update/apply", s.requireAuth(http.HandlerFunc(s.handleUpdateApply)))

	return secureHeaders(mux)
}

// secureHeaders applies the headers every response needs.
//
// no-store because this is live incident state and a cached board is a lying
// board. The CSP forbids inline script, which is why the page's JavaScript is
// an embedded file rather than a <script> block -- a page that renders operator
// data would otherwise have one obvious way to go wrong.
func secureHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; " +
		"script-src 'self'; style-src 'self'; img-src 'self' data:; " +
		"connect-src 'self'; font-src 'self'; object-src 'none'; " +
		"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", csp)
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.page.ExecuteTemplate(w, "index.html", struct{ Version string }{s.deps.Version}); err != nil {
		// The header is already written by now, so there is nothing useful to
		// say to the client. Record it instead.
		s.record(r, audit.Entry{
			Kind: audit.KindService, Actor: "web",
			Summary: "the operator page failed to render",
			Fields:  map[string]string{"error": err.Error()},
		})
	}
}

// handleAsset serves the embedded CSS and JS.
//
// The {file} wildcard matches one path segment, so there is no traversal to
// defend against, and only the two files that exist can be found.
func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	switch name {
	case "app.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case "style.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	default:
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(s.fsys, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(b)
}
