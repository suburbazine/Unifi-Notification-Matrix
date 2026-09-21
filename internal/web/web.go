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
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/reconcile"
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

	// LinkState reports peer pairing for the interface, and LinkOfferCode
	// generates a pairing code. Both nil in a build with no link listener,
	// where the honest answer is that there is nowhere for a peer to pair
	// rather than that pairing failed.
	LinkState     func() LinkPairing
	LinkOfferCode func() (code string, expires time.Duration, err error)

	// LinkCancelCode withdraws an offered code, and LinkUnpair forgets a
	// paired peer -- reporting whether there was one to forget. Both exist
	// because pairing is granting a credential from this page, and a grant
	// that can only be taken back by editing YAML is one most operators
	// cannot take back.
	LinkCancelCode func()
	LinkUnpair     func(slug string) (found bool, err error)

	// LinkApproveCondition adds one PROPOSED condition to a peer's approved
	// manifest, and LinkDismissCondition drops the proposal without approving
	// it.
	//
	// The vocabulary stays closed either way: these change what saying yes
	// COSTS, not what a peer may send without being asked. An implementation
	// must refuse a condition the peer has not actually tried to send --
	// ErrNotProposed -- so this cannot become a general way to write
	// configuration through one POST.
	LinkApproveCondition func(slug string, c ApprovedCondition) error
	LinkDismissCondition func(slug, condition string)

	// The capability probe, run from the interface. All four are optional
	// together: a build that supplies none simply has no Probe section, which
	// is a different thing from a probe that cannot run and says why.
	//
	// ProbeStart takes the console by NAME rather than by host. The host is
	// the operator's to type in a terminal; from a page the console is one
	// they already configured, and resolving it here means the key that goes
	// with it cannot be mismatched to it.
	ProbeStatus func() ProbeStatus
	ProbeStart  func(console string, listen time.Duration, products []string) error
	ProbeStop   func()
	ProbeRead   func(name string) ([]byte, error)

	// FetchFingerprint reads the certificate a console is presenting, so the
	// interface can show it to an operator who is deciding whether to pin it.
	//
	// It SHOWS; it never pins. The caller supplies the local-network check --
	// this is a daemon dialling an address somebody typed into a form, and
	// the rule the probe follows applies here for the same reason.
	FetchFingerprint func(ctx context.Context, host string) (string, error)

	// TestChannel sends one channel's proof-of-configuration message and
	// reports what happened. Optional: a build that does not supply it simply
	// has no test button.
	TestChannel func(ctx context.Context, name string) (summary string, err error)

	// HookTestMode arms a hook's test mode for minutes, or disarms it when
	// minutes is zero or less. It returns when the mode lapses.
	//
	// While armed the hook accepts, counts and DISCARDS arrivals, so an
	// operator can press Test in Alarm Manager and find out whether the rule
	// reaches this machine without raising an alarm and without an incident to
	// close afterwards.
	HookTestMode func(name string, minutes int) (until time.Time, err error)

	// FireHookTest raises the alarm this hook would raise, through the real
	// rules, ladder and channels, and returns the incident's title.
	//
	// The other half of testing a hook: test mode proves UniFi can reach us,
	// and this proves that when it does, somebody's phone rings.
	FireHookTest func(name string) (title string, err error)

	// KnownEntities is what this daemon has actually seen events about.
	//
	// The entity field of a rule is the one no fixed list can supply -- camera
	// and door names belong to the site, not to this build -- so the only
	// honest suggestions are the things that have really come through. Empty
	// on a fresh start, which is the truth rather than a gap.
	KnownEntities func() []EntitySeen

	// ObservedEntities is the PERMANENT record of what this site has had, as
	// opposed to KnownEntities, which is what this process has seen.
	//
	// A different question, and the difference is the whole point of the rule
	// review: the camera that stopped reporting before the last restart is
	// absent from one and present in the other, and it is exactly the row that
	// answers "was this lost, or did it never exist". Optional -- a build
	// without a record says the rules were not checked rather than saying
	// they are fine.
	ObservedEntities func(ctx context.Context) ([]reconcile.Entity, error)

	// SelfWatch reports whether anything outside this machine would notice if
	// this installation stopped. Optional: a build that does not supply it
	// says nothing, which is right for every deployment where the answer is
	// yes by construction.
	SelfWatch func() SelfWatch

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

// ApprovedCondition is the operator's decision about one proposed condition.
type ApprovedCondition struct {
	Condition string
	Meaning   string
	Severity  string

	// Momentary decides whether an incident that cleared before its first rung
	// is still delivered. Getting it wrong on a high-volume condition floods
	// whoever is on call, so it is the operator's call rather than a default.
	Momentary bool
}

// ErrNotProposed is returned when the named condition is not one this peer has
// been refused for.
//
// The guard that keeps the amendment route narrow: an operator may approve
// what a peer ASKED for, not whatever a request body contains.
var ErrNotProposed = errors.New("web: that condition has not been proposed by this peer")

// SelfWatch answers one question: if this installation stopped, would
// anything say so?
//
// Normally the answer is yes by construction -- the daemon runs somewhere
// other than the equipment it watches, so the equipment failing and the
// daemon failing are different events. On a UniFi gateway they are the same
// event, and the alarm about it is the one thing that cannot be sent.
//
// PUBLIC, on the same endpoint as the incident counts, and that is
// deliberate. A wall display showing "all clear" is exactly who needs the
// caveat: without it, the board cannot be told apart from one whose daemon
// died an hour ago. The demo banner is here for the same reason -- somebody
// arriving at a tab somebody else left open has to be able to tell what they
// are looking at without reading anything else.
type SelfWatch struct {
	// AtRisk is true when the daemon shares fate with what it watches AND
	// nothing outside this machine would notice it stop.
	//
	// Both halves. Sharing fate is a fact about where it runs and not in
	// itself a problem; it becomes one only when nothing else is watching,
	// which is why pairing a peer elsewhere clears this rather than merely
	// adding a feature.
	AtRisk bool `json:"at_risk"`

	// Detail is what the banner says. It names the LIMITATION and not the
	// hardware or the remedy, because this reaches anybody who can see the
	// board: that this installation cannot report its own failure is
	// something an operator must know, and which box it runs on is not.
	Detail string `json:"detail,omitempty"`
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

	// NeverConnected is a source that has not once reached its console since
	// this daemon started.
	//
	// A THIRD STATE, because it is a different fact from silence and a much
	// worse one. Silent means it was working and stopped; this means it has
	// never worked, and on a misconfigured installation it is the state that
	// matters -- the board showed three sources "reporting" on a console
	// where two of the three applications were not installed at all.
	NeverConnected bool `json:"never_connected,omitempty"`
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
	// Unauthenticated on purpose, and it says nothing this listener was not
	// already saying: GET / serves the product name and version to anybody.
	// See internal/web/hello.go.
	mux.HandleFunc("GET /hello", s.handleHello)

	// Authentication itself.
	mux.HandleFunc("POST /api/session", s.handleSignIn)
	mux.HandleFunc("POST /api/signout", s.handleSignOut)
	mux.HandleFunc("POST /api/setup", s.handleSetup)

	// Authenticated: every write, and every read carrying configuration
	// detail.
	mux.Handle("GET /api/settings", s.requireAuth(http.HandlerFunc(s.handleGetSettings)))
	mux.Handle("POST /api/settings", s.requireAuth(http.HandlerFunc(s.handleSaveSettings)))
	mux.Handle("GET /api/audit", s.requireAuth(http.HandlerFunc(s.handleAudit)))
	// The other direction: what the rules point at, against what this site has
	// actually had. Configuration detail, so it is behind a session like the
	// settings it reports on.
	mux.Handle("GET /api/rules/review", s.requireAuth(http.HandlerFunc(s.handleRuleReview)))
	mux.Handle("POST /api/rules/repoint", s.requireAuth(http.HandlerFunc(s.handleRepointRule)))
	mux.Handle("POST /api/password", s.requireAuth(http.HandlerFunc(s.handleChangePassword)))
	mux.Handle("POST /api/channels/{name}/test", s.requireAuth(http.HandlerFunc(s.handleTestChannel)))
	// Gated: arming makes this installation deliberately deaf to one hook, and
	// firing costs real notifications and possibly a real phone call.
	mux.Handle("POST /api/hooks/{name}/test-mode", s.requireAuth(http.HandlerFunc(s.handleHookTestMode)))
	mux.Handle("POST /api/hooks/{name}/fire", s.requireAuth(http.HandlerFunc(s.handleFireHookTest)))
	mux.Handle("POST /api/incidents/{id}/ack", s.requireAuth(http.HandlerFunc(s.handleAck)))
	mux.Handle("POST /api/incidents/{id}/close", s.requireAuth(http.HandlerFunc(s.handleClose)))
	mux.Handle("POST /api/service", s.requireAuth(http.HandlerFunc(s.handleServiceAction)))
	// Pairing a peer hands it the ability to raise alarms here and to take
	// over a capability, so both routes are behind a session like every other
	// change.
	mux.Handle("GET /api/link", s.requireAuth(http.HandlerFunc(s.handleLinkState)))
	mux.Handle("POST /api/link/code", s.requireAuth(http.HandlerFunc(s.handleLinkPairCode)))
	mux.Handle("DELETE /api/link/code", s.requireAuth(http.HandlerFunc(s.handleLinkCancelCode)))
	mux.Handle("DELETE /api/link/peers/{slug}", s.requireAuth(http.HandlerFunc(s.handleLinkUnpair)))
	// Amending an approved manifest is granting a peer the right to raise a
	// new kind of alarm here, so it is gated exactly like pairing was.
	mux.Handle("POST /api/link/peers/{slug}/conditions",
		s.requireAuth(http.HandlerFunc(s.handleLinkApproveCondition)))
	mux.Handle("DELETE /api/link/peers/{slug}/conditions/{condition}",
		s.requireAuth(http.HandlerFunc(s.handleLinkDismissCondition)))
	// The probe reads the console's whole surface and writes a file about it,
	// so every route is behind a session: running one is an action against
	// the console, and a report is configuration detail about the site even
	// after redaction.
	// Reading a console's certificate is a dial to an address from a form, so
	// it is behind a session like every other write, and the daemon refuses
	// anything that is not on a local network.
	mux.Handle("POST /api/consoles/fingerprint",
		s.requireAuth(http.HandlerFunc(s.handleFetchFingerprint)))
	mux.Handle("GET /api/probe", s.requireAuth(http.HandlerFunc(s.handleProbeStatus)))
	mux.Handle("POST /api/probe/run", s.requireAuth(http.HandlerFunc(s.handleProbeRun)))
	mux.Handle("POST /api/probe/stop", s.requireAuth(http.HandlerFunc(s.handleProbeStop)))
	mux.Handle("GET /api/probe/reports/{name}", s.requireAuth(http.HandlerFunc(s.handleProbeReport)))
	mux.Handle("GET /api/probe/reports/{name}/download",
		s.requireAuth(http.HandlerFunc(s.handleProbeDownload)))
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

// EntitySeen is one thing the daemon has observed, offered to the Rules
// editor. Mirrors ingest.EntitySeen; declared here so this package does not
// depend on the ingest supervisor for a shape it only renders.
type EntitySeen struct {
	Source string    `json:"source"`
	ID     string    `json:"id"`
	Name   string    `json:"name"`
	Kind   string    `json:"kind"`
	LastAt time.Time `json:"last_at"`
}
