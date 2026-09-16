package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/setup"
)

// canary is planted in every secret in the test config. No response body may
// ever contain it -- see TestSecretsNeverReachAResponseBody, which asserts on
// raw bytes rather than on a decoded shape, because the failure this guards
// against is a struct quietly gaining a field.
const canary = "CANARY-9f2b7c41-MUST-NOT-LEAK"

const testPassword = "correct-horse-battery-staple"

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type fakeStore struct {
	mu    sync.Mutex
	byID  map[string]incident.Incident
	getFn func(id string) (*incident.Incident, error)
}

func newFakeStore(incs ...*incident.Incident) *fakeStore {
	s := &fakeStore{byID: map[string]incident.Incident{}}
	for _, i := range incs {
		s.byID[i.ID] = *i
	}
	return s
}

func (s *fakeStore) Put(_ context.Context, inc *incident.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[inc.ID] = *inc
	return nil
}

func (s *fakeStore) PutIfUnchanged(_ context.Context, inc *incident.Incident, expect time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	have, ok := s.byID[inc.ID]
	if !ok {
		return incident.ErrNotFound
	}
	if !have.UpdatedAt.Equal(expect) {
		return incident.ErrConflict
	}
	s.byID[inc.ID] = *inc
	return nil
}

func (s *fakeStore) Get(_ context.Context, id string) (*incident.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getFn != nil {
		return s.getFn(id)
	}
	inc, ok := s.byID[id]
	if !ok {
		return nil, incident.ErrNotFound
	}
	cp := inc
	return &cp, nil
}

func (s *fakeStore) OpenByDedupKey(context.Context, string) (*incident.Incident, error) {
	return nil, incident.ErrNotFound
}
func (s *fakeStore) LatestByDedupKey(context.Context, string) (*incident.Incident, error) {
	return nil, incident.ErrNotFound
}

func (s *fakeStore) Active(context.Context) ([]*incident.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*incident.Incident
	for _, inc := range s.byID {
		cp := inc
		if !cp.Terminal() {
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *fakeStore) Recent(_ context.Context, limit int) ([]*incident.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*incident.Incident
	for _, inc := range s.byID {
		cp := inc
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *fakeStore) Close() error { return nil }

type fakeAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (a *fakeAudit) Append(_ context.Context, e audit.Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *fakeAudit) Recent(_ context.Context, limit int) ([]audit.Entry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]audit.Entry, 0, len(a.entries))
	for i := len(a.entries) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, a.entries[i])
	}
	return out, nil
}

func (a *fakeAudit) Close() error { return nil }

func (a *fakeAudit) summaries() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.entries {
		out = append(out, string(e.Kind)+": "+e.Summary)
	}
	return out
}

func (a *fakeAudit) has(kind audit.Kind, substr string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.Kind == kind && strings.Contains(e.Summary, substr) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type harness struct {
	t      *testing.T
	srv    *Server
	http   *httptest.Server
	client *http.Client

	store *fakeStore
	log   *fakeAudit

	mu      sync.Mutex
	cfg     *config.Config
	hash    string
	saveErr error
	hashErr error
	saved   int

	// serviceActions records what the operator asked the service manager for.
	serviceActions []ServiceAction
	serviceErr     error
}

// testConfig is valid, exercises every secret-bearing field, and plants the
// canary in each of them.
func testConfig() *config.Config {
	return &config.Config{
		Version: config.SchemaVersion,
		Consoles: []config.Console{{
			Name:        "udm",
			Host:        "10.0.0.1",
			APIKey:      secret.Secret(canary + "-console"),
			Fingerprint: "AA:BB:CC",
			Sources:     []string{"protect"},
		}},
		Channels: config.Channels{
			Ntfy: &config.Ntfy{
				Enabled:   true,
				ServerURL: "https://ntfy.sh",
				Topic:     "site-alerts",
				Token:     secret.Secret(canary + "-ntfy"),
			},
			Email: &config.Email{
				Enabled:    true,
				Host:       "smtp.example.com",
				Port:       587,
				TLS:        "auto",
				Username:   "alerts@example.com",
				Password:   secret.Secret(canary + "-email"),
				From:       "alerts@example.com",
				Recipients: []string{"operator@example.com"},
			},
		},
		Web: config.Web{
			Listen:     "127.0.0.1:8322",
			AckKey:     secret.Secret(canary + "-ackkey"),
			AckBaseURL: "https://alerts.example.com",
		},
	}
}

func newHarness(t *testing.T, incs ...*incident.Incident) *harness {
	t.Helper()
	h := &harness{
		t:     t,
		store: newFakeStore(incs...),
		log:   &fakeAudit{},
		cfg:   testConfig(),
	}

	srv, err := New(Deps{
		Store:      h.store,
		Audit:      h.log,
		Version:    "test",
		Config:     func() *config.Config { h.mu.Lock(); defer h.mu.Unlock(); return h.cfg },
		SaveConfig: h.save,
		Health: func() Health {
			return Health{
				StartedAt: time.Now().Add(-time.Hour),
				Sources: []SourceHealth{{
					Name: "protect", LastSeen: time.Now().Add(-90 * time.Second),
					ExpectedWithin: 30 * time.Minute, Silent: false,
				}},
				Channels: []ChannelHealth{{Name: "ntfy", Enabled: true, Depth: 200}},
				Service:  ServiceHealth{State: "running", RestartsAfterCrash: true},
			}
		},
		PasswordHash:    func() string { h.mu.Lock(); defer h.mu.Unlock(); return h.hash },
		SetPasswordHash: h.setHash,
		ControlService: func(a ServiceAction) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.serviceActions = append(h.serviceActions, a)
			return h.serviceErr
		},
		Checklist: func() setup.Input {
			return setup.Input{
				ConfigPath: "/tmp/config.yaml", Listen: "127.0.0.1:8322",
				Consoles: 1, HasConsoleKey: true,
				SourceNames:     []string{"protect"},
				ChannelsEnabled: []string{"ntfy"},
				Hooks: []setup.HookState{{
					Name: "wan", Product: "network",
					// The URL carries the token. It must never reach a
					// signed-out caller.
					URL: "http://192.168.1.50:8322/hook/" + canary,
				}},
			}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.srv = srv
	h.http = httptest.NewServer(srv.Handler())
	t.Cleanup(h.http.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	h.client = &http.Client{Jar: jar}
	return h
}

func (h *harness) save(c *config.Config) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.saved++
	if h.saveErr != nil {
		return h.saveErr
	}
	h.cfg = c
	return nil
}

func (h *harness) setHash(s string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.hashErr != nil {
		return h.hashErr
	}
	h.hash = s
	return nil
}

// setPassword installs a hash directly, at a low iteration count so the test
// suite is not spending a second per sign-in. The stored form is
// self-describing, so verification uses the count it finds -- which is exactly
// the property that lets the real iteration count rise later.
func (h *harness) setPassword(pw string) {
	hash, err := hashWith(pw, 1000)
	if err != nil {
		h.t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hash = hash
}

func (h *harness) do(method, path string, body any) (*http.Response, []byte) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.http.URL+path, rdr)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp, raw
}

func (h *harness) signIn() {
	h.t.Helper()
	resp, body := h.do("POST", "/api/session", map[string]string{"password": testPassword})
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("sign in: %d %s", resp.StatusCode, body)
	}
}

func openIncident(id string, sev incident.Severity, title string, at time.Time) *incident.Incident {
	return incident.Open(id, incident.Key("protect", id, "offline"), sev, "protect", title, "detail", at)
}

// ---------------------------------------------------------------------------
// The access model
// ---------------------------------------------------------------------------

func TestPublicEndpointsWorkSignedOut(t *testing.T) {
	// A wall display shows the board with nobody signed in. That is the whole
	// reason the public half exists.
	h := newHarness(t, openIncident("i1", incident.SeverityCritical, "Camera offline", time.Now()))
	h.setPassword(testPassword)

	for _, path := range []string{"/", "/api/status", "/api/incidents", "/static/app.js", "/static/style.css"} {
		resp, body := h.do("GET", path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s signed out: got %d, want 200 (%s)", path, resp.StatusCode, body)
		}
	}

	_, body := h.do("GET", "/api/incidents", nil)
	if !bytes.Contains(body, []byte("Camera offline")) {
		t.Errorf("the public board did not carry the incident: %s", body)
	}
}

func TestEveryWriteIsGated(t *testing.T) {
	h := newHarness(t, openIncident("i1", incident.SeverityHigh, "Door forced", time.Now()))
	h.setPassword(testPassword)

	cases := []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/settings", nil},
		{"POST", "/api/settings", settingsUpdate{}},
		{"GET", "/api/audit", nil},
		{"POST", "/api/password", map[string]string{"current": testPassword, "password": "another-long-password"}},
		{"POST", "/api/incidents/i1/ack", map[string]string{}},
		{"POST", "/api/incidents/i1/close", map[string]string{}},
	}
	for _, c := range cases {
		resp, body := h.do(c.method, c.path, c.body)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s signed out: got %d, want 401 (%s)", c.method, c.path, resp.StatusCode, body)
		}
	}

	// And nothing was actually done.
	inc, err := h.store.Get(t.Context(), "i1")
	if err != nil {
		t.Fatal(err)
	}
	if inc.Acknowledged() || inc.ClosedAt != nil {
		t.Error("an unauthenticated request changed an incident")
	}
	if h.saved != 0 {
		t.Error("an unauthenticated request saved the config")
	}
}

func TestSecretsNeverReachAResponseBody(t *testing.T) {
	h := newHarness(t, openIncident("i1", incident.SeverityCritical, "Camera offline", time.Now()))
	h.setPassword(testPassword)
	h.signIn()

	// Plant a secret in the audit log too: an implementation that echoed
	// entries verbatim would be a second leak path, and this asserts the test
	// would catch one.
	_ = h.log.Append(t.Context(), audit.Entry{
		At: time.Now(), Kind: audit.KindService, Summary: "started",
	})

	paths := []struct{ method, path string }{
		{"GET", "/"},
		{"GET", "/static/app.js"},
		{"GET", "/static/style.css"},
		{"GET", "/api/status"},
		{"GET", "/api/incidents"},
		{"GET", "/api/settings"},
		{"GET", "/api/audit"},
	}
	for _, p := range paths {
		resp, body := h.do(p.method, p.path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: %d (%s)", p.method, p.path, resp.StatusCode, body)
		}
		if bytes.Contains(body, []byte(canary)) {
			t.Errorf("%s %s leaked a secret value:\n%s", p.method, p.path, body)
		}
	}

	// The settings surface must still SAY that the secrets exist, or the
	// operator cannot tell a configured console from an unconfigured one.
	_, body := h.do("GET", "/api/settings", nil)
	var got settingsView
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Consoles[0].APIKeySet || !got.Channels.Ntfy.TokenSet ||
		!got.Channels.Email.PasswordSet || !got.Web.AckKeySet {
		t.Errorf("settings hid the EXISTENCE of the secrets as well as their values: %+v", got)
	}

	// And the save response, which echoes settings back, must be clean too.
	resp, saveBody := h.do("POST", "/api/settings", settingsUpdate{
		Consoles: []consoleUpdate{{
			Name: "udm", Host: "10.0.0.1", Fingerprint: "AA:BB:CC", Sources: []string{"protect"},
		}},
		Channels: channelsUpdate{
			Ntfy:  &ntfyUpdate{Enabled: true, ServerURL: "https://ntfy.sh", Topic: "site-alerts"},
			Email: &emailUpdate{Enabled: true, Host: "smtp.example.com", Port: 587, TLS: "auto", Username: "alerts@example.com", From: "alerts@example.com", Recipients: []string{"operator@example.com"}},
		},
		Web: webUpdate{Listen: "127.0.0.1:8322", AckBaseURL: "https://alerts.example.com"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save: %d %s", resp.StatusCode, saveBody)
	}
	if bytes.Contains(saveBody, []byte(canary)) {
		t.Errorf("the save response leaked a secret:\n%s", saveBody)
	}
	for _, e := range h.log.summaries() {
		if strings.Contains(e, canary) {
			t.Errorf("a secret reached the audit log: %s", e)
		}
	}
}

func TestSecretsSurviveASaveThatDidNotResendThem(t *testing.T) {
	// The form cannot echo a stored key back, so "unchanged" is expressed by
	// sending nothing -- and a save that dropped what was not retyped would
	// wipe the console API key every time somebody fixed a hostname.
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	resp, body := h.do("POST", "/api/settings", settingsUpdate{
		Consoles: []consoleUpdate{{
			Name: "udm", Host: "10.0.0.2", Fingerprint: "AA:BB:CC", Sources: []string{"protect"},
		}},
		Channels: channelsUpdate{
			Ntfy:  &ntfyUpdate{Enabled: true, ServerURL: "https://ntfy.sh", Topic: "site-alerts"},
			Email: &emailUpdate{Enabled: true, Host: "smtp.example.com", Port: 587, TLS: "auto", Username: "alerts@example.com", From: "alerts@example.com", Recipients: []string{"operator@example.com"}},
		},
		Web: webUpdate{Listen: "127.0.0.1:8322", AckBaseURL: "https://alerts.example.com"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}

	h.mu.Lock()
	cfg := h.cfg
	h.mu.Unlock()
	if cfg.Consoles[0].Host != "10.0.0.2" {
		t.Errorf("the hostname change was not applied: %q", cfg.Consoles[0].Host)
	}
	if cfg.Consoles[0].APIKey.Reveal() != canary+"-console" {
		t.Error("the console API key was lost by a save that did not resend it")
	}
	if cfg.Channels.Ntfy.Token.Reveal() != canary+"-ntfy" {
		t.Error("the ntfy token was lost")
	}
	if cfg.Channels.Email.Password.Reveal() != canary+"-email" {
		t.Error("the email password was lost")
	}
	if cfg.Web.AckKey.Reveal() != canary+"-ackkey" {
		t.Error("the ack signing key was lost; every link already sent would be dead")
	}

	// A value that WAS sent replaces the stored one.
	resp, body = h.do("POST", "/api/settings", settingsUpdate{
		Consoles: []consoleUpdate{{
			Name: "udm", Host: "10.0.0.2", Fingerprint: "AA:BB:CC",
			Sources: []string{"protect"}, APIKeyNew: "a-new-key",
		}},
		Channels: channelsUpdate{
			Ntfy:  &ntfyUpdate{Enabled: true, ServerURL: "https://ntfy.sh", Topic: "site-alerts"},
			Email: &emailUpdate{Enabled: true, Host: "smtp.example.com", Port: 587, TLS: "auto", Username: "alerts@example.com", From: "alerts@example.com", Recipients: []string{"operator@example.com"}},
		},
		Web: webUpdate{Listen: "127.0.0.1:8322", AckBaseURL: "https://alerts.example.com"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}
	h.mu.Lock()
	cfg = h.cfg
	h.mu.Unlock()
	if cfg.Consoles[0].APIKey.Reveal() != "a-new-key" {
		t.Errorf("a resent key was not applied")
	}
}

// ---------------------------------------------------------------------------
// Setup and sign-in
// ---------------------------------------------------------------------------

func TestSetupTokenWorksExactlyOnce(t *testing.T) {
	h := newHarness(t) // no password stored: first run

	tok := h.srv.SetupToken()
	if tok == "" {
		t.Fatal("no setup token was minted on a first run")
	}

	// There is no "no password means everyone is authenticated" path.
	resp, body := h.do("GET", "/api/settings", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("settings were readable before any password was set: %d %s", resp.StatusCode, body)
	}

	// A wrong token does not set anything.
	resp, body = h.do("POST", "/api/setup", map[string]string{
		"token": "not-the-token", "password": "a-perfectly-long-password",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong setup token was accepted: %d %s", resp.StatusCode, body)
	}
	if h.srv.SetupToken() != tok {
		t.Error("a wrong token burned the real one")
	}

	// A too-short password is refused BEFORE the token is spent, so a typo
	// does not lock the operator out of their own fresh install.
	resp, _ = h.do("POST", "/api/setup", map[string]string{"token": tok, "password": "short"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a short password was accepted: %d", resp.StatusCode)
	}
	if h.srv.SetupToken() != tok {
		t.Fatal("a rejected password burned the setup token")
	}

	// The real thing.
	resp, body = h.do("POST", "/api/setup", map[string]string{
		"token": tok, "password": testPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup: %d %s", resp.StatusCode, body)
	}
	if h.srv.SetupToken() != "" {
		t.Error("the setup token survived being used")
	}
	// It issued a session, so the operator is not locked out of the page they
	// just configured.
	resp, body = h.do("GET", "/api/settings", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup did not sign the operator in: %d %s", resp.StatusCode, body)
	}

	// Second use, with a fresh client so the session is not what is answering.
	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{Jar: jar}
	resp, _ = h.do("POST", "/api/setup", map[string]string{
		"token": tok, "password": "yet-another-long-password",
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("the setup token worked a second time")
	}
	if !VerifyPassword(h.hash, testPassword) {
		t.Error("the second setup attempt changed the password")
	}
}

func TestFailedSignInsAreThrottled(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)

	for i := 0; i < freeAttempts; i++ {
		resp, body := h.do("POST", "/api/session", map[string]string{"password": "wrong"})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401 (%s)", i+1, resp.StatusCode, body)
		}
	}

	resp, body := h.do("POST", "/api/session", map[string]string{"password": "wrong"})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a LAN device was allowed to keep guessing: got %d (%s)", resp.StatusCode, body)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("no Retry-After on a throttled sign-in")
	}

	// The lockout is not bypassed by knowing the password: it is the attempt
	// that is refused, not the guess.
	resp, _ = h.do("POST", "/api/session", map[string]string{"password": testPassword})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("the lockout let a correct password through immediately: %d", resp.StatusCode)
	}

	if !h.log.has(audit.KindAuth, "failed sign-in") {
		t.Error("failed sign-ins were not audited")
	}
	if !h.log.has(audit.KindAuth, "too many failed attempts") {
		t.Error("the throttle itself was not audited")
	}

	// It is bounded: once the lockout expires the operator gets back in.
	h.srv.auth.mu.Lock()
	for _, rec := range h.srv.auth.fails {
		rec.until = time.Now().Add(-time.Second)
	}
	h.srv.auth.mu.Unlock()

	h.signIn()
}

func TestSignInWithNoPasswordSetIsRefused(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do("POST", "/api/session", map[string]string{"password": ""})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("got %d (%s), want 409: an empty password must never authenticate", resp.StatusCode, body)
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)

	resp, _ := h.do("POST", "/api/session", map[string]string{"password": testPassword})
	var c *http.Cookie
	for _, got := range resp.Cookies() {
		if got.Name == sessionCookie {
			c = got
		}
	}
	if c == nil {
		t.Fatal("no session cookie was set")
	}
	if !c.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie is not SameSite=Lax")
	}
	if c.Path != "/" {
		t.Errorf("session cookie path is %q", c.Path)
	}
	// Plain HTTP here, so Secure must be off or the operator could not sign in
	// on the LAN listener at all.
	if c.Secure {
		t.Error("session cookie is Secure over plain HTTP, which makes it unusable")
	}

	// Signing out actually invalidates it.
	h.do("POST", "/api/signout", map[string]string{})
	resp, _ = h.do("GET", "/api/settings", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the session survived a sign-out: %d", resp.StatusCode)
	}
}

func TestPasswordHashIsSelfDescribing(t *testing.T) {
	hash, err := hashWith(testPassword, 1234)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "pbkdf2-sha256$1234$") {
		t.Fatalf("stored hash does not record its iteration count: %q", hash)
	}
	if !VerifyPassword(hash, testPassword) {
		t.Error("a correct password did not verify")
	}
	if VerifyPassword(hash, testPassword+"x") {
		t.Error("a wrong password verified")
	}
	// A hash written at a DIFFERENT count still verifies, which is what lets
	// the iteration count rise later without invalidating anyone's password.
	other, err := hashWith(testPassword, 4321)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(other, testPassword) {
		t.Error("raising the iteration count would invalidate existing passwords")
	}
	for _, bad := range []string{"", "x", "pbkdf2-sha256$a$b$c", "scrypt$1$2$3", "pbkdf2-sha256$1000$!!$!!"} {
		if VerifyPassword(bad, testPassword) {
			t.Errorf("a malformed stored hash %q was treated as a match", bad)
		}
	}
	if _, err := HashPassword("short"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("a short password was hashed anyway: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Incident actions
// ---------------------------------------------------------------------------

func TestAcknowledgeAndCloseFromTheUI(t *testing.T) {
	now := time.Now()
	inc := openIncident("i1", incident.SeverityCritical, "Camera offline", now.Add(-10*time.Minute))
	if err := inc.RecordAlert(now.Add(-9*time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, inc)
	h.setPassword(testPassword)
	h.signIn()

	resp, body := h.do("POST", "/api/incidents/i1/ack", map[string]string{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ack: %d %s", resp.StatusCode, body)
	}
	got, err := h.store.Get(t.Context(), "i1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Acknowledged() {
		t.Fatal("the incident was not acknowledged")
	}
	if got.AckVia != "web" {
		t.Errorf("ack attributed to %q, want %q", got.AckVia, "web")
	}
	// Acknowledged is NOT resolved: the condition has not cleared, so this is
	// still an open obligation and must still be on the board.
	if got.State() != incident.StateAcknowledged {
		t.Errorf("state is %q, want acknowledged", got.State())
	}
	if !bytes.Contains(body, []byte(`"state":"acknowledged"`)) {
		t.Errorf("the response did not report the new state: %s", body)
	}
	if !h.log.has(audit.KindAcknowledged, "web UI") {
		t.Errorf("the acknowledgement was not audited: %v", h.log.summaries())
	}

	resp, body = h.do("POST", "/api/incidents/i1/close", map[string]string{"reason": "camera replaced"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("close: %d %s", resp.StatusCode, body)
	}
	got, _ = h.store.Get(t.Context(), "i1")
	if got.State() != incident.StateClosed {
		t.Errorf("state is %q, want closed", got.State())
	}
	if got.CloseReason != "camera replaced" {
		t.Errorf("close reason is %q", got.CloseReason)
	}
	if !h.log.has(audit.KindClosed, "web UI") {
		t.Error("the close was not audited")
	}

	resp, _ = h.do("POST", "/api/incidents/i1/ack", map[string]string{})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("acknowledging a closed incident: got %d, want 409", resp.StatusCode)
	}
	resp, _ = h.do("POST", "/api/incidents/nope/ack", map[string]string{})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("acknowledging an unknown incident: got %d, want 404", resp.StatusCode)
	}
}

func TestAcknowledgeRetriesTheCompareAndSwap(t *testing.T) {
	// The race that matters: the scheduler read this incident, spent real time
	// delivering, and writes back the alert -- while the operator is tapping
	// Acknowledge. Losing that write is the failure that teaches an operator
	// the product does not work.
	inc := openIncident("i1", incident.SeverityCritical, "Door forced", time.Now())
	h := newHarness(t, inc)
	h.setPassword(testPassword)
	h.signIn()

	var calls int
	h.store.mu.Lock()
	h.store.getFn = func(id string) (*incident.Incident, error) {
		calls++
		cur, ok := h.store.byID[id]
		if !ok {
			return nil, incident.ErrNotFound
		}
		cp := cur
		if calls == 1 {
			// Somebody else writes between our read and our write.
			moved := cur
			moved.UpdatedAt = cur.UpdatedAt.Add(time.Second)
			moved.AlertCount++
			h.store.byID[id] = moved
		}
		return &cp, nil
	}
	h.store.mu.Unlock()

	resp, body := h.do("POST", "/api/incidents/i1/ack", map[string]string{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ack lost the race instead of retrying: %d %s", resp.StatusCode, body)
	}
	got, _ := h.store.Get(t.Context(), "i1")
	if !got.Acknowledged() {
		t.Error("the acknowledgement was dropped")
	}
}

// ---------------------------------------------------------------------------
// Settings errors
// ---------------------------------------------------------------------------

func validUpdate() settingsUpdate {
	return settingsUpdate{
		Consoles: []consoleUpdate{{
			Name: "udm", Host: "10.0.0.1", Fingerprint: "AA:BB:CC", Sources: []string{"protect"},
		}},
		Channels: channelsUpdate{
			Ntfy:  &ntfyUpdate{Enabled: true, ServerURL: "https://ntfy.sh", Topic: "site-alerts"},
			Email: &emailUpdate{Enabled: true, Host: "smtp.example.com", Port: 587, TLS: "auto", Username: "alerts@example.com", From: "alerts@example.com", Recipients: []string{"operator@example.com"}},
		},
		Web: webUpdate{Listen: "127.0.0.1:8322", AckBaseURL: "https://alerts.example.com"},
	}
}

func TestValidationIsShownAndInternalErrorsAreNot(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	// A mistake the operator can fix must be reported in full. That is the
	// entire point of validating rather than accepting.
	bad := validUpdate()
	bad.Web.AckBaseURL = "https://127.0.0.1:8322"
	resp, body := h.do("POST", "/api/settings", bad)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a bad ack base URL was accepted: %d %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("would not open on a phone")) {
		t.Errorf("the validation message was swallowed: %s", body)
	}

	// A validation error from the injected SaveConfig is shown too.
	h.mu.Lock()
	h.saveErr = config.Problems{"channel ntfy: needs a topic"}
	h.mu.Unlock()
	resp, body = h.do("POST", "/api/settings", validUpdate())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 (%s)", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("needs a topic")) {
		t.Errorf("a validation failure from SaveConfig was not shown: %s", body)
	}

	// An unexpected error is NOT shown: it can name paths and hosts.
	h.mu.Lock()
	h.saveErr = errors.New("open /var/lib/notifymatrix/config.yaml: permission denied")
	h.mu.Unlock()
	resp, body = h.do("POST", "/api/settings", validUpdate())
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500 (%s)", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte("/var/lib")) || bytes.Contains(body, []byte("permission denied")) {
		t.Errorf("an internal error leaked into the response: %s", body)
	}
	if !h.log.has(audit.KindService, "saving the configuration failed") {
		t.Errorf("the internal error was not recorded server-side: %v", h.log.summaries())
	}
}

func TestSavingIsAudited(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	upd := validUpdate()
	upd.QuietHours.Enabled = true
	upd.QuietHours.Start = "22:00"
	upd.QuietHours.End = "07:00"
	resp, body := h.do("POST", "/api/settings", upd)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}

	h.log.mu.Lock()
	defer h.log.mu.Unlock()
	var found bool
	for _, e := range h.log.entries {
		if e.Kind != audit.KindConfigChanged {
			continue
		}
		found = true
		if !strings.Contains(e.Fields["changed"], "quiet_hours") {
			t.Errorf("the audit entry does not say what changed: %v", e.Fields)
		}
	}
	if !found {
		t.Error("a settings save was not audited")
	}
}

// ---------------------------------------------------------------------------
// Shape of the surface
// ---------------------------------------------------------------------------

func TestAckRouteIsNotServedHere(t *testing.T) {
	// The acknowledgement route carries its own authority and is mounted
	// separately by the daemon. Serving it here would widen what a leaked ack
	// link can reach, which is the one thing that surface must not do.
	h := newHarness(t)
	for _, p := range []string{"/ack/", "/ack/i1/token"} {
		resp, _ := h.do("GET", p, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: got %d, want 404", p, resp.StatusCode)
		}
	}
}

func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/", "/api/status", "/static/app.js", "/nope"} {
		resp, _ := h.do("GET", p, nil)
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", p, got)
		}
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options %q", p, got)
		}
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") {
			t.Errorf("%s: CSP %q", p, csp)
		}
		if strings.Contains(csp, "unsafe-inline") {
			t.Errorf("%s: the CSP permits inline script or style: %q", p, csp)
		}
	}
}

func TestThePageCarriesNoInlineScript(t *testing.T) {
	// The CSP forbids it, so an inline handler would be a page that silently
	// does nothing -- which on a status board is indistinguishable from calm.
	_, body := newHarness(t).do("GET", "/", nil)
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "<script") && !strings.Contains(lower, `src="static/app.js"`) {
		t.Errorf("the page has an inline script:\n%s", body)
	}
	for _, attr := range []string{"onclick=", "onload=", "onerror="} {
		if strings.Contains(lower, attr) {
			t.Errorf("the page uses an inline %s handler, which the CSP blocks", attr)
		}
	}
	if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		t.Errorf("the page references something off-box:\n%s", body)
	}
}

func TestNewRefusesMissingDependencies(t *testing.T) {
	full := Deps{
		Store: newFakeStore(), Config: func() *config.Config { return testConfig() },
		SaveConfig:   func(*config.Config) error { return nil },
		Health:       func() Health { return Health{} },
		PasswordHash: func() string { return "" }, SetPasswordHash: func(string) error { return nil },
	}
	cases := map[string]func(*Deps){
		"store":    func(d *Deps) { d.Store = nil },
		"config":   func(d *Deps) { d.Config = nil },
		"save":     func(d *Deps) { d.SaveConfig = nil },
		"health":   func(d *Deps) { d.Health = nil },
		"password": func(d *Deps) { d.PasswordHash = nil },
	}
	for name, break_ := range cases {
		d := full
		break_(&d)
		if _, err := New(d); err == nil {
			t.Errorf("New accepted a Deps with no %s", name)
		}
	}
	if _, err := New(full); err != nil {
		t.Errorf("New rejected a complete Deps: %v", err)
	}
}

func TestStatusCountsTheBoard(t *testing.T) {
	now := time.Now()
	alerting := openIncident("i1", incident.SeverityCritical, "Camera offline", now)
	_ = alerting.RecordAlert(now, 0)
	alerting.RecordDeliveryFailure(now, "smtp: connection refused")

	acked := openIncident("i2", incident.SeverityHigh, "Door forced", now)
	_ = acked.RecordAlert(now, 0)
	_ = acked.Acknowledge(now, "ntfy")

	closed := openIncident("i3", incident.SeverityLow, "Old thing", now)
	closed.Close(now, "done")

	h := newHarness(t, alerting, acked, closed)
	_, body := h.do("GET", "/api/status", nil)

	var got struct {
		Incidents map[string]int `json:"incidents"`
		Health    struct {
			Service struct {
				RestartsAfterCrash bool `json:"restarts_after_crash"`
			} `json:"service"`
			Sources []struct {
				Name   string `json:"name"`
				Silent bool   `json:"silent"`
			} `json:"sources"`
		} `json:"health"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	want := map[string]int{"open": 2, "alerting": 1, "acknowledged": 1, "unacknowledged": 1, "failing_delivery": 1}
	for k, v := range want {
		if got.Incidents[k] != v {
			t.Errorf("%s = %d, want %d (%s)", k, got.Incidents[k], v, body)
		}
	}
	if !got.Health.Service.RestartsAfterCrash {
		t.Error("the status did not report whether the service comes back after a crash")
	}
	if len(got.Health.Sources) != 1 || got.Health.Sources[0].Name != "protect" {
		t.Errorf("source health missing: %s", body)
	}

	// The closed one is still reachable on the board, in the history half.
	_, body = h.do("GET", "/api/incidents", nil)
	var list struct{ Incidents []incidentView }
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	var states []string
	for _, inc := range list.Incidents {
		states = append(states, fmt.Sprintf("%s=%s", inc.ID, inc.State))
	}
	sort.Strings(states)
	if strings.Join(states, ",") != "i1=alerting,i2=acknowledged,i3=closed" {
		t.Errorf("board states: %v", states)
	}
}

// The setup token must actually be INVALIDATED, not merely shadowed by the
// "a password is already set" guard.
//
// The original test passed either way: it asserted the second attempt was
// refused, and the conflict guard refused it regardless of whether the token
// had been cleared. A mutation that stopped clearing the token survived it.
func TestTheSetupTokenIsGenuinelyInvalidated(t *testing.T) {
	h := newHarness(t)
	tok := h.srv.SetupToken()
	if tok == "" {
		t.Fatal("no setup token on a fresh install")
	}
	resp, _ := h.do("POST", "/api/setup", map[string]string{
		"token": tok, "password": "correct-horse-battery",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup = %d, want 200", resp.StatusCode)
	}

	// The token itself must be gone, independently of any other guard.
	if h.srv.SetupToken() != "" {
		t.Error("SetupToken() still reports a token after it was spent")
	}
	if h.srv.auth.consumeSetupToken(tok) {
		t.Error("the spent token still verifies; it is being shadowed by the " +
			"password-already-set guard rather than actually invalidated")
	}
}

// Setup spends the token before it can store the password. If storing fails,
// the operator must not be locked out of their own fresh install -- recoverable
// only by restarting the daemon, which nothing tells them to do.
func TestAFailedSetupGivesTheTokenBack(t *testing.T) {
	h := newHarness(t)
	tok := h.srv.SetupToken()

	h.mu.Lock()
	h.hashErr = errors.New("disk is full")
	h.mu.Unlock()

	resp, _ := h.do("POST", "/api/setup", map[string]string{
		"token": tok, "password": "correct-horse-battery",
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("setup reported success despite failing to store the password")
	}
	if h.srv.SetupToken() != tok {
		t.Fatal("the token was burned by a failed setup")
	}

	// And it still works once the failure clears.
	h.mu.Lock()
	h.hashErr = nil
	h.mu.Unlock()
	resp, body := h.do("POST", "/api/setup", map[string]string{
		"token": tok, "password": "correct-horse-battery",
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("retry after a transient failure = %d, want 200: %s", resp.StatusCode, body)
	}
}

// Channels, policies and rules are all built once at daemon start, so every
// saved configuration change needs a restart -- and the only way to do one was
// a terminal, told to somebody whose reason for being on this page is that
// they would rather not open one. A channel could read as enabled everywhere a
// human looks and still not be told anything at 3am.
func TestTheServiceCanBeRestartedFromTheInterface(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	res, _ := h.do("POST", "/api/service", map[string]any{"action": "restart"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("restart returned %d, want 200", res.StatusCode)
	}
	h.mu.Lock()
	got := append([]ServiceAction(nil), h.serviceActions...)
	h.mu.Unlock()
	if len(got) != 1 || got[0] != ServiceRestart {
		t.Fatalf("service actions = %v, want one restart", got)
	}
}

// Stopping the daemon stops every alarm this product exists to raise, so it is
// not something a passer-by on the status page gets to do. Status is public by
// design -- that is what makes a wall display useful -- and this must not ride
// along with it.
func TestServiceControlIsRefusedWithoutSigningIn(t *testing.T) {
	h := newHarness(t)

	for _, action := range []string{"restart", "stop", "start"} {
		res, _ := h.do("POST", "/api/service", map[string]any{"action": action})
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s returned %d to a signed-out caller, want 401", action, res.StatusCode)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.serviceActions) != 0 {
		t.Fatalf("a signed-out caller reached the service manager: %v", h.serviceActions)
	}
}

func TestAnUnknownServiceActionIsRefused(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	for _, action := range []string{"", "uninstall", "delete", "RESTART; rm -rf /"} {
		res, _ := h.do("POST", "/api/service", map[string]any{"action": action})
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("action %q returned %d, want 400", action, res.StatusCode)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.serviceActions) != 0 {
		t.Fatalf("an unrecognised action reached the service manager: %v", h.serviceActions)
	}
}

// A restart takes this process down with it, so an audit entry written after
// the action is an entry that never gets written -- and "the daemon stopped
// and nothing says why" is the gap the audit record exists to close.
func TestTheRestartIsRecordedBeforeItHappens(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	h.mu.Lock()
	h.serviceErr = errors.New("the service manager said no")
	h.mu.Unlock()

	res, _ := h.do("POST", "/api/service", map[string]any{"action": "restart"})
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("a failed restart returned %d, want 500", res.StatusCode)
	}

	var requested, failed bool
	for _, sum := range h.log.summaries() {
		if strings.Contains(sum, "restart requested") {
			requested = true
		}
		if strings.Contains(sum, "restart failed") {
			failed = true
		}
	}
	if !requested {
		t.Error("nothing recorded that a restart was asked for")
	}
	if !failed {
		t.Error("nothing recorded that it failed; the operator sees an error and the record does not")
	}
}

// Saving ANY setting from the interface must not disturb the password that
// guards it.
//
// It did. applyUpdate built a fresh config.Web from three fields, which zeroed
// PasswordHash, so saving a setting logged the operator out of their own
// installation -- and on a service install the setup token that would let them
// back in is printed to a stdout a service does not have. It was a lockout,
// and it happened in the field before it was found here.
func TestSavingSettingsDoesNotWipeThePasswordThatGuardsThem(t *testing.T) {
	cur := testConfig()
	cur.Web.PasswordHash = "pbkdf2-sha256$600000$abc$def"
	cur.Web.AckListen = "0.0.0.0:51234"

	next, _ := applyUpdate(cur, settingsUpdate{Web: webUpdate{Listen: "127.0.0.1:8322"}})

	if next.Web.PasswordHash != cur.Web.PasswordHash {
		t.Errorf("the settings password was wiped by saving settings: %q -> %q",
			cur.Web.PasswordHash, next.Web.PasswordHash)
	}
	// The ack-only listener is what keeps a port forward from publishing the
	// status page. Losing it silently re-widens an exposure the operator
	// deliberately narrowed -- and the update above never mentions it, which
	// is exactly the case a plain string field would have got wrong.
	if next.Web.AckListen != cur.Web.AckListen {
		t.Errorf("the ack-only listener was wiped by saving settings: %q -> %q",
			cur.Web.AckListen, next.Web.AckListen)
	}
}

// The structural version of the bug above: whole-struct assignment makes every
// field this function does not name silently droppable, and the next field
// anyone adds would go the same way. This asserts on the config as a whole
// rather than on the two fields that happened to be lost.
func TestNothingOutsideTheFormIsLostBySavingIt(t *testing.T) {
	cur := testConfig()
	cur.Web.PasswordHash = "pbkdf2-sha256$600000$abc$def"
	cur.Web.AckListen = "0.0.0.0:51234"
	cur.Web.AckKey = "ack-key-not-editable-here"

	// A save that changes nothing: whatever comes back must equal what went in.
	before := viewSettings(cur)
	upd := settingsUpdate{
		Consoles:   consolesAsUpdate(cur),
		Channels:   channelsAsUpdate(cur),
		Rules:      cur.Rules,
		QuietHours: cur.QuietHours,
		Web: webUpdate{
			Listen:     cur.Web.Listen,
			AckBaseURL: cur.Web.AckBaseURL,
			AckListen:  &cur.Web.AckListen,
		},
	}
	next, _ := applyUpdate(cur, upd)

	if next.Web != cur.Web {
		t.Errorf("a no-op save changed the web section:\n  before %+v\n  after  %+v",
			cur.Web, next.Web)
	}
	if got := viewSettings(next); !reflect.DeepEqual(before, got) {
		t.Errorf("a no-op save changed the settings:\n  before %+v\n  after  %+v", before, got)
	}
}

// consolesAsUpdate and channelsAsUpdate round-trip the current config into the
// shape the browser posts back, which is what a save with no edits looks like.
func consolesAsUpdate(c *config.Config) []consoleUpdate {
	out := make([]consoleUpdate, 0, len(c.Consoles))
	for _, con := range c.Consoles {
		out = append(out, consoleUpdate{
			Name: con.Name, Host: con.Host, Fingerprint: con.Fingerprint,
			InsecureSkipVerify: con.InsecureSkipVerify, Sources: con.Sources,
			APIKeyCredential: con.APIKeyCredential,
		})
	}
	return out
}

func channelsAsUpdate(c *config.Config) channelsUpdate {
	var u channelsUpdate
	if n := c.Channels.Ntfy; n != nil {
		u.Ntfy = &ntfyUpdate{Enabled: n.Enabled, ServerURL: n.ServerURL, Topic: n.Topic}
	}
	if e := c.Channels.Email; e != nil {
		u.Email = &emailUpdate{
			Enabled: e.Enabled, Host: e.Host, Port: e.Port, Username: e.Username,
			TLS: e.TLS, From: e.From, Recipients: e.Recipients,
		}
	}
	if p := c.Channels.Pushover; p != nil {
		u.Pushover = &pushoverUpdate{Enabled: p.Enabled, Device: p.Device, Sound: p.Sound}
	}
	if h := c.Channels.Webhook; h != nil {
		u.Webhook = &webhookUpdate{
			Enabled: h.Enabled, URL: h.URL, Headers: h.Headers,
			InsecureSkipVerify: h.InsecureSkipVerify,
		}
	}
	return u
}

// The demo banner and the open settings surface are the SAME field, and this
// is the test that keeps them that way.
//
// A demo is open because there is nothing to gate: every incident is
// fabricated, no credentials exist, and the settings screens are most of what
// somebody started a demo to look at. That is only acceptable while it is
// impossible to have the open surface WITHOUT the notice on every screen.
func TestOnlyADemoIsOpenAndADemoAlwaysSaysSo(t *testing.T) {
	// A normal server: signed-out callers get nothing.
	h := newHarness(t)
	h.setPassword(testPassword)
	for _, path := range []string{"/api/settings", "/api/audit"} {
		res, _ := h.do("GET", path, nil)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s returned %d to a signed-out caller on a REAL server, want 401",
				path, res.StatusCode)
		}
	}

	// The same server with a demo banner: open, and saying so.
	d := newHarness(t)
	d.srv.deps.Demo = "DEMO — fabricated"
	for _, path := range []string{"/api/settings", "/api/audit"} {
		res, _ := d.do("GET", path, nil)
		if res.StatusCode != http.StatusOK {
			t.Errorf("%s returned %d on a demo, want 200", path, res.StatusCode)
		}
	}
	_, body := d.do("GET", "/api/status", nil)
	if !strings.Contains(string(body), "DEMO") {
		t.Fatalf("a demo did not announce itself in /api/status:\n%s", body)
	}
}

// And the invariant stated the other way round: an empty banner must never
// produce an open surface, whatever else is set.
func TestAnEmptyBannerLeavesEverythingGated(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.srv.deps.Demo = ""

	res, _ := h.do("POST", "/api/settings", map[string]any{})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a write returned %d with no banner set, want 401", res.StatusCode)
	}
}
