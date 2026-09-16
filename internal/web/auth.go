package web

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
)

// Password storage. Carried over whole from prior in-house work, because the
// design is sound and the reasons are worth keeping:
//
//   - PBKDF2-HMAC-SHA256 from the standard library. No new dependency, and
//     nothing here is worth adding one for: the threat is an operator who
//     reused a password, not a nation state with the config file.
//   - A per-password salt, so two installations with the same password do not
//     share a hash.
//   - The stored form is SELF-DESCRIBING -- it carries the iteration count it
//     was made with. That is what lets the count rise on a later build without
//     invalidating every existing password: old hashes keep verifying at their
//     own cost, and the next password change writes the new one.
const (
	// Iterations is what new hashes are written with. OWASP's floor for
	// PBKDF2-HMAC-SHA256 at the time of writing.
	Iterations = 600_000

	// MinPasswordLength is enforced and is stated in the UI. Twelve rather
	// than eight: this password is the only thing between a LAN device and the
	// console API key, and it is typed rarely enough that length costs little.
	MinPasswordLength = 12

	saltLen = 16
	keyLen  = 32

	hashScheme = "pbkdf2-sha256"

	sessionCookie = "notifymatrix_session"

	// sessionTTL is refreshed on use. Sessions live in memory and die with the
	// process; a restart signing everyone out is correct for a daemon whose
	// restarts are themselves an event worth noticing.
	sessionTTL = 8 * time.Hour
)

// ErrWeakPassword is returned for a password under the minimum length.
var ErrWeakPassword = fmt.Errorf("the password must be at least %d characters", MinPasswordLength)

// HashPassword produces a stored hash for a new password.
func HashPassword(password string) (string, error) { return hashWith(password, Iterations) }

func hashWith(password string, iter int) (string, error) {
	if len([]rune(password)) < MinPasswordLength {
		return "", ErrWeakPassword
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, keyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", hashScheme, iter,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a stored hash, in constant time
// with respect to the key material.
//
// Returns false for a malformed or unrecognised stored hash rather than an
// error: every caller has the same response to both, and a hash this build
// cannot read must not be treated as a match.
func VerifyPassword(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// newToken mints a 256-bit random token, URL-safe.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

type authState struct {
	mu sync.Mutex

	// sessions is keyed by the SHA-256 of the cookie value, so the raw token
	// is not sitting in process memory in a form that a heap dump hands
	// straight back.
	sessions map[[32]byte]time.Time

	// setupToken authorises setting the FIRST password, once.
	setupToken string

	fails   map[string]*failRecord
	nowFunc func() time.Time
}

type failRecord struct {
	count   int
	until   time.Time
	touched time.Time
}

func newAuthState(now func() time.Time) *authState {
	return &authState{
		sessions: map[[32]byte]time.Time{},
		fails:    map[string]*failRecord{},
		nowFunc:  now,
	}
}

func (a *authState) token() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.setupToken
}

// consumeSetupToken checks the token and, on a match, destroys it. ONE USE:
// a token that still works after the password is set is a second front door.
func (a *authState) consumeSetupToken(given string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.setupToken == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(a.setupToken), []byte(given)) != 1 {
		return false
	}
	a.setupToken = ""
	return true
}

// restoreSetupToken hands a consumed token back.
//
// Setup spends the token BEFORE it can persist the password hash, because the
// token is what authorises the attempt. If storing the hash then fails, the
// token is gone and no password is set -- and the operator is locked out of
// their own fresh install, recoverable only by restarting the daemon to mint a
// new one, which nothing tells them to do.
//
// Only restored when no password was set, so this can never revive a token
// after a setup that actually succeeded.
func (a *authState) restoreSetupToken(tok string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.setupToken == "" && tok != "" {
		a.setupToken = tok
	}
}

func (a *authState) newSession() (string, error) {
	tok, err := newToken()
	if err != nil {
		return "", err
	}
	now := a.nowFunc()
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, k)
		}
	}
	a.sessions[sha256.Sum256([]byte(tok))] = now.Add(sessionTTL)
	return tok, nil
}

// valid reports whether the cookie names a live session, and extends it.
func (a *authState) valid(tok string) bool {
	if tok == "" {
		return false
	}
	now := a.nowFunc()
	k := sha256.Sum256([]byte(tok))
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[k]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(a.sessions, k)
		return false
	}
	a.sessions[k] = now.Add(sessionTTL)
	return true
}

func (a *authState) drop(tok string) {
	if tok == "" {
		return
	}
	k := sha256.Sum256([]byte(tok))
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, k)
}

// dropAll signs every session out. Used when the password changes: a password
// is changed because it may be known, and leaving old sessions alive would
// make the change cosmetic.
func (a *authState) dropAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions = map[[32]byte]time.Time{}
}

// ---------------------------------------------------------------------------
// Failed sign-in throttling
// ---------------------------------------------------------------------------

const (
	freeAttempts    = 5
	baseLockout     = time.Minute
	maxLockout      = 15 * time.Minute
	maxTrackedPeers = 4096
	failForget      = time.Hour
)

// allow reports whether this client may attempt a sign-in, and how long it must
// wait if not.
//
// Keyed on the peer address ONLY. X-Forwarded-For is deliberately ignored: this
// listens on the LAN, nothing in front of it is trusted to set that header, and
// honouring it would let one device rotate the key on every attempt and grind
// the password at full speed.
func (a *authState) allow(peer string) (bool, time.Duration) {
	now := a.nowFunc()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweepLocked(now)

	rec := a.fails[peer]
	if rec == nil {
		if len(a.fails) >= maxTrackedPeers {
			// The table is full of recent failures, which is itself an attack
			// or a very broken client. Refuse rather than grow: a bounded
			// table that occasionally locks out a bystander is better than an
			// unbounded one that a LAN device can use as a memory bomb.
			return false, baseLockout
		}
		return true, 0
	}
	if now.Before(rec.until) {
		return false, rec.until.Sub(now)
	}
	return true, 0
}

func (a *authState) recordFailure(peer string) {
	now := a.nowFunc()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweepLocked(now)

	rec := a.fails[peer]
	if rec == nil {
		if len(a.fails) >= maxTrackedPeers {
			return
		}
		rec = &failRecord{}
		a.fails[peer] = rec
	}
	rec.count++
	rec.touched = now
	if rec.count >= freeAttempts {
		// Doubling from one minute, capped. The cap matters: an unbounded
		// lockout is a denial of service an attacker can aim at the operator,
		// on the one interface they need during an incident.
		over := rec.count - freeAttempts
		d := baseLockout << min(over, 8)
		if d > maxLockout || d <= 0 {
			d = maxLockout
		}
		rec.until = now.Add(d)
	}
}

func (a *authState) recordSuccess(peer string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, peer)
}

func (a *authState) sweepLocked(now time.Time) {
	for k, rec := range a.fails {
		if now.Sub(rec.touched) > failForget && now.After(rec.until) {
			delete(a.fails, k)
		}
	}
}

// peerOf identifies the client for throttling. Host only, so a client cannot
// escape its bucket by using a new source port.
func peerOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------------------------------------------------------------------------
// Middleware and handlers
// ---------------------------------------------------------------------------

func (s *Server) authenticated(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	return s.auth.valid(c.Value)
}

// requireAuth gates every write, and every read that carries configuration
// detail.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			writeJSON(w, http.StatusUnauthorized, errorBody("sign in to do that"))
			return
		}
		// SameSite=Lax already stops a cross-site form POST carrying the
		// cookie. This closes the rest: a request that announces an origin
		// must announce ours.
		if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r) {
			writeJSON(w, http.StatusForbidden, errorBody("cross-origin request refused"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(origin string, r *http.Request) bool {
	trimmed := origin
	if i := strings.Index(trimmed, "://"); i >= 0 {
		trimmed = trimmed[i+3:]
	}
	return strings.EqualFold(trimmed, r.Host)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure only over TLS: setting it unconditionally would make the
		// cookie unusable on the plain-HTTP LAN listener this normally runs
		// on, and an operator who cannot sign in has no interface at all.
		Secure:  r.TLS != nil,
		MaxAge:  int(sessionTTL / time.Second),
		Expires: s.now().Add(sessionTTL),
	})
}

type credentials struct {
	Password string `json:"password"`
	Current  string `json:"current"`
	Token    string `json:"token"`
}

func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	peer := peerOf(r)
	if ok, wait := s.auth.allow(peer); !ok {
		s.record(r, audit.Entry{
			Kind: audit.KindAuth, Actor: "web",
			Summary: "sign-in refused: too many failed attempts",
			Fields:  map[string]string{"client": peer},
		})
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests,
			errorBody(fmt.Sprintf("too many failed attempts; try again in %s", roundWait(wait))))
		return
	}

	var creds credentials
	if err := readJSON(r, &creds); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("that request could not be read"))
		return
	}

	stored := s.deps.PasswordHash()
	if stored == "" {
		// THERE IS NO "no password means everyone is in" PATH. A fresh install
		// is unusable until the setup token is spent.
		writeJSON(w, http.StatusConflict,
			errorBody("no password is set yet; use the setup token the daemon printed at start, "+
				"or run `notifymatrix set-password` on the machine it runs on -- "+
				"which is the only way when it runs as a service, because a service has no console to print to"))
		return
	}

	if !VerifyPassword(stored, creds.Password) {
		s.auth.recordFailure(peer)
		s.record(r, audit.Entry{
			Kind: audit.KindAuth, Actor: "web",
			Summary: "failed sign-in",
			Fields:  map[string]string{"client": peer},
		})
		writeJSON(w, http.StatusUnauthorized, errorBody("that password is not right"))
		return
	}

	s.auth.recordSuccess(peer)
	tok, err := s.auth.newSession()
	if err != nil {
		s.fail(w, r, "minting a session", err)
		return
	}
	s.setSessionCookie(w, r, tok)
	s.record(r, audit.Entry{
		Kind: audit.KindAuth, Actor: "web",
		Summary: "signed in",
		Fields:  map[string]string{"client": peer},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.auth.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSetup spends the one-time token to set the first password.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	peer := peerOf(r)
	if ok, wait := s.auth.allow(peer); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests,
			errorBody(fmt.Sprintf("too many failed attempts; try again in %s", roundWait(wait))))
		return
	}
	var creds credentials
	if err := readJSON(r, &creds); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("that request could not be read"))
		return
	}
	if s.deps.PasswordHash() != "" {
		writeJSON(w, http.StatusConflict, errorBody("a password is already set; sign in instead"))
		return
	}
	// Length is checked BEFORE the token is spent, so a typo in the new
	// password does not burn the only token and lock the operator out of their
	// own fresh install.
	if len([]rune(creds.Password)) < MinPasswordLength {
		writeJSON(w, http.StatusBadRequest, errorBody(ErrWeakPassword.Error()))
		return
	}
	if !s.auth.consumeSetupToken(creds.Token) {
		s.auth.recordFailure(peer)
		s.record(r, audit.Entry{
			Kind: audit.KindAuth, Actor: "web",
			Summary: "setup refused: wrong or spent token",
			Fields:  map[string]string{"client": peer},
		})
		writeJSON(w, http.StatusUnauthorized, errorBody("that setup token is not valid"))
		return
	}

	hash, err := HashPassword(creds.Password)
	if err != nil {
		// The token was spent to get here and the install still has no
		// password, so give it back rather than leaving a fresh install that
		// can only be rescued by restarting the daemon.
		s.auth.restoreSetupToken(creds.Token)
		s.fail(w, r, "hashing the new password", err)
		return
	}
	if err := s.deps.SetPasswordHash(hash); err != nil {
		s.auth.restoreSetupToken(creds.Token)
		s.fail(w, r, "storing the new password", err)
		return
	}
	s.auth.recordSuccess(peer)
	tok, err := s.auth.newSession()
	if err != nil {
		s.fail(w, r, "minting a session", err)
		return
	}
	s.setSessionCookie(w, r, tok)
	s.record(r, audit.Entry{
		Kind: audit.KindAuth, Actor: "web",
		Summary: "first password set with the setup token",
		Fields:  map[string]string{"client": peer},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	peer := peerOf(r)
	var creds credentials
	if err := readJSON(r, &creds); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("that request could not be read"))
		return
	}
	stored := s.deps.PasswordHash()
	if stored == "" || !VerifyPassword(stored, creds.Current) {
		s.auth.recordFailure(peer)
		s.record(r, audit.Entry{
			Kind: audit.KindAuth, Actor: "web",
			Summary: "failed password change: current password wrong",
			Fields:  map[string]string{"client": peer},
		})
		writeJSON(w, http.StatusUnauthorized, errorBody("the current password is not right"))
		return
	}
	hash, err := HashPassword(creds.Password)
	if errors.Is(err, ErrWeakPassword) {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	if err != nil {
		s.fail(w, r, "hashing the new password", err)
		return
	}
	if err := s.deps.SetPasswordHash(hash); err != nil {
		s.fail(w, r, "storing the new password", err)
		return
	}
	// Every session dies, including this one, and a fresh one is issued here.
	s.auth.dropAll()
	tok, err := s.auth.newSession()
	if err != nil {
		s.fail(w, r, "minting a session", err)
		return
	}
	s.setSessionCookie(w, r, tok)
	s.record(r, audit.Entry{
		Kind: audit.KindAuth, Actor: "web",
		Summary: "password changed; all other sessions signed out",
		Fields:  map[string]string{"client": peer},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func roundWait(d time.Duration) time.Duration {
	if d < time.Second {
		return time.Second
	}
	return d.Round(time.Second)
}
