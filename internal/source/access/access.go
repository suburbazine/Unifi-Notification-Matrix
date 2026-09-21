package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/unifi"
)

// SourceName is the identifier that appears in dedup keys and diagnostics.
const SourceName = "access"

// Mode selects how this console's Access application is reached.
type Mode string

const (
	// ModeProxy goes through UniFi OS on 443. The ordinary case.
	ModeProxy Mode = "proxy"

	// ModeDirect talks to the Access application's own port.
	ModeDirect Mode = "direct"
)

// DefaultDirectPort is Access's own listener.
const DefaultDirectPort = 12445

// Path segments.
//
// THE REST BASE SAYS `integration` AND THE SOCKET SAYS `api`. That asymmetry
// is real on both sides and is not a typo in either. It has cost enough time
// elsewhere to be worth stating here rather than leaving to be rediscovered.
const (
	proxyRESTBase = "/proxy/access/integration/v1/developer"
	proxyWSPath   = "/proxy/access/api/v1/developer/devices/notifications"

	// THE SOCKET MOVED. On an ENVR running current Access the `api` path
	// above answers 404 to a key whose `integration` REST paths return
	// twenty-eight doors, and the same path under the REST base connects and
	// delivers. Captured by the probe on real hardware, which is the only
	// reason this is a fact rather than a guess.
	//
	// Both are kept: the two door-state message shapes this build knows were
	// captured on the older path, and a site on that firmware must not lose
	// its socket to a fix for another.
	proxyWSPathIntegration = "/proxy/access/integration/v1/developer/devices/notifications"
	directBase             = "/api/v1/developer"
	directWSPath           = "/api/v1/developer/devices/notifications"
)

var (
	// ErrNoHost and ErrNoAPIKey are configuration faults: Run returns them
	// rather than retrying, because no amount of reconnecting fixes them.
	ErrNoHost   = errors.New("access: no console host configured")
	ErrNoAPIKey = errors.New("access: no API key configured")
)

// Defaults.
const (
	// defaultHeldAfter is how long a door may stand open before it is an
	// incident. Sixty seconds is long enough for a delivery and short enough
	// that a wedged fire door is reported while it still matters. Access has no
	// equivalent setting at all, so there is nothing on the console to match.
	defaultHeldAfter = 60 * time.Second

	// defaultUnlockGrace is how recently the lock must have been unlocked for
	// an opening to count as authorised.
	//
	// The trade is explicit and there is no setting that avoids it. Too short
	// and a lock that relocks slowly turns ordinary entries into critical
	// alarms. Too long and somebody who badges in and then props the door for
	// an accomplice is not reported. Forty-five seconds covers observed relock
	// behaviour with margin; a site whose locks are slower should raise it, and
	// will know to because the false alarms name the window.
	defaultUnlockGrace = 45 * time.Second

	// defaultPositionEvery is how often door position is read.
	//
	// Fast relative to the log, because this is the ONLY timely surface for
	// door state -- the log lags minutes and carries position as informational
	// rows. One request per interval against a 10/s budget is affordable.
	defaultPositionEvery = 10 * time.Second

	defaultHandshakeTimeout = 20 * time.Second
	defaultPingInterval     = 60 * time.Second
	defaultPongWait         = 150 * time.Second
	defaultMinBackoff       = 1 * time.Second
	defaultMaxBackoff       = 2 * time.Minute
	defaultStableAfter      = 60 * time.Second
	defaultRequestTimeout   = 30 * time.Second

	// defaultMuteThreshold is how many frames may arrive with nothing
	// recognised before the socket is reported as a fault.
	//
	// Both known message shapes came from ONE hub model on ONE day. Different
	// hardware plausibly gives a socket that connects, streams, and updates
	// nothing -- which looks exactly like a healthy quiet site unless
	// something counts it.
	defaultMuteThreshold = 50

	defaultLiveness = 15 * time.Minute

	maxFrameBytes = 4 << 20
)

// Config is everything this source needs.
type Config struct {
	// Host is the UniFi OS console, with or without a scheme.
	Host string

	// APIKey is the Access API key. It travels in a header, never in a URL.
	APIKey secret.Secret

	// Mode selects the proxy path or Access's own port. Empty means proxy.
	//
	// It also selects the AUTH HEADER, and a wrong header is indistinguishable
	// from a wrong key in the console's reply -- so a 401 here reports both
	// possibilities rather than blaming the key.
	Mode Mode

	// DirectPort overrides 12445 in ModeDirect.
	DirectPort int

	// TLS is the console's certificate policy, per HOST rather than per
	// application: Protect, Access and Network are served the same certificate
	// by the same reverse proxy.
	TLS *unifi.TLS

	Dialer     *websocket.Dialer
	HTTPClient *http.Client

	// Pace is the shared per-console rate limiter. EVERY request goes through
	// it, the socket dial included. Left nil, the shared pacer for this host is
	// used -- which is the point: Access polling door position every ten
	// seconds and Protect sweeping on its own timer are one budget, not two.
	Pace func(context.Context) error

	HeldAfter      time.Duration
	UnlockGrace    time.Duration
	PositionEvery  time.Duration
	LogPollEvery   time.Duration
	LogOverlap     time.Duration
	RequestTimeout time.Duration

	PingInterval     time.Duration
	PongWait         time.Duration
	HandshakeTimeout time.Duration
	MinBackoff       time.Duration
	MaxBackoff       time.Duration
	StableAfter      time.Duration

	MuteThreshold  int
	LivenessWindow time.Duration

	Now  func() time.Time
	Rand func() float64
	Logf func(format string, args ...any)
}

func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeProxy
	}
	if c.DirectPort <= 0 {
		c.DirectPort = DefaultDirectPort
	}
	if c.HeldAfter <= 0 {
		c.HeldAfter = defaultHeldAfter
	}
	if c.UnlockGrace <= 0 {
		c.UnlockGrace = defaultUnlockGrace
	}
	if c.PositionEvery <= 0 {
		c.PositionEvery = defaultPositionEvery
	}
	if c.LogPollEvery <= 0 {
		c.LogPollEvery = defaultPollEvery
	}
	if c.LogOverlap <= 0 {
		c.LogOverlap = defaultOverlap
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = defaultRequestTimeout
	}
	if c.PingInterval <= 0 {
		c.PingInterval = defaultPingInterval
	}
	if c.PongWait <= c.PingInterval {
		c.PongWait = 2*c.PingInterval + 30*time.Second
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = defaultHandshakeTimeout
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = defaultMinBackoff
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = defaultMaxBackoff
	}
	if c.StableAfter <= 0 {
		c.StableAfter = defaultStableAfter
	}
	if c.MuteThreshold <= 0 {
		c.MuteThreshold = defaultMuteThreshold
	}
	if c.LivenessWindow <= 0 {
		c.LivenessWindow = defaultLiveness
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// Health is what this source currently believes about itself.
type Health struct {
	Connected     bool
	Connects      int64
	LastMessageAt time.Time
	LastEmitAt    time.Time

	// Recognised and Unrecognised count socket frames. A socket that is
	// connected with Unrecognised climbing and Recognised at zero is a
	// live-but-mute stream, which looks identical to a quiet site unless it is
	// counted.
	Recognised   int64
	Unrecognised int64

	// UnknownEvents counts socket event names by NAME, so a firmware that
	// invents a third message shape is actionable rather than a number.
	UnknownEvents map[string]int64

	// UnknownLogKeys counts log keys no rule matched. The log key vocabulary
	// has never been enumerated from hardware, so this is how it gets found.
	UnknownLogKeys map[string]int64

	// Noise counts frames that are neither door state nor a failure to read
	// one: keepalives and informational events. Separated from Unrecognised
	// because that counter is the evidence for an alarm, and a keepalive is
	// not evidence of anything.
	Noise int64

	// LastSocketErr is why the notifications socket last failed, kept so the
	// interface can say what is wrong rather than only that nothing arrived.
	// On a console with no Access installed the handshake fails against the
	// UniFi OS web page, and that sentence is the whole diagnosis.
	LastSocketErr string

	StreamMuteReported bool

	DoorsKnown int

	// DoorsWithPosition is how many doors actually have a position sensor.
	//
	// REPORTED BECAUSE IT IS USUALLY SMALL. A measurement across 28 doors found
	// 26 with no sensor at all, and on those doors forced-entry and held-open
	// cannot be derived by anything. An operator who believes this product
	// watches every door, when it can only watch two of them, has been misled
	// by the product rather than by the console.
	DoorsWithPosition int

	LastPositionAt  time.Time
	LastPositionErr string

	LogRowsSeen int64
	LastLogAt   time.Time
	LastLogErr  string
}

// Source is the Access ingest path. It satisfies event.Source.
type Source struct {
	cfg  Config
	base *url.URL

	restBase string
	wsPath   string

	// wsAlso are the other paths this firmware might serve the socket on,
	// tried in order when the first answers 404.
	wsAlso []string

	doors *doors
	poll  *poller

	backoff unifi.Backoff
	pacer   *unifi.Pacer
	hc      *http.Client

	dialOnce sync.Once
	dialer   *websocket.Dialer

	mu     sync.Mutex
	health Health

	fatalMu  sync.Mutex
	fatalErr error
}

// New validates the configuration and builds the source.
func New(cfg Config) (*Source, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, ErrNoHost
	}
	if cfg.APIKey.IsZero() {
		return nil, ErrNoAPIKey
	}
	cfg.applyDefaults()

	base, err := parseHost(cfg.Host)
	if err != nil {
		return nil, err
	}

	s := &Source{
		cfg:   cfg,
		base:  base,
		doors: newDoors(cfg.HeldAfter, cfg.UnlockGrace),
		health: Health{
			UnknownEvents:  map[string]int64{},
			UnknownLogKeys: map[string]int64{},
		},
	}
	switch cfg.Mode {
	case ModeDirect:
		base.Host = hostWithPort(base.Host, cfg.DirectPort)
		s.restBase, s.wsPath = directBase, directWSPath
		s.wsAlso = nil
	default:
		// Current firmware first: a 404 costs a reconnect delay, and the
		// common case should not pay it.
		s.restBase, s.wsPath = proxyRESTBase, proxyWSPathIntegration
		s.wsAlso = []string{proxyWSPath}
	}

	s.backoff = unifi.Backoff{Base: cfg.MinBackoff, Max: cfg.MaxBackoff, Rand: cfg.Rand}

	if s.cfg.Pace == nil {
		// The shared path is the default path. A second pacer for one console
		// doubles the request rate against a single server-side budget and
		// looks correct in review.
		s.pacer = unifi.PacerFor(base.Host)
		s.cfg.Pace = s.pacer.Wait
	}

	s.hc = cfg.HTTPClient
	if s.hc == nil {
		if cfg.TLS != nil {
			c, err := cfg.TLS.HTTPClient(cfg.RequestTimeout)
			if err != nil {
				return nil, err
			}
			s.hc = c
		} else {
			s.hc = &http.Client{Timeout: cfg.RequestTimeout}
		}
	}
	s.poll = newPoller(s.fetchLogPage, cfg.LogPollEvery, cfg.LogOverlap, cfg.Now)
	return s, nil
}

func parseHost(host string) (*url.URL, error) {
	h := strings.TrimSpace(host)
	if !strings.Contains(h, "://") {
		h = "https://" + h
	}
	u, err := url.Parse(h)
	if err != nil {
		return nil, fmt.Errorf("access: unusable host: %w", err)
	}
	if u.Host == "" {
		return nil, ErrNoHost
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func hostWithPort(host string, port int) string {
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	return host + ":" + strconv.Itoa(port)
}

func (s *Source) Name() string { return SourceName }

// Liveness is the deadman window.
//
// Meaningful here in a way it is not for every source: the notifications
// socket pushes full state syncs on a timer even when nothing is happening, so
// prolonged silence really does mean a dead peer rather than a quiet site. The
// log poller runs on its own schedule regardless, so the window is not
// resting on the socket alone.
func (s *Source) Liveness() time.Duration { return s.cfg.LivenessWindow }

// LastContact is the last frame from the notifications socket, or the last
// successful door or log poll. See event.Contactable: a door that nobody opens
// all night is not a broken source.
func (s *Source) LastContact() time.Time {
	s.mu.Lock()
	last := s.health.LastMessageAt
	s.mu.Unlock()
	if _, lastRun, lastErr, _ := s.poll.stats(); lastErr == "" && lastRun.After(last) {
		last = lastRun
	}
	return last
}

// wsCandidates is every path the notifications socket might live on, in the
// order they are tried.
func (s *Source) wsCandidates() []string {
	return append([]string{s.wsPath}, s.wsAlso...)
}

// LastError is the most recent reason a read failed, or "" when the last one
// worked. See event.Diagnosable.
//
// Access already declined to count a failed poll as contact, which is why its
// row went quiet rather than green on a console with no Access installed. It
// still could not say what was wrong, so "silent" was as much as the board
// could offer for "this application is not on this machine".
func (s *Source) LastError() string {
	s.mu.Lock()
	last := s.health.LastSocketErr
	s.mu.Unlock()
	if _, _, lastErr, _ := s.poll.stats(); lastErr != "" {
		return lastErr
	}
	return last
}

// Health reports what this source believes about itself.
func (s *Source) Health() Health {
	s.mu.Lock()
	h := s.health
	h.UnknownEvents = copyCounts(s.health.UnknownEvents)
	s.mu.Unlock()

	rows, lastRun, lastErr, unknown := s.poll.stats()
	h.LogRowsSeen, h.LastLogAt, h.LastLogErr, h.UnknownLogKeys = rows, lastRun, lastErr, unknown

	h.DoorsKnown = s.doors.count()
	for _, d := range s.doors.snapshot() {
		if d.position.derivable() {
			h.DoorsWithPosition++
		}
	}
	return h
}

func copyCounts(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Run ingests until ctx is done.
//
// Returns nil on cancellation and non-nil only for something reconnecting
// cannot fix. A REJECTED CREDENTIAL IS NOT ONE OF THOSE: after a console
// restart the reverse proxy answers 4xx for a while as applications
// re-initialise, so treating 401 as terminal permanently abandons ingest for a
// key that was correct all along.
func (s *Source) Run(ctx context.Context, out event.Sink) error {
	if s.base == nil {
		return ErrNoHost
	}
	if s.cfg.APIKey.IsZero() {
		return ErrNoAPIKey
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	fail := func(err error) {
		s.fatalMu.Lock()
		if s.fatalErr == nil {
			s.fatalErr = err
		}
		s.fatalMu.Unlock()
		cancel()
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); s.runSocket(runCtx, out, fail) }()
	go func() { defer wg.Done(); s.runPositions(runCtx, out) }()
	go func() { defer wg.Done(); s.runLogs(runCtx, out) }()
	wg.Wait()

	s.fatalMu.Lock()
	defer s.fatalMu.Unlock()
	return s.fatalErr
}

// ---------------------------------------------------------------- REST

func (s *Source) restURL(path string) string {
	return s.base.Scheme + "://" + s.base.Host + s.restBase + path
}

// authorise sets the credential header for the configured mode.
//
// Assigned into the map rather than through Header.Set, which canonicalises
// X-API-KEY to X-Api-Key. No console has been observed to care, but the
// field-proven clients send the upper-case form and matching them exactly
// costs nothing.
func (s *Source) authorise(h http.Header) {
	if s.cfg.Mode == ModeDirect {
		h["Authorization"] = []string{"Bearer " + s.cfg.APIKey.Reveal()}
		return
	}
	h["X-API-KEY"] = []string{s.cfg.APIKey.Reveal()}
}

// call performs one paced REST request and unwraps the envelope.
func (s *Source) call(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	if err := s.cfg.Pace(ctx); err != nil {
		return nil, err
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	reqCtx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, s.restURL(path), rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	s.authorise(req.Header)

	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxFrameBytes))
		_ = resp.Body.Close()
	}()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFrameBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("access: console refused the credential (HTTP %d) -- "+
			"either the key is wrong or this is the wrong mode for it: %s mode sends %s",
			resp.StatusCode, s.cfg.Mode, s.authHeaderName())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("access: HTTP %d on %s", resp.StatusCode, path)
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("access: unreadable response on %s: %w", path, err)
	}
	// Checked SEPARATELY from the HTTP status: Access answers 200 with
	// {"code":"CODE_SYSTEM_ERROR"}, and a client that trusts the status treats
	// a refusal as an empty result -- which for the log poller is the
	// difference between "no denials happened" and "we never asked".
	if ok, why := env.ok(); !ok {
		return nil, fmt.Errorf("access: console refused %s: %s", path, why)
	}
	return env.Data, nil
}

func (s *Source) authHeaderName() string {
	if s.cfg.Mode == ModeDirect {
		return "Authorization: Bearer"
	}
	return "X-API-KEY"
}

// listDoors reads every door.
func (s *Source) listDoors(ctx context.Context) ([]door, error) {
	data, err := s.call(ctx, http.MethodGet, "/doors", nil)
	if err != nil {
		return nil, err
	}
	t := strings.TrimSpace(string(data))
	if t == "" || t == "null" {
		// An empty list arrives as "data":null, which is not an error and is
		// not a site with no doors either -- it is a site with no doors
		// VISIBLE TO THIS KEY, which looks the same from here.
		return nil, nil
	}
	var out []door
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("access: unreadable door list: %w", err)
	}
	return out, nil
}

// fetchLogPage reads one page of one log topic.
func (s *Source) fetchLogPage(ctx context.Context, topic string, since, until time.Time, page int) ([]logHit, error) {
	// page_num and page_size MUST be query parameters. Placed in the body they
	// are silently ignored and the console returns the entire log -- a
	// nineteen-megabyte response has been observed.
	path := fmt.Sprintf("/system/logs?page_num=%d&page_size=%d", page, logPageSize)

	// since and until are UNIX SECONDS. Milliseconds are rejected outright,
	// which is the opposite of event.published inside the rows this returns.
	body := map[string]any{
		"topic": topic,
		"since": since.Unix(),
		"until": until.Unix(),
	}
	data, err := s.call(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	// `data` is an OBJECT with `.hits`, not a bare array. The usual "data is
	// the array" assumption decodes to nothing at all, silently.
	var wrapper struct {
		Hits []logHit `json:"hits"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("access: unreadable log page: %w", err)
	}
	return wrapper.Hits, nil
}

// ---------------------------------------------------------------- loops

// runPositions polls door position and drives the held-open clock.
func (s *Source) runPositions(ctx context.Context, out event.Sink) {
	t := time.NewTicker(s.cfg.PositionEvery)
	defer t.Stop()

	s.sweepPositions(ctx, out)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepPositions(ctx, out)
		}
	}
}

func (s *Source) sweepPositions(ctx context.Context, out event.Sink) {
	doorsNow, err := s.listDoors(ctx)
	now := s.cfg.Now()

	s.mu.Lock()
	s.health.LastPositionAt = now
	if err != nil {
		s.health.LastPositionErr = err.Error()
	} else {
		s.health.LastPositionErr = ""
	}
	s.mu.Unlock()

	if err != nil {
		// A failed read is not evidence about any door. The held-open clock
		// still runs below, because a door that was open before the console
		// stopped answering is still open as far as anybody knows -- and
		// "the console went quiet" is not a reason to stop reporting it.
		s.emit(ctx, out, s.doors.tick(now))
		return
	}

	present := make(map[string]bool, len(doorsNow))
	var all []transition
	for _, d := range doorsNow {
		if d.ID == "" {
			continue
		}
		present[d.ID] = true
		all = append(all, s.doors.observePosition(d.ID, d.displayName(),
			parseRESTLock(d.LockRelay), parsePosition(d.Position), now)...)
	}
	s.doors.forget(present)
	all = append(all, s.doors.tick(now)...)
	s.emit(ctx, out, all)
}

// runLogs polls the system log.
func (s *Source) runLogs(ctx context.Context, out event.Sink) {
	t := time.NewTicker(s.cfg.LogPollEvery)
	defer t.Stop()

	s.pollLogs(ctx, out)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.pollLogs(ctx, out)
		}
	}
}

func (s *Source) pollLogs(ctx context.Context, out event.Sink) {
	rows, err := s.poll.poll(ctx)
	if err != nil && ctx.Err() == nil {
		s.cfg.Logf("access: system log poll failed: %v", err)
	}
	for _, r := range rows {
		if ev, ok := s.eventFromLog(r); ok {
			s.emitEvent(out, ev)
			continue
		}
		s.poll.noteUnknown(r.topic, r.hit.Source.Event.LogKey)
	}
}

// ---------------------------------------------------------------- socket

func (s *Source) dial() *websocket.Dialer {
	s.dialOnce.Do(func() {
		if s.cfg.Dialer != nil {
			s.dialer = s.cfg.Dialer
			return
		}
		d := *websocket.DefaultDialer
		d.HandshakeTimeout = s.cfg.HandshakeTimeout
		if s.cfg.TLS != nil {
			if cfg, err := s.cfg.TLS.Config(); err == nil {
				d.TLSClientConfig = cfg
			}
		}
		// No proxy. The console is on the operator's LAN and an environment
		// proxy would receive API-key-bearing traffic nobody chose to send it.
		d.Proxy = nil
		s.dialer = &d
	})
	return s.dialer
}

func (s *Source) runSocket(ctx context.Context, out event.Sink, fail func(error)) {
	for attempt := 0; ctx.Err() == nil; attempt++ {
		lasted, err := s.readSocket(ctx, out)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, unifi.ErrPinMismatch) {
			// The one terminal failure. A certificate that does not match the
			// pin is not a transient fault and retrying it forever against
			// whatever is answering is worse than stopping.
			fail(err)
			return
		}
		if lasted >= s.cfg.StableAfter {
			// A connection that lived long enough counts as a success, so the
			// ladder restarts. Without the threshold a console that completes
			// the handshake and drops immediately resets the ladder on every
			// attempt and reconnects in a hot loop.
			attempt = 0
		}
		if err != nil {
			s.cfg.Logf("access: notifications socket: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.backoff.Delay(attempt)):
		}
	}
}

func (s *Source) readSocket(ctx context.Context, out event.Sink) (time.Duration, error) {
	if err := s.cfg.Pace(ctx); err != nil {
		return 0, err
	}
	hdr := http.Header{}
	s.authorise(hdr)

	// A 404 MEANS "NOT HERE", NOT "NOT ALLOWED", so it is the one handshake
	// failure worth answering by asking somewhere else. The path that
	// connects is remembered, so a reconnect does not re-walk the list and a
	// site never pays the 404 twice.
	var (
		conn    *websocket.Conn
		resp    *http.Response
		err     error
		wsURL   string
		started = s.cfg.Now()
	)
	for i, path := range s.wsCandidates() {
		wsURL = "wss://" + s.base.Host + path
		started = s.cfg.Now()
		conn, resp, err = s.dial().DialContext(ctx, wsURL, hdr)
		if err == nil {
			if i > 0 {
				// Promote it: this firmware serves the socket here.
				s.mu.Lock()
				s.wsAlso = append([]string{s.wsPath}, s.wsAlso[:i]...)
				s.wsAlso = append(s.wsAlso, s.wsAlso[i:]...)
				s.wsPath = path
				s.mu.Unlock()
			}
			break
		}
		if resp == nil || resp.StatusCode != http.StatusNotFound {
			break
		}
		_ = resp.Body.Close()
		s.cfg.Logf("access: the notifications socket is not at %s on this "+
			"firmware (404); trying the next known path", path)
	}
	if err != nil {
		s.mu.Lock()
		s.health.LastSocketErr = err.Error()
		s.mu.Unlock()
		if resp != nil {
			code := resp.StatusCode
			_ = resp.Body.Close()
			if code == http.StatusUnauthorized || code == http.StatusForbidden {
				return 0, fmt.Errorf("notifications handshake refused (HTTP %d) -- "+
					"the key may be wrong, or this may be the wrong mode for it: "+
					"%s mode sends %s: %w", code, s.cfg.Mode, s.authHeaderName(), err)
			}
		}
		return 0, err
	}
	defer conn.Close()

	s.mu.Lock()
	s.health.Connected = true
	s.health.Connects++
	s.health.LastSocketErr = ""
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.health.Connected = false
		s.mu.Unlock()
	}()

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Unblocks a reader parked in ReadMessage when the context is cancelled.
	//
	// gorilla's DialContext stops watching the context once the handshake
	// succeeds, and this socket is CHATTY AT IDLE -- it pushes full state
	// syncs on a timer -- so ReadMessage keeps returning happily and the loop
	// below never looks at ctx again. On shutdown the daemon waits for this
	// goroutine, the Windows service manager gives the whole stop 25 seconds,
	// and the process was killed before the clean-shutdown marker could be
	// written -- so the NEXT start raised an "did not shut down cleanly"
	// incident about a shutdown that was fine. Protect has had this since it
	// was written; Access was missing it.
	go func() {
		<-connCtx.Done()
		conn.Close()
	}()

	go s.keepalive(connCtx, conn)

	conn.SetReadLimit(maxFrameBytes)
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.PongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(s.cfg.PongWait))
	})

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return s.cfg.Now().Sub(started), err
		}
		_ = conn.SetReadDeadline(time.Now().Add(s.cfg.PongWait))
		s.handleFrame(data, out)
	}
}

func (s *Source) keepalive(ctx context.Context, conn *websocket.Conn) {
	t := time.NewTicker(s.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			deadline := time.Now().Add(s.cfg.PingInterval / 2)
			if err := conn.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
				return
			}
		}
	}
}

// handleFrame decodes one notification.
//
// The socket is CHATTY AT IDLE: it pushes full state syncs on a timer, so an
// arriving frame is not a change. Everything below therefore diffs against
// remembered state rather than emitting on arrival.
func (s *Source) handleFrame(data []byte, out event.Sink) {
	now := s.cfg.Now()
	s.mu.Lock()
	s.health.LastMessageAt = now
	s.mu.Unlock()

	// PROTOCOL NOISE IS NOT A FRAME WE FAILED TO UNDERSTAND.
	//
	// A real ENVR sends a bare string six times a minute as a keepalive, and
	// an informational event about its own log depth. Counted as unreadable,
	// fifty of those raise the stream-unintelligible alarm -- HIGH, saying
	// door-forced detection is degraded -- on a console whose socket is
	// working perfectly, because nobody has opened a door yet. Which is most
	// sites at 3am.
	//
	// The alarm exists for door state arriving in a shape this build cannot
	// read. A frame that is not even an object is not evidence of that.
	if !isJSONObject(data) {
		s.mu.Lock()
		s.health.Noise++
		s.mu.Unlock()
		return
	}

	var n notification
	if err := json.Unmarshal(data, &n); err != nil {
		s.noteUnrecognised("<undecodable>", out)
		return
	}
	if informational[n.Event] {
		// Recorded so an operator can see what the socket actually carries,
		// and kept out of the mute evidence: this one is understood well
		// enough to know it says nothing about a door.
		s.mu.Lock()
		s.health.Noise++
		if len(s.health.UnknownEvents) < 512 {
			s.health.UnknownEvents[n.Event]++
		}
		s.mu.Unlock()
		return
	}
	states := n.states()
	if len(states) == 0 {
		s.noteUnrecognised(n.Event, out)
		return
	}

	s.mu.Lock()
	s.health.Recognised++
	s.mu.Unlock()

	var all []transition
	for _, st := range states {
		if !st.Known {
			// remain_unlock carried a value nobody has ever captured. The lock
			// state is still usable, so it is taken; the held flag is not
			// guessed, because a guess here either raises an incident that can
			// never clear or hides a door somebody left open.
			s.noteUnknownEvent(n.Event + "/remain_unlock")
			all = append(all, s.doors.observeLock(st.DoorID, st.Name, st.Lock, false, now)...)
			continue
		}
		all = append(all, s.doors.observeLock(st.DoorID, st.Name, st.Lock, st.Held, now)...)
	}
	s.emit(context.Background(), out, all)
}

// informational names socket events that carry no door state and are known to
// carry none. Captured from a real console by the probe.
//
// Kept SHORT and explicit. Anything not in here that fails to yield door state
// is still evidence the stream is unintelligible, which is the direction the
// error should point: an unfamiliar door event must not be waved through as
// housekeeping.
var informational = map[string]bool{
	"access.base.info": true,
}

// isJSONObject reports whether a frame is an object rather than a bare string,
// number or array.
func isJSONObject(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

// noteUnrecognised counts a frame nothing understood, and reports a socket
// that has never understood anything as a fault.
func (s *Source) noteUnrecognised(name string, out event.Sink) {
	s.mu.Lock()
	s.health.Unrecognised++
	if name != "" && len(s.health.UnknownEvents) < 512 {
		s.health.UnknownEvents[name]++
	}
	mute := s.health.Recognised == 0 &&
		s.health.Unrecognised >= int64(s.cfg.MuteThreshold) &&
		!s.health.StreamMuteReported
	if mute {
		s.health.StreamMuteReported = true
	}
	s.mu.Unlock()

	if !mute {
		return
	}
	// A connected socket that has never been understood is a silent total
	// failure of this input, and on unfamiliar hardware it is the likely one:
	// both known message shapes came from a single hub model.
	s.emitEvent(out, event.Event{
		Source:    SourceName,
		Kind:      "stream-unintelligible",
		Condition: event.ConditionStreamMute,
		Entity:    event.Entity{ID: "notifications", Name: "Access notifications", Kind: "site"},
		Severity:  incident.SeverityHigh,
		Title:     "The Access notifications stream is connected but unintelligible",
		Detail: fmt.Sprintf("%d messages have arrived and none has been understood. "+
			"Lock state is not being tracked, so door-forced detection is degraded. "+
			"Run `notifymatrix probe --products access` to capture what this console "+
			"is actually sending.", s.cfg.MuteThreshold),
		At:              s.cfg.Now(),
		ReceivedAt:      s.cfg.Now(),
		AtIsArrivalTime: true,
	})
}

func (s *Source) noteUnknownEvent(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.health.UnknownEvents) < 512 {
		s.health.UnknownEvents[name]++
	}
}

// ---------------------------------------------------------------- emit

func (s *Source) emit(_ context.Context, out event.Sink, ts []transition) {
	for _, t := range ts {
		s.emitEvent(out, s.eventFromTransition(t))
	}
}

func (s *Source) emitEvent(out event.Sink, ev event.Event) {
	s.mu.Lock()
	s.health.LastEmitAt = s.cfg.Now()
	s.mu.Unlock()
	out.Emit(ev)
}
