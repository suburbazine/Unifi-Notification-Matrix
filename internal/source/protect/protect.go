// Package protect ingests UniFi Protect over its OFFICIAL Integration API.
//
// Two WebSockets, not one. Protect's event vocabulary has no disconnect,
// cameraDisconnected or offline type anywhere in it -- a camera going dark is
// a `state` field flipping to DISCONNECTED on the separate devices channel. A
// product that watches only subscribe/events never learns a camera went dark,
// which for a product whose job is noticing is a headline failure rather than
// a gap.
//
// Neither socket accepts a resume cursor. A reconnect therefore loses
// everything that happened during the gap WITH NO WAY TO DETECT THAT IT DID,
// so every reconnect runs a REST reconciliation sweep and re-derives open
// state from it rather than trusting the stream to have been continuous. That
// sweep is not a cleanup task bolted on afterwards; it is the half of this
// source that makes the other half trustworthy.
//
// The unofficial wss://.../proxy/protect/ws/updates socket is deliberately not
// used: it requires storing a local admin username and password rather than an
// API key, and its largest consumer is migrating off it. See docs/SOURCES.md.
package protect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
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
const SourceName = "protect"

const (
	pathEvents  = "/proxy/protect/integration/v1/subscribe/events"
	pathDevices = "/proxy/protect/integration/v1/subscribe/devices"
)

// Defaults. Each one that is not obvious says what it is defending against.
const (
	// An idle tunnel through the console's reverse proxy is killed at around
	// ten minutes. Pinging every minute sits an order of magnitude inside that,
	// because the cost of an unnecessary ping is a few bytes and the cost of a
	// missed one is a socket that looks connected and delivers nothing.
	defaultPingInterval = 60 * time.Second
	defaultPongWait     = 150 * time.Second

	defaultHandshakeTimeout = 20 * time.Second

	defaultMinBackoff = 1 * time.Second
	defaultMaxBackoff = 2 * time.Minute

	// defaultStableAfter is how long a connection must last before it counts as
	// a success and resets the backoff ladder. A console that completes the
	// handshake and drops immediately would otherwise reset the ladder on every
	// attempt and reconnect in a hot loop, which is the exact behaviour the
	// backoff exists to prevent.
	defaultStableAfter = 60 * time.Second

	// The sweep also runs on a timer, not only on reconnect. Push paths here
	// can fail silently in ways a live socket cannot detect, so polling is a
	// permanent backstop rather than a fallback.
	defaultSweepEvery = 15 * time.Minute

	// Two sockets reconnecting together, as they do after a console reboot,
	// must produce one sweep between them rather than one each against a
	// console that is still re-initialising.
	defaultSweepDebounce = 2 * time.Second

	// defaultSweepTimeout bounds ONE reconciliation read. Generous, because a
	// large site behind a pacer is legitimately slow -- but finite, because the
	// sweeper is the only thing that re-derives state after a gap and a wedged
	// sweeper is a watchdog that has quietly stopped watching.
	defaultSweepTimeout = 2 * time.Minute

	// Enough unintelligible frames to be a pattern rather than one odd message
	// from a device model nobody has seen.
	defaultMuteThreshold = 5

	defaultLiveness = 30 * time.Minute

	defaultMaxOpenEvents = 512

	// maxFrameBytes bounds one text frame. A console that starts sending
	// something enormous is a fault, not a reason to exhaust memory.
	maxFrameBytes = 4 << 20
)

var (
	// ErrNoHost and ErrNoAPIKey are configuration faults: Run returns them
	// rather than retrying, because no amount of reconnecting fixes them.
	ErrNoHost   = errors.New("protect: no console host configured")
	ErrNoAPIKey = errors.New("protect: no API key configured")
)

// Config is everything this source needs.
type Config struct {
	// Host is the UniFi OS console, with or without a scheme: "192.168.1.1",
	// "10.0.0.5:443" or "https://unifi.example.com". https is assumed.
	Host string

	// APIKey is the Protect Integration API key. It travels in a header and
	// never in a URL.
	APIKey secret.Secret

	// States supplies the reconciliation sweep. Left nil, a REST reader is
	// built from Host and APIKey.
	States StateReader

	// TLS is the console's certificate policy, and it belongs to the HOST
	// rather than to this application. Console certificates are self-signed,
	// so verifying them is certificate PINNING rather than skipped
	// verification -- and Protect, Access and Network are served the same
	// certificate by the same reverse proxy, so the pin is configured once per
	// console in internal/unifi and shared here.
	//
	// Nil gets ordinary system-root verification, which is right for a console
	// behind a real certificate and wrong for everything else.
	TLS *unifi.TLS

	// Dialer overrides the WebSocket dialer entirely, TLS included. Set by
	// tests; a caller with a console to talk to sets TLS instead.
	Dialer *websocket.Dialer

	// HTTPClient is used by the default REST reader only. Left nil it is built
	// from TLS, so the sweep and the sockets pin the same certificate.
	HTTPClient *http.Client

	// Pace is the shared per-console rate limiter, and EVERY request to the
	// console goes through it: the three REST collection reads of a sweep and
	// both WebSocket dials.
	//
	// ONE pacer per console, not per client. Left nil, New takes the shared
	// pacer for this host from internal/unifi -- which is the point of that
	// registry: three independently paced clients against one UniFi OS host
	// multiply the request rate by three against a single server-side budget,
	// and each of them looks correct on its own. Setting this to a private
	// pacer is possible and is a decision worth asking about.
	Pace func(context.Context) error

	PingInterval     time.Duration
	PongWait         time.Duration
	HandshakeTimeout time.Duration

	MinBackoff  time.Duration
	MaxBackoff  time.Duration
	StableAfter time.Duration

	SweepEvery    time.Duration
	SweepDebounce time.Duration

	// SweepTimeout bounds one reconciliation read.
	//
	// An injected StateReader -- or an injected HTTPClient with no timeout of
	// its own -- can otherwise block forever against a console that accepts the
	// connection and never answers, which is a normal thing for one to do while
	// it reboots. The sweeper is a single goroutine, so one hung read stops
	// every later sweep including the periodic backstop: the source would keep
	// reporting itself connected while nothing re-derived state again.
	SweepTimeout time.Duration

	// MuteThreshold is how many consecutive unintelligible messages, with none
	// understood, make a connected socket a reported fault.
	MuteThreshold int

	// LivenessWindow is what Liveness reports to the deadman.
	LivenessWindow time.Duration

	// MaxOpenEvents bounds the in-flight event table used to turn an `end`
	// update into a clear. Bounded because an unbounded one turns a busy site
	// into a memory leak.
	MaxOpenEvents int

	Now  func() time.Time
	Rand func() float64
	Logf func(format string, args ...any)
}

func (c *Config) applyDefaults() {
	if c.PingInterval <= 0 {
		c.PingInterval = defaultPingInterval
	}
	if c.PongWait <= 0 {
		c.PongWait = defaultPongWait
	}
	if c.PongWait <= c.PingInterval {
		// A read deadline shorter than the ping interval kills every healthy
		// connection on schedule.
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
	if c.SweepEvery <= 0 {
		c.SweepEvery = defaultSweepEvery
	}
	// Zero means unset, so it gets the default. A caller that genuinely wants
	// no debounce says so with a negative value, which is normalised to zero
	// here -- otherwise "I did not set this" and "I want it off" are the same
	// value and one of them is wrong.
	if c.SweepDebounce == 0 {
		c.SweepDebounce = defaultSweepDebounce
	}
	if c.SweepDebounce < 0 {
		c.SweepDebounce = 0
	}
	if c.SweepTimeout <= 0 {
		c.SweepTimeout = defaultSweepTimeout
	}
	if c.MuteThreshold <= 0 {
		c.MuteThreshold = defaultMuteThreshold
	}
	if c.LivenessWindow <= 0 {
		c.LivenessWindow = defaultLiveness
	}
	if c.MaxOpenEvents <= 0 {
		c.MaxOpenEvents = defaultMaxOpenEvents
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Rand == nil {
		c.Rand = rand.Float64
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// Health is what this source will say about itself.
//
// Exposed as more than a bool because "connected" is not the question. A
// socket that is connected and has never been understood is the failure mode
// that matters, so the counters that reveal it are part of the public surface
// rather than a debug log line.
type Health struct {
	// All four maps are keyed by channel name ("events", "devices"), because
	// the two sockets fail independently and a product that reports them as one
	// hides exactly the case where the devices channel -- the only one carrying
	// camera disconnect -- is the one that is down.
	Connected    map[string]bool
	Recognised   map[string]int64
	Unrecognised map[string]int64

	// UnknownTypes is keyed "<channel>/<type>" and counts by NAME, so a
	// firmware that adds an event type shows up as something actionable rather
	// than as a number.
	UnknownTypes map[string]int64

	// LastMessageAt is any frame at all, understood or not; LastEmitAt is the
	// last event that actually reached the sink. The gap between them is what
	// tells a mute socket from a quiet site.
	LastMessageAt time.Time
	LastEmitAt    time.Time

	// Connects counts successful handshakes, first one included. A number that
	// keeps climbing is a socket that keeps dropping.
	Connects int64

	LastSweepAt        time.Time
	LastSweepErr       string
	SweepTransitions   int64
	DevicesKnown       int
	StreamMuteReported map[string]bool
}

// Source is the Protect ingest path. It satisfies event.Source.
type Source struct {
	cfg  Config
	base *url.URL
	reg  *registry

	// backoff is the shared console ladder: exponential with HALF jitter, so a
	// retry can never collapse to zero and a console restart does not bring
	// every dropped client back in the same instant.
	backoff unifi.Backoff

	// pacer is non-nil only when this source took the SHARED per-console pacer
	// rather than an injected one. Kept so that the sharing is testable.
	pacer *unifi.Pacer

	sweepReq chan struct{}

	mu     sync.Mutex
	health Health

	// open remembers in-flight events so that an `update` frame carrying only
	// an `end` can be turned into a clear. Update frames do not repeat the
	// event type or the device, so without this table a motion event opens an
	// incident that nothing ever resolves.
	open     map[string]pendingEvent
	openSeq  []string
	dialOnce sync.Once
	dialer   *websocket.Dialer

	// fatalErr is the one failure this source does not retry. See runSocket.
	fatalMu  sync.Mutex
	fatalErr error
}

type pendingEvent struct {
	condition string
	severity  incident.Severity
	kind      string
	entity    event.Entity
}

// New validates the configuration and builds the source.
func New(cfg Config) (*Source, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, ErrNoHost
	}
	if cfg.APIKey.IsZero() {
		return nil, ErrNoAPIKey
	}
	base, err := parseHost(cfg.Host)
	if err != nil {
		return nil, err
	}
	cfg.applyDefaults()

	s := &Source{
		cfg:      cfg,
		base:     base,
		reg:      newRegistry(),
		sweepReq: make(chan struct{}, 4),
		open:     map[string]pendingEvent{},
		health: Health{
			Connected:          map[string]bool{},
			Recognised:         map[string]int64{},
			Unrecognised:       map[string]int64{},
			UnknownTypes:       map[string]int64{},
			StreamMuteReported: map[string]bool{},
		},
	}
	s.backoff = unifi.Backoff{Base: s.cfg.MinBackoff, Max: s.cfg.MaxBackoff, Rand: s.cfg.Rand}

	// The shared path is the default path. A caller that says nothing about
	// pacing gets the pacer every other client of this console already uses,
	// because the failure mode of the alternative -- a second pacer, silently,
	// for the same host -- is invisible in review and doubles the request rate.
	if s.cfg.Pace == nil {
		s.pacer = unifi.PacerFor(base.Host)
		s.cfg.Pace = s.pacer.Wait
	}

	if s.cfg.States == nil {
		hc := s.cfg.HTTPClient
		if hc == nil && s.cfg.TLS != nil {
			// The sweep and the sockets talk to one console, so they pin one
			// certificate. Two differently-configured clients for one host is
			// not redundancy; it is two chances to be wrong.
			c, err := s.cfg.TLS.HTTPClient(0)
			if err != nil {
				return nil, err
			}
			hc = c
		}
		s.cfg.States = newRESTReader(base, s.cfg.APIKey, hc, s.cfg.Pace)
	}
	return s, nil
}

// parseHost accepts a bare host, a host:port or a full URL.
func parseHost(host string) (*url.URL, error) {
	h := strings.TrimSpace(host)
	if !strings.Contains(h, "://") {
		h = "https://" + h
	}
	u, err := url.Parse(h)
	if err != nil {
		return nil, fmt.Errorf("protect: unusable host: %w", err)
	}
	if u.Host == "" {
		return nil, ErrNoHost
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func (s *Source) Name() string { return SourceName }

// Liveness is the deadman window.
//
// Thirty minutes rather than something tight, because silence on these sockets
// is not automatically a fault: a site with detections tuned down can be
// legitimately quiet at 3am, and a deadman that cries wolf every night gets
// switched off, which costs more than it ever saved. The periodic
// reconciliation sweep is what keeps the window meaningful -- it re-derives
// state every SweepEvery regardless of what the stream is doing -- and Health
// is the finer-grained surface for anything that needs to distinguish "quiet"
// from "mute".
func (s *Source) Liveness() time.Duration { return s.cfg.LivenessWindow }

// LastContact is the last time this source heard from the console at all: any
// frame on either socket, understood or not, or a completed reconciliation
// sweep.
//
// Deliberately NOT the last emitted event. Protect speaks when something
// happens, so a quiet evening produces no events at all while the socket stays
// perfectly healthy -- and the deadman, which used to watch emitted events,
// called that a dead source after thirty minutes and paged about it every half
// hour thereafter. The sockets are chatty at idle even when nothing is
// happening, which is exactly what makes them worth watching instead.
// LastError is the most recent reason a read failed, or "" when the last one
// worked. See event.Diagnosable.
//
// The interface needs this to say something true about a source that has
// never once succeeded: without it, "no contact" is a state an operator has
// to go and investigate, when the daemon already knows the answer -- and on
// the console that prompted this, the answer was that Protect is not
// installed on it at all.
func (s *Source) LastError() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.health.LastSweepErr
}

func (s *Source) LastContact() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	last := s.health.LastMessageAt
	if s.health.LastSweepAt.After(last) {
		last = s.health.LastSweepAt
	}
	return last
}

// Health reports what this source currently believes about itself. Safe to
// call from another goroutine.
func (s *Source) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.health
	h.Connected = copyBool(s.health.Connected)
	h.Recognised = copyInt(s.health.Recognised)
	h.Unrecognised = copyInt(s.health.Unrecognised)
	h.UnknownTypes = copyInt(s.health.UnknownTypes)
	h.StreamMuteReported = copyBool(s.health.StreamMuteReported)
	s.reg.mu.Lock()
	h.DevicesKnown = len(s.reg.byID)
	s.reg.mu.Unlock()
	return h
}

func copyBool(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyInt(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

type channelSpec struct {
	name string
	path string
}

var (
	eventsChannel  = channelSpec{name: "events", path: pathEvents}
	devicesChannel = channelSpec{name: "devices", path: pathDevices}
)

// Run ingests until ctx is done.
//
// It returns nil on cancellation and a non-nil error only for something no
// amount of reconnecting can fix: a configuration that cannot work, or a
// certificate pin mismatch.
//
// In particular a REJECTED CREDENTIAL IS NOT AN ERROR HERE. After a console
// restart the reverse proxy answers 4xx and 5xx for a while as applications
// re-initialise, so treating 401 as terminal permanently abandons ingest for a
// key that was correct all along.
func (s *Source) Run(ctx context.Context, out event.Sink) error {
	if s.base == nil {
		return ErrNoHost
	}
	if s.cfg.APIKey.IsZero() {
		return ErrNoAPIKey
	}

	// A private cancel, so that the one terminal failure can stop the sweeper
	// and the other socket rather than leaving half a source running against a
	// console we have just decided we cannot identify.
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runSweeper(runCtx, out)
	}()

	// A cold start is a reconnect from infinity: we know nothing about current
	// state and the stream will not tell us what is already true.
	s.requestSweep()

	for _, spec := range []channelSpec{eventsChannel, devicesChannel} {
		wg.Add(1)
		go func(spec channelSpec) {
			defer wg.Done()
			s.runSocket(runCtx, spec, out, fail)
		}(spec)
	}

	wg.Wait()

	s.fatalMu.Lock()
	defer s.fatalMu.Unlock()
	return s.fatalErr
}

func (s *Source) requestSweep() {
	select {
	case s.sweepReq <- struct{}{}:
	default:
		// A sweep is already pending. Two sockets reconnecting together want
		// one sweep between them, not one each.
	}
}

// runSocket keeps one channel connected for the life of ctx.
//
// Everything is retried except one thing. A 401 is retried because a rejected
// credential is not a dead connection: the reverse proxy answers 4xx and 5xx
// while applications re-initialise after a console restart. A 502 is retried
// for the same reason, and so is a dropped socket.
//
// A CERTIFICATE PIN MISMATCH IS TERMINAL. Every other failure here is "the
// console is not ready yet"; this one is "the thing answering is not the
// console we pinned", and retrying it means repeatedly presenting an API key
// to something we have already decided we cannot identify. It is matched on
// the sentinel, never on the text of a message.
func (s *Source) runSocket(ctx context.Context, spec channelSpec, out event.Sink, fail func(error)) {
	attempt := 0
	for ctx.Err() == nil {
		lasted, advised, err := s.serve(ctx, spec, out)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, unifi.ErrPinMismatch) {
			s.cfg.Logf("protect %s: %v; this is not the console we pinned, so ingest stops rather than retrying", spec.name, err)
			fail(fmt.Errorf("protect %s: %w", spec.name, err))
			return
		}
		if lasted >= s.cfg.StableAfter {
			attempt = 0
		}
		attempt++
		delay := s.backoff.Delay(attempt)
		if advised > delay {
			// The console asked for longer than our ladder wants. It knows
			// more about its own load than we do; the ladder is a floor, not a
			// contradiction of it.
			delay = advised
		}
		if err != nil {
			s.cfg.Logf("protect %s: %v; reconnecting in %s", spec.name, err, delay.Round(time.Millisecond))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// serve runs one connection and returns how long it lasted.
func (s *Source) serve(ctx context.Context, spec channelSpec, out event.Sink) (lasted, advised time.Duration, err error) {
	u := *s.base
	switch u.Scheme {
	case "https", "wss", "":
		u.Scheme = "wss"
	default:
		u.Scheme = "ws"
	}
	u.Path = spec.path

	hdr := http.Header{}
	setAPIKey(hdr, s.cfg.APIKey)

	// The dial goes through the console pacer like every other request.
	//
	// It used not to, and that was the defect: a console reboot brings BOTH of
	// this source's sockets back at the same moment, each reconnect fires a
	// three-request reconciliation sweep behind it, and Access and Network add
	// their own dials to the same host. Handshakes are requests to the same
	// rate-limited front door as everything else, and a limiter tripped here
	// costs the whole reconnect rather than one read.
	//
	// Paced against ctx rather than the handshake deadline: waiting for a slot
	// is not part of the handshake, and charging it to HandshakeTimeout would
	// fail dials that never got to start.
	if err := s.cfg.Pace(ctx); err != nil {
		return 0, 0, fmt.Errorf("pacing the %s dial: %w", spec.name, err)
	}

	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.HandshakeTimeout)
	conn, resp, err := s.dial().DialContext(dialCtx, u.String(), hdr)
	cancel()
	if err != nil {
		status := 0
		var wait time.Duration
		if resp != nil {
			status = resp.StatusCode
			if d, ok := unifi.RetryAfter(resp, s.cfg.Rand); ok {
				wait = d
			}
			resp.Body.Close()
		}
		// Status code only. The body of a credential-bearing endpoint never
		// reaches a log, and the URL is redacted to scheme and host because
		// Protect path components can themselves be credentials.
		return 0, wait, fmt.Errorf("connecting to %s: status %d: %w", redactURL(&u), status, err)
	}

	started := s.cfg.Now()
	s.setConnected(spec.name, true)
	defer func() {
		s.setConnected(spec.name, false)
		conn.Close()
	}()

	// Every connect triggers a sweep. There is no resume cursor on either
	// socket, so everything that happened while this one was down is gone and
	// unknowable from the stream -- the sweep is the only thing that can tell
	// us a camera went dark during the gap.
	s.requestSweep()

	connCtx, stop := context.WithCancel(ctx)
	defer stop()

	go func() {
		<-connCtx.Done()
		// Unblocks a reader parked in ReadMessage.
		conn.Close()
	}()

	conn.SetReadLimit(maxFrameBytes)
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.PongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(s.cfg.PongWait))
	})

	go s.keepalive(connCtx, conn)

	st := &socketState{spec: spec}
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return s.cfg.Now().Sub(started), 0, fmt.Errorf("reading %s: %w", spec.name, err)
		}
		// Any frame at all resets the read deadline: the console is alive even
		// if we cannot understand what it just said.
		_ = conn.SetReadDeadline(time.Now().Add(s.cfg.PongWait))
		s.noteMessage()
		s.handle(spec, st, data, out)
	}
}

func (s *Source) dial() *websocket.Dialer {
	s.dialOnce.Do(func() {
		s.dialer = s.cfg.Dialer
		if s.dialer != nil {
			return
		}
		d := *websocket.DefaultDialer
		if s.cfg.TLS != nil {
			// Ignored deliberately: New already built an HTTP client from the
			// same TLS settings and returned any error there, so a malformed
			// pin cannot reach this point.
			if cfg, err := s.cfg.TLS.Config(); err == nil {
				d.TLSClientConfig = cfg
			}
		}
		// No Proxy function. The console is on the operator's LAN and an
		// environment proxy would receive API-key-bearing traffic nobody chose
		// to send it.
		d.Proxy = nil
		s.dialer = &d
	})
	return s.dialer
}

// keepalive pings well inside the ~10 minute idle timeout the console's
// reverse proxy applies to tunnels. A socket killed for idleness looks exactly
// like a healthy one until the read deadline expires, and everything that
// happened in between is unrecoverable.
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

// socketState is per-connection, because the question "has this socket ever
// been understood" resets when the socket does.
//
// Whether the mute fault has been REPORTED is not kept here: that is an open
// incident, and it survives the connection that raised it. See
// unrecognisedMessage.
type socketState struct {
	spec         channelSpec
	recognised   int
	unrecognised int
}

func (s *Source) handle(spec channelSpec, st *socketState, data []byte, out event.Sink) {
	var f frame
	if err := json.Unmarshal(data, &f); err != nil || strings.TrimSpace(f.Type) == "" {
		s.unrecognisedMessage(spec, st, "", out)
		return
	}

	var it item
	if len(f.Item) > 0 {
		// A failure here is a genuinely unfamiliar payload: every field in item
		// is tolerant, so reaching this branch means the item was not an object
		// at all.
		if err := json.Unmarshal(f.Item, &it); err != nil {
			s.unrecognisedMessage(spec, st, f.Type, out)
			return
		}
	}

	var (
		handled bool
		label   string
	)
	if spec.name == devicesChannel.name {
		handled, label = s.handleDeviceFrame(f, &it, out)
	} else {
		handled, label = s.handleEventFrame(f, &it, out)
	}
	if !handled {
		// The label is the item's own event type where there was one. A
		// firmware that adds a 40th event type must show up by NAME in Health,
		// because "17 unrecognised messages" is a mystery and
		// "17 x sensorArson" is a one-line fix.
		s.unrecognisedMessage(spec, st, label, out)
		return
	}
	s.recognisedMessage(spec, st, out)
}

// handleDeviceFrame processes the channel that carries camera disconnect.
func (s *Source) handleDeviceFrame(f frame, it *item, out event.Sink) (handled bool, label string) {
	ids := decodeIDs(it.ID)

	switch f.Type {
	case "add", "update", "devicesAdd", "devicesBulkUpdate":
		if len(ids) == 0 {
			return false, f.Type + "/no-id"
		}
		now := s.cfg.Now()
		for _, id := range ids {
			d := DeviceState{
				ID:    id,
				Name:  it.Name,
				Kind:  deviceKind(it.ModelKey),
				MAC:   it.MAC,
				State: it.State,
			}
			prev := s.reg.observe(d, now)
			cond, clears, emit := classifyState(prev, it.State)
			if !emit {
				continue
			}
			ent := s.entityFor(id, d.Kind)
			s.emitStateEvent(out, ent, cond, clears, it.State, now, f, it)
		}
		return true, ""

	case "remove", "devicesBulkRemove":
		// A removed device is an inventory change, not an alarm. Recognised so
		// that a console doing housekeeping is not mistaken for a mute socket.
		if len(ids) == 0 {
			return false, f.Type + "/no-id"
		}
		return true, ""

	default:
		return false, f.Type
	}
}

// handleEventFrame processes the events channel.
func (s *Source) handleEventFrame(f frame, it *item, out event.Sink) (handled bool, label string) {
	switch f.Type {
	case "add", "update":
	case "remove":
		return true, ""
	default:
		return false, f.Type
	}

	ids := decodeIDs(it.ID)
	eventID := ""
	if len(ids) > 0 {
		eventID = ids[0]
	}

	// An update frame typically carries only `end`, with no type and no device.
	// Resolving it against the in-flight table is the only way to know what
	// ended.
	if it.Type == "" {
		if it.End == nil || eventID == "" {
			return false, f.Type + "/no-type"
		}
		p, ok := s.takeOpen(eventID)
		if !ok {
			// The event it ends began before we connected. With no resume
			// cursor there is nothing to resolve it against, and inventing a
			// clear for an unknown condition could resolve an incident nobody
			// looked at. Recognised, deliberately inert.
			return true, ""
		}
		s.emitEventEvent(out, eventEmit{
			id:        eventID + ":end",
			kind:      p.kind,
			condition: p.condition,
			severity:  p.severity,
			clears:    true,
			entity:    p.entity,
			at:        millisToTime(it.End),
			frame:     f,
			item:      it,
		})
		return true, ""
	}

	m, known := classify(it)
	if !known {
		return false, it.Type
	}

	ent := s.entityFor(it.Device, kindForType(it.Type))
	at := millisToTime(it.Start)

	s.emitEventEvent(out, eventEmit{
		id:        eventID,
		kind:      it.Type,
		condition: m.condition,
		severity:  m.severity,
		clears:    m.clears,
		entity:    ent,
		at:        at,
		frame:     f,
		item:      it,
	})

	// Remember the in-flight event so a later `end` update becomes a clear,
	// but only where an end genuinely means the condition stopped.
	if m.endClears && !m.clears && eventID != "" {
		if it.End == nil {
			s.putOpen(eventID, pendingEvent{condition: m.condition, severity: m.severity, kind: it.Type, entity: ent})
		} else {
			// Already-complete event: open and close it in one go rather than
			// leaving an incident that nothing will ever resolve.
			s.emitEventEvent(out, eventEmit{
				id:        eventID + ":end",
				kind:      it.Type,
				condition: m.condition,
				severity:  m.severity,
				clears:    true,
				entity:    ent,
				at:        millisToTime(it.End),
				frame:     f,
				item:      it,
			})
		}
	}
	return true, ""
}

type eventEmit struct {
	id        string
	kind      string
	condition string
	severity  incident.Severity
	clears    bool
	entity    event.Entity
	at        time.Time
	frame     frame
	item      *item
}

func (s *Source) emitEventEvent(out event.Sink, e eventEmit) {
	now := s.cfg.Now()
	at := e.at
	arrival := false
	if at.IsZero() {
		// The source told us nothing usable about when this happened. Say so
		// rather than presenting arrival time as observation time: somebody
		// will scrub footage to it.
		at = now
		arrival = true
	}

	ev := event.Event{
		ID:              e.id,
		Source:          SourceName,
		Kind:            e.kind,
		Entity:          e.entity,
		Condition:       e.condition,
		Clears:          e.clears,
		At:              at,
		ReceivedAt:      now,
		AtIsArrivalTime: arrival,
		Severity:        e.severity,
		Title:           buildTitle(e.condition, e.clears, e.entity),
		Detail:          buildDetail(e.kind, e.item),
		Raw:             rawOf(e.frame),
	}
	s.emit(out, ev)
}

func (s *Source) emitStateEvent(out event.Sink, ent event.Entity, cond string, clears bool, state string, now time.Time, f frame, it *item) {
	sev := incident.SeverityHigh
	ev := event.Event{
		ID:        fmt.Sprintf("%s:%s:%d", ent.ID, normaliseState(state), now.UnixMilli()),
		Source:    SourceName,
		Kind:      "deviceState",
		Entity:    ent,
		Condition: cond,
		Clears:    clears,
		At:        now,
		// The devices channel carries no timestamp on a state flip, so the only
		// honest claim is when WE saw it.
		AtIsArrivalTime: true,
		ReceivedAt:      now,
		Severity:        sev,
		Title:           buildTitle(cond, clears, ent),
		Detail:          fmt.Sprintf("Protect reports state %s", normaliseState(state)),
		Raw:             rawOf(f),
	}
	s.emit(out, ev)
}

func (s *Source) emit(out event.Sink, ev event.Event) {
	s.mu.Lock()
	s.health.LastEmitAt = ev.ReceivedAt
	s.mu.Unlock()
	out.Emit(ev)
}

// putOpen records an in-flight event, evicting the oldest when full. Bounded
// because a busy site with a socket that never sends `end` would otherwise
// grow this table until the process dies.
func (s *Source) putOpen(id string, p pendingEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.open[id]; !exists {
		s.openSeq = append(s.openSeq, id)
	}
	s.open[id] = p
	for len(s.openSeq) > s.cfg.MaxOpenEvents {
		oldest := s.openSeq[0]
		s.openSeq = s.openSeq[1:]
		delete(s.open, oldest)
	}
}

func (s *Source) takeOpen(id string) (pendingEvent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.open[id]
	if !ok {
		return pendingEvent{}, false
	}
	delete(s.open, id)
	for i, v := range s.openSeq {
		if v == id {
			s.openSeq = append(s.openSeq[:i], s.openSeq[i+1:]...)
			break
		}
	}
	return p, true
}

func (s *Source) entityFor(id, fallbackKind string) event.Entity {
	if id == "" {
		return event.Entity{Kind: fallbackKind}
	}
	if d, ok := s.reg.lookup(id); ok {
		kind := d.Kind
		if kind == "" {
			kind = fallbackKind
		}
		return event.Entity{ID: d.ID, Name: d.Name, Kind: kind, MAC: d.MAC}
	}
	return event.Entity{ID: id, Kind: fallbackKind}
}

// kindForType is what the event type itself tells us about the hardware. It is
// information, not a guess: only a camera sends a ring and only a sensor sends
// sensorOpened. The reconciliation sweep replaces it with the real record as
// soon as one exists.
func kindForType(t string) string {
	switch {
	case strings.HasPrefix(t, "sensor"):
		return "sensor"
	case strings.HasPrefix(t, "alarmHub"):
		return "device"
	case t == "ring", t == "motion", strings.HasPrefix(t, "smart"), t == "lightMotion",
		t == "cameraDigitalInputChanged", t == "nfcCardScanned", t == "fingerprintIdentified":
		return "camera"
	default:
		return "device"
	}
}

func deviceKind(modelKey string) string {
	k := strings.TrimSpace(strings.ToLower(modelKey))
	switch k {
	case "":
		return "device"
	case "camera", "sensor", "nvr":
		return k
	default:
		return k
	}
}

func millisToTime(m *flexMillis) time.Time {
	if m == nil || *m == 0 {
		return time.Time{}
	}
	// Unix MILLISECONDS. Read as seconds these land in 1970 and the alert
	// points at footage that does not exist.
	return time.UnixMilli(int64(*m)).UTC()
}

func buildTitle(condition string, clears bool, ent event.Entity) string {
	label := "Unknown condition"
	if condition != "" {
		// Guarded rather than assumed: a panic in the ingest loop takes the
		// whole source down, and a source that is down is the failure this
		// product exists to prevent.
		label = strings.ToUpper(condition[:1]) + strings.ReplaceAll(condition[1:], "-", " ")
	}
	name := ent.Name
	if name == "" {
		name = ent.ID
	}
	if name == "" {
		name = "unknown device"
	}
	if clears {
		return fmt.Sprintf("Cleared: %s - %s", label, name)
	}
	return fmt.Sprintf("%s - %s", label, name)
}

func buildDetail(kind string, it *item) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Protect event %s", kind)
	if it == nil {
		return b.String()
	}
	if len(it.SmartDetectTypes) > 0 {
		fmt.Fprintf(&b, "; detected %s", strings.Join(it.SmartDetectTypes, ", "))
	}
	// Metadata is rendered from the scrubbed map, so a PIN or card number that
	// arrived on the wire is already gone by the time anything can format it.
	for _, k := range []string{"alarmType", "sensorType", "status", "inputState", "inputChannel", "sensorMountType"} {
		if v, ok := it.Metadata.Text(k); ok && v != "" {
			fmt.Fprintf(&b, "; %s=%s", k, v)
		}
	}
	if v, ok := it.Metadata.Number("sensorBatteryPercentage"); ok {
		fmt.Fprintf(&b, "; battery=%.0f%%", v)
	}
	return b.String()
}

// rawOf keeps the original payload for the audit record, with credential
// metadata already dropped by the item decoder's scrub.
func rawOf(f frame) map[string]any {
	raw := map[string]any{"type": f.Type}
	if len(f.Item) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(f.Item, &m); err != nil {
		return raw
	}
	scrubCredentials(m)
	raw["item"] = m
	return raw
}

// scrubCredentials drops PINs and card numbers from the audit copy. A struct
// field is all it takes for one to reach a crash dump; only their presence
// survives.
func scrubCredentials(m map[string]any) {
	md, ok := m["metadata"].(map[string]any)
	if !ok {
		return
	}
	for k := range md {
		if credentialMetadata[k] {
			md[k] = presentSentinel
		}
	}
}

func (s *Source) setConnected(name string, up bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if up {
		s.health.Connects++
	}
	s.health.Connected[name] = up
	// StreamMuteReported is deliberately NOT reset here. It records that an
	// incident was OPENED, and an incident outlives the connection that opened
	// it: clearing the flag on disconnect would leave a stream-unintelligible
	// incident nagging with nothing left that could ever resolve it, because
	// the only thing that emits the clear is the first frame we understand.
}

func (s *Source) noteMessage() {
	now := s.cfg.Now()
	s.mu.Lock()
	s.health.LastMessageAt = now
	s.mu.Unlock()
}

func (s *Source) recognisedMessage(spec channelSpec, st *socketState, out event.Sink) {
	st.recognised++
	s.mu.Lock()
	s.health.Recognised[spec.name]++
	// The first frame we understand clears the fault, whether or not it arrived
	// on the connection that raised it. A socket that drops and comes back
	// speaking a language we know has resolved the condition; nothing else can,
	// so a clear that only fired on the original connection would leave the
	// incident open forever.
	reported := s.health.StreamMuteReported[spec.name]
	if reported {
		s.health.StreamMuteReported[spec.name] = false
	}
	s.mu.Unlock()

	if reported {
		s.emitMute(out, spec, true, st)
	}
}

// unrecognisedMessage counts what we could not understand, and reports a
// socket that has never been understood at all.
//
// A stream that connects and is never understood is a fault, not a success.
// Unfamiliar hardware otherwise produces a live-looking, never-updating source
// -- silent total failure, which for this product is the worst possible
// outcome, because it occupies the slot a working watchdog would have.
func (s *Source) unrecognisedMessage(spec channelSpec, st *socketState, frameType string, out event.Sink) {
	st.unrecognised++
	s.mu.Lock()
	s.health.Unrecognised[spec.name]++
	if frameType != "" {
		s.health.UnknownTypes[spec.name+"/"+frameType]++
	}
	reported := s.health.StreamMuteReported[spec.name]
	s.mu.Unlock()

	// recognised is per-CONNECTION -- the question is whether THIS socket has
	// ever been understood, and that genuinely resets when the socket does.
	// reported is per-SOURCE, because it tracks an open incident rather than a
	// connection, and re-raising it on every reconnect would nag about a
	// condition that was already reported.
	if reported || st.recognised > 0 || st.unrecognised < s.cfg.MuteThreshold {
		return
	}
	s.mu.Lock()
	s.health.StreamMuteReported[spec.name] = true
	s.mu.Unlock()
	s.emitMute(out, spec, false, st)
}

func (s *Source) emitMute(out event.Sink, spec channelSpec, clears bool, st *socketState) {
	now := s.cfg.Now()
	ent := event.Entity{
		ID:   SourceName + ":" + spec.name,
		Name: "Protect " + spec.name + " stream",
		Kind: "site",
	}
	detail := fmt.Sprintf("%d messages received on the %s socket and none understood", st.unrecognised, spec.name)
	if clears {
		detail = fmt.Sprintf("%s socket is intelligible again", spec.name)
	}
	s.emit(out, event.Event{
		ID:              fmt.Sprintf("%s-mute-%d", spec.name, now.UnixMilli()),
		Source:          SourceName,
		Kind:            "streamUnintelligible",
		Entity:          ent,
		Condition:       ConditionStreamMute,
		Clears:          clears,
		At:              now,
		ReceivedAt:      now,
		AtIsArrivalTime: true,
		Severity:        incident.SeverityHigh,
		Title:           buildTitle(ConditionStreamMute, clears, ent),
		Detail:          detail,
	})
}
