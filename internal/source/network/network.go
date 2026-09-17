// Package network is the UniFi Network ingest path.
//
// It is the odd one of the three, and the reason is a single measurable fact:
// **the Network Integration API has no events.** Its OpenAPI specification
// contains zero occurrences of "event", "alarm", "webhook" or "subscribe". It
// will tell you what every device IS; it will never tell you that something
// HAPPENED.
//
// So this source has two halves that do not resemble each other:
//
//   - **Polling**, here. Device reachability is derived by reading the device
//     list and remembering what it said last time. That is the whole mechanism
//     -- with no events, the only way to tell a device that WENT down from one
//     that is merely still down is to have looked before.
//   - **An inbound webhook**, in internal/inbound. WAN outages, threats, PoE
//     faults and client events exist only in Network's Alarm Manager, whose
//     rules are configured in the UI and in no API at all. This product cannot
//     create them; a person has to. That is why onboarding walks the operator
//     through it and why the receiver reports whether anything has ever
//     actually arrived.
//
// One more thing is unlike the other two sources: no prior in-house client for
// this API exists to copy shapes from. Every field name and every state value
// here comes from documentation rather than from a console anybody here has
// queried, which is why the decoding is tolerant and the state vocabulary is
// treated as unestablished.
package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/unifi"
)

// SourceName is the identifier that appears in dedup keys and diagnostics.
const SourceName = "network"

// apiBase is the Local Integration API, introduced in Network 9.0.
const apiBase = "/proxy/network/integration/v1"

var (
	// ErrNoHost and ErrNoAPIKey are configuration faults: Run returns them
	// rather than retrying, because no amount of reconnecting fixes them.
	ErrNoHost   = errors.New("network: no console host configured")
	ErrNoAPIKey = errors.New("network: no API key configured")
)

// Defaults.
const (
	// defaultPollEvery is how often the device list is read.
	//
	// A minute, not ten seconds. There is nothing time-critical in this half of
	// the source -- a switch that is down stays down, and the alarm classes
	// that ARE time-critical (WAN, threats) come through the webhook, not
	// through here. Polling harder would spend a rate budget shared with
	// Protect's reconciliation sweeps to learn the same thing sooner by
	// seconds.
	defaultPollEvery = 60 * time.Second

	// defaultDownFor is how long a device must read down before it is raised.
	defaultDownFor = 3 * time.Minute

	// defaultPageLimit is the page size requested.
	defaultPageLimit = 200

	// maxPages bounds one list read, so a console that ignores paging cannot
	// make this loop forever.
	maxPages = 50

	defaultRequestTimeout = 30 * time.Second
	maxBodyBytes          = 8 << 20

	// defaultLiveness is what Liveness reports to the deadman.
	//
	// Long, because silence here is NORMAL: a healthy network emits no
	// transitions for weeks at a time, and this source only speaks when
	// something changes. The poll loop failing is reported through Health and
	// through the source's own error path rather than through the deadman.
	defaultLiveness = 0
)

// Config is everything this source needs.
type Config struct {
	// Host is the UniFi OS console, with or without a scheme.
	Host string

	// APIKey is the Network Integration API key.
	//
	// The header is X-API-Key. Ubiquiti's own Network documentation names it
	// directly, which matters because the OpenAPI spec declares no security
	// scheme at all -- the keys are absent from it, not null -- so this does
	// not have to be inferred from the sibling products.
	APIKey secret.Secret

	TLS        *unifi.TLS
	HTTPClient *http.Client

	// Pace is the shared per-console rate limiter. One budget per console, not
	// one per application.
	Pace func(context.Context) error

	PollEvery      time.Duration
	DownFor        time.Duration
	RequestTimeout time.Duration
	PageLimit      int
	LivenessWindow time.Duration

	Now  func() time.Time
	Logf func(format string, args ...any)
}

func (c *Config) applyDefaults() {
	if c.PollEvery <= 0 {
		c.PollEvery = defaultPollEvery
	}
	if c.DownFor <= 0 {
		c.DownFor = defaultDownFor
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = defaultRequestTimeout
	}
	if c.PageLimit <= 0 {
		c.PageLimit = defaultPageLimit
	}
	if c.LivenessWindow < 0 {
		c.LivenessWindow = 0
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
	LastPollAt  time.Time
	LastPollErr string
	Polls       int64

	SitesKnown   int
	DevicesKnown int

	// ByState counts devices by what this build made of their state.
	ByState map[string]int

	// UnknownStates counts state strings this build has no rule for, BY NAME.
	//
	// The important number on this struct. These lists came from documentation
	// rather than from hardware, and a state that is absent from them is a
	// device this source will never alarm about. Counting them by name is what
	// turns that from a silent blind spot into something an operator can see
	// and report.
	UnknownStates map[string]int64

	LastEmitAt time.Time
}

// Source is the Network ingest path. It satisfies event.Source.
type Source struct {
	cfg  Config
	base *url.URL
	hc   *http.Client

	devices *devices
	pacer   *unifi.Pacer

	mu     sync.Mutex
	health Health
	sites  []site
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
		cfg: cfg, base: base,
		devices: newDevices(cfg.DownFor),
		health: Health{
			ByState:       map[string]int{},
			UnknownStates: map[string]int64{},
		},
	}
	if s.cfg.Pace == nil {
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
	return s, nil
}

func parseHost(host string) (*url.URL, error) {
	h := strings.TrimSpace(host)
	if !strings.Contains(h, "://") {
		h = "https://" + h
	}
	u, err := url.Parse(h)
	if err != nil {
		return nil, fmt.Errorf("network: unusable host: %w", err)
	}
	if u.Host == "" {
		return nil, ErrNoHost
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func (s *Source) Name() string { return SourceName }

// Liveness is zero: this source makes no promise about speaking.
//
// Deliberate, and the one source that opts out. A healthy network produces no
// transitions for weeks, so a deadman here would fire on every quiet site --
// and a deadman that cries wolf gets the whole mechanism switched off,
// including for the sources where silence really does mean something is wrong.
// The poll loop's own failures are reported through Health instead.
func (s *Source) Liveness() time.Duration { return s.cfg.LivenessWindow }

// LastContact is the last poll that actually reached the console. See
// event.Contactable. This source has no deadman of its own by default, but it
// reports contact anyway so the interface can show when it last managed to
// read anything.
func (s *Source) LastContact() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.health.LastPollAt
}

// Health reports what this source believes about itself.
func (s *Source) Health() Health {
	s.mu.Lock()
	h := s.health
	h.UnknownStates = copyCounts(s.health.UnknownStates)
	h.SitesKnown = len(s.sites)
	s.mu.Unlock()

	h.DevicesKnown = s.devices.count()
	h.ByState = map[string]int{}
	for st, n := range s.devices.countsByState() {
		name := string(st)
		if name == "" {
			name = "unknown"
		}
		h.ByState[name] = n
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
func (s *Source) Run(ctx context.Context, out event.Sink) error {
	if s.base == nil {
		return ErrNoHost
	}
	if s.cfg.APIKey.IsZero() {
		return ErrNoAPIKey
	}

	t := time.NewTicker(s.cfg.PollEvery)
	defer t.Stop()

	s.poll(ctx, out)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.poll(ctx, out)
		}
	}
}

// poll reads every site's devices and emits what changed.
func (s *Source) poll(ctx context.Context, out event.Sink) {
	now := s.cfg.Now()

	sites, err := s.listSites(ctx)
	if err != nil {
		s.notePoll(now, err)
		// The clock still runs. A device that was already down before the
		// console stopped answering is still down as far as anybody knows, and
		// "the console went quiet" is not a reason to stop reporting it.
		s.emit(out, s.devices.tick(now))
		return
	}
	s.mu.Lock()
	s.sites = sites
	s.mu.Unlock()

	present := map[string]bool{}
	var all []transition
	var firstErr error
	for _, si := range sites {
		devs, err := s.listDevices(ctx, si.ID)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, d := range devs {
			if d.ID != "" {
				present[d.ID] = true
			}
			if _, raw := classifyState(d.State); raw != "" {
				s.noteState(d.State, raw)
			}
		}
		all = append(all, s.devices.observe(si.label(), devs, now)...)
	}

	if firstErr == nil {
		// Only when EVERY site was read. A site that failed is a site whose
		// devices were not listed, and forgetting them because they were
		// absent from a list we never received would drop their state.
		s.devices.forget(present)
	}
	all = append(all, s.devices.tick(now)...)
	s.notePoll(now, firstErr)
	s.emit(out, all)
}

func (s *Source) notePoll(now time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health.LastPollAt = now
	s.health.Polls++
	if err != nil {
		s.health.LastPollErr = err.Error()
		return
	}
	s.health.LastPollErr = ""
}

// noteState counts a state string this build had no rule for.
func (s *Source) noteState(raw json.RawMessage, value string) {
	st, _ := classifyState(raw)
	if st != StateUnknown {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.health.UnknownStates) < 256 {
		s.health.UnknownStates[value]++
	}
}

// ---------------------------------------------------------------- REST

func (s *Source) call(ctx context.Context, path string) ([]byte, error) {
	if err := s.cfg.Pace(ctx); err != nil {
		return nil, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()

	full := s.base.Scheme + "://" + s.base.Host + apiBase + path
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	// X-API-Key, in the casing Ubiquiti's Network documentation uses. Assigned
	// into the map rather than through Header.Set so the casing is the one
	// chosen here rather than Go's canonical form.
	req.Header["X-API-Key"] = []string{s.cfg.APIKey.Reveal()}

	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("network: console refused the credential (HTTP %d) -- "+
			"the Network API key is separate from the Protect and Access ones, "+
			"and is created under Settings > Control Plane > Integrations",
			resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("network: %s is not served by this console -- the "+
			"Local Integration API arrived in Network 9.0, so an older "+
			"controller has no such path", path)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("network: HTTP %d on %s", resp.StatusCode, path)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

func (s *Source) listSites(ctx context.Context) ([]site, error) {
	raw, err := s.callPaged(ctx, "/sites")
	if err != nil {
		return nil, err
	}
	out := make([]site, 0, len(raw))
	for _, item := range raw {
		var si site
		if err := json.Unmarshal(item, &si); err != nil {
			// One unreadable site does not cost us the others.
			continue
		}
		if si.ID != "" {
			out = append(out, si)
		}
	}
	return out, nil
}

func (s *Source) listDevices(ctx context.Context, siteID string) ([]device, error) {
	raw, err := s.callPaged(ctx, "/sites/"+url.PathEscape(siteID)+"/devices")
	if err != nil {
		return nil, err
	}
	out := make([]device, 0, len(raw))
	for _, item := range raw {
		var d device
		if err := json.Unmarshal(item, &d); err != nil {
			continue
		}
		if d.ID != "" {
			out = append(out, d)
		}
	}
	return out, nil
}

// callPaged walks every page of a list endpoint.
func (s *Source) callPaged(ctx context.Context, path string) ([]json.RawMessage, error) {
	var out []json.RawMessage
	offset := 0
	for p := 0; p < maxPages; p++ {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		body, err := s.call(ctx, fmt.Sprintf("%s%soffset=%d&limit=%d", path, sep, offset, s.cfg.PageLimit))
		if err != nil {
			return nil, err
		}
		items, total, err := decodePage(body)
		if err != nil {
			return nil, fmt.Errorf("network: unreadable response on %s: %w", path, err)
		}
		out = append(out, items...)
		offset += len(items)
		if len(items) == 0 || offset >= total {
			break
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- emit

func (s *Source) emit(out event.Sink, ts []transition) {
	for _, t := range ts {
		s.emitEvent(out, s.eventFor(t))
	}
}

func (s *Source) emitEvent(out event.Sink, ev event.Event) {
	s.mu.Lock()
	s.health.LastEmitAt = s.cfg.Now()
	s.mu.Unlock()
	out.Emit(ev)
}

func (s *Source) eventFor(t transition) event.Event {
	now := s.cfg.Now()
	name := t.device.name
	if name == "" {
		name = "device " + t.device.id
	}
	title := "Device offline — " + name
	if t.clears {
		title = "Device back online — " + name
	}
	detail := t.detail
	if t.device.model != "" {
		detail = t.device.model + ": " + detail
	}
	if t.device.site != "" {
		detail += " (site " + t.device.site + ")"
	}

	return event.Event{
		Source:    SourceName,
		Kind:      "device-state",
		Condition: event.ConditionOffline,
		Clears:    t.clears,
		Entity: event.Entity{
			ID: t.device.id, Name: name, Kind: "device", MAC: t.device.mac,
		},
		Severity: incident.SeverityHigh,
		Title:    title,
		Detail:   detail,

		// Derived from polling, so the time is when WE noticed rather than
		// when it happened. The API carries no event and therefore no event
		// time; saying otherwise would put a precise-looking timestamp on a
		// number that is accurate only to the poll interval.
		At:              now,
		ReceivedAt:      now,
		AtIsArrivalTime: true,
	}
}
