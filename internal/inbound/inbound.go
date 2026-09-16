// Package inbound receives alarms that UniFi pushes to us.
//
// It exists because of one hard limit: **UniFi's Alarm Manager rules are
// configured in the UI and in no API at all.** Nothing this product can call
// creates them, so it cannot provision its own push path — a person has to go
// into Network (or Protect) and make the rule by hand. That is not a gap to be
// designed around; it is a fact to be designed *for*, which is why this
// package tracks whether an alarm has ever actually arrived and says so on
// every surface an operator looks at.
//
// The second limit shapes the rest: **the payload is undocumented and
// inconsistent between firmware revisions.** The message field alone has been
// spelled `message`, `msg`, `text` and `description`, and it carries no
// controller timestamp. So this package does not try to classify what arrived.
// The URL does that instead — one hook per Alarm Manager rule, with the
// meaning attached to the token rather than parsed out of the body — because
// the operator chooses the URL when they create the rule, and a URL is a thing
// this product can be certain about.
package inbound

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// SourceName is the identifier that appears in dedup keys and diagnostics.
const SourceName = "inbound"

// PathPrefix is where the receiver is mounted.
const PathPrefix = "/hook/"

// maxBodyBytes caps a webhook body. Generous for a JSON alarm and far short of
// anything that could exhaust memory on the operator's machine.
const maxBodyBytes = 256 << 10

// Hook is one configured endpoint: one URL, one meaning.
type Hook struct {
	// Name identifies the hook to the operator. It is what the setup checklist
	// and the interface call it, so it should match the name of the Alarm
	// Manager rule that posts to it.
	Name string

	// Token is the secret in the URL. It selects WHICH hook an arrival belongs
	// to, and it is a credential in its own right.
	Token secret.Secret

	// Bearer is the Authorization header the caller must present, and it is
	// REQUIRED. A hook with no bearer accepts nothing.
	//
	// A URL alone is not an authenticator. It travels through the Alarm
	// Manager form, the console's own configuration backup, browser history,
	// any proxy access log on the path, and whatever screenshot somebody takes
	// while setting it up -- all places a header does not go. Requiring both
	// means learning the URL is not enough to raise a false alarm on somebody
	// else's security system.
	//
	// There is deliberately no way to switch this off. An "allow unauthenticated"
	// flag is a flag that ends up in a forum post, and the protection is then
	// one copied line away from being absent.
	Bearer secret.Secret

	// Product is the UniFi application this hook is for, for diagnostics only.
	Product string

	// Condition is what an arrival at this URL MEANS.
	//
	// Attached to the hook rather than read from the body, because the body
	// cannot be relied on: it is undocumented, it has changed between
	// firmware revisions, and a rule that guessed wrong would either raise the
	// wrong alarm or silently raise none. The operator picks the URL when they
	// create the Alarm Manager rule, so this is the one fact about an inbound
	// alarm that is knowable.
	Condition string

	// Severity is this hook's proposal. Rules may override it.
	Severity incident.Severity

	// EntityName is what the incident is about when the payload names nothing
	// -- typically the site or the WAN.
	EntityName string
}

// Receipt is what has actually arrived at a hook.
//
// THE POINT OF TRACKING THIS is the Test Alarm button. Because the rule cannot
// be created through an API, the only way to know the operator got it right is
// to observe an alarm arriving -- so every setup surface can say "nothing has
// ever arrived here" instead of showing a configuration that looks complete
// and does nothing.
type Receipt struct {
	Name     string
	Product  string
	Count    int64
	LastAt   time.Time
	LastFrom string

	// Rejected counts arrivals that reached this hook's URL and were refused.
	//
	// THE DIAGNOSTIC THAT MAKES A CLOSED DOOR DEBUGGABLE. A caller gets a bare
	// 404 whatever went wrong, so an attacker learns nothing -- but an operator
	// who pasted the URL and forgot the header would otherwise see "nothing has
	// ever arrived" and have no idea their rule is firing. This is read from
	// behind the session gate, where saying why costs nothing.
	Rejected     int64
	LastRejectAt time.Time
	LastReject   string
}

// Receiver is the HTTP endpoint UniFi posts to.
type Receiver struct {
	hooks []Hook
	emit  func(event.Event)
	now   func() time.Time
	logf  func(string, ...any)

	mu       sync.Mutex
	receipts map[string]*Receipt
}

// Options configure a Receiver.
type Options struct {
	Emit func(event.Event)
	Now  func() time.Time
	Logf func(format string, args ...any)
}

// New builds a receiver over the configured hooks.
func New(hooks []Hook, opts Options) *Receiver {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	r := &Receiver{
		hooks: hooks, emit: opts.Emit, now: opts.Now, logf: opts.Logf,
		receipts: map[string]*Receipt{},
	}
	for _, h := range hooks {
		r.receipts[h.Name] = &Receipt{Name: h.Name, Product: h.Product}
	}
	return r
}

// ServeHTTP accepts an alarm.
//
// GET is accepted as well as POST, which is the opposite of the
// acknowledgement endpoint's rule, and the difference is deliberate. There,
// GET must not act because a mail scanner prefetching a link in an alert would
// acknowledge an alarm nobody saw. Here, Alarm Manager offers GET or POST and
// the operator may well pick GET -- and nothing prefetches this URL, because
// it is never sent to anybody. What IS true of both is that the URL is a
// credential, which is why it is never logged and never echoed back.
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut:
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimPrefix(req.URL.Path, PathPrefix)
	if i := strings.IndexByte(token, '/'); i >= 0 {
		// A trailing segment is tolerated so an operator can make the URL
		// self-describing in the Alarm Manager UI (/hook/<token>/wan-down).
		token = token[:i]
	}

	hook, ok := r.match(token)
	if !ok {
		// 404 rather than 401, and with no detail: an attacker probing for a
		// valid hook must not be able to tell a wrong token from a wrong path.
		http.NotFound(w, req)
		return
	}

	// The URL identified the hook; the header has to authenticate it.
	if why := authorised(req, hook); why != "" {
		r.reject(hook, why, req)
		// Still a bare 404. Answering 401 here would confirm that the URL is
		// live, which is precisely what an attacker holding a leaked URL and no
		// header wants to know.
		http.NotFound(w, req)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(req.Body, maxBodyBytes))
	payload := parsePayload(req, body)

	now := r.now()
	r.mu.Lock()
	rec := r.receipts[hook.Name]
	if rec == nil {
		rec = &Receipt{Name: hook.Name, Product: hook.Product}
		r.receipts[hook.Name] = rec
	}
	rec.Count++
	rec.LastAt = now
	rec.LastFrom = clientIP(req)
	r.mu.Unlock()

	// Answered immediately and unconditionally. The console is waiting on this
	// response and will retry or mark the rule failed if it is slow -- and an
	// alarm we have already read is one we are responsible for regardless of
	// what the store does with it next.
	w.WriteHeader(http.StatusNoContent)

	if r.emit == nil {
		return
	}
	r.emit(r.eventFor(hook, payload, now))
}

// match finds the hook for a token in constant time with respect to the token.
func (r *Receiver) match(token string) (Hook, bool) {
	var (
		found Hook
		ok    bool
	)
	for _, h := range r.hooks {
		// Every hook is compared, and the loop is not broken early, so the
		// time taken does not reveal how many leading characters were right or
		// which hook matched.
		if subtle.ConstantTimeCompare([]byte(token), []byte(h.Token.Reveal())) == 1 {
			found, ok = h, true
		}
	}
	if token == "" {
		return Hook{}, false
	}
	return found, ok
}

// authorised reports why a request is not authorised, or "" if it is.
//
// Constant-time, and it checks the FULL header value rather than parsing a
// scheme out of it first -- a comparison whose length is decided by attacker
// input leaks that length.
func authorised(req *http.Request, h Hook) string {
	if h.Bearer.IsZero() {
		// A hook with no bearer accepts nothing. Failing closed matters more
		// here than anywhere else in this package: the alternative is a live
		// endpoint that anybody who learns the URL can feed alarms to, which
		// is the exact thing the bearer exists to prevent.
		return "this hook has no bearer token configured, so it cannot accept anything"
	}
	got := req.Header.Get("Authorization")
	if got == "" {
		return "no Authorization header"
	}
	want := "Bearer " + h.Bearer.Reveal()
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return "the Authorization header did not match"
	}
	return ""
}

// reject records a refused arrival against the hook it was aimed at.
func (r *Receiver) reject(h Hook, why string, req *http.Request) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.receipts[h.Name]
	if rec == nil {
		rec = &Receipt{Name: h.Name, Product: h.Product}
		r.receipts[h.Name] = rec
	}
	rec.Rejected++
	rec.LastRejectAt = now
	rec.LastReject = why + " (from " + clientIP(req) + ")"
}

// payload is the little that can be relied on from an inbound body.
type payload struct {
	// Message is the console's own description, from whichever of the four
	// spellings this firmware uses.
	Message string

	// MAC identifies the device, when one was named. Protect's Alarm Manager
	// webhook carries a bare MAC and nothing else usable, which is why this is
	// resolved to a device by the source rather than rendered raw.
	MAC string

	// Trigger is the Alarm Manager rule name, when present.
	Trigger string

	// Raw is the decoded body, kept for the audit record only.
	Raw map[string]any
}

// messageKeys are the spellings the description has appeared under.
//
// Four, across firmware revisions, for one field. This is why the meaning of
// an inbound alarm comes from its URL and not from its body.
var messageKeys = []string{"message", "msg", "text", "description", "alert", "body"}

var macKeys = []string{"mac", "device_mac", "deviceMac", "device", "id"}

var triggerKeys = []string{"trigger", "name", "rule", "alarm", "title", "subject", "event"}

func parsePayload(req *http.Request, body []byte) payload {
	var p payload

	// A GET carries everything in the query string, so both are read and the
	// body wins where they overlap.
	if q := req.URL.Query(); len(q) > 0 {
		flat := map[string]any{}
		for k, v := range q {
			if len(v) > 0 {
				flat[k] = v[0]
			}
		}
		p.fill(flat)
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return p
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		// Not JSON. The body is still the console's own description of what
		// happened, so it is kept as text rather than discarded -- but it is
		// capped, because an HTML error page is not a message.
		if len(trimmed) > 500 {
			trimmed = trimmed[:500] + "…"
		}
		if p.Message == "" {
			p.Message = trimmed
		}
		return p
	}
	p.Raw = doc
	p.fill(doc)
	return p
}

// fill reads the keys that are worth having, at the top level and one level
// down -- some firmware nests the whole alarm under `alarm` or `data`.
func (p *payload) fill(doc map[string]any) {
	take := func(d map[string]any, keys []string, into *string) {
		if *into != "" {
			return
		}
		for _, k := range keys {
			if s, ok := stringish(d[k]); ok && s != "" {
				*into = s
				return
			}
		}
	}
	take(doc, messageKeys, &p.Message)
	take(doc, macKeys, &p.MAC)
	take(doc, triggerKeys, &p.Trigger)

	for _, nest := range []string{"alarm", "data", "payload", "event"} {
		inner, ok := doc[nest].(map[string]any)
		if !ok {
			continue
		}
		take(inner, messageKeys, &p.Message)
		take(inner, macKeys, &p.MAC)
		take(inner, triggerKeys, &p.Trigger)
	}
}

func stringish(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t), true
	case json.Number:
		return t.String(), true
	case float64:
		if t == float64(int64(t)) {
			return strings.TrimSpace(json.Number(formatInt(int64(t))).String()), true
		}
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	}
	return "", false
}

func formatInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// eventFor renders an arrival as an event.
func (r *Receiver) eventFor(h Hook, p payload, now time.Time) event.Event {
	name := h.EntityName
	if name == "" {
		name = h.Name
	}
	detail := p.Message
	if detail == "" {
		detail = "The console sent an alarm with no message this build could read. " +
			"The rule that fired is the one posting to the \"" + h.Name + "\" hook."
	}
	if p.Trigger != "" && !strings.Contains(strings.ToLower(detail), strings.ToLower(p.Trigger)) {
		detail = p.Trigger + ": " + detail
	}

	return event.Event{
		Source:    SourceName,
		Kind:      h.Product + "/" + h.Name,
		Condition: h.Condition,
		Entity: event.Entity{
			ID: "hook/" + h.Name, Name: name, Kind: "site", MAC: p.MAC,
		},
		Severity: h.Severity,
		Title:    titleFor(h, name),
		Detail:   detail,

		// STAMPED ON ARRIVAL, and said so. Network's Alarm Manager payload
		// carries no controller timestamp at all -- unlike Protect's -- so
		// presenting this as an observation time would send somebody scrubbing
		// to the wrong point in the footage.
		At:              now,
		ReceivedAt:      now,
		AtIsArrivalTime: true,

		Raw: p.Raw,
	}
}

func titleFor(h Hook, name string) string {
	if h.Condition == "" {
		return "Alarm from " + name
	}
	return humanise(h.Condition) + " — " + name
}

func humanise(condition string) string {
	s := strings.ReplaceAll(condition, "-", " ")
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func clientIP(req *http.Request) string {
	host := req.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

// Receipts reports what has arrived at each hook, for the setup checklist and
// the interface.
func (r *Receiver) Receipts() []Receipt {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Receipt, 0, len(r.hooks))
	for _, h := range r.hooks {
		if rec := r.receipts[h.Name]; rec != nil {
			out = append(out, *rec)
		}
	}
	return out
}

// HeaderName is the header UniFi Alarm Manager must be told to send.
const HeaderName = "Authorization"

// HeaderValueFor renders the header value to paste alongside the URL.
//
// A credential, like the URL. Both are needed: the URL says which hook, the
// header says it is really the console.
func HeaderValueFor(h Hook) string {
	if h.Bearer.IsZero() {
		return ""
	}
	return "Bearer " + h.Bearer.Reveal()
}

// URLFor renders the URL an operator must paste into the Alarm Manager rule.
//
// The token is IN the URL, so this string is a credential. It is shown on
// request and never logged.
func URLFor(base string, h Hook) string {
	base = strings.TrimSuffix(strings.TrimSpace(base), "/")
	if base == "" {
		base = "http://<this-machine>:8322"
	}
	return base + PathPrefix + h.Token.Reveal()
}
