// Package webhook POSTs a JSON document to an operator-supplied URL.
//
// The audience is whatever the operator already runs: Home Assistant, Node-RED,
// n8n, a Slack bridge, or a shell script behind a reverse proxy. That audience
// is why this file is shaped the way it is:
//
//  1. THE PAYLOAD IS A PUBLISHED CONTRACT. The moment somebody writes an
//     automation against it, changing a field name breaks them silently -- their
//     flow keeps running and keeps doing nothing. So the envelope carries a
//     version number, every key is always present, and the golden test in
//     webhook_test.go pins the exact bytes.
//
//  2. THE RECEIVER IS USUALLY UNAUTHENTICATED. A Home Assistant webhook URL is
//     an unguessable id in the path and nothing more -- a bearer credential by
//     any other name. Signing exists so a receiver that cares can prove a
//     request came from us and is not a replay.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// PayloadVersion is the envelope version. It changes only when a field changes
// meaning or disappears, and changing it is a decision to break every automation
// already written against version 1.
const PayloadVersion = 1

// Header names used for signing. Exported because a receiver's author has to
// type them exactly, and the operator documentation is generated from here.
//
// Spelled "Notifymatrix", not "NotifyMatrix", and that lowercase m is not a
// typo. net/http canonicalises every header name it writes, so the bytes that
// actually go on the wire are X-Notifymatrix-Signature whatever these constants
// say. HTTP header names are case-insensitive and most receivers do not care --
// but a jq handler, an n8n expression indexing $request.headers, or any raw
// dictionary lookup is case-SENSITIVE, and a receiver that misses the header
// either treats every signed alert as unsigned or rejects the lot. Both look
// like an ordinary 4xx from here, so the operator gets no hint that a spelling
// is the cause. These constants therefore state what is sent, exactly.
const (
	HeaderTimestamp = "X-Notifymatrix-Timestamp"
	HeaderSignature = "X-Notifymatrix-Signature"
)

// Config is everything this channel needs. Plain data: no clients, no state.
type Config struct {
	// ChannelName distinguishes this endpoint from other webhook endpoints.
	//
	// Empty means "webhook", which is what a single configured endpoint is
	// called and what every existing policy and rule already names. A site
	// pushing to more than one receiver -- a home automation box and an
	// on-call service want different documents at different times -- needs
	// each to be addressable by an escalation rung, and a rung names a
	// channel by its name.
	ChannelName string

	// URL is where the document is POSTed.
	//
	// It is treated as a credential in its own right, because for most receivers
	// it IS one: Home Assistant, Slack and n8n all put an unguessable token in
	// the path or the query string, and anyone holding the URL can inject fake
	// alarms. It therefore never appears whole in an error -- see redactURL.
	URL string

	// Secret, when set, enables request signing. A secret.Secret rather than a
	// string so that a Config reaching a log line through %v cannot leak it.
	Secret secret.Secret

	// Headers are static headers added to every request, for receivers that want
	// an API key or a routing hint. They cannot override the signing headers or
	// Content-Type -- New refuses those keys; see reservedHeaders.
	Headers map[string]string

	// InsecureSkipVerify disables certificate verification.
	//
	// It exists because the realistic deployment is a Home Assistant box on the
	// same LAN with a self-signed certificate, and the alternative an operator
	// reaches for is plain HTTP -- which loses confidentiality as well as
	// authenticity. Skipping verification keeps the traffic encrypted against a
	// passive observer and gives up only proof of who is on the other end. That
	// trade is defensible on a LAN, which is why this is per-endpoint and opt-in
	// rather than a global switch.
	InsecureSkipVerify bool
}

// Channel POSTs alerts to one webhook endpoint.
type Channel struct {
	cfg     Config
	url     *url.URL
	headers map[string]string // validated and copied at New
	http    *http.Client

	// now is a field so the signature tests can pin a timestamp. Production
	// always uses time.Now.
	now func() time.Time

	// backoff and sleep are fields rather than package constants so the retry
	// test can exercise the real loop in milliseconds. A retry test that
	// actually waits fifteen seconds is a test nobody runs.
	backoff []time.Duration
	sleep   func(ctx context.Context, d time.Duration) error
}

// retryBackoff is the bounded ladder for a retryable STATUS -- 429 and 5xx, and
// nothing else.
//
// IT DOES NOT COVER A RECEIVER THAT IS NOT ANSWERING. A restarting Home
// Assistant or a container being redeployed does not reply 503; it refuses the
// connection, or drops it, or fails the TLS handshake. Those come back from
// attempt as a plain transport error, are not wrapped in retryableError, and
// are reported after a single try. That is deliberate: the escalation ladder
// above this channel is what provides persistence, and a receiver that is down
// entirely is precisely the case it exists to handle -- with the incident state
// that makes retrying safe, which this channel does not have. Anybody tempted
// to widen the ladder to cover connection failures should change the escalation
// policy instead.
//
// Shorter than the ntfy channel's ladder, deliberately. A webhook receiver is
// typically on the same LAN, so the failures it does report are fast and local
// -- an overloaded instance answering 502 through its own proxy, a receiver
// shedding load with 503 -- and those clear in seconds or not at all. The
// trade: a receiver that is failing for a full minute is not waited out here,
// because holding the channel's single queue worker for a minute delays every
// alert queued behind this one.
//
// The exact rungs are a judgement, not a derivation: four attempts inside
// fifteen seconds covers a brief overload without becoming its own nag loop.
var retryBackoff = []time.Duration{1 * time.Second, 4 * time.Second, 10 * time.Second}

// maxRetryAfter bounds how far we will trust a server-advised delay. A
// Retry-After of 600 means the receiver has decided this alarm can wait ten
// minutes, and it is not the thing that gets to decide that.
const maxRetryAfter = 15 * time.Second

// maxErrorBody caps how much of a failure response is quoted back. Receivers
// answer errors with anything from a one-line JSON object to a full HTML error
// page from whatever proxy sits in front of them, and that page helps nobody and
// is not going in an incident record.
const maxErrorBody = 512

// reservedHeader is a name an operator may not set, and the reason why, because
// a refusal that does not say why just gets worked around.
type reservedHeader struct {
	name string
	why  string
}

// reservedHeaders may never be set by an operator's static header map.
//
// Not tidiness. An operator who sets the signature header by hand -- copying a
// value out of a request that worked, say -- produces requests that verify
// against a constant, which is worse than unsigned because the receiver believes
// it checked something. Overriding Content-Type breaks every receiver's parser
// instead, which at least fails loudly.
//
// Content-Length and Transfer-Encoding are here for a different reason: net/http
// computes the framing from the body and ignores anything the header map says
// about it, so setting either was accepted at config time and then silently did
// nothing. Silence is the one outcome this file is built to avoid, and there is
// no legitimate value for them anyway -- so they are refused rather than
// honoured. Host is NOT in this set; see the loop in attempt.
var reservedHeaders = map[string]reservedHeader{
	http.CanonicalHeaderKey(HeaderSignature): {HeaderSignature,
		"it would break signature verification on every receiver"},
	http.CanonicalHeaderKey(HeaderTimestamp): {HeaderTimestamp,
		"it would break signature verification on every receiver"},
	http.CanonicalHeaderKey("Content-Type"): {"Content-Type",
		"every receiver parses this payload as application/json"},
	http.CanonicalHeaderKey("Content-Length"): {"Content-Length",
		"net/http frames the request from the body and would discard this silently"},
	http.CanonicalHeaderKey("Transfer-Encoding"): {"Transfer-Encoding",
		"net/http frames the request from the body and would discard this silently"},
}

// New builds a channel. A nil client means a fresh one with a timeout.
func New(cfg Config, client *http.Client) (*Channel, error) {
	raw := strings.TrimSpace(cfg.URL)
	if raw == "" {
		return nil, errors.New("webhook: url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Deliberately NOT wrapped: net/url's parse error quotes the whole input
		// back, and that is the one place a token-bearing URL would escape into
		// an incident record.
		return nil, errors.New("webhook: url is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("webhook: url must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("webhook: url has no host")
	}
	cfg.URL = raw

	// Copied rather than referenced: the caller keeps its map, and a config
	// reload that mutates it must not silently re-header a live channel.
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		name := strings.TrimSpace(k)
		if name == "" {
			return nil, errors.New("webhook: a static header has an empty name")
		}
		if reserved, ok := reservedHeaders[http.CanonicalHeaderKey(name)]; ok {
			return nil, fmt.Errorf("webhook: static header %q is set by this channel and cannot be "+
				"overridden (%s); remove it", reserved.name, reserved.why)
		}
		// The value is TRIMMED rather than refused for surrounding whitespace.
		// An API key pasted out of a file or a terminal arrives with a trailing
		// newline far more often than anyone intends -- the same paste artefact
		// internal/secret absorbs for credential files -- and HTTP strips
		// optional whitespace around a field value anyway, so nothing is lost.
		value := strings.TrimSpace(v)
		// Whatever survives the trim has to be legal, and has to be checked HERE.
		// net/http rejects an illegal name or value inside Transport.roundTrip,
		// which means the config loads clean and then every single delivery dies
		// before the request leaves the process, with an error naming net/http
		// rather than the field the operator typed. Nothing leaks either way --
		// Go deliberately omits the value from that error -- so this is purely
		// about moving a permanently dead alert channel back to a config refusal
		// the operator can read.
		if !validHeaderFieldName(name) {
			return nil, fmt.Errorf("webhook: static header name %q is not a legal HTTP header name "+
				"(letters, digits and !#$%%&'*+-.^_`|~ only); every request would be rejected before it was sent", name)
		}
		if !validHeaderFieldValue(value) {
			// The value is NOT quoted back: it is frequently an API key, and this
			// error is read off a config-load failure that gets logged.
			return nil, fmt.Errorf("webhook: the value of static header %q contains a control character "+
				"(an embedded newline, usually); every request would be rejected before it was sent", name)
		}
		headers[name] = value
	}

	hc, err := buildClient(cfg, client)
	if err != nil {
		return nil, err
	}
	return &Channel{
		cfg:     cfg,
		url:     u,
		headers: headers,
		http:    hc,
		now:     time.Now,
		backoff: retryBackoff,
		sleep:   sleepCtx,
	}, nil
}

// validHeaderFieldName reports whether s is an RFC 7230 token, which is what
// net/http will accept as a header name.
//
// Reimplemented rather than imported from golang.org/x/net/http/httpguts: the
// rule is a dozen lines and this repository is not worth a new module
// dependency for it.
func validHeaderFieldName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// validHeaderFieldValue mirrors what net/http's transport accepts: any byte
// except a control character, with tab excepted. Bytes above ASCII are allowed
// through because net/http allows them, and refusing them here would reject a
// value the transport would have sent.
func validHeaderFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < ' ' && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// buildClient copies the caller's client rather than mutating it.
//
// Mutating it would change redirect handling and certificate verification for
// every other user of that client, which in this process includes the clients
// talking to the UniFi consoles.
func buildClient(cfg Config, client *http.Client) (*http.Client, error) {
	hc := &http.Client{Timeout: 20 * time.Second}
	if client != nil {
		copied := *client
		hc = &copied
	}
	hc.CheckRedirect = refuseRedirect
	if cfg.InsecureSkipVerify {
		t, err := insecureTransport(hc.Transport)
		if err != nil {
			return nil, err
		}
		hc.Transport = t
	}
	return hc, nil
}

// ErrRedirect is returned when the endpoint answers with a redirect.
//
// REDIRECTS ARE NOT FOLLOWED. Go's default would resend the body -- with its
// valid signature and its live ack URL -- to whatever host the Location header
// names. That turns a mistyped hostname, or a receiver whose DNS is hijacked,
// into an alert feed for a third party, and the signature that third party
// forwards on would still verify. The operator configured one host, so one host
// is what we talk to.
var ErrRedirect = errors.New("webhook: endpoint redirected and redirects are not followed")

func refuseRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("%w (to %s)", ErrRedirect, redactURL(req.URL))
}

func insecureTransport(base http.RoundTripper) (http.RoundTripper, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	t, ok := base.(*http.Transport)
	if !ok {
		// A custom RoundTripper owns its own TLS decisions and there is no way to
		// reach inside it. Returning it unchanged would be worse than refusing:
		// the operator ticked the box, saw the config save, and would discover at
		// 3am that the alert died on the certificate error the setting was meant
		// to waive. Refusing at New puts the failure where it can be read.
		return nil, errors.New("webhook: insecure_skip_verify was requested, but this endpoint's HTTP " +
			"client uses a custom transport whose certificate verification cannot be changed from here")
	}
	c := t.Clone()
	if c.TLSClientConfig == nil {
		c.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	// Operator-requested, per endpoint, and the reasoning is on Config.
	c.TLSClientConfig.InsecureSkipVerify = true
	return c, nil
}

// Name is the identifier used in policy stage lists and diagnostics.
func (c *Channel) Name() string {
	if n := strings.TrimSpace(c.cfg.ChannelName); n != "" {
		return n
	}
	return DefaultName
}

// DefaultName is what a webhook endpoint is called when it is the only one.
const DefaultName = "webhook"

// Send delivers one alert.
func (c *Channel) Send(ctx context.Context, a channel.Alert) error {
	return c.post(ctx, build(a, false))
}

// Test posts the same envelope with "test" set.
//
// The flag exists so a receiver can tell a drill from a real alarm without
// guessing at the title. Without it the only way to recognise a self-test is to
// string-match the title -- and an automation that unlocks a door on a critical
// alert would run during the scheduled self-test.
func (c *Channel) Test(ctx context.Context) error {
	now := c.now()
	return c.post(ctx, payload{
		Version:    PayloadVersion,
		Test:       true,
		IncidentID: "test",
		Severity:   string(incident.SeverityInfo),
		Title:      "UniFi Notification Matrix test",
		Body:       "Delivery test. If this arrived, the webhook is configured correctly.",
		OpenedAt:   stamp(now),
		At:         stamp(now),
	})
}

// payload is the published contract. FIELD NAMES AND ORDER ARE FROZEN for a
// given Version, and no field is omitempty: a receiver that reads
// payload["entity"] must not have to distinguish "absent" from "empty".
//
// Alert.Snapshot is deliberately absent. Base64 of a UniFi JPEG runs to a
// hundred kilobytes or more, which would multiply the size of an ordinary alert
// by two or three orders of magnitude -- on every delivery, including every
// escalation repeat -- for a field that Home Assistant, Node-RED, n8n and a
// Slack bridge all ignore. A receiver that wants the image can fetch it from the
// incident record.
type payload struct {
	Version int  `json:"version"`
	Test    bool `json:"test"`

	IncidentID string `json:"incident_id"`
	Severity   string `json:"severity"`

	Title  string `json:"title"`
	Body   string `json:"body"`
	Entity string `json:"entity"`

	AckURL string `json:"ack_url"`

	// Timestamps are pre-formatted strings rather than time.Time so the wire
	// format is RFC3339 and stays RFC3339: encoding/json emits RFC3339Nano
	// whenever a source happens to supply sub-second precision, which silently
	// changes the string a receiver's parser sees, and a zero time would go out
	// as the year 1. Empty means "we do not have this".
	OpenedAt string `json:"opened_at"`
	At       string `json:"at"`

	// AtIsArrivalTime says "at" is when WE received the event, not when it
	// happened, because the source supplied no time of its own. Anyone who
	// scrubs footage to this timestamp will find nothing, so it has to be said.
	AtIsArrivalTime bool `json:"at_is_arrival_time"`

	Stage  int `json:"stage"`
	Repeat int `json:"repeat"`
}

func build(a channel.Alert, test bool) payload {
	return payload{
		Version:         PayloadVersion,
		Test:            test,
		IncidentID:      a.IncidentID,
		Severity:        string(a.Severity),
		Title:           a.Title,
		Body:            a.Body,
		Entity:          a.Entity,
		AckURL:          a.AckURL,
		OpenedAt:        stamp(a.OpenedAt),
		At:              stamp(a.At),
		AtIsArrivalTime: a.AtIsArrivalTime,
		Stage:           a.Stage,
		Repeat:          a.Repeat,
	}
}

// stamp renders a timestamp in the offset it arrived in rather than normalising
// to UTC. A judgement: RFC3339 carries the offset either way, so nothing is lost
// for a parser, and an operator reading raw JSON in a Node-RED debug pane should
// see the wall clock the camera saw rather than a number to convert at 3am.
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func (c *Channel) post(ctx context.Context, p payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		// Every field is a string, bool or int, so this cannot fail in practice.
		// It is still not swallowed: a silent non-delivery is the one outcome
		// this product must never produce.
		return fmt.Errorf("webhook: encoding the payload: %w", err)
	}

	var last error
	for attempt := 0; ; attempt++ {
		wait, err := c.attempt(ctx, body)
		if err == nil {
			return nil
		}
		last = err

		var re *retryableError
		if !errors.As(err, &re) || attempt >= len(c.backoff) {
			return last
		}
		delay := c.backoff[attempt]
		if wait > 0 && wait <= maxRetryAfter {
			delay = wait
		}
		if !fitsInBudget(ctx, delay) {
			// The wait cannot finish inside this delivery's deadline, so sitting
			// it out changes nothing except when the failure is reported -- and
			// it holds the channel's single queue worker for the length of the
			// rung, delaying every alert behind this one for a sleep already
			// known to be futile.
			return fmt.Errorf("%w (no time left in this delivery's budget to wait it out)", last)
		}
		if serr := c.sleep(ctx, delay); serr != nil {
			return fmt.Errorf("%w (gave up waiting out a retryable failure: %v)", last, serr)
		}
	}
}

// attempt performs one POST. It returns the server-advised delay alongside the
// error so the caller can decide whether to honour it.
func (c *Channel) attempt(ctx context.Context, body []byte) (time.Duration, error) {
	// A fresh reader per attempt. Reusing one across a retry sends an empty body
	// the second time, which a receiver accepts as a valid-looking empty alert
	// rather than rejecting -- exactly the kind of quiet degradation this product
	// cannot have.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("webhook: building request for %s: %w", c.redacted(), err)
	}

	// Operator headers first, ours second. New already refuses the reserved
	// names, so this ordering is belt and braces -- but it means a future
	// addition to the reserved set cannot be defeated by a config written before
	// that addition existed.
	for k, v := range c.headers {
		if strings.EqualFold(k, "Host") {
			// net/http writes the Host header from req.Host and ignores whatever
			// the header map says, so a Host set here would be accepted at config
			// time and then dropped on every request -- and behind a LAN reverse
			// proxy doing vhost routing, every alert would land on the default
			// vhost: a 404, correctly not retried, with an error that says
			// nothing about the header that caused it.
			//
			// Honoured rather than refused, because a Host IS the routing hint
			// Config.Headers documents and an operator behind such a proxy has no
			// other way to express it. The trade is that this one name behaves
			// differently from the rest of the map; the alternative is telling
			// that operator to run a second proxy.
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	if !c.cfg.Secret.IsZero() {
		// Signed per attempt, not once per delivery. A retry that reused the
		// first attempt's timestamp would arrive up to fifteen seconds stale and
		// be rejected by any receiver enforcing a tight freshness window --
		// silently, and as a replay, which is the worst way to fail.
		ts := strconv.FormatInt(c.now().Unix(), 10)
		req.Header.Set(HeaderTimestamp, ts)
		req.Header.Set(HeaderSignature, "sha256="+sign(c.cfg.Secret, ts, body))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// NOTHING TO CLOSE HERE, and that is worth stating because it looks like
		// an omission. Client.Do returns BOTH a response and an error when
		// CheckRedirect refuses -- a Go 1 compatibility quirk -- but it has
		// already closed that body before returning it, which its documentation
		// promises and Client.do implements by calling closeBody on exactly that
		// path. A drain and Close here would read a closed body, achieve nothing,
		// and teach the next channel a net/http failure mode that does not exist.
		return 0, fmt.Errorf("webhook: posting to %s: %w", c.redacted(), scrubTransportError(err))
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode/100 == 2 {
		return 0, nil
	}
	detail := readErrorBody(resp.Body)
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode/100 == 5 {
		return retryAfter(resp.Header.Get("Retry-After")),
			&retryableError{endpoint: c.redacted(), status: resp.Status, detail: detail}
	}
	// A 4xx is the receiver saying the request itself is wrong: a revoked token,
	// a path that no longer exists, a body it will not parse. Retrying that
	// produces the same answer four times over and delays the honest failure
	// report the escalation ladder needs.
	return 0, fmt.Errorf("webhook: %s rejected the post: %s%s", c.redacted(), resp.Status, detail)
}

// signingMaterial is the timestamp, a ".", then the exact request body bytes.
//
// THE TIMESTAMP IS INSIDE THE SIGNATURE, and that is the whole point. A
// signature computed over the body alone stays valid forever: anyone who
// captures one request -- an intermediate proxy, anything on the LAN watching a
// plain-HTTP receiver -- can replay that exact pair whenever they like and the
// receiver cannot tell it from a fresh alert. Binding the timestamp in lets the
// receiver reject anything outside a freshness window, and an attacker cannot
// move the timestamp forward without invalidating the signature.
//
// The "." separator is not decoration either: without an unambiguous boundary,
// timestamp 12 with body "34..." and timestamp 1234 with body "..." hash the
// same material, so two different requests could share one signature.
func signingMaterial(ts string, body []byte) []byte {
	m := make([]byte, 0, len(ts)+1+len(body))
	m = append(m, ts...)
	m = append(m, '.')
	m = append(m, body...)
	return m
}

func sign(s secret.Secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(s.Reveal()))
	mac.Write(signingMaterial(ts, body))
	return hex.EncodeToString(mac.Sum(nil))
}

// retryableError marks a status worth retrying: 429 and 5xx, nothing else.
type retryableError struct {
	endpoint string
	status   string
	detail   string
}

func (e *retryableError) Error() string {
	return fmt.Sprintf("webhook: %s could not accept the post: %s%s", e.endpoint, e.status, e.detail)
}

// scrubTransportError removes the URL that net/http puts in every error.
//
// http.Client.Do wraps failures in *url.Error, whose Error() prints the full
// request URL, query string included. Since that URL is frequently the
// receiver's only credential, and this error string is stored on the incident
// and rendered in the UI, the wrapper has to go. Unwrapping keeps the cause --
// connection refused, a TLS failure, our own redirect refusal -- and drops only
// the part we already print redacted.
func scrubTransportError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

// redacted renders the endpoint as scheme, host and port. No path, no query, no
// userinfo.
//
// THE PATH IS THE CREDENTIAL for every receiver this channel names, not just the
// query string: Home Assistant is /api/webhook/<id>, Slack is
// /services/T../B../<token>, n8n is /webhook/<uuid>. Anyone holding one of those
// paths can inject fake alarms into the operator's automation or post into their
// Slack -- and these error strings are stored on the incident record and
// rendered in the web UI, so keeping the path there handed the credential to
// everyone who can read an incident.
//
// The trade: an error can no longer say WHICH hook failed when one host serves
// several. A channel is configured with exactly one URL and names itself in
// every message, so the host is enough to identify it, and that diagnostic
// detail is worth far less than the token. Same reasoning as the ntfy channel,
// which drops its topic for the same reason.
func (c *Channel) redacted() string { return redactURL(c.url) }

func redactURL(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// retryAfter reads the delta-seconds form only.
//
// The HTTP-date form needs both clocks to agree, and is not worth the code: the
// payoff is a few seconds of accuracy on a delay we already bound.
func retryAfter(h string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || secs < 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

func readErrorBody(r io.Reader) string {
	b, err := io.ReadAll(io.LimitReader(r, maxErrorBody))
	if err != nil || len(bytes.TrimSpace(b)) == 0 {
		return ""
	}
	return ": " + strings.Join(strings.Fields(string(b)), " ")
}

// minAttemptBudget is the slack a retry needs after its backoff: waiting out a
// failure is only worth doing if there is still time to make the request the
// wait was for.
const minAttemptBudget = 250 * time.Millisecond

// fitsInBudget reports whether ctx leaves room to wait d and still post. A ctx
// with no deadline always fits: the bound is then the ladder itself.
func fitsInBudget(ctx context.Context, d time.Duration) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return time.Now().Add(d + minAttemptBudget).Before(deadline)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// String renders the channel without its credentials.
//
// Two of them here, not one: the signing secret, and the URL itself -- which
// for most receivers carries an unguessable token in its path or query and is
// therefore a credential in its own right. redactURL handles the second.
//
// See the identical method on the ntfy channel for why this is necessary at
// all: secret.Secret redaction does not survive being reached through an
// unexported struct field.
func (c Channel) String() string {
	return fmt.Sprintf("webhook{url:%s signed:%t headers:%d secret:<redacted>}",
		redactURL(c.url), !c.cfg.Secret.IsZero(), len(c.headers))
}
