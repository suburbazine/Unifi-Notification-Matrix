// Package ntfy delivers alerts through an ntfy server -- ntfy.sh or a
// self-hosted instance.
//
// Two facts about ntfy drive nearly every decision in this file, and both were
// measured against a live server rather than read off the docs:
//
//  1. Text fields go as URL QUERY PARAMETERS, never as headers. ntfy accepts
//     both, but an HTTP header cannot carry a newline and needs RFC 2047
//     encoding for anything outside ASCII. Alert bodies are multi-line by
//     construction and entity names are whatever the operator typed into the
//     UniFi console, so the header path loses both. Query parameters carry
//     newlines and UTF-8 through ordinary percent-encoding.
//
//  2. ntfy renders a tag that maps to an emoji as an emoji PREPENDED TO THE
//     TITLE, and only non-emoji tags appear as visible text under the message.
//     So the tag list is one severity-calibrated emoji plus readable words --
//     see tagsFor.
package ntfy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// DefaultServer is the public ntfy instance.
const DefaultServer = "https://ntfy.sh"

// Config is everything this channel needs. Plain data: no clients, no state.
type Config struct {
	// ServerURL is the base URL of the ntfy instance. Empty means
	// DefaultServer. Self-hosting is a first-class case, not an afterthought:
	// a security product that can only notify through somebody else's server
	// is not one most of this audience will run.
	ServerURL string

	// Topic is the topic to publish to.
	Topic string

	// Token is an optional access token for a protected topic. It is a
	// secret.Secret rather than a string so that a Config reaching a log line
	// through %v cannot leak it, and it travels in the Authorization header --
	// ntfy also accepts ?auth=, and we deliberately do not use it, because a
	// credential in a URL ends up in every proxy and server log on the path.
	Token secret.Secret
}

// Channel publishes alerts to one ntfy topic.
type Channel struct {
	cfg  Config
	base *url.URL
	http *http.Client

	// backoff and sleep are fields rather than package constants so the retry
	// test can exercise the real loop in milliseconds. A 429 test that
	// actually waits thirty seconds is a test nobody runs.
	backoff []time.Duration
	sleep   func(ctx context.Context, d time.Duration) error
}

// retryBackoff is the bounded ladder for a rate-limited publish.
//
// The trade being made: an alert that lands ten minutes late is nearly
// useless, but an alert dropped because a shared quota was briefly exhausted
// is worse -- ntfy.sh rate-limits per visitor IP, so one noisy neighbour on
// the same egress address can 429 a genuine alarm. Four attempts inside half a
// minute buys past that without turning the channel into its own nag loop.
//
// NOTHING ELSE IS RETRIED. The escalation ladder above this channel is what
// provides persistence, so a channel that retries a 500 for minutes is
// duplicating a job already being done better, and doing it without any of the
// incident state that makes the retry safe.
var retryBackoff = []time.Duration{2 * time.Second, 8 * time.Second, 20 * time.Second}

// maxRetryAfter bounds how far we will trust a server-advised delay.
//
// Honoured only in its delta-seconds form and only when sane: a Retry-After of
// 900 means the server has decided this alert can wait fifteen minutes, and it
// is not the thing that gets to decide that.
const maxRetryAfter = 30 * time.Second

// maxErrorBody caps how much of a failure response is quoted back. The body of
// an ntfy error is a short JSON object; anything longer is a proxy's HTML
// error page, which helps nobody and is not going in an incident record.
const maxErrorBody = 512

// New builds a channel. A nil client means http.DefaultClient with a timeout.
func New(cfg Config, client *http.Client) (*Channel, error) {
	raw := strings.TrimSpace(cfg.ServerURL)
	if raw == "" {
		raw = DefaultServer
	}
	base, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("ntfy: server url: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("ntfy: server url must be http or https, got %q", base.Scheme)
	}
	if base.Host == "" {
		return nil, errors.New("ntfy: server url has no host")
	}
	topic := strings.Trim(strings.TrimSpace(cfg.Topic), "/")
	if topic == "" {
		return nil, errors.New("ntfy: topic is required")
	}
	if strings.ContainsAny(topic, "/?#") {
		return nil, fmt.Errorf("ntfy: topic %q must be a single path segment", topic)
	}
	cfg.Topic = topic

	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &Channel{
		cfg:     cfg,
		base:    base,
		http:    client,
		backoff: retryBackoff,
		sleep:   sleepCtx,
	}, nil
}

// Name is the identifier used in policy stage lists and diagnostics.
func (c *Channel) Name() string { return "ntfy" }

// Send delivers one alert.
func (c *Channel) Send(ctx context.Context, a channel.Alert) error {
	return c.publish(ctx, build(a))
}

// Test publishes a harmless message proving the topic and any token work.
//
// Sent at default priority rather than low on purpose: the point of the test
// is to prove a human gets woken, and a silent delivery proves half of that.
func (c *Channel) Test(ctx context.Context) error {
	return c.publish(ctx, publication{
		title:    "UniFi Notification Matrix test",
		message:  "Delivery test. If this arrived, ntfy is configured correctly.",
		priority: "default",
		tags:     []string{"white_check_mark", "notification matrix", "test"},
	})
}

// publication is one ntfy request, already formatted.
type publication struct {
	title    string
	message  string
	priority string
	tags     []string
	actions  string
	filename string
	body     []byte // the attachment, if any
}

func (c *Channel) publish(ctx context.Context, p publication) error {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + c.cfg.Topic

	q := url.Values{}
	if p.title != "" {
		q.Set("title", p.title)
	}
	if p.message != "" {
		q.Set("message", p.message)
	}
	if p.priority != "" {
		q.Set("priority", p.priority)
	}
	if len(p.tags) > 0 {
		q.Set("tags", strings.Join(p.tags, ","))
	}
	if p.actions != "" {
		q.Set("actions", p.actions)
	}
	if p.filename != "" {
		q.Set("filename", p.filename)
	}
	u.RawQuery = q.Encode()

	var last error
	for attempt := 0; ; attempt++ {
		wait, err := c.attempt(ctx, &u, p.body)
		if err == nil {
			return nil
		}
		last = err

		var rl *rateLimitedError
		if !errors.As(err, &rl) || attempt >= len(c.backoff) {
			return last
		}
		delay := c.backoff[attempt]
		if wait > 0 && wait <= maxRetryAfter {
			delay = wait
		}
		if !fitsInBudget(ctx, delay) {
			// The wait cannot finish inside this delivery's deadline, so
			// sitting it out changes nothing except when the failure is
			// reported. It matters because the caller is a single-worker
			// per-channel queue: a sleep that is already known to be futile
			// holds the worker and delays every alert queued behind this one
			// by the length of the rung. Report the rate limit now.
			return fmt.Errorf("%w (no time left in this delivery's budget to wait it out)", last)
		}
		if serr := c.sleep(ctx, delay); serr != nil {
			return fmt.Errorf("%w (gave up waiting out a rate limit: %v)", last, serr)
		}
	}
}

// attempt performs one publish. It returns the server-advised delay alongside
// the error so the caller can decide whether to honour it.
func (c *Channel) attempt(ctx context.Context, u *url.URL, body []byte) (time.Duration, error) {
	// A fresh reader per attempt. Reusing one across a retry sends an empty
	// body the second time, which silently drops the snapshot rather than
	// failing -- exactly the kind of quiet degradation this product cannot
	// have.
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("ntfy: building request for %s: %w", redact(u), err)
	}
	if len(body) > 0 {
		// Snapshots are the only body this channel ever sends.
		req.Header.Set("Content-Type", "image/jpeg")
	}
	if !c.cfg.Token.IsZero() {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token.Reveal())
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("ntfy: publishing to %s: %w%s", redact(u), err,
			reachabilityNote(ctx, c.base))
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode/100 == 2 {
		return 0, nil
	}
	detail := readErrorBody(resp.Body)
	if resp.StatusCode == http.StatusTooManyRequests {
		return retryAfter(resp.Header.Get("Retry-After")),
			&rateLimitedError{server: redact(u), detail: detail}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return 0, fmt.Errorf("ntfy: %s rejected the publish: %s%s\n%s",
			redact(u), resp.Status, detail, unauthorisedAdvice(!c.cfg.Token.IsZero()))
	}
	return 0, fmt.Errorf("ntfy: %s rejected the publish: %s%s", redact(u), resp.Status, detail)
}

// unauthorisedAdvice explains a 401 from ntfy, because the useful response is
// the opposite of the obvious one.
//
// A token that is wrong is rejected even on a topic that needs no token at
// all: ntfy validates the credential it was given before it considers whether
// the topic was open. So the fix for "401 on my public topic" is usually to
// REMOVE the token, which nobody guesses -- the instinct is to go and find a
// better one.
func unauthorisedAdvice(hadToken bool) string {
	if !hadToken {
		return "       This topic requires a token. Create one at your ntfy server " +
			"(Account > Access tokens on ntfy.sh) and put it in the ntfy channel " +
			"settings."
	}
	return "       The token was sent and refused. Note that ntfy checks a token " +
		"BEFORE it checks whether the topic needed one, so a stale or mistyped " +
		"token fails even on a topic that is open to anybody -- if yours is a " +
		"public topic, clearing the token is the fix. Otherwise the token has " +
		"expired, or lacks write access to this topic."
}

// reachabilityNote says whether the server can be connected to at all.
//
// Go reports a dial that timed out and a server that accepted the connection
// and never answered with the SAME text -- "Client.Timeout exceeded while
// awaiting headers" -- because the client deadline covers both. Those are
// different faults with different fixes: one is DNS, a firewall or a blocked
// address, the other is a service that is up and struggling. Telling them
// apart matters enough to spend one short TCP dial on it.
//
// Observed: a machine whose firewall was dropping traffic to ntfy.sh reported
// a timeout indistinguishable from the public service being slow, and the
// operator went looking for a better token.
func reachabilityNote(ctx context.Context, base *url.URL) string {
	host := hostPortOf(base)
	if host == "" {
		return ""
	}
	// Short, and bounded separately from the request that already failed --
	// this runs on a path where something has just gone wrong and must not
	// become a second thing that hangs.
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reachabilityProbe)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(probeCtx, "tcp", host)
	if err != nil {
		return "\n       Could not open a connection to " + host + " at all, so " +
			"this is not a credentials or topic problem: the address is " +
			"unreachable from this machine. Check DNS, the outbound firewall, " +
			"and whether anything on the network is blocking that host."
	}
	_ = conn.Close()
	return "\n       The connection itself succeeded, so " + host + " is reachable " +
		"and did not answer in time -- the server is up and slow, or the request " +
		"was refused without a reply."
}

// hostPortOf turns the server URL into a dialable host:port.
func hostPortOf(u *url.URL) string {
	if u == nil || u.Host == "" {
		return ""
	}
	if u.Port() != "" {
		return u.Host
	}
	if strings.EqualFold(u.Scheme, "http") {
		return u.Hostname() + ":80"
	}
	return u.Hostname() + ":443"
}

// reachabilityProbe bounds the diagnostic dial.
const reachabilityProbe = 3 * time.Second

// rateLimitedError marks the one status worth retrying.
type rateLimitedError struct {
	server string
	detail string
}

func (e *rateLimitedError) Error() string {
	return fmt.Sprintf("ntfy: %s rate-limited the publish (429)%s", e.server, e.detail)
}

// retryAfter reads the delta-seconds form only.
//
// The HTTP-date form needs both clocks to agree, and is not worth the code:
// the payoff is a few seconds of accuracy on a delay we already bound.
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

// redact reduces the URL to scheme, host and port.
//
// The path is the topic and the query is the alert text. An ntfy topic is a
// bearer credential in all but name -- anyone who knows it can read every
// alert this installation sends and publish convincing fakes into it -- so it
// does not go in an error that will be stored on the incident and shown in the
// UI. Same reasoning as the redaction applied to Protect's snapshot URLs.
func redact(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// minAttemptBudget is the slack a retry needs after its backoff: waiting out a
// rate limit is only worth doing if there is still time to make the request
// the wait was for.
const minAttemptBudget = 250 * time.Millisecond

// fitsInBudget reports whether ctx leaves room to wait d and still publish.
//
// A ctx with no deadline always fits: the bound is then the ladder itself,
// which is what Test() and any direct caller get.
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

// --- formatting -----------------------------------------------------------

func build(a channel.Alert) publication {
	p := publication{
		title:    titleFor(a),
		message:  messageFor(a),
		priority: priorityFor(a.Severity),
		tags:     tagsFor(a),
	}
	if action, ok := ackAction(a.AckURL); ok {
		p.actions = action
	} else if a.AckURL != "" {
		// The action button could not be expressed safely (see ackAction).
		// Falling back to a plain URL in the body keeps the ack reachable with
		// two taps instead of one, which is worth far more than a tidy body:
		// an alert nobody can acknowledge nags forever.
		p.message = strings.TrimRight(p.message, "\n") + "\n\nAcknowledge: " + a.AckURL
	}
	if len(a.Snapshot) > 0 {
		p.body = a.Snapshot
		p.filename = snapshotName(a)
	}
	return p
}

func titleFor(a channel.Alert) string {
	t := strings.TrimSpace(a.Title)
	if t == "" {
		t = strings.TrimSpace(a.Entity)
	}
	if t == "" {
		t = "UniFi alert"
	}
	// The reminder count goes in the TITLE, not the body. ntfy shows the title
	// on the lock screen and the body may be truncated there; a re-alert that
	// looks identical to the one already swiped away gets swiped away too.
	if a.IsRepeat() {
		t = fmt.Sprintf("%s (reminder %d)", t, a.Repeat)
	}
	return t
}

func messageFor(a channel.Alert) string {
	var b strings.Builder
	if body := strings.TrimSpace(a.Body); body != "" {
		b.WriteString(body)
		b.WriteString("\n\n")
	}
	if line := whenLine(a); line != "" {
		b.WriteString(line)
	}
	if d, ok := openFor(a); ok {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Open for %s", d)
	}
	if b.Len() == 0 {
		return "See the incident for detail."
	}
	return b.String()
}

// whenLine words the timestamp according to whether it is an observation time
// or merely our arrival time.
//
// This is not pedantry. Network's Alarm Manager webhook carries no controller
// timestamp at all, so for those events the only time we have is when we
// happened to receive it -- and someone who reads "at 03:14" will scrub the
// footage to 03:14 and find nothing, then distrust the product rather than the
// timestamp.
func whenLine(a channel.Alert) string {
	if a.At.IsZero() {
		return strings.TrimSpace(a.Entity)
	}
	verb := "at"
	if a.AtIsArrivalTime {
		verb = "received"
	}
	stamp := a.At.Format("15:04:05 MST")
	if entity := strings.TrimSpace(a.Entity); entity != "" {
		return fmt.Sprintf("%s %s %s", entity, verb, stamp)
	}
	return verb + " " + stamp
}

// openFor reports how long the condition has been true, when that is long
// enough to be worth saying.
func openFor(a channel.Alert) (string, bool) {
	if a.OpenedAt.IsZero() || a.At.IsZero() {
		return "", false
	}
	d := a.At.Sub(a.OpenedAt)
	if d < time.Minute {
		return "", false
	}
	return humanDuration(d), true
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}

// priorityFor maps severity onto ntfy's five priorities.
//
// critical is the only one that gets "urgent", because urgent is the priority
// that bypasses Android's Do Not Disturb. Handing it to "high" as well would
// mean every high-severity event pierces DND at 3am, and the operator's
// response to that is to mute the app -- which costs them the critical alerts
// too. The escalation ladder, not the priority field, is what makes a
// high-severity incident eventually impossible to ignore.
func priorityFor(sev incident.Severity) string {
	switch sev {
	case incident.SeverityCritical:
		return "urgent"
	case incident.SeverityHigh:
		return "high"
	case incident.SeverityMedium:
		return "high"
	case incident.SeverityLow:
		return "default"
	case incident.SeverityInfo:
		return "low"
	default:
		// An unrecognised severity is not an excuse to be quiet.
		return "default"
	}
}

// emojiTag is the single tag ntfy will render as an emoji on the title.
//
// One, not several: every emoji-mappable tag is consumed into the title
// prefix, so a handful of them produces a title buried under pictograms and no
// visible tags at all.
func emojiTag(sev incident.Severity) string {
	switch sev {
	case incident.SeverityCritical, incident.SeverityHigh:
		return "rotating_light"
	case incident.SeverityMedium:
		return "warning"
	default:
		return ""
	}
}

func tagsFor(a channel.Alert) []string {
	var tags []string
	if e := emojiTag(a.Severity); e != "" {
		tags = append(tags, e)
	}
	if a.Severity != "" {
		tags = append(tags, string(a.Severity))
	}
	if entity := sanitizeTag(a.Entity); entity != "" {
		tags = append(tags, entity)
	}
	if a.IsRepeat() {
		tags = append(tags, fmt.Sprintf("reminder %d", a.Repeat))
	}
	return tags
}

// sanitizeTag strips what the tag list cannot carry.
//
// Tag values are comma-separated in the wire format, so a camera named
// "Front Door, West" becomes two tags -- one of them the nonsense "West" --
// unless the comma is removed here. Entity names come from whatever the
// operator typed into the UniFi console, so this is a normal case rather than
// an exotic one.
func sanitizeTag(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == ',':
			return -1
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		default:
			return r
		}
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// ackLabel is the action button's text. Deliberately a constant containing no
// comma or semicolon, because those are the short-format separators.
const ackLabel = "Acknowledge"

// ackAction builds ntfy's Actions value for a one-tap acknowledgement.
//
// Short format, per ntfy's documentation:
//
//	<action>, <label>, <param>=<value>, ...[; <next action>]
//
// with values quotable in double or single quotes when they contain a comma or
// a semicolon. The JSON array form is NOT used: ntfy accepts it only when the
// whole notification is published as a JSON body, which would cost us the
// query-parameter delivery this file exists to preserve.
//
// method=GET because the ack route is designed to be opened by a phone and
// answers with a confirmation page; clear=true because an acknowledged alert
// that stays on the lock screen gets acknowledged again on the next glance,
// and the operator learns the button does nothing.
//
// This is NOT wired to ntfy's "click" parameter, which would acknowledge on a
// tap of the notification body itself. Acknowledgement asserts that a human
// saw it; a gesture people make to read a notification must not be able to
// assert that on their behalf.
func ackAction(ackURL string) (string, bool) {
	ackURL = strings.TrimSpace(ackURL)
	if ackURL == "" {
		return "", false
	}
	if strings.ContainsAny(ackURL, "\n\r") {
		return "", false
	}
	quoted, ok := quoteActionValue(ackURL)
	if !ok {
		// Unrepresentable in the short format. Emitting it anyway would
		// produce an action ntfy parses into something else entirely, and a
		// button that acknowledges the wrong thing is worse than no button.
		return "", false
	}
	return fmt.Sprintf("http, %s, %s, method=GET, clear=true", ackLabel, quoted), true
}

func quoteActionValue(v string) (string, bool) {
	if !strings.ContainsAny(v, `,;"'`) {
		return v, true
	}
	switch {
	case !strings.Contains(v, `"`):
		return `"` + v + `"`, true
	case !strings.Contains(v, `'`):
		return `'` + v + `'`, true
	default:
		return "", false
	}
}

// snapshotName names the attachment so a saved image says what it is of.
func snapshotName(a channel.Alert) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, strings.TrimSpace(a.Entity))
	slug = strings.Trim(collapseDashes(slug), "-")
	if slug == "" {
		return "snapshot.jpg"
	}
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-")
	}
	return slug + ".jpg"
}

func collapseDashes(s string) string {
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return s
}

// String renders the channel without its credentials.
//
// Config.Token is a secret.Secret exactly so that %v cannot print it, and that
// protection is DEFEATED the moment the Config is reached through Channel's
// unexported cfg field: fmt calls String() only on a value it may hand to an
// interface, and a value read out of an unexported field is not one, so
// Secret.String() is skipped and the raw token is printed.
//
// Measured, not assumed. Without this method, %v on a *Channel printed
// &{{https://ntfy.sh topic TOKEN...}} while %v on the same Config correctly
// printed {https://ntfy.sh topic <redacted>}.
//
// Nothing formats a *Channel today. This exists because the next diagnostic
// that dumps the configured channels, or an error that interpolates the
// channel rather than its Name(), is an entirely ordinary line to write -- and
// it must not be the line that puts an access token in a log file that
// outlives the incident.
//
// Value receiver, so a stray copy is covered as well as the pointer everything
// actually holds. %#v is NOT covered and cannot be from here: it consults
// GoStringer rather than Stringer, and leaks through a bare Config too.
func (c Channel) String() string {
	return fmt.Sprintf("ntfy{server:%s topic:%q token:<redacted>}", c.base, c.cfg.Topic)
}
