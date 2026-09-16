// Package pushover delivers alerts through Pushover's message API.
//
// Four facts about Pushover drive nearly every decision in this file:
//
//  1. BOTH CREDENTIALS ARE FORM FIELDS. The application token and the user key
//     travel in the x-www-form-urlencoded request body, never in the query
//     string. Pushover's own examples are all POST bodies, but the API would
//     accept a query string just as happily, and that is the trap: a
//     credential in a URL is copied into every proxy access log, every
//     reverse-proxy error page and every packet capture on the path. The body
//     is not a secret channel either, but it is not routinely logged.
//
//  2. PRIORITY 2 IS AN ESCALATION LADDER, AND WE ALREADY HAVE ONE. See the
//     comment on maxPriority. It is the single most important rule here.
//
//  3. EVERY TEXT FIELD IS LENGTH-CAPPED AND PUSHOVER REJECTS THE WHOLE
//     MESSAGE when one is over. A rejected alert is a silent alert, so this
//     file truncates rather than letting the server refuse -- and it truncates
//     the prose, never the acknowledgement link.
//
//  4. PUSHOVER CAN CARRY AN IMAGE, AND THIS CHANNEL DOES NOT SEND ONE.
//     Alert.Snapshot is deliberately dropped: a Pushover alert is text plus
//     the acknowledgement link. This is a choice, not an oversight, and it is
//     written down here because the next person editing this file would
//     otherwise have no way to tell those apart. An attachment would have to
//     go as multipart/form-data rather than the single urlencoded body of
//     fact 1, and Pushover caps it at 2.5 MB and refuses the WHOLE message
//     when it is over -- which by fact 3 is a silent alert traded for a
//     picture. Doing it properly therefore means a size check and a
//     text-only fallback path, which is a change worth making deliberately
//     rather than as a rider on this one.
//
//     The cost until then is real and belongs in plain sight: an operator
//     whose ntfy or email alerts carry the camera frame gets no frame here,
//     on the one notification that decides whether they get out of bed. What
//     they get instead is the ack link, which leads to the incident record,
//     which still holds the snapshot.
package pushover

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
	"time"
	"unicode/utf8"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// DefaultEndpoint is Pushover's message API. There is no self-hosted Pushover,
// so unlike ntfy this is not configurable -- an operator-supplied endpoint
// would be a way to aim the credentials at somebody else's server and nothing
// more.
const DefaultEndpoint = "https://api.pushover.net/1/messages.json"

// Config is everything this channel needs. Plain data: no clients, no state.
type Config struct {
	// Token is the APPLICATION token, from the Pushover application this
	// installation registered. It is a secret.Secret rather than a string so
	// that a Config reaching a log line through %v cannot leak it.
	Token secret.Secret

	// User is the user key or group key the alerts are delivered to. Also a
	// secret: it is not a password, but anyone holding it plus an application
	// token can push arbitrary notifications at this operator's phone, which
	// for a security product means convincing fakes.
	User secret.Secret

	// Device optionally restricts delivery to one registered device name.
	// Empty means every device on the account, which is the right default:
	// this product's job is to wake somebody, and narrowing that to a single
	// handset is a choice the operator has to make deliberately.
	Device string

	// Sound optionally overrides the per-device sound. Empty means the
	// device's own setting.
	Sound string
}

// Channel sends alerts to one Pushover user or group.
type Channel struct {
	cfg  Config
	http *http.Client

	// endpoint, backoff and sleep are fields rather than package constants so
	// the tests can drive the real code paths against an httptest server in
	// milliseconds. A retry test that actually waits fifteen seconds is a test
	// nobody runs, and a test nobody runs is not a specification.
	endpoint string
	backoff  []time.Duration
	sleep    func(ctx context.Context, d time.Duration) error
}

// PRIORITY 2 MUST NEVER BE EMITTED. THIS IS NOT A TUNABLE.
//
// Pushover priority 2 is "emergency": Pushover itself re-alerts the device on
// its own timer until somebody acknowledges IN PUSHOVER. That is a second
// escalation ladder with a second acknowledgement, and this product cannot see
// either of them.
//
// The failure is not theoretical, and it cuts both ways:
//
//   - Acknowledging in Pushover silences the phone while the incident is still
//     open here, so the ladder keeps escalating to email, to the next stage,
//     to whoever is on after that -- and the one person who actually saw it
//     has been told the matter is closed.
//   - Acknowledging the incident here does not stop Pushover, so the handset
//     keeps re-alerting for an incident that was dealt with, and the operator
//     learns to ignore the re-alerts.
//
// Two acknowledgement systems that do not know about each other are strictly
// worse than one, because each one makes the other untrustworthy. The
// escalation ladder above this channel is the one that owns persistence; this
// channel's only job is to deliver once and offer the ack link.
//
// maxPriority is enforced in form() as well as in priorityFor, deliberately
// belt-and-braces: today priorityFor cannot return 2, and the clamp is a guard
// against a future edit that makes it possible, not a reachable branch.
const maxPriority = 1

// minPriority is Pushover's quiet delivery: no sound, no vibration, and no
// notification badge on some clients. The floor is -2 ("no notification at
// all"), which this channel never uses -- a channel configured to alert that
// produces nothing visible is indistinguishable from a broken one.
const minPriority = -1

// Pushover's own field limits, enforced server-side by rejecting the whole
// message. Counted in characters, so this file counts runes.
const (
	maxMessage  = 1024
	maxTitle    = 250
	maxURL      = 512
	maxURLTitle = 100
)

// truncationMarker tells the reader the sentence was cut rather than that the
// event stopped mid-word. Spelled out rather than an ellipsis because at 3am
// "..." reads as trailing off, and the difference matters: a reader who thinks
// they have the whole story will not go and look at the incident.
const truncationMarker = " [truncated]"

// minBodyRunes is the least prose worth keeping alongside an inlined ack link.
// A judgement: below roughly this much the notification is a URL with a word
// in front of it, which tells nobody what happened. See ackTrailer.
const minBodyRunes = 80

// ackLabel is the link text. Capped by maxURLTitle, which it is nowhere near.
const ackLabel = "Acknowledge"

// retryBackoff is the bounded ladder for a rate-limited or broken-server post.
//
// Four attempts inside fifteen seconds. Two quite different failures share
// this ladder, and they need separate arguments:
//
// 5xx is what the ladder is sized for. Pushover is a commercial service behind
// a single API host, so a 5xx is almost always a brief blip that a short retry
// rides out, and losing an alert to a blip is the failure that matters.
//
// 429 is retried in spite of its usual cause rather than because of it.
// Pushover returns 429 when the application's MONTHLY message allowance is
// spent, and that resets at the start of the month -- fifteen seconds of
// sleeping cannot clear it. So in the common case the whole ladder is wasted,
// and because the caller is one worker per channel (see channel.Queue), it
// also delays every alert queued behind this one by that much. We pay it
// anyway: 429 is not only ever the quota. A burst limit at an edge in front of
// the API, or a short Retry-After the server actually supplies, both clear
// inside this ladder, and dropping an alarm that would have gone through is
// worse than sending it fifteen seconds late. What the quota case gets instead
// is an error that names it rather than calling it a momentary blip -- see
// retryableError -- because the operator's remedy there is to buy more
// messages or put this stage on another channel, and no amount of retrying
// substitutes for being told that.
//
// Against both: the whole ladder plus four round trips has to fit inside
// channel.DefaultSendTimeout (60s) or the last rung is one the channel could
// never actually climb -- a collision that has already happened once in this
// codebase and is documented on that constant. Fifteen seconds of sleeping
// leaves a very wide margin.
//
// NOTHING ELSE IS RETRIED. A 4xx is a configuration fact: a bad application
// token will still be bad in eight seconds, and retrying it only delays the
// error message that would have told the operator to fix it.
var retryBackoff = []time.Duration{1 * time.Second, 4 * time.Second, 10 * time.Second}

// maxRetryAfter bounds how far we will trust a server-advised delay. A
// Retry-After of 900 means the server has decided this alert can wait fifteen
// minutes, and the server is not the thing that gets to decide that.
const maxRetryAfter = 30 * time.Second

// maxErrorBody caps how much of a failure response is quoted back. A Pushover
// error is a short JSON object; anything longer is a proxy's HTML error page,
// which helps nobody and is not going into an incident record that the UI
// renders.
const maxErrorBody = 512

// New builds a channel. A nil client means a client with a timeout.
func New(cfg Config, client *http.Client) (*Channel, error) {
	// Both credentials are checked here rather than at first send, because the
	// alternative is discovering the misconfiguration at 3am from a delivery
	// failure on a live incident.
	if cfg.Token.IsZero() {
		return nil, errors.New("pushover: application token is required")
	}
	if cfg.User.IsZero() {
		return nil, errors.New("pushover: user or group key is required")
	}
	cfg.Device = strings.TrimSpace(cfg.Device)
	cfg.Sound = strings.TrimSpace(cfg.Sound)

	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &Channel{
		cfg:      cfg,
		http:     client,
		endpoint: DefaultEndpoint,
		backoff:  retryBackoff,
		sleep:    sleepCtx,
	}, nil
}

// Name is the identifier used in policy stage lists and diagnostics.
func (c *Channel) Name() string { return "pushover" }

// String renders the channel without its credentials.
//
// Config's fields are secret.Secret exactly so that %v cannot print them, and
// that protection is defeated the moment the Config is reached through
// Channel's unexported cfg field: fmt calls String() only on a value it is
// allowed to hand to an interface, and a value read out of an unexported field
// is not one, so Secret.String() is skipped and the raw token is printed.
// Measured rather than assumed -- without this method, %v on a *Channel prints
// &{{tk-... uk-...}} while %v on the same Config prints {<redacted>
// <redacted>}.
//
// Nothing formats a *Channel today. This method exists because the next
// diagnostic that dumps the configured channels, or an error that interpolates
// the channel instead of its Name(), is an entirely ordinary line to write,
// and it must not be the line that writes the application token into a log
// file that outlives the incident.
//
// Value receiver, unlike every other method here, so that a stray Channel copy
// is covered as well as the *Channel everything actually holds.
//
// %#v is NOT covered and cannot be from here: it asks fmt for the raw struct
// and consults GoStringer rather than Stringer, so it leaks through a Config
// too. Nobody reaches for %#v by accident, and the fix for it belongs on
// secret.Secret rather than on every type that holds one.
func (c Channel) String() string {
	return fmt.Sprintf("pushover{endpoint:%s device:%q sound:%q credentials:<redacted>}",
		c.endpoint, c.cfg.Device, c.cfg.Sound)
}

// Send delivers one alert.
func (c *Channel) Send(ctx context.Context, a channel.Alert) error {
	return c.post(ctx, build(a))
}

// Test sends a harmless message proving the token, the user key and the
// device name all work.
//
// Sent quiet (priority -1) on purpose. The trade: a quiet test proves the
// credentials and the delivery path but NOT that this account's alerting
// settings would actually wake somebody, so it is half a proof. The other half
// is bought by pressing "send test" repeatedly while tuning, and a self-test
// that sirens every time it runs is one the operator switches off -- which
// costs the whole proof rather than half of it. Pushover's own per-device
// sound test is the right tool for the other half.
func (c *Channel) Test(ctx context.Context) error {
	return c.post(ctx, message{
		title:    "UniFi Notification Matrix test",
		body:     "Delivery test. If this arrived, Pushover is configured correctly.",
		priority: minPriority,
	})
}

// message is one Pushover request, already formatted and already within every
// length limit.
type message struct {
	title    string
	body     string
	priority int
	url      string
	urlTitle string

	// at is the observation time, sent as Pushover's timestamp. Zero means
	// "let Pushover stamp it on receipt" -- see build.
	at time.Time
}

func (c *Channel) post(ctx context.Context, m message) error {
	form := c.form(m).Encode()

	var last error
	for attempt := 0; ; attempt++ {
		wait, err := c.attempt(ctx, form)
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
			// The wait cannot finish inside this delivery's deadline, so
			// sitting it out changes nothing except when the failure gets
			// reported. It matters because the caller is a single-worker
			// per-channel queue: a sleep already known to be futile holds that
			// worker and delays every alert queued behind this one.
			return fmt.Errorf("%w (no time left in this delivery's budget to wait it out)", last)
		}
		if serr := c.sleep(ctx, delay); serr != nil {
			return fmt.Errorf("%w (gave up waiting out a retry: %v)", last, serr)
		}
	}
}

// attempt performs one post. It returns the server-advised delay alongside the
// error so the caller can decide whether to honour it.
func (c *Channel) attempt(ctx context.Context, form string) (time.Duration, error) {
	// A fresh reader per attempt. Reusing one across a retry posts an empty
	// body the second time, which Pushover answers with a 4xx that looks like
	// a configuration error -- exactly the sort of misdirection that costs an
	// operator an evening.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form))
	if err != nil {
		return 0, fmt.Errorf("pushover: building request for %s: %w", c.endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		// err here can quote the request URL but never the body, so the
		// credentials cannot ride out in it.
		return 0, fmt.Errorf("pushover: posting to %s: %w", c.endpoint, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		_ = resp.Body.Close()
	}()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	detail := c.describe(raw)

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode/100 == 5 {
		return retryAfter(resp.Header.Get("Retry-After")),
			&retryableError{
				status:      resp.Status,
				detail:      detail,
				rateLimited: resp.StatusCode == http.StatusTooManyRequests,
			}
	}
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("pushover: rejected the message: %s%s", resp.Status, detail)
	}

	// A 2xx is necessary but not sufficient: Pushover answers with
	// {"status":1,...} on success and {"status":0,"errors":[...]} on refusal,
	// and the status field is the authoritative one.
	var body apiResponse
	if err := json.Unmarshal(bytes.TrimSpace(raw), &body); err != nil {
		// An unreadable 2xx body probably means the message landed and
		// something in front of the API mangled the response. Reporting
		// success anyway would be guessing, and this product's stated bias
		// (see channel.Queue) is to err toward a duplicate alert and never
		// toward silence: a failure here leaves the incident due, so somebody
		// gets told twice rather than not at all. The duplicate is visible and
		// the operator can act on it; silence is not.
		return 0, fmt.Errorf("pushover: %s but the response was not the expected JSON%s", resp.Status, detail)
	}
	if body.Status != 1 {
		return 0, fmt.Errorf("pushover: refused the message%s", detail)
	}
	return 0, nil
}

// apiResponse is Pushover's answer in both its shapes.
type apiResponse struct {
	Status  int      `json:"status"`
	Request string   `json:"request"`
	Errors  []string `json:"errors"`
}

// describe turns a response body into the operator-facing detail.
//
// Pushover's errors array says exactly what is wrong -- "application token is
// invalid", "user identifier is not a valid user, group, or subscribed user
// key" -- and that is precisely the sentence an operator needs to fix their
// config. Quoting it is worth far more than a tidy error string.
func (c *Channel) describe(raw []byte) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var body apiResponse
	if err := json.Unmarshal(bytes.TrimSpace(raw), &body); err == nil && len(body.Errors) > 0 {
		return ": " + c.scrub(strings.Join(body.Errors, "; "))
	}
	return ": " + c.scrub(strings.Join(strings.Fields(string(raw)), " "))
}

// scrub removes the credentials from anything we are about to quote.
//
// A remote server we do not control decides what is in that body, and that
// body is stored on the incident and rendered in the UI. Pushover does not
// echo credentials back today; this costs two string comparisons and removes
// the need to keep trusting that.
func (c *Channel) scrub(s string) string {
	for _, cred := range []string{c.cfg.Token.Reveal(), c.cfg.User.Reveal()} {
		if cred != "" {
			s = strings.ReplaceAll(s, cred, "<redacted>")
		}
	}
	return s
}

// retryableError marks the statuses worth a second attempt: 429 and 5xx.
type retryableError struct {
	status string
	detail string

	// rateLimited separates the two, because they need different sentences.
	// This error string is stored on the incident and rendered in the UI, so
	// it is the only account of the failure most operators will ever read.
	rateLimited bool
}

// Error says which of the two failures happened, and for a 429 says what the
// operator is actually supposed to do about it.
//
// Both statuses used to share "could not accept the message right now", which
// is true of a 5xx blip and misleading about a 429: Pushover's 429 is normally
// the application's spent monthly allowance, "right now" is the rest of the
// month, and retrying is the one thing that will not help. Naming the quota
// costs a clause and saves an operator an evening of re-testing a token that
// was never wrong.
func (e *retryableError) Error() string {
	if e.rateLimited {
		return fmt.Sprintf("pushover: %s rate-limited the message (%s)%s"+
			" -- a 429 here is usually the application's monthly message allowance,"+
			" which resets at the start of the month rather than in seconds",
			DefaultEndpoint, e.status, e.detail)
	}
	return fmt.Sprintf("pushover: %s could not accept the message right now (%s)%s",
		DefaultEndpoint, e.status, e.detail)
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

// minAttemptBudget is the slack a retry needs after its backoff: waiting out a
// rate limit is only worth doing if there is still time to make the request
// the wait was for.
const minAttemptBudget = 250 * time.Millisecond

// fitsInBudget reports whether ctx leaves room to wait d and still post.
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

// --- the wire form --------------------------------------------------------

func (c *Channel) form(m message) url.Values {
	v := url.Values{}
	// Reveal() at the single point where the value has to go on the wire, so
	// that every use site is greppable.
	v.Set("token", c.cfg.Token.Reveal())
	v.Set("user", c.cfg.User.Reveal())
	v.Set("message", m.body)
	if m.title != "" {
		v.Set("title", m.title)
	}
	if m.url != "" {
		v.Set("url", m.url)
		v.Set("url_title", m.urlTitle)
	}

	p := m.priority
	// See maxPriority. A guard against a future edit, not a reachable branch.
	if p > maxPriority {
		p = maxPriority
	}
	if p < minPriority {
		p = minPriority
	}
	v.Set("priority", strconv.Itoa(p))

	if !m.at.IsZero() {
		v.Set("timestamp", strconv.FormatInt(m.at.Unix(), 10))
	}
	if c.cfg.Device != "" {
		v.Set("device", c.cfg.Device)
	}
	if c.cfg.Sound != "" {
		v.Set("sound", c.cfg.Sound)
	}
	// "html" is deliberately never set. Entity names are whatever the operator
	// typed into the UniFi console, so a camera called "Gate <rear> & side"
	// would render as broken markup or silently vanish. Plain text carries
	// every name intact, and nothing in an alert body needs styling.
	return v
}

// --- formatting -----------------------------------------------------------

func build(a channel.Alert) message {
	m := message{
		title:    titleFor(a),
		priority: priorityFor(a.Severity),
	}

	// Only a real observation time is sent as Pushover's timestamp. When the
	// time is merely when WE received the event, letting Pushover stamp it on
	// receipt is the honest answer -- the notification then says when it
	// arrived, which is what that time actually means. The body says so in
	// words as well; see whenLine.
	if !a.At.IsZero() && !a.AtIsArrivalTime {
		m.at = a.At
	}

	body := bodyFor(a)

	// a.Snapshot is deliberately not sent -- see fact 4 in the package doc for
	// what that costs and why it has not been paid for yet. It is named here
	// because build() is where a reader looks for it.

	// THE ACK LINK IS NEVER TRUNCATED. A cut-off URL is a link that fails when
	// somebody taps it at 3am, which is worse than a cut-off sentence: the
	// sentence still tells them something, the broken link tells them this
	// product does not work. So the link claims its space first and the prose
	// gets whatever is left.
	trailer := ""
	if link, ok := ackForURLField(a.AckURL); ok {
		m.url = link
		m.urlTitle = ackLabel
	} else {
		trailer = ackTrailer(a.AckURL)
	}

	budget := maxMessage - utf8.RuneCountInString(trailer)
	m.body = truncateRunes(body, budget, truncationMarker) + trailer
	if strings.TrimSpace(m.body) == "" {
		m.body = "See the incident for detail."
	}
	return m
}

// ackForURLField reports whether the ack URL can ride in Pushover's own "url"
// field, which renders it as a tappable link under the message.
func ackForURLField(ackURL string) (string, bool) {
	ackURL = strings.TrimSpace(ackURL)
	if ackURL == "" {
		return "", false
	}
	if strings.ContainsAny(ackURL, "\n\r") {
		return "", false
	}
	if utf8.RuneCountInString(ackURL) > maxURL {
		return "", false
	}
	return ackURL, true
}

// ackTrailer is the fallback for an ack URL that Pushover's url field cannot
// carry.
//
// Putting it in the message costs a tap -- select the text, open it -- but an
// alert nobody can acknowledge nags forever, so two taps beats none. It is
// returned as a separate string so build can reserve its length before
// truncating the prose.
//
// Returning "" gives up entirely, which happens only when the link is so long
// that keeping it would leave no room to say what happened. At that point the
// notification has stopped being an alert.
func ackTrailer(ackURL string) string {
	ackURL = strings.TrimSpace(ackURL)
	if ackURL == "" || strings.ContainsAny(ackURL, "\n\r") {
		return ""
	}
	t := "\n\n" + ackLabel + ": " + ackURL
	if utf8.RuneCountInString(t) > maxMessage-minBodyRunes {
		return ""
	}
	return t
}

func titleFor(a channel.Alert) string {
	t := strings.TrimSpace(a.Title)
	if t == "" {
		t = strings.TrimSpace(a.Entity)
	}
	if t == "" {
		t = "UniFi alert"
	}
	// The reminder count goes in the TITLE, not the body: the title is what
	// shows on a locked screen, and a re-alert that looks identical to the one
	// already swiped away gets swiped away too.
	//
	// The marker is appended AFTER truncation so that a long title loses its
	// tail rather than losing the fact that this is the fourth time of asking.
	if a.IsRepeat() {
		marker := fmt.Sprintf(" (reminder %d)", a.Repeat)
		return truncateRunes(t, maxTitle-utf8.RuneCountInString(marker), truncationMarker) + marker
	}
	return truncateRunes(t, maxTitle, truncationMarker)
}

// bodyFor says what happened, to what, and when -- the three things somebody
// woken at 3am needs before they decide whether to get up.
func bodyFor(a channel.Alert) string {
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
	return strings.TrimRight(b.String(), "\n")
}

// whenLine words the timestamp according to whether it is an observation time
// or merely our arrival time.
//
// This is not pedantry. Some sources carry no controller timestamp at all, so
// the only time we have is when we happened to receive the event -- and
// someone who reads "at 03:14" will scrub the footage to 03:14, find nothing,
// and distrust the product rather than the timestamp.
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

// priorityFor maps severity onto the three Pushover priorities this channel
// will use.
//
// 2 IS NOT AMONG THEM AND NEVER WILL BE -- see maxPriority for why.
//
// critical and high both get 1, which bypasses the account's quiet hours. That
// is the whole reason this channel exists: quiet hours are exactly when an
// intrusion matters most, and a channel that respects them at 3am is a channel
// that does nothing at 3am.
//
// The trade against giving high a 0 instead: some high-severity events will
// now pierce quiet hours, and an operator annoyed often enough mutes the app
// and loses the critical ones too. That is a real cost, and it is paid in
// SEVERITY CLASSIFICATION rather than here -- the rules decide what is high,
// and a rule producing too much noise is a rule to fix, not a reason for this
// channel to quietly downgrade what it was handed.
//
// low and info get -1: delivered, visible in the notification list, but no
// sound. They are the ones the operator reads over breakfast.
func priorityFor(sev incident.Severity) int {
	switch sev {
	case incident.SeverityCritical, incident.SeverityHigh:
		return 1
	case incident.SeverityMedium:
		return 0
	case incident.SeverityLow, incident.SeverityInfo:
		return -1
	default:
		// An unrecognised severity is not an excuse to be quiet, nor an excuse
		// to siren. Normal priority, and the operator sees it.
		return 0
	}
}

// truncateRunes cuts s to limit CHARACTERS, marking the cut.
//
// Runes, not bytes: Pushover counts characters, and a byte-wise cut would both
// under-fill the field for any non-ASCII text and could split a multi-byte
// rune into mojibake -- on a camera named "Café" that is the difference
// between a readable alert and a corrupt one.
func truncateRunes(s string, limit int, marker string) string {
	if limit <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	r := []rune(s)
	keep := limit - utf8.RuneCountInString(marker)
	if keep <= 0 {
		// No room for the marker. A hard cut is still better than a rejected
		// message, which would be no alert at all.
		return string(r[:limit])
	}
	return strings.TrimRight(string(r[:keep]), " \t\n") + marker
}
