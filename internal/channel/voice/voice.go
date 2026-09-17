// Package voice places a phone call through Twilio that speaks the alert and
// hangs up.
//
// It exists for the one failure every other channel shares: a push
// notification, an email and an ntfy message all arrive on a device that is
// face-down, silenced, or out of battery, and none of them makes the handset
// ring through a Do Not Disturb schedule the way an ordinary phone call does.
// This channel is the rung below "nobody is answering".
//
// Five facts about Twilio drive nearly every decision in this file:
//
//  1. A 201 MEANS QUEUED, NOT ANSWERED. The create-call response comes back
//     with status "queued": Twilio has accepted the request and nothing more.
//     The phone has not rung. Whether it was answered, went to voicemail or
//     failed outright is knowable only from a StatusCallback webhook or by
//     re-fetching the call resource, and this product does not expose an
//     inbound endpoint (ARCHITECTURE.md §8) and does not poll for call state
//     in this pass. So everything here proves DISPATCH and nothing proves
//     DELIVERY -- see the comment where the 201 is handled, which is the one
//     place a future reader is most likely to conclude the job is done. The
//     escalation ladder above this channel must keep escalating on that basis.
//
//  2. THE SPOKEN SCRIPT IS BILLED PER 100 CHARACTERS, AND ESCALATION REPEATS.
//     Twilio charges text-to-speech per 100 characters of <Say> text,
//     independently of how long the call lasts, and a critical incident
//     re-alerts every couple of minutes until somebody acknowledges. Every
//     character is therefore a recurring cost multiplied by the number of
//     recipients. See maxSpokenRunes for the arithmetic. The script says
//     severity, what happened, where, when and whether this is a reminder,
//     and nothing else.
//
//  3. THE ACKNOWLEDGEMENT LINK CANNOT BE USED AT ALL. Every other channel
//     treats Alert.AckURL as the one field that must never be truncated. A
//     spoken URL is useless -- nobody transcribes a signed HMAC path at 3am --
//     and with no inbound endpoint and no DTMF this pass there is no keypress
//     to acknowledge with either. The cost is real and belongs in plain sight:
//     a phone call from this channel cannot be acknowledged, so the ladder
//     keeps calling until the operator acknowledges somewhere else. That is a
//     deliberate omission, not an oversight, and closing it is a later pass.
//
//  4. NEARLY EVERY FAILURE IS PERMANENT. Twilio's own error codes for an
//     unverified From number, an unverified trial destination, a destination
//     country the account is not permitted to call, bad credentials or a
//     suspended account are all configuration facts that will fail identically
//     forever. Only 429 and 5xx are worth another attempt, and those two are
//     not equally safe -- see retryBackoff.
//
//  5. THE MESSAGE IS ONLY SPOKEN AFTER THE CALL IS ANSWERED, AND IT IS SPOKEN
//     ONCE. Deliberately once: a <Say loop="2"> would be the kinder design for
//     somebody who answers with "hello?" and talks over the first sentence.
//     What it costs is a second billed block of text-to-speech on every call
//     of every repeat (fact 2), so it is a change worth making deliberately
//     with the operator's pricing tier in front of us rather than as a rider
//     on this one. Until then the script leads with "UniFi alert", which is
//     the part somebody who missed the opening can still act on.
package voice

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
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

// DefaultEndpoint is the root of Twilio's REST API. Not configurable, for the
// same reason Pushover's is not: there is no self-hosted Twilio, so an
// operator-supplied endpoint would be a way to aim the account credentials at
// somebody else's server and nothing more.
const DefaultEndpoint = "https://api.twilio.com"

// apiVersion is the literal path segment Twilio uses for its REST API. It is
// a date and it has not moved since 2010; it is not a version this code gets
// to pick.
const apiVersion = "2010-04-01"

// testSummary is what the operator must be shown when Test succeeds; it
// reaches them through the TestSummary method below, which satisfies
// channel.TestDescriber.
//
// Every other channel's "send test" button delivers a message, so the generic
// "Sent. If it does not arrive, the problem is between the channel and the
// device" text the UI prints is true for them. It is a lie here: this test
// deliberately places no call (see Test). A button that means something
// different for one channel without saying so is exactly the state this
// product refuses, so the caller is expected to print this instead.
const testSummary = "Checked the Twilio credentials. NO CALL WAS PLACED and nobody's " +
	"phone rang: a test that costs money and wakes somebody is not a harmless test, " +
	"so this verifies the account SID and auth token against Twilio's account " +
	"resource instead. It does not prove the From number can dial your recipients."

// TestSummary satisfies channel.TestDescriber, so the audit record and the
// interface both say what the test actually did rather than claiming a
// delivery that never happened.
func (c *Channel) TestSummary() string { return testSummary }

// Config is everything this channel needs. Plain data: no clients, no state.
type Config struct {
	// AccountSID is the Twilio account identifier, beginning "AC". It is half
	// of the credential pair -- it is the HTTP Basic username and it also
	// appears in the request PATH -- so it is a secret.Secret rather than a
	// string, both so that a Config reaching a log line through %v cannot leak
	// it and so that every place it goes on the wire is greppable through
	// Reveal().
	AccountSID secret.Secret

	// AuthToken is the account's auth token: the HTTP Basic password. Anyone
	// holding it plus the account SID can place calls and send messages billed
	// to this operator, which is both a financial loss and a way to make
	// convincing fake calls from a number their family recognises.
	AuthToken secret.Secret

	// From is the caller ID, in E.164 (+15552223214). It must be a number
	// bought from Twilio or a verified outgoing caller ID on the account;
	// anything else is refused at call time with error 21210, which reads like
	// a credentials problem and is not one.
	//
	// Not a secret: it is the number the recipient sees, and it has to be
	// quotable in an error to be fixable.
	From string

	// Recipients are the numbers to call, in E.164. Every one is attempted on
	// every alert; see Send for why one accepted call is a success even when
	// the others failed.
	//
	// A list rather than a single number because the whole point of reaching
	// for a phone call is that the first person did not answer, and a
	// single-number voice channel would make the operator build the fan-out
	// out of escalation stages instead -- which spaces the calls minutes apart
	// rather than seconds.
	Recipients []string

	// Voice is the <Say> voice. Empty means DefaultVoice.
	//
	// Set explicitly on every call rather than left to Twilio: the documented
	// default is "man", but an account-level default configured in the Twilio
	// Console OVERRIDES it, so the spoken voice could otherwise change because
	// somebody clicked something in a web UI this product cannot see.
	//
	// An invalid voice, or a valid voice paired with a language it does not
	// speak, makes the <Say> fail AFTER the 201 has already come back -- a
	// clean success followed by silence, which is the worst failure this
	// product has. The UI must therefore offer a constrained choice rather
	// than a free-text box.
	Voice string

	// Language is the <Say> language-locale code, e.g. en-US or en-GB. Empty
	// means DefaultLanguage. Same after-the-201 failure mode as Voice.
	Language string
}

// DefaultVoice is Twilio's Basic tier, which is billed at nothing per
// character (see maxSpokenRunes). The Polly and Google voices sound better and
// the Generative tier costs roughly sixteen times the Standard one per
// character, on a script that repeats for every recipient on every escalation
// rung -- so the better voice is an opt-in the operator makes knowing that,
// not a default this file picks for them.
const DefaultVoice = "man"

// DefaultLanguage is Twilio's own default. Named here anyway so the value sent
// on the wire is one this file chose.
const DefaultLanguage = "en-US"

// Channel places speaking calls to one or more numbers.
type Channel struct {
	cfg  Config
	http *http.Client

	// endpoint, backoff and sleep are fields rather than package constants so
	// the tests can drive the real code paths against an httptest server in
	// milliseconds. A retry test that actually waits eight seconds is a test
	// nobody runs, and a test nobody runs is not a specification.
	endpoint string
	backoff  []time.Duration
	sleep    func(ctx context.Context, d time.Duration) error
}

// retryBackoff is the bounded ladder for a call Twilio would not accept.
//
// SHORTER THAN EVERY OTHER CHANNEL'S, ON PURPOSE. Posting to /Calls is a
// billed, side-effecting action: unlike a push notification, a retry that the
// server actually processed and whose response was lost rings somebody's phone
// a second time and charges for it. So the ladder is sized against what Twilio
// actually documents about each failure:
//
//   - 429 is safe. Twilio states that requests answered with 429 "aren't
//     processed and are safe to retry after backing off", so no call was
//     placed and a retry cannot double-dial. This ladder is for that case:
//     three attempts, 2s + 6s.
//
//   - 5xx is NOT documented as unprocessed. Twilio says nothing about whether
//     a request that got a 500 was acted on, so a retry after one carries a
//     genuine chance of placing a second call. It gets exactly one retry --
//     see maxServerErrorRetries -- because a transient blip losing the one
//     alarm that was going to wake somebody is worse than a duplicate 3am
//     call, and a duplicate is at least visible and explicable.
//
//   - NOTHING ELSE IS RETRIED. An unverified From number, an unverified trial
//     destination, a country the account may not call, a bad token: every one
//     is a configuration fact that fails identically forever, and retrying it
//     only delays the honest report the escalation ladder needs in order to
//     try a different channel. Retrying a 401 in a loop is also how accounts
//     get flagged for abuse.
//
// Arithmetic against channel.DefaultSendTimeout (60s), which bounds one
// delivery INCLUDING every recipient and every internal retry: worst case is
// 8s of sleeping per recipient, so three recipients is 24s of sleeping plus
// nine round trips, comfortably inside the budget. Beyond that the per-call
// and per-recipient fitsInBudget checks stop the ladder rather than letting it
// overrun -- and Send says in the error which recipients it did not get to,
// because a recipient silently skipped is an alarm nobody was told about.
var retryBackoff = []time.Duration{2 * time.Second, 6 * time.Second}

// maxServerErrorRetries bounds the 5xx case tighter than the 429 case. See
// retryBackoff: a 429 provably placed no call, a 500 might have.
const maxServerErrorRetries = 1

// maxRetryAfter bounds how far we will trust a server-advised delay. Twilio
// does not actually document a Retry-After header on 429 -- it documents
// exponential backoff -- so this is read opportunistically and never depended
// on. A Retry-After of 900 would mean the server has decided this alarm can
// wait fifteen minutes, and the server is not the thing that gets to decide
// that.
const maxRetryAfter = 30 * time.Second

// maxErrorBody caps how much of a failure response is quoted back. A Twilio
// error is a short JSON object; anything longer is a proxy's HTML error page,
// which helps nobody and is not going into an incident record that the UI
// renders without asking anyone to sign in.
const maxErrorBody = 512

// maxResourceBody caps how much of a SUCCESS response is read.
//
// Separate from maxErrorBody, and the separation is the whole point. Reading
// the success body through the error cap truncated it: Twilio's real call
// resource is well over a kilobyte -- every documented field plus nine
// subresource_uris -- and "sid" sorts late enough to land past the first 512
// bytes. So the parse that decides whether the call was accepted failed on
// every real call, while passing in tests against a 230-byte stub.
//
// The consequence was not a wrong log line. Every phone rang, every call was
// billed, the incident recorded that nothing was accepted, and the escalation
// ladder re-dialled on that basis -- indefinitely, for critical. The pattern
// was copied from the Pushover channel, where one cap is safe only because
// Pushover's success body is about fifty bytes.
const maxResourceBody = 16 << 10

// maxTwiML is Twilio's documented cap on the inline-TwiML form parameter. It
// covers the WHOLE <Response> document -- attributes, tags and escaping -- not
// just the spoken text.
const maxTwiML = 4000

// maxSpokenRunes caps the whole spoken script.
//
// The arithmetic, because it is the reason this constant is small: Twilio
// bills text-to-speech per 100 characters, so 240 characters is three billed
// blocks. At the Standard tier ($0.0008 per block) that is $0.0024 of speech
// per call; at the Generative tier ($0.0130) it is $0.039. A critical incident
// that nobody acknowledges re-alerts every two minutes, so an hour of an
// unattended alarm across three recipients is ninety calls -- $0.22 of speech
// on Standard, $3.51 on Generative, on top of the call minutes themselves.
// Under the default Basic voice the per-character cost is zero and only the
// minutes are billed.
//
// In practice a script comes out around a hundred characters. This is the
// backstop for an entity or title the operator typed at length, not the
// target.
const maxSpokenRunes = 240

// maxSpokenTitleRunes and maxSpokenEntityRunes cap the two fields that come
// from whatever somebody typed into the UniFi console, before the script as a
// whole is capped. Cutting them individually means a very long camera name
// cannot swallow the severity and the time, which are the parts that decide
// whether the listener gets out of bed.
const (
	maxSpokenTitleRunes  = 120
	maxSpokenEntityRunes = 60
)

// hardSpokenRunes is the length the script is cut to if the marshalled TwiML
// somehow still exceeds maxTwiML. 120 runes cannot exceed 4000 bytes even if
// every single character expanded into a five-byte XML entity. A guard against
// a future edit that grows the document, not a reachable branch.
const hardSpokenRunes = 120

// truncationMarker is SPOKEN, so unlike the text channels' " [truncated]" it
// is words rather than punctuation in brackets. The listener has to hear that
// the sentence was cut rather than that the event stopped mid-word: somebody
// who thinks they have the whole story will not go and look at the incident.
const truncationMarker = ", and more"

// New builds a channel. A nil client means a client with a timeout.
func New(cfg Config, client *http.Client) (*Channel, error) {
	// Everything is validated here rather than at first send, because the
	// alternative is discovering the misconfiguration at 3am from a failed
	// delivery on a live incident -- and for this channel the misconfiguration
	// is usually Twilio's, in the shape of a From number nobody verified.
	if cfg.AccountSID.IsZero() {
		return nil, errors.New("voice: twilio account sid is required")
	}
	if cfg.AuthToken.IsZero() {
		return nil, errors.New("voice: twilio auth token is required")
	}
	// The account SID is the one credential with a checkable shape, and the
	// mistake it catches is the common one: the auth token pasted into the SID
	// box. Left to Twilio that produces a 401 "permission denied", which reads
	// as a bad token rather than as the pair being the wrong way round, and
	// sends the operator off to rotate a token that was never wrong.
	//
	// The error must not quote what it received -- if the auth token really is
	// in this field, echoing it publishes the credential into a startup log.
	if !strings.HasPrefix(cfg.AccountSID.Reveal(), "AC") {
		return nil, errors.New("voice: twilio account sid must start with \"AC\"" +
			" (it is the value labelled Account SID in the Twilio console;" +
			" the auth token goes in the other field)")
	}

	cfg.From = strings.TrimSpace(cfg.From)
	if cfg.From == "" {
		return nil, errors.New("voice: a From number is required")
	}
	if !validE164(cfg.From) {
		return nil, fmt.Errorf("voice: From number %q is not E.164:"+
			" Twilio wants a + followed by the country code and the number,"+
			" with no spaces, dashes or parentheses (for example +15552223214)", cfg.From)
	}

	recipients, err := cleanRecipients(cfg.Recipients)
	if err != nil {
		return nil, err
	}
	cfg.Recipients = recipients

	cfg.Voice = strings.TrimSpace(cfg.Voice)
	if cfg.Voice == "" {
		cfg.Voice = DefaultVoice
	}
	if !safeSayAttr(cfg.Voice) {
		return nil, fmt.Errorf("voice: %q is not a usable <Say> voice name", cfg.Voice)
	}
	cfg.Language = strings.TrimSpace(cfg.Language)
	if cfg.Language == "" {
		cfg.Language = DefaultLanguage
	}
	if !safeSayAttr(cfg.Language) {
		return nil, fmt.Errorf("voice: %q is not a usable <Say> language code", cfg.Language)
	}

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

// cleanRecipients trims, validates and de-duplicates the call list.
//
// De-duplicated because the same number listed twice is two billed calls to
// one handset, and the second one arrives while the first is still ringing --
// which reads to the person holding the phone as the system malfunctioning at
// exactly the moment they most need to trust it.
func cleanRecipients(in []string) ([]string, error) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !validE164(r) {
			return nil, fmt.Errorf("voice: recipient %q is not E.164:"+
				" Twilio wants a + followed by the country code and the number,"+
				" with no spaces, dashes or parentheses (for example +15558675310)", r)
		}
		if seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errors.New("voice: at least one recipient number is required")
	}
	return out, nil
}

// validE164 checks the shape Twilio insists on: a leading +, then a country
// code that never starts with 0, then digits, at most fifteen of them.
func validE164(s string) bool {
	if !strings.HasPrefix(s, "+") {
		return false
	}
	digits := s[1:]
	if len(digits) < 2 || len(digits) > 15 {
		return false
	}
	if digits[0] == '0' {
		return false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	return true
}

// safeSayAttr rejects anything that cannot be a voice or language name.
//
// This is not the constraint that matters -- a syntactically fine voice name
// Twilio does not know still fails after the 201, silently, which is why the
// UI has to offer a list rather than a text box. It is here so a value
// carrying a quote or a newline cannot reshape the TwiML document from inside
// an attribute.
func safeSayAttr(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// Name is the identifier used in policy stage lists and diagnostics.
func (c *Channel) Name() string { return "voice" }

// String renders the channel without its credentials.
//
// Config's credential fields are secret.Secret exactly so that %v cannot print
// them, and that protection is defeated the moment the Config is reached
// through Channel's unexported cfg field: fmt calls String() only on a value
// it is allowed to hand to an interface, and a value read out of an unexported
// field is not one, so Secret.String() is skipped and the raw auth token is
// printed. Measured in two other channels in this package rather than assumed.
//
// The recipient numbers are counted rather than listed. They are not
// credentials, but they are somebody's personal mobile number, and this is a
// diagnostic string with no guarantee about where it ends up.
//
// Value receiver, unlike every other method here, so that a stray Channel copy
// is covered as well as the *Channel everything actually holds.
//
// %#v is NOT covered and cannot be from here: it asks fmt for the raw struct
// and consults GoStringer rather than Stringer, so it leaks through a Config
// too. The fix for that belongs on secret.Secret rather than on every type
// that holds one.
func (c Channel) String() string {
	return fmt.Sprintf("voice{endpoint:%s from:%q recipients:%d say:%s/%s credentials:<redacted>}",
		c.endpoint, c.cfg.From, len(c.cfg.Recipients), c.cfg.Voice, c.cfg.Language)
}

// Send calls every recipient and speaks the alert.
//
// SUCCESS MEANS AT LEAST ONE CALL WAS ACCEPTED BY TWILIO. If one phone was
// dialled, somebody was told, and reporting the whole delivery as a failure
// would leave the incident due and have the ladder call that same person again
// on the next rung -- punishing them for the fact that a second number is
// misconfigured. So a partial failure returns nil.
//
// What that costs, said out loud because it is the weak point of this method:
// when two of three numbers are unreachable, the incident record shows a clean
// delivery and the operator has no way to notice from the incident alone. The
// dial result names every failure and every recipient the budget could not
// fund, and surfacing that to the operator needs a per-channel warning path
// the Channel interface does not have -- there is nowhere to put it that is
// not an error, and calling this an error would be the larger lie. Until that
// path exists, the thing that catches a dead recipient is the scheduled
// self-test and the operator reading it.
//
// When NOTHING was accepted the error names each recipient's failure
// separately, because "voice failed" sends an operator looking at their
// credentials when the real answer is that one country is not enabled on the
// account.
func (c *Channel) Send(ctx context.Context, a channel.Alert) error {
	twiml, err := c.twiml(script(a))
	if err != nil {
		return err
	}
	res := c.dial(ctx, twiml)
	if len(res.accepted) > 0 {
		return nil
	}
	return errors.New(res.summary())
}

// dialResult is the outcome across every recipient.
type dialResult struct {
	accepted []string // masked numbers Twilio took the call for
	failures []string // one sentence per recipient that was refused
	skipped  []string // masked numbers the delivery budget could not fund
}

// summary is the operator-facing account of the whole fan-out. It is written
// for the incident record, which is served from /api/incidents without a
// sign-in, so it carries masked numbers and no credentials.
func (r dialResult) summary() string {
	var b strings.Builder
	b.WriteString("voice: no call was accepted")
	for _, f := range r.failures {
		b.WriteString("\n       ")
		b.WriteString(f)
	}
	if len(r.skipped) > 0 {
		// Never a silent skip. A recipient dropped without a word is an alarm
		// nobody was told about that looks exactly like one that was
		// delivered, which is the single failure this product exists to
		// prevent.
		b.WriteString("\n       not attempted at all, because this delivery's 60-second budget " +
			"ran out first: " + strings.Join(r.skipped, ", "))
	}
	return b.String()
}

func (c *Channel) dial(ctx context.Context, twiml string) dialResult {
	var res dialResult
	for i, to := range c.cfg.Recipients {
		// The first recipient is always attempted: if the budget is already
		// spent, the request's own context will say so, and that is a more
		// honest report than declining to try. Every recipient after the first
		// is gated, because sitting in a retry for a call that cannot be
		// placed inside the deadline holds the single per-channel queue worker
		// and delays every alert queued behind this one.
		if i > 0 && !fitsInBudget(ctx, 0) {
			res.skipped = append(res.skipped, maskNumbers(c.cfg.Recipients[i:])...)
			break
		}
		// Twilio's default outbound rate is ONE call per second and excess
		// calls are QUEUED rather than refused, so a fan-out to several numbers
		// is spread over seconds with no error raised anywhere. Nothing to do
		// about it here beyond knowing it: the delay is Twilio's, it is
		// counted inside our budget, and the 201 says nothing about it.
		if err := c.place(ctx, to, twiml); err != nil {
			res.failures = append(res.failures, err.Error())
			continue
		}
		res.accepted = append(res.accepted, maskNumber(to))
	}
	return res
}

// place makes one call, with the bounded retry described on retryBackoff.
func (c *Channel) place(ctx context.Context, to, twiml string) error {
	form := url.Values{}
	form.Set("To", to)
	form.Set("From", c.cfg.From)
	form.Set("Twiml", twiml)
	// "Url" is deliberately never set, not even empty. Twilio documents Twiml
	// and Url as mutually exclusive and states that Twiml is IGNORED when Url
	// is also present -- an empty Url in the body would risk the entire spoken
	// script being dropped while the request still came back 201.
	//
	// "StatusCallback" is likewise never set: it is an inbound endpoint, which
	// this product does not have by design (ARCHITECTURE.md §8).
	encoded := form.Encode()

	var last error
	serverErrors := 0
	for attempt := 0; ; attempt++ {
		wait, err := c.attempt(ctx, to, encoded)
		if err == nil {
			return nil
		}
		last = err

		var re *retryableError
		if !errors.As(err, &re) || attempt >= len(c.backoff) {
			return last
		}
		if !re.rateLimited {
			// A 5xx might have been processed; see retryBackoff.
			serverErrors++
			if serverErrors > maxServerErrorRetries {
				return last
			}
		}
		delay := c.backoff[attempt]
		if re.rateLimited && wait > 0 && wait <= maxRetryAfter {
			delay = wait
		}
		if !fitsInBudget(ctx, delay) {
			// The wait cannot finish inside this delivery's deadline, so
			// sitting it out changes nothing except when the failure gets
			// reported -- while holding the single per-channel queue worker
			// and every recipient still to be called.
			return fmt.Errorf("%w (no time left in this delivery's budget to wait it out)", last)
		}
		if serr := c.sleep(ctx, delay); serr != nil {
			return fmt.Errorf("%w (gave up waiting out a retry: %v)", last, serr)
		}
	}
}

// callResource is the part of Twilio's 201 body this channel reads.
type callResource struct {
	SID    string `json:"sid"`
	Status string `json:"status"`
}

// attempt performs one create-call request. It returns the server-advised
// delay alongside the error so the caller can decide whether to honour it.
func (c *Channel) attempt(ctx context.Context, to, form string) (time.Duration, error) {
	// A fresh reader per attempt. Reusing one across a retry posts an empty
	// body the second time, which Twilio answers with "No to number is
	// specified" -- a 400 that reads as a bad recipient and sends the operator
	// to check a number that was never wrong.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.callsURL(), strings.NewReader(form))
	if err != nil {
		return 0, fmt.Errorf("voice: building the call request for %s: %w", maskNumber(to), err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.authorise(req)

	resp, err := c.http.Do(req)
	if err != nil {
		// Scrubbed: the *url.Error net/http returns prints the full request
		// URL, and this URL carries the account SID in its PATH -- so an
		// unscrubbed transport failure publishes half the credential pair to
		// the sign-in-free /api/incidents.
		return 0, fmt.Errorf("voice: calling %s through %s: %w", maskNumber(to),
			c.redactedEndpoint(), channel.ScrubTransportError(err))
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResourceBody))
		_ = resp.Body.Close()
	}()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResourceBody))

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode/100 == 5 {
		return retryAfter(resp.Header.Get("Retry-After")), &retryableError{
			to:          maskNumber(to),
			status:      resp.Status,
			detail:      c.describe(raw),
			rateLimited: resp.StatusCode == http.StatusTooManyRequests,
		}
	}
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("voice: Twilio refused the call to %s: %s%s%s",
			maskNumber(to), resp.Status, c.describe(raw), permanentAdvice(twilioCode(raw), resp.StatusCode))
	}

	// A 2xx is necessary but not sufficient. Twilio answers a created call
	// with the call resource; a 2xx that is not that resource means something
	// in front of the API answered -- a captive portal, a proxy error page --
	// and reporting it as delivered would be a guess. This product's stated
	// bias (see channel.Queue) is to err toward a duplicate alert and never
	// toward silence: a failure here leaves the incident due, so somebody gets
	// called twice rather than not at all.
	var body callResource
	if err := json.Unmarshal(bytes.TrimSpace(raw), &body); err != nil || body.SID == "" {
		return 0, fmt.Errorf("voice: %s from Twilio for the call to %s, but the response"+
			" was not a call resource%s", resp.Status, maskNumber(to), c.describe(raw))
	}

	// THIS IS NOT PROOF THAT ANYBODY HEARD ANYTHING. body.Status here is
	// "queued": Twilio has accepted the request and the phone has not rung
	// yet. Answered, busy, no-answer and failed are only learnable from a
	// StatusCallback webhook or by re-fetching the call resource, and this
	// pass does neither. Returning nil means DISPATCHED, and the escalation
	// ladder above this channel is what has to keep going on that basis --
	// nothing below this line may be read as delivery.
	return 0, nil
}

// Test checks the credentials against Twilio WITHOUT PLACING A CALL.
//
// This is a deliberate divergence from the Channel interface, which describes
// Test as sending "a harmless message". A phone call is not harmless: it costs
// money, and it rings somebody -- and the "send test" button is pressed
// repeatedly while an operator is tuning their configuration, so a dialling
// self-test is one they switch off, which costs the whole proof rather than
// part of it. The scheduled self-test would make it worse: a recurring
// automated call to a human being.
//
// So it does the cheapest authenticated thing Twilio offers, a GET of the
// account resource, which is not billed and rings nobody. What that buys is
// the account SID and the auth token proven correct, and the account proven
// reachable, active and not in trial. What it does NOT buy, and the operator
// has to be told this in the words of TestSummary: it does not prove the From
// number is verified for outbound calls, that the destination country is
// enabled on the account, or that anybody answers.
//
// Not retried. A test is a person standing in front of the screen waiting for
// an answer, and the answer to "did this work" is about this attempt.
func (c *Channel) Test(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.accountURL(), nil)
	if err != nil {
		return fmt.Errorf("voice: building the credential check: %w", err)
	}
	c.authorise(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("voice: checking the credentials against %s: %w",
			c.redactedEndpoint(), channel.ScrubTransportError(err))
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResourceBody))
		_ = resp.Body.Close()
	}()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResourceBody))

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("voice: Twilio rejected the credential check: %s%s%s",
			resp.Status, c.describe(raw), permanentAdvice(twilioCode(raw), resp.StatusCode))
	}

	var acct accountResource
	if err := json.Unmarshal(bytes.TrimSpace(raw), &acct); err != nil || acct.SID == "" {
		return fmt.Errorf("voice: %s from %s, but the response was not a Twilio account"+
			" resource -- something in front of the API answered%s",
			resp.Status, c.redactedEndpoint(), c.describe(raw))
	}
	if st := strings.ToLower(acct.Status); st != "" && st != "active" {
		return fmt.Errorf("voice: the credentials are correct, but the Twilio account is %q"+
			" rather than active, so no call can be placed. A suspended account is usually"+
			" an exhausted balance; reactivation takes a few minutes after payment.", acct.Status)
	}
	if strings.EqualFold(acct.Type, "Trial") {
		// Reported as a failure even though the credentials are perfect,
		// because on a trial account this channel does not do its job. Twilio
		// plays its own trial message before our TwiML runs and, by Twilio's
		// own support documentation, asks the callee to press a key before the
		// call proceeds -- so an unattended phone, or somebody half asleep
		// saying "hello", never hears the alarm while the API returns a
		// perfectly clean 201. Calling that "configured correctly" is exactly
		// the lie this product cannot tell.
		return errors.New("voice: the credentials are correct, but this is a TRIAL Twilio account." +
			"\n       On a trial account Twilio plays its own message before the alert is spoken" +
			"\n       and asks the person who answered to press a key to continue, so an" +
			"\n       unattended phone hears nothing at all -- while the API still reports the" +
			"\n       call as accepted. A trial account can also only call numbers you have" +
			"\n       verified in the console (up to five). Upgrade the account before relying" +
			"\n       on this channel.")
	}
	return nil
}

// accountResource is the part of the account GET this channel reads.
type accountResource struct {
	SID          string `json:"sid"`
	FriendlyName string `json:"friendly_name"`
	Status       string `json:"status"`
	Type         string `json:"type"`
}

// authorise puts the credentials in the Authorization header.
//
// HTTP Basic, never the query string. Twilio would accept neither credential
// as a query parameter, but the account SID has to go in the URL PATH and the
// temptation to put the pair somewhere convenient alongside it is exactly the
// trap the other channels in this package document refusing: a credential in a
// URL is copied into every proxy access log, every reverse-proxy error page
// and every packet capture on the path.
//
// Reveal() at the single point each value goes on the wire, so every use site
// is greppable.
func (c *Channel) authorise(req *http.Request) {
	req.SetBasicAuth(c.cfg.AccountSID.Reveal(), c.cfg.AuthToken.Reveal())
}

func (c *Channel) callsURL() string {
	return c.accountBase() + "/Calls.json"
}

func (c *Channel) accountURL() string {
	return c.accountBase() + ".json"
}

func (c *Channel) accountBase() string {
	return strings.TrimSuffix(c.endpoint, "/") + "/" + apiVersion +
		"/Accounts/" + url.PathEscape(c.cfg.AccountSID.Reveal())
}

// redactedEndpoint reduces the API URL to scheme, host and port.
//
// The path is what has to go: it carries the account SID, which is half the
// credential pair. Same reasoning as the ntfy channel's redact() -- this
// string is stored on the incident as LastDeliveryError and served from
// /api/incidents, which is deliberately readable without signing in so that a
// wall display works.
func (c *Channel) redactedEndpoint() string {
	u, err := url.Parse(c.endpoint)
	if err != nil || u.Host == "" {
		return "the Twilio API"
	}
	return u.Scheme + "://" + u.Host
}

// maskNumber keeps enough of a number to tell recipients apart and no more.
//
// The full number would be somebody's personal mobile, published by a failed
// delivery into an incident record that /api/incidents serves without a
// sign-in. The last four digits distinguish the operator's phone from their
// partner's, which is the whole job this string has to do.
func maskNumber(e164 string) string {
	if n := utf8.RuneCountInString(e164); n <= 4 {
		return e164
	}
	r := []rune(e164)
	return "+..." + string(r[len(r)-4:])
}

func maskNumbers(in []string) []string {
	out := make([]string, 0, len(in))
	for _, n := range in {
		out = append(out, maskNumber(n))
	}
	return out
}

// --- errors ---------------------------------------------------------------

// apiError is Twilio's failure body.
//
// NOTE that "status" here is the HTTP STATUS CODE, not a call status. Twilio
// uses the same field name for two entirely different things on two adjacent
// JSON shapes from the same endpoint, and crossing them in a struct definition
// is an easy mistake to make and a hard one to see.
//
// Code and MoreInfo are OPTIONAL -- Twilio's own documented 404 example
// carries neither -- so an absent code decodes as 0 and classification falls
// back to the HTTP status.
type apiError struct {
	Status   int    `json:"status"`
	Message  string `json:"message"`
	Code     int    `json:"code"`
	MoreInfo string `json:"more_info"`
}

// describe turns a response body into the operator-facing detail.
//
// Twilio's message field says exactly what is wrong -- "The 'To' number
// +15558675310 is not a valid phone number", "Account not active" -- and that
// is the sentence an operator needs in order to fix their configuration.
// Quoting it is worth far more than a tidy error string.
func (c *Channel) describe(raw []byte) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	// Quote at most maxErrorBody, however much was READ. Success bodies are
	// now read up to maxResourceBody so a real call resource survives parsing,
	// and without this a proxy's sixteen-kilobyte HTML error page would go
	// into the incident record and be rendered to anyone who can see the board.
	if len(trimmed) > maxErrorBody {
		trimmed = append(append([]byte{}, trimmed[:maxErrorBody]...), "..."...)
	}
	var body apiError
	if err := json.Unmarshal(trimmed, &body); err == nil && strings.TrimSpace(body.Message) != "" {
		detail := ": " + strings.Join(strings.Fields(body.Message), " ")
		if body.Code != 0 {
			detail += " (Twilio error " + strconv.Itoa(body.Code) + ")"
		}
		return c.scrub(detail)
	}
	return c.scrub(": " + strings.Join(strings.Fields(string(trimmed)), " "))
}

// twilioCode reads the Twilio-specific error code, or 0 when there is none.
func twilioCode(raw []byte) int {
	var body apiError
	if err := json.Unmarshal(bytes.TrimSpace(raw), &body); err != nil {
		return 0
	}
	return body.Code
}

// scrub removes the credentials from anything we are about to quote.
//
// A remote server we do not control decides what is in that body, and that
// body is stored on the incident and rendered in the UI. Twilio does not echo
// credentials back today; this costs two string comparisons and removes the
// need to keep trusting that.
func (c *Channel) scrub(s string) string {
	for _, cred := range []string{c.cfg.AuthToken.Reveal(), c.cfg.AccountSID.Reveal()} {
		if cred != "" {
			s = strings.ReplaceAll(s, cred, "<redacted>")
		}
	}
	// The NUMBERS too, and they are the easier ones to forget.
	//
	// Twilio quotes the offending number back in its own error text -- "The
	// 'To' number +1865... is not a valid phone number", and the same for
	// unverified trial numbers and geo-permission refusals. This string is
	// stored on the incident as LastDeliveryError and served from
	// /api/incidents, which does not require signing in so that a wall display
	// works. Masking the number three lines earlier and then pasting Twilio's
	// message in verbatim published the operator's personal mobile to every
	// device on the network, and to anyone reading the board.
	for _, n := range append([]string{c.cfg.From}, c.cfg.Recipients...) {
		if len(n) > 4 {
			s = strings.ReplaceAll(s, n, maskNumber(n))
		}
	}
	return s
}

// permanentAdvice says what the operator is actually supposed to do.
//
// Every code here is a configuration fact that no amount of retrying will
// change, and each one has a different remedy in a different place -- the
// Twilio console's verified caller IDs, its geographic permissions, its
// billing page. An error that says only "400 Bad Request" sends an operator to
// read API documentation instead of to the one page that fixes their problem.
//
// Keyed on the Twilio code when there is one and on the HTTP status when there
// is not, because the code field is optional and a switch that assumes it is
// present falls through for exactly the responses that carry the least
// information.
func permanentAdvice(code, status int) string {
	switch code {
	case 20003:
		return "\n       The account SID and auth token were refused. Check them against the" +
			"\n       Twilio console, watching for stray whitespace, and note that a subaccount's" +
			"\n       credentials do not work against the main account."
	case 21210:
		return "\n       The From number is not a Twilio number on this account and is not a" +
			"\n       verified caller ID. Buy the number, or verify it under Phone Numbers >" +
			"\n       Verified Caller IDs, before this channel can dial anybody."
	case 21211, 21212, 21217:
		return "\n       Twilio did not recognise one of the numbers. They must be E.164: a +," +
			"\n       the country code, then the number, with no spaces, dashes or parentheses."
	case 21215:
		return "\n       This account is not permitted to call that country. Enable it under" +
			"\n       Voice > Settings > Geographic Permissions in the Twilio console. This is" +
			"\n       the usual first failure for anybody outside the US calling their own mobile."
	case 21219:
		return "\n       This is a trial account and that number has not been verified. Verify it" +
			"\n       in the Twilio console, or upgrade the account -- and note that even once" +
			"\n       verified, a trial account plays its own message and asks for a keypress" +
			"\n       before the alert is spoken, so an unattended phone still hears nothing."
	case 20005, 30002:
		return "\n       The Twilio account is not active -- usually an exhausted balance or an" +
			"\n       unactivated trial. Nothing will be delivered on this channel until that is" +
			"\n       resolved; reactivation takes a few minutes after payment."
	case 20404:
		return "\n       Twilio could not find that account. This is almost always a wrong account" +
			"\n       SID, since the SID forms part of the request path."
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "\n       The credentials were refused. Check the account SID and auth token in" +
			"\n       the Twilio console."
	case http.StatusNotFound:
		return "\n       Twilio could not find that account, which is almost always a wrong" +
			"\n       account SID."
	}
	return ""
}

// retryableError marks the two statuses worth a second attempt: 429 and 5xx.
type retryableError struct {
	to     string
	status string
	detail string

	// rateLimited separates the two, because they are not the same failure and
	// are not equally safe to retry. Twilio documents a 429 as unprocessed;
	// it documents nothing of the kind about a 500. This string is stored on
	// the incident and rendered in the UI, so it is the only account of the
	// failure most operators will ever read.
	rateLimited bool
}

func (e *retryableError) Error() string {
	if e.rateLimited {
		return fmt.Sprintf("voice: Twilio rate-limited the call to %s (%s)%s"+
			" -- an account is allowed one outbound call per second by default,"+
			" raised to five once a business profile is approved",
			e.to, e.status, e.detail)
	}
	return fmt.Sprintf("voice: Twilio could not accept the call to %s right now (%s)%s",
		e.to, e.status, e.detail)
}

// retryAfter reads the delta-seconds form only.
//
// Twilio does not document a Retry-After header at all, so this is
// opportunistic: when the header is absent, which is the normal case, the
// ladder's own rung is used. The HTTP-date form needs both clocks to agree and
// is not worth the code.
func retryAfter(h string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || secs < 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// minAttemptBudget is the slack an attempt needs after its backoff: waiting
// out a rate limit, or moving on to the next recipient, is only worth doing if
// there is still time to make the request the wait was for.
const minAttemptBudget = 250 * time.Millisecond

// fitsInBudget reports whether ctx leaves room to wait d and still place a
// call.
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

// --- the TwiML document ---------------------------------------------------

// sayResponse is the whole TwiML document: one <Say> inside <Response>.
//
// No <Hangup/>: a Response whose verbs have all finished hangs up by itself,
// so the tag would be decoration. No <Gather>, no <Dial>, no <Record> -- this
// pass speaks and hangs up, and each of those would be a second thing that can
// fail after the 201.
type sayResponse struct {
	XMLName xml.Name `xml:"Response"`
	Say     sayVerb  `xml:"Say"`
}

type sayVerb struct {
	Voice    string `xml:"voice,attr,omitempty"`
	Language string `xml:"language,attr,omitempty"`
	Text     string `xml:",chardata"`
}

// twiml renders the spoken script as a TwiML document.
//
// Built with encoding/xml rather than by concatenating strings, and that is
// not a style preference. Entity names come from whatever the operator typed
// into the UniFi console, so a camera called "Front & Side" or "Gate <rear>"
// is an ordinary case -- and hand-concatenated XML turns it into a malformed
// document that Twilio ACCEPTS at create time, returns 201 for, and then fails
// to execute. A clean 201 followed by silence is the worst failure this
// product has, so the escaping is done by code that cannot forget.
//
// Note that two independent encoding layers are in play and both are required:
// this function XML-escapes the text into the document, and url.Values.Encode
// in place() then percent-encodes the whole document as one form field value.
func (c *Channel) twiml(spoken string) (string, error) {
	doc, err := c.marshalSay(spoken)
	if err != nil {
		return "", err
	}
	if len(doc) <= maxTwiML {
		return doc, nil
	}
	// A guard against a future edit that grows the document, not a reachable
	// branch: maxSpokenRunes bounds the script far below Twilio's 4000
	// character cap even if every character expanded into a five-byte entity.
	//
	// The plain text is cut BEFORE escaping, deliberately. Cutting the escaped
	// document instead can split "&amp;" in half and produce invalid XML --
	// which is the very failure this function exists to prevent.
	return c.marshalSay(truncateRunes(spoken, hardSpokenRunes, truncationMarker))
}

func (c *Channel) marshalSay(spoken string) (string, error) {
	out, err := xml.Marshal(sayResponse{
		Say: sayVerb{Voice: c.cfg.Voice, Language: c.cfg.Language, Text: spoken},
	})
	if err != nil {
		return "", fmt.Errorf("voice: building the spoken message: %w", err)
	}
	return string(out), nil
}

// --- the spoken script ----------------------------------------------------

// script says what somebody woken by a phone call needs before they decide
// whether to get up, in the fewest characters that can carry it.
//
// Order is deliberate. "UniFi alert" first because the recipient sees an
// unfamiliar number and has no other way to know who is calling, and because
// it is the one clause that still works if they talk over the opening.
// Severity next, because it is what decides whether they get out of bed. Then
// what happened, where, when, and whether this is a reminder.
//
// Everything Alert carries that is not in that list is omitted on purpose:
// AckURL (see package doc fact 3), Snapshot (no audio representation),
// IncidentID (a spoken GUID is noise) and the multi-line Body detail, which is
// prose written for a screen and is billed by the character here.
func script(a channel.Alert) string {
	parts := []string{"UniFi alert.", spokenSeverity(a.Severity) + "."}

	title := sanitizeSpoken(a.Title)
	entity := sanitizeSpoken(a.Entity)
	if title == "" {
		title, entity = entity, ""
	}
	if title != "" {
		parts = append(parts, endSentence(truncateRunes(title, maxSpokenTitleRunes, truncationMarker)))
	}
	// A title that is just the camera name would otherwise be spoken twice.
	if entity != "" && !strings.EqualFold(entity, title) {
		parts = append(parts, endSentence(truncateRunes(entity, maxSpokenEntityRunes, truncationMarker)))
	}
	if when := spokenWhen(a); when != "" {
		parts = append(parts, when)
	}
	if a.IsRepeat() {
		// Same reason the text channels put the reminder count in the title: a
		// re-alert indistinguishable from the one already dismissed gets
		// dismissed too, and on voice the caller ID is identical every time.
		parts = append(parts, fmt.Sprintf("Reminder %d.", a.Repeat))
	}
	return truncateRunes(strings.Join(parts, " "), maxSpokenRunes, truncationMarker)
}

// spokenWhen words the timestamp according to whether it is an observation
// time or merely our arrival time.
//
// This matters more spoken than anywhere else in the product. Somebody who
// hears "at three fourteen" will scrub the footage to 03:14, find nothing, and
// distrust the product rather than the timestamp -- and unlike a written
// alert, they cannot re-read the sentence to check what it said.
//
// Seconds and the zone abbreviation that the text channels print are dropped:
// text-to-speech reads "03:14:07 GMT" as a string of numbers and letters that
// nobody can hold in their head, and neither the seconds nor the zone changes
// what the listener does next.
func spokenWhen(a channel.Alert) string {
	if a.At.IsZero() {
		return ""
	}
	if a.AtIsArrivalTime {
		return "Received " + a.At.Format("3:04 PM") + "."
	}
	return "At " + a.At.Format("3:04 PM") + "."
}

// spokenSeverity maps severity onto words rather than onto a number.
//
// "Critical" is a word somebody half asleep acts on; "severity 1" is one they
// have to decode. The default arm exists because an unrecognised severity is
// not an excuse to be quiet -- the call has already been placed and billed, so
// saying something useful costs nothing.
func spokenSeverity(sev incident.Severity) string {
	switch sev {
	case incident.SeverityCritical:
		return "Critical"
	case incident.SeverityHigh:
		return "High priority"
	case incident.SeverityMedium:
		return "Warning"
	case incident.SeverityLow:
		return "Low priority"
	case incident.SeverityInfo:
		return "For information"
	default:
		return "Alert"
	}
}

// sanitizeSpoken collapses whatever the operator typed into one speakable
// line.
//
// Newlines and tabs are legal in TwiML character data but read badly, and
// control characters are not legal XML at all -- encoding/xml would replace
// them with a replacement character that text-to-speech then has to guess at.
// Collapsing here means the document that goes on the wire contains only text
// somebody could have said out loud.
func sanitizeSpoken(s string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(cleaned), " ")
}

// endSentence gives a clause a full stop so text-to-speech pauses between the
// severity, the event and the location instead of running them together.
func endSentence(s string) string {
	if s == "" {
		return ""
	}
	switch s[len(s)-1] {
	case '.', '!', '?', ':', ';', ',':
		return s
	}
	return s + "."
}

// truncateRunes cuts s to limit CHARACTERS, marking the cut.
//
// Runes, not bytes: Twilio bills characters, and a byte-wise cut could split a
// multi-byte rune -- on a camera named "Café" that is the difference between a
// spoken name and a replacement character the voice stumbles over.
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
		return string(r[:limit])
	}
	return strings.TrimRight(string(r[:keep]), " \t\n") + marker
}
