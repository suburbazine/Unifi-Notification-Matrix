package voice

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// The credentials and numbers used throughout. Distinctive strings so that a
// leak into a URL, an error or a log line is unambiguous when a test finds
// one. The SID keeps its real "AC" prefix because New refuses anything else.
const (
	testAccountSID = "ACSIDCANARY00000000000000000leakme"
	testAuthToken  = "AUTHTOKENCANARY-leakme"
	testFrom       = "+15552223214"
	testTo         = "+15558675310"
	testToSecond   = "+447700900123"
	testToThird    = "+15005550006"
)

// capture records what the server actually received, which is the only thing
// worth asserting on: every bug this file guards against is a bug in what goes
// on the wire. rawURL and rawBody are kept unparsed, because "this must never
// appear" is only provable against the bytes.
type capture struct {
	method   string
	path     string
	rawURL   string
	query    url.Values
	header   http.Header
	rawBody  []byte
	form     url.Values
	authUser string
	authPass string
	authOK   bool
}

// newServer stands in for the Twilio API. respond is handed the 1-based
// request count so a test can fail the first attempt and accept the second.
func newServer(t *testing.T, respond func(w http.ResponseWriter, r *http.Request, n int)) (*httptest.Server, *[]capture) {
	t.Helper()
	var mu sync.Mutex
	var got []capture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		user, pass, ok := r.BasicAuth()
		mu.Lock()
		got = append(got, capture{
			method:   r.Method,
			path:     r.URL.Path,
			rawURL:   r.URL.String(),
			query:    r.URL.Query(),
			header:   r.Header.Clone(),
			rawBody:  body,
			form:     form,
			authUser: user,
			authPass: pass,
			authOK:   ok,
		})
		n := len(got)
		mu.Unlock()
		// The body has already been drained to record it, so put it back:
		// a handler that wants to branch on the To number reads it through
		// r.FormValue, which parses r.Body.
		r.Body = io.NopCloser(bytes.NewReader(body))
		respond(w, r, n)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

// createdCall is Twilio's 201 body for a call it has QUEUED. Note the status:
// nothing here says the phone rang.
func createdCall(to string) string {
	return fmt.Sprintf(`{"account_sid":"%s","sid":"CA10000000000000000000000000000001",`+
		`"status":"queued","to":"%s","from":"%s","direction":"outbound-api",`+
		`"duration":null,"price":null,"queue_time":"1000"}`, testAccountSID, to, testFrom)
}

func twilioError(status, code int, message string) string {
	return fmt.Sprintf(`{"status":%d,"message":%q,"code":%d,"more_info":"https://www.twilio.com/docs/errors/%d"}`,
		status, message, code, code)
}

func okServer(t *testing.T) (*httptest.Server, *[]capture) {
	t.Helper()
	return newServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, createdCall(r.FormValue("To")))
	})
}

func validConfig() Config {
	return Config{
		AccountSID: secret.Secret(testAccountSID),
		AuthToken:  secret.Secret(testAuthToken),
		From:       testFrom,
		Recipients: []string{testTo},
	}
}

func newChannel(t *testing.T, srv *httptest.Server, cfg Config) *Channel {
	t.Helper()
	if cfg.AccountSID.IsZero() {
		cfg.AccountSID = secret.Secret(testAccountSID)
	}
	if cfg.AuthToken.IsZero() {
		cfg.AuthToken = secret.Secret(testAuthToken)
	}
	if cfg.From == "" {
		cfg.From = testFrom
	}
	if len(cfg.Recipients) == 0 {
		cfg.Recipients = []string{testTo}
	}
	c, err := New(cfg, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.endpoint = srv.URL
	// No real sleeping in tests; the retry ladder is still exercised in full.
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func sampleAlert() channel.Alert {
	at := time.Date(2026, 9, 15, 3, 14, 7, 0, time.UTC)
	return channel.Alert{
		IncidentID: "inc-1",
		Severity:   incident.SeverityCritical,
		Title:      "Door forced open",
		Body:       "Front entrance was forced.\nDoor position reports open.",
		Entity:     "Front Door",
		AckURL:     "https://alerts.example.net/ack/inc-1/9f3a",
		OpenedAt:   at.Add(-12 * time.Minute),
		At:         at,
	}
}

// spokenText parses the TwiML that actually went on the wire and returns what
// the caller would hear. Parsing rather than string-matching is the point: a
// document that does not unmarshal is one Twilio accepts with a 201 and then
// fails to execute, which is a silent non-delivery.
func spokenText(t *testing.T, form url.Values) (text, voice, language string) {
	t.Helper()
	raw := form.Get("Twiml")
	if raw == "" {
		t.Fatal("no Twiml parameter in the request body")
	}
	var doc struct {
		XMLName xml.Name `xml:"Response"`
		Say     struct {
			Voice    string `xml:"voice,attr"`
			Language string `xml:"language,attr"`
			Text     string `xml:",chardata"`
		} `xml:"Say"`
	}
	if err := xml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("the TwiML is not well-formed XML: %v\n%s", err, raw)
	}
	return doc.Say.Text, doc.Say.Voice, doc.Say.Language
}

func callsOnly(got []capture) []capture {
	var out []capture
	for _, c := range got {
		if strings.HasSuffix(c.path, "/Calls.json") {
			out = append(out, c)
		}
	}
	return out
}

// --- the wire -------------------------------------------------------------

func TestSendPostsOneFormEncodedCallPerRecipient(t *testing.T) {
	// Twilio accepts only x-www-form-urlencoded (or multipart) on this
	// endpoint, and the parameter names are case-sensitive: To, From, Twiml.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{Recipients: []string{testTo, testToSecond}})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	calls := callsOnly(*got)
	if len(calls) != 2 {
		t.Fatalf("placed %d calls, want one per recipient (2)", len(calls))
	}
	for i, req := range calls {
		if req.method != http.MethodPost {
			t.Errorf("call %d: method = %s, want POST", i, req.method)
		}
		if ct := req.header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("call %d: content-type = %q", i, ct)
		}
		want := "/" + apiVersion + "/Accounts/" + testAccountSID + "/Calls.json"
		if req.path != want {
			t.Errorf("call %d: path = %q, want %q", i, req.path, want)
		}
		if req.form.Get("From") != testFrom {
			t.Errorf("call %d: From = %q", i, req.form.Get("From"))
		}
		// Url and StatusCallback would each undo the design: Twilio ignores
		// Twiml when Url is present, and StatusCallback is an inbound endpoint
		// this product deliberately does not have.
		for _, banned := range []string{"Url", "ApplicationSid", "StatusCallback", "StatusCallbackEvent"} {
			if _, ok := req.form[banned]; ok {
				t.Errorf("call %d: form carries %q", i, banned)
			}
		}
	}
	if calls[0].form.Get("To") != testTo || calls[1].form.Get("To") != testToSecond {
		t.Errorf("recipients = %q then %q, want %q then %q",
			calls[0].form.Get("To"), calls[1].form.Get("To"), testTo, testToSecond)
	}
}

func TestCredentialsTravelInTheAuthorizationHeaderAndNowhereElse(t *testing.T) {
	// A credential in a URL is copied into every proxy access log, every
	// reverse-proxy error page and every packet capture on the path. Asserted
	// against the raw bytes, because that is the only way to prove absence.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := callsOnly(*got)[0]

	if !req.authOK {
		t.Fatal("no HTTP Basic credentials were sent")
	}
	if req.authUser != testAccountSID {
		t.Errorf("basic auth username = %q, want the account SID", req.authUser)
	}
	if req.authPass != testAuthToken {
		t.Error("basic auth password is not the auth token")
	}
	// The account SID legitimately appears in the path -- Twilio puts it
	// there -- so only the auth token is asserted absent from the URL.
	if strings.Contains(req.rawURL, testAuthToken) {
		t.Fatalf("auth token leaked into the request URL: %q", req.rawURL)
	}
	if strings.Contains(string(req.rawBody), testAuthToken) {
		t.Fatal("auth token leaked into the request body")
	}
	for k, vs := range req.query {
		for _, v := range vs {
			if strings.Contains(v, testAuthToken) || strings.Contains(v, testAccountSID) {
				t.Fatalf("credential leaked into query parameter %q", k)
			}
		}
	}
	for k, vs := range req.header {
		if strings.EqualFold(k, "Authorization") {
			continue
		}
		for _, v := range vs {
			if strings.Contains(v, testAuthToken) || strings.Contains(v, testAccountSID) {
				t.Fatalf("credential leaked into header %q", k)
			}
		}
	}
}

// --- the spoken script ----------------------------------------------------

func TestTheScriptSaysSeverityWhatHappenedAndWhere(t *testing.T) {
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	text, voice, language := spokenText(t, callsOnly(*got)[0].form)

	for _, want := range []string{"UniFi alert", "Critical", "Door forced open", "Front Door"} {
		if !strings.Contains(text, want) {
			t.Errorf("spoken script = %q\nwant it to say %q", text, want)
		}
	}
	// Twilio bills text-to-speech per 100 characters and the escalation ladder
	// repeats, so length here is a recurring cost rather than a one-off.
	if n := len([]rune(text)); n > maxSpokenRunes {
		t.Errorf("spoken script is %d characters, over the %d cap", n, maxSpokenRunes)
	}
	// Never relied on as a default: an account-level default in the Twilio
	// console overrides <Say>'s own, so the spoken voice could otherwise
	// change because somebody clicked something in a web UI.
	if voice != DefaultVoice || language != DefaultLanguage {
		t.Errorf("voice/language = %q/%q, want them set explicitly", voice, language)
	}
}

func TestTheScriptNeverSpeaksTheAckURL(t *testing.T) {
	// A spoken signed URL is useless -- nobody transcribes an HMAC path at 3am
	// -- and it is billed by the character. The cost of leaving it out is that
	// this call cannot be acknowledged; see the package doc.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	body := string(callsOnly(*got)[0].rawBody)
	for _, fragment := range []string{"alerts.example.net", "ack", "9f3a", "inc-1"} {
		if strings.Contains(body, fragment) {
			t.Errorf("the request body carries %q; the ack link must not be spoken", fragment)
		}
	}
}

func TestARepeatIsSpokenAsOne(t *testing.T) {
	// A re-alert indistinguishable from the one already dismissed gets
	// dismissed too, and on voice the caller ID is identical every time.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.Repeat = 3
	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	text, _, _ := spokenText(t, callsOnly(*got)[0].form)
	if !strings.Contains(text, "Reminder 3") {
		t.Errorf("spoken script = %q, want it to say this is the third time of asking", text)
	}
}

func TestAnArrivalTimeIsWordedDifferentlyFromAnObservationTime(t *testing.T) {
	// Somebody who hears "at three fourteen" scrubs the footage to 03:14,
	// finds nothing, and distrusts the product rather than the timestamp. On
	// voice they cannot re-read the sentence to check what it said.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{Recipients: []string{testTo}})

	observed := sampleAlert()
	if err := c.Send(context.Background(), observed); err != nil {
		t.Fatalf("Send: %v", err)
	}
	arrived := sampleAlert()
	arrived.AtIsArrivalTime = true
	if err := c.Send(context.Background(), arrived); err != nil {
		t.Fatalf("Send: %v", err)
	}
	calls := callsOnly(*got)
	first, _, _ := spokenText(t, calls[0].form)
	second, _, _ := spokenText(t, calls[1].form)

	if !strings.Contains(first, "At 3:14 AM") {
		t.Errorf("observation time = %q, want \"At 3:14 AM\"", first)
	}
	if !strings.Contains(second, "Received 3:14 AM") {
		t.Errorf("arrival time = %q, want \"Received ...\"", second)
	}
	if strings.Contains(second, "At 3:14 AM") {
		t.Errorf("an arrival time was spoken as an observation time: %q", second)
	}
}

func TestTwiMLSurvivesWhateverTheOperatorNamedTheCamera(t *testing.T) {
	// THE BUG THIS PINS. Hand-concatenated XML turns a camera called
	// "Front & Side" into a malformed document that Twilio ACCEPTS with a 201
	// and then fails to execute -- a clean success followed by silence, which
	// is the worst failure this product has.
	for _, tc := range []struct {
		name   string
		title  string
		entity string
	}{
		{"ampersand", "Gate & Drive forced", "Front & Side"},
		{"angle brackets", "Motion at <rear>", "Gate <rear>"},
		{"quotes and apostrophes", `Door "main" forced`, "Bob's Office"},
		{"non-ascii", "Porte forcée", "Café Camera"},
		{"newlines and tabs", "Line one\nline two", "Front\tDoor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, got := okServer(t)
			c := newChannel(t, srv, Config{})

			a := sampleAlert()
			a.Title, a.Entity = tc.title, tc.entity
			if err := c.Send(context.Background(), a); err != nil {
				t.Fatalf("Send: %v", err)
			}
			// spokenText fails the test if the document does not parse.
			text, _, _ := spokenText(t, callsOnly(*got)[0].form)
			// The escaping must be reversible: what comes back out is what the
			// operator typed, collapsed onto one speakable line.
			flat := strings.Join(strings.Fields(strings.ReplaceAll(tc.title, "\n", " ")), " ")
			if !strings.Contains(text, flat) {
				t.Errorf("spoken script = %q, want it to carry %q intact", text, flat)
			}
		})
	}
}

func TestTheTwiMLDocumentStaysUnderTwiliosCap(t *testing.T) {
	// Twilio caps the Twiml parameter at 4000 characters for the WHOLE
	// document, and an ampersand-heavy name expands roughly fivefold on
	// escaping. The plain text is cut before escaping so a cut cannot land in
	// the middle of "&amp;" and produce invalid XML.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.Title = strings.Repeat("Ampersand & ", 400)
	a.Entity = strings.Repeat("<angle> ", 400)
	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	doc := callsOnly(*got)[0].form.Get("Twiml")
	if len(doc) > maxTwiML {
		t.Errorf("TwiML document is %d bytes, over Twilio's %d cap", len(doc), maxTwiML)
	}
	// And it still parses, which is the thing the cap exists to protect.
	spokenText(t, callsOnly(*got)[0].form)
}

// --- retry behaviour ------------------------------------------------------

func TestPermanentTwilioFailuresAreNeverRetried(t *testing.T) {
	// Every one of these is a configuration fact that will fail identically
	// forever. Retrying burns the escalation window and, for a 401, risks
	// tripping Twilio's abuse detection -- while delaying the honest report
	// that would have sent the operator to the one console page that fixes it.
	for _, tc := range []struct {
		name       string
		status     int
		code       int
		message    string
		wantAdvice string
	}{
		{"bad credentials", 401, 20003, "Authenticate", "account SID and auth token were refused"},
		{"from not verified", 400, 21210, "The source phone number provided is not yet verified", "verified caller ID"},
		{"invalid to", 400, 21211, "Invalid 'To' Phone Number", "E.164"},
		{"geo permission", 400, 21215, "Geo Permission configuration is not permitting call", "Geographic Permissions"},
		{"trial destination unverified", 400, 21219, "The number is unverified", "trial account"},
		{"account not active", 400, 20005, "Account not active", "not active"},
		{"not found", 404, 20404, "The requested resource was not found", "wrong account"},
		{"no twilio code at all", 404, 0, "The requested resource was not found", "wrong"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := twilioError(tc.status, tc.code, tc.message)
			if tc.code == 0 {
				// Twilio's own 404 example carries neither code nor more_info.
				// A switch that assumes the code is present falls through for
				// exactly the responses that say the least.
				body = fmt.Sprintf(`{"status":%d,"message":%q}`, tc.status, tc.message)
			}
			srv, got := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, body)
			})
			c := newChannel(t, srv, Config{})
			slept := 0
			c.sleep = func(context.Context, time.Duration) error { slept++; return nil }

			err := c.Send(context.Background(), sampleAlert())
			if err == nil {
				t.Fatal("want an error")
			}
			if n := len(callsOnly(*got)); n != 1 {
				t.Errorf("attempts = %d, want exactly 1", n)
			}
			if slept != 0 {
				t.Errorf("slept %d times on a permanent failure", slept)
			}
			if !strings.Contains(err.Error(), tc.message) {
				t.Errorf("error = %v\nwant it to quote what Twilio said", err)
			}
			if !strings.Contains(err.Error(), tc.wantAdvice) {
				t.Errorf("error = %v\nwant it to point at the remedy (%q)", err, tc.wantAdvice)
			}
		})
	}
}

func TestRateLimitIsRetriedAndBounded(t *testing.T) {
	// Twilio documents a 429 as NOT PROCESSED and safe to retry, so no call
	// was placed and a retry cannot double-dial. It must still stop: the
	// escalation ladder above this channel is what provides persistence.
	srv, got := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, twilioError(429, 20429, "Too many requests"))
	})
	c := newChannel(t, srv, Config{})
	var waits []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}

	err := c.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("want an error once the retry budget is spent")
	}
	if n := len(callsOnly(*got)); n != len(retryBackoff)+1 {
		t.Errorf("attempts = %d, want %d (one plus the ladder)", n, len(retryBackoff)+1)
	}
	if len(waits) != len(retryBackoff) {
		t.Fatalf("waits = %v, want the full ladder %v", waits, retryBackoff)
	}
	for i := range retryBackoff {
		if waits[i] != retryBackoff[i] {
			t.Errorf("wait %d = %v, want %v", i, waits[i], retryBackoff[i])
		}
	}
	if !strings.Contains(err.Error(), "Too many requests") {
		t.Errorf("error should still quote what the server said: %v", err)
	}
}

func TestServerErrorsGetExactlyOneRetry(t *testing.T) {
	// THE DIFFERENCE THAT MATTERS. Twilio says a 429 was not processed; it
	// says nothing of the kind about a 500, so a retry after one can place a
	// SECOND billed phone call. One retry is the trade: losing the alarm that
	// was going to wake somebody is worse than a duplicate 3am call, and a
	// duplicate is at least visible.
	for _, status := range []int{
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		srv, got := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.WriteHeader(status)
		})
		c := newChannel(t, srv, Config{})
		slept := 0
		c.sleep = func(context.Context, time.Duration) error { slept++; return nil }

		if err := c.Send(context.Background(), sampleAlert()); err == nil {
			t.Errorf("status %d: want an error", status)
		}
		if n := len(callsOnly(*got)); n != maxServerErrorRetries+1 {
			t.Errorf("status %d: attempts = %d, want %d -- a 5xx might have placed the call",
				status, n, maxServerErrorRetries+1)
		}
		if slept != maxServerErrorRetries {
			t.Errorf("status %d: slept %d times, want %d", status, slept, maxServerErrorRetries)
		}
	}
}

func TestRetrySucceedsOnASecondAttemptWithItsBodyIntact(t *testing.T) {
	// The form has to be re-readable per attempt: a reader reused across a
	// retry posts an empty body the second time, which Twilio answers with
	// "No to number is specified" -- a 400 that reads as a bad recipient.
	srv, got := newServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, createdCall(r.FormValue("To")))
	})
	c := newChannel(t, srv, Config{})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	calls := callsOnly(*got)
	if len(calls) != 2 {
		t.Fatalf("attempts = %d, want 2", len(calls))
	}
	second := calls[1]
	if second.form.Get("To") != testTo || second.form.Get("Twiml") == "" {
		t.Errorf("the retried request lost its body: %v", second.form)
	}
}

func TestRetryAfterIsHonouredWhenSane(t *testing.T) {
	// Twilio does not document a Retry-After header at all, so this is read
	// opportunistically and the ladder is the fallback in the normal case.
	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{name: "sane delta seconds wins over the ladder", header: "5", want: 5 * time.Second},
		{name: "at the bound it is still honoured", header: "30", want: 30 * time.Second},
		{name: "absurd value falls back to the ladder", header: "900", want: retryBackoff[0]},
		{name: "http-date form is ignored", header: "Wed, 21 Oct 2026 07:28:00 GMT", want: retryBackoff[0]},
		{name: "garbage is ignored", header: "soon", want: retryBackoff[0]},
		{name: "absent is ignored", header: "", want: retryBackoff[0]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
				if tt.header != "" {
					w.Header().Set("Retry-After", tt.header)
				}
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, twilioError(429, 20429, "Too many requests"))
			})
			c := newChannel(t, srv, Config{})

			var first time.Duration
			seen := false
			c.sleep = func(_ context.Context, d time.Duration) error {
				if !seen {
					first, seen = d, true
				}
				return nil
			}
			_ = c.Send(context.Background(), sampleAlert())
			if !seen {
				t.Fatal("never slept; the 429 was not retried")
			}
			if first != tt.want {
				t.Errorf("first wait = %v, want %v", first, tt.want)
			}
		})
	}
}

func TestAServerAdvisedDelayIsIgnoredOnA5xx(t *testing.T) {
	// A 5xx gets the ladder's own rung and nothing longer. Twilio does not
	// document Retry-After here, and a server that has just failed does not
	// get to decide how long this alarm waits.
	srv, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Retry-After", "25")
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := newChannel(t, srv, Config{})
	var first time.Duration
	seen := false
	c.sleep = func(_ context.Context, d time.Duration) error {
		if !seen {
			first, seen = d, true
		}
		return nil
	}
	_ = c.Send(context.Background(), sampleAlert())
	if !seen {
		t.Fatal("never slept; the 500 was not retried")
	}
	if first != retryBackoff[0] {
		t.Errorf("first wait = %v, want the ladder rung %v", first, retryBackoff[0])
	}
}

func TestRetryDoesNotOutlastTheDeliveryBudget(t *testing.T) {
	// The caller is channel.Queue: one worker per channel, each Send bounded
	// by channel.DefaultSendTimeout. A sleep that cannot finish inside the
	// deadline changes nothing except when the failure is reported, while
	// holding the single worker and every alert queued behind it.
	srv, got := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, twilioError(429, 20429, "Too many requests"))
	})
	c := newChannel(t, srv, Config{})
	slept := 0
	c.sleep = func(context.Context, time.Duration) error { slept++; return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := c.Send(ctx, sampleAlert())
	if err == nil {
		t.Fatal("want an error")
	}
	if slept != 0 {
		t.Errorf("slept %d times inside a budget that cannot fit a single rung", slept)
	}
	if n := len(callsOnly(*got)); n != 1 {
		t.Errorf("attempts = %d, want 1", n)
	}
	// The incident record has to name the underlying failure, not just the
	// fact that we stopped waiting.
	if !strings.Contains(err.Error(), "rate-limited") {
		t.Errorf("error lost the underlying failure: %v", err)
	}
}

func TestAGenerousDeadlineDoesNotShortenTheLadder(t *testing.T) {
	srv, got := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	c := newChannel(t, srv, Config{})
	slept := 0
	c.sleep = func(context.Context, time.Duration) error { slept++; return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	_ = c.Send(ctx, sampleAlert())
	if slept != len(retryBackoff) {
		t.Errorf("slept %d times, want the full ladder (%d)", slept, len(retryBackoff))
	}
	if n := len(callsOnly(*got)); n != len(retryBackoff)+1 {
		t.Errorf("attempts = %d, want %d", n, len(retryBackoff)+1)
	}
}

func TestContextCancellationStopsTheRetryLoop(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, twilioError(429, 20429, "Too many requests"))
	})
	c := newChannel(t, srv, Config{})

	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	err := c.Send(ctx, sampleAlert())
	if err == nil {
		t.Fatal("want an error")
	}
	// The underlying failure is what the incident record has to say; the
	// cancellation is a detail of how we stopped waiting for it.
	if !strings.Contains(err.Error(), "Too many requests") {
		t.Errorf("error lost the underlying failure: %v", err)
	}
}

// --- several recipients ---------------------------------------------------

func TestOneAcceptedCallIsADeliveryEvenWhenOthersFailed(t *testing.T) {
	// If one phone was dialled, somebody was told. Reporting the whole
	// delivery as a failure would leave the incident due and have the ladder
	// call that same person again on the next rung, punishing them for a
	// second number being misconfigured.
	srv, got := newServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		if r.FormValue("To") == testToSecond {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, twilioError(400, 21215,
				"Geo Permission configuration is not permitting call"))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, createdCall(r.FormValue("To")))
	})
	c := newChannel(t, srv, Config{Recipients: []string{testTo, testToSecond}})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send reported a failure although one call was accepted: %v", err)
	}
	if n := len(callsOnly(*got)); n != 2 {
		t.Errorf("attempts = %d; every recipient must be tried", n)
	}

	// And the failure is named rather than swallowed. This is the detail an
	// operator needs in order to notice that one of their two phones has been
	// unreachable for a week.
	twiml, err := c.twiml(script(sampleAlert()))
	if err != nil {
		t.Fatalf("twiml: %v", err)
	}
	res := c.dial(context.Background(), twiml)
	if len(res.accepted) != 1 || len(res.failures) != 1 {
		t.Fatalf("accepted = %v, failures = %v; want one of each", res.accepted, res.failures)
	}
	if !strings.Contains(res.failures[0], maskNumber(testToSecond)) {
		t.Errorf("failure = %q, want it to name which recipient failed", res.failures[0])
	}
	if !strings.Contains(res.failures[0], "Geographic Permissions") {
		t.Errorf("failure = %q, want it to point at the remedy", res.failures[0])
	}
}

func TestWhenNobodyCouldBeCalledEveryFailureIsNamed(t *testing.T) {
	// "voice failed" sends an operator to check their credentials when the
	// real answer is that one country is not enabled on the account.
	srv, got := newServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		w.WriteHeader(http.StatusBadRequest)
		if r.FormValue("To") == testToSecond {
			_, _ = io.WriteString(w, twilioError(400, 21215, "Geo Permission configuration is not permitting call"))
			return
		}
		_, _ = io.WriteString(w, twilioError(400, 21219, "The number is unverified"))
	})
	c := newChannel(t, srv, Config{Recipients: []string{testTo, testToSecond}})

	err := c.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("want an error when no call at all was accepted")
	}
	if n := len(callsOnly(*got)); n != 2 {
		t.Errorf("attempts = %d; every recipient must still be tried", n)
	}
	for _, want := range []string{
		maskNumber(testTo), maskNumber(testToSecond),
		"The number is unverified", "Geo Permission configuration is not permitting call",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v\nwant it to carry %q", err, want)
		}
	}
}

func TestRecipientsTheBudgetCannotFundAreNamedRatherThanDropped(t *testing.T) {
	// A recipient skipped without a word is an alarm nobody was told about
	// that looks exactly like one that was delivered -- the single failure
	// this product exists to prevent.
	srv, got := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, twilioError(400, 21219, "The number is unverified"))
	})
	c := newChannel(t, srv, Config{Recipients: []string{testTo, testToSecond, testToThird}})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	err := c.Send(ctx, sampleAlert())
	if err == nil {
		t.Fatal("want an error")
	}
	if n := len(callsOnly(*got)); n != 1 {
		t.Errorf("attempts = %d, want 1: the budget could not fund the rest", n)
	}
	if !strings.Contains(err.Error(), "not attempted at all") {
		t.Errorf("error = %v\nwant it to say plainly that recipients were skipped", err)
	}
	for _, want := range []string{maskNumber(testToSecond), maskNumber(testToThird)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v\nwant it to name the skipped recipient %s", err, want)
		}
	}
}

func TestDuplicateRecipientsAreCalledOnce(t *testing.T) {
	// The same number twice is two billed calls to one handset, the second
	// arriving while the first is still ringing -- which reads as the system
	// malfunctioning at the moment it most needs to be trusted.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{Recipients: []string{testTo, " " + testTo + " ", testToSecond}})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if n := len(callsOnly(*got)); n != 2 {
		t.Errorf("placed %d calls, want 2", n)
	}
}

// --- what a 2xx does and does not prove -----------------------------------

func TestASuccessBodyThatIsNotACallResourceIsAFailure(t *testing.T) {
	// A 2xx that is not the call resource means something in front of the API
	// answered -- a captive portal, a proxy error page. Calling that delivered
	// is a guess, and this product's bias is to err toward a duplicate call
	// rather than toward silence.
	for _, body := range []string{
		"<html>hello from the captive portal</html>",
		`{"sid":""}`,
		`{"status":"queued"}`,
	} {
		srv, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, body)
		})
		c := newChannel(t, srv, Config{})
		if err := c.Send(context.Background(), sampleAlert()); err == nil {
			t.Errorf("body %q was accepted as a placed call", body)
		}
	}
}

// --- Test() ---------------------------------------------------------------

func TestTestPlacesNoCall(t *testing.T) {
	// THE WHOLE POINT. A test that costs money and rings somebody is not the
	// harmless message the Channel interface describes, and it is pressed
	// repeatedly while an operator tunes their configuration.
	srv, got := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"sid":"`+testAccountSID+`","friendly_name":"Home",`+
			`"status":"active","type":"Full"}`)
	})
	c := newChannel(t, srv, Config{})

	if err := c.Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}
	if n := len(callsOnly(*got)); n != 0 {
		t.Fatalf("Test placed %d calls; it must ring nobody", n)
	}
	if len(*got) != 1 {
		t.Fatalf("requests = %d, want exactly 1", len(*got))
	}
	req := (*got)[0]
	if req.method != http.MethodGet {
		t.Errorf("method = %s, want GET", req.method)
	}
	want := "/" + apiVersion + "/Accounts/" + testAccountSID + ".json"
	if req.path != want {
		t.Errorf("path = %q, want the account resource %q", req.path, want)
	}
	if !req.authOK || req.authUser != testAccountSID || req.authPass != testAuthToken {
		t.Error("the credential check must use the real credentials or it proves nothing")
	}
	// And the operator has to be told what was and was not proven, because
	// this button means something different here than on every other channel.
	for _, want := range []string{"NO CALL WAS PLACED", "credentials"} {
		if !strings.Contains(testSummary, want) {
			t.Errorf("TestSummary = %q\nwant it to say %q", testSummary, want)
		}
	}
}

func TestTestReportsBadCredentials(t *testing.T) {
	// The whole reason Test exists: catching a wrong credential at
	// configuration time rather than at 3am on a live incident.
	srv, got := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, twilioError(401, 20003, "Authenticate"))
	})
	c := newChannel(t, srv, Config{})

	err := c.Test(context.Background())
	if err == nil {
		t.Fatal("want an error")
	}
	if n := len(callsOnly(*got)); n != 0 {
		t.Error("a failed credential check must not fall back to placing a call")
	}
	if !strings.Contains(err.Error(), "account SID and auth token were refused") {
		t.Errorf("error = %v\nwant it to say what is wrong and where to fix it", err)
	}
	if strings.Contains(err.Error(), testAuthToken) {
		t.Errorf("the credential check leaked the auth token: %v", err)
	}
}

func TestTestRefusesToCallATrialAccountConfigured(t *testing.T) {
	// On a trial account Twilio plays its own message before our TwiML runs
	// and asks the person who answered to press a key, so an unattended phone
	// hears nothing while the API still returns a clean 201. Calling that
	// "configured correctly" is the one lie this product cannot tell.
	srv, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"sid":"`+testAccountSID+`","status":"active","type":"Trial"}`)
	})
	c := newChannel(t, srv, Config{})

	err := c.Test(context.Background())
	if err == nil {
		t.Fatal("a trial account must not be reported as working")
	}
	if !strings.Contains(err.Error(), "TRIAL") {
		t.Errorf("error = %v\nwant it to name the trial account", err)
	}
	// It must still be clear that the credentials themselves are fine, or the
	// operator goes and rotates a token that was never wrong.
	if !strings.Contains(err.Error(), "credentials are correct") {
		t.Errorf("error = %v\nwant it to say the credentials were accepted", err)
	}
}

func TestTestReportsASuspendedAccount(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"sid":"`+testAccountSID+`","status":"suspended","type":"Full"}`)
	})
	c := newChannel(t, srv, Config{})

	err := c.Test(context.Background())
	if err == nil {
		t.Fatal("want an error: a suspended account delivers nothing")
	}
	if !strings.Contains(err.Error(), "suspended") {
		t.Errorf("error = %v", err)
	}
}

func TestTestIsNotRetried(t *testing.T) {
	// A test is a person standing in front of the screen waiting for an
	// answer, and the answer to "did this work" is about this attempt.
	srv, got := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := newChannel(t, srv, Config{})
	slept := 0
	c.sleep = func(context.Context, time.Duration) error { slept++; return nil }

	if err := c.Test(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	if len(*got) != 1 {
		t.Errorf("requests = %d, want 1", len(*got))
	}
	if slept != 0 {
		t.Errorf("slept %d times during a test somebody is waiting on", slept)
	}
}

// --- what must never reach an error string --------------------------------

func TestCredentialsNeverReachAnErrorString(t *testing.T) {
	// This error string is stored on the incident as LastDeliveryError and
	// served from /api/incidents, which is deliberately readable without
	// signing in so that a wall display works. The response body is hostile on
	// purpose: a server we do not control decides what is in it.
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"4xx echoing the token", 400,
			`{"status":400,"message":"token ` + testAuthToken + ` is invalid","code":20003}`},
		{"5xx echoing the sid", 500,
			`{"status":500,"message":"account ` + testAccountSID + ` blew up"}`},
		{"non-JSON body echoing both", 502,
			"<html>" + testAuthToken + " " + testAccountSID + "</html>"},
		{"201 that is not a call resource", 201,
			"<html>" + testAuthToken + "</html>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			c := newChannel(t, srv, Config{})
			c.sleep = func(context.Context, time.Duration) error { return nil }

			err := c.Send(context.Background(), sampleAlert())
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), testAuthToken) {
				t.Errorf("error leaked the auth token: %v", err)
			}
			if strings.Contains(err.Error(), testAccountSID) {
				t.Errorf("error leaked the account SID: %v", err)
			}
		})
	}
}

func TestErrorsCarryNeitherThePathNorTheWholeRecipientNumber(t *testing.T) {
	// The request path carries the account SID, which is half the credential
	// pair; the recipient is somebody's personal mobile number. Both would be
	// published by a failed delivery into the sign-in-free /api/incidents.
	srv, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, twilioError(400, 21219, "The number is unverified"))
	})
	c := newChannel(t, srv, Config{})

	err := c.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "/Accounts/") {
		t.Errorf("error carries the request path: %v", err)
	}
	if strings.Contains(err.Error(), testTo) {
		t.Errorf("error published the recipient's full number: %v", err)
	}
	if !strings.Contains(err.Error(), maskNumber(testTo)) {
		t.Errorf("error = %v\nwant it to identify WHICH recipient failed", err)
	}
}

func TestATransportFailureDoesNotLeakThePath(t *testing.T) {
	// http.Client.Do wraps failures in *url.Error, whose Error() prints the
	// full request URL -- account SID and all -- which undoes the redaction
	// applied right next to it.
	srv, _ := okServer(t)
	c := newChannel(t, srv, Config{})
	srv.Close() // nothing is listening now

	err := c.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("want an error against a closed server")
	}
	if strings.Contains(err.Error(), testAccountSID) || strings.Contains(err.Error(), "/Accounts/") {
		t.Errorf("transport error leaked the request path: %v", err)
	}
	if !strings.Contains(err.Error(), "voice: calling") {
		t.Errorf("error = %v\nwant it to still say what was being attempted", err)
	}
}

func TestQuotedErrorBodyIsCapped(t *testing.T) {
	// A proxy's HTML error page is not going into an incident record whole.
	srv, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "<html>"+strings.Repeat("padding ", 5000)+"</html>")
	})
	c := newChannel(t, srv, Config{})

	err := c.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("want an error")
	}
	if len(err.Error()) > maxErrorBody+500 {
		t.Errorf("error is %d bytes; the response body was not capped", len(err.Error()))
	}
}

// --- construction ---------------------------------------------------------

func TestNewValidatesEverythingUpFront(t *testing.T) {
	// Refusing at construction rather than at first send: the alternative is
	// discovering the misconfiguration from a failed delivery on a live
	// incident, and for this channel the misconfiguration is usually a From
	// number nobody verified.
	base := validConfig()
	tests := []struct {
		name string
		mut  func(*Config)
	}{
		{"no account sid", func(c *Config) { c.AccountSID = "" }},
		{"no auth token", func(c *Config) { c.AuthToken = "" }},
		{"credentials the wrong way round", func(c *Config) { c.AccountSID = secret.Secret(testAuthToken) }},
		{"no from number", func(c *Config) { c.From = "" }},
		{"from without a plus", func(c *Config) { c.From = "15552223214" }},
		{"from with punctuation", func(c *Config) { c.From = "+1 (555) 222-3214" }},
		{"from starting with a zero", func(c *Config) { c.From = "+0442079460000" }},
		{"no recipients", func(c *Config) { c.Recipients = nil }},
		{"blank recipients only", func(c *Config) { c.Recipients = []string{"", "   "} }},
		{"recipient not E.164", func(c *Config) { c.Recipients = []string{"0770 090 0123"} }},
		{"recipient too long", func(c *Config) { c.Recipients = []string{"+1234567890123456"} }},
		{"voice with a quote in it", func(c *Config) { c.Voice = `man" onload="` }},
		{"language with a space", func(c *Config) { c.Language = "en US" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			cfg.Recipients = append([]string(nil), base.Recipients...)
			tt.mut(&cfg)
			if _, err := New(cfg, nil); err == nil {
				t.Error("New returned nil error, want a refusal")
			}
		})
	}

	c, err := New(base, nil)
	if err != nil {
		t.Fatalf("New with a valid config: %v", err)
	}
	if c.endpoint != DefaultEndpoint {
		t.Errorf("endpoint = %q, want %q", c.endpoint, DefaultEndpoint)
	}
	if c.cfg.Voice != DefaultVoice || c.cfg.Language != DefaultLanguage {
		t.Errorf("voice/language = %q/%q, want the defaults filled in", c.cfg.Voice, c.cfg.Language)
	}
}

func TestNewRefusalDoesNotLeakTheCredentialItDidReceive(t *testing.T) {
	// Including the case where the auth token was pasted into the SID field,
	// which is the mistake the "AC" check exists to catch: echoing the value
	// back would write the credential into a startup log.
	for _, cfg := range []Config{
		{AccountSID: secret.Secret(testAccountSID)},
		{AccountSID: secret.Secret(testAuthToken), AuthToken: secret.Secret(testAuthToken)},
	} {
		_, err := New(cfg, nil)
		if err == nil {
			t.Fatal("want an error")
		}
		if strings.Contains(err.Error(), testAuthToken) || strings.Contains(err.Error(), testAccountSID) {
			t.Errorf("the refusal leaked a credential: %v", err)
		}
	}
}

func TestName(t *testing.T) {
	c, err := New(validConfig(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Name() != "voice" {
		t.Errorf("Name = %q", c.Name())
	}
}

// Formatting a Channel must never print a credential.
//
// This is not hypothetical and it is not obvious. secret.Secret renders as
// <redacted> through %v -- but ONLY when fmt is allowed to call its String()
// method, and fmt refuses to call methods on values it reaches through an
// unexported struct field. Channel holds its Config unexported, so without
// Channel.String(), %v on a *Channel prints every credential in cleartext
// while %v on the same Config prints <redacted>. Measured in two other
// channels in this package before it was fixed there.
//
// %#v is deliberately NOT asserted: it consults GoStringer rather than
// Stringer and leaks through a bare Config too. Fixing that belongs on
// secret.Secret, not on every type that holds one.
func TestFormattingAChannelNeverPrintsACredential(t *testing.T) {
	ch, err := New(validConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	canaries := []string{testAccountSID, testAuthToken, testTo}
	for _, verb := range []string{"%v", "%+v", "%s"} {
		for _, subject := range []any{ch, *ch} {
			got := fmt.Sprintf(verb, subject)
			for _, c := range canaries {
				if strings.Contains(got, c) {
					t.Errorf("%s leaked %q: %s", verb, c, got)
				}
			}
			if !strings.Contains(got, "redacted") {
				t.Errorf("%s did not say anything was redacted: %s", verb, got)
			}
		}
	}
}

// Compile-time proof that this satisfies the interface the scheduler uses.
var _ channel.Channel = (*Channel)(nil)

// realCreatedCall is the call resource Twilio ACTUALLY returns for a created
// call: every documented field, and the nine subresource_uris.
//
// The short stub above is convenient and dishonest. Twilio's real 201 body is
// well over a kilobyte, and "sid" sorts late enough to land past the first
// half of it -- so a body read through a 512-byte cap is truncated into
// invalid JSON, and the parse that decides whether the call was accepted fails
// on every real call while passing against the stub.
func realCreatedCall(to string) string {
	return `{"account_sid":"` + testAccountSID + `","annotation":null,"answered_by":null,` +
		`"api_version":"2010-04-01","caller_name":null,` +
		`"date_created":"Tue, 16 Sep 2026 22:45:28 +0000",` +
		`"date_updated":"Tue, 16 Sep 2026 22:45:28 +0000",` +
		`"direction":"outbound-api","duration":null,"end_time":null,` +
		`"forwarded_from":null,"from":"` + testFrom + `","from_formatted":"(865) 555-0100",` +
		`"group_sid":null,"parent_call_sid":null,` +
		`"phone_number_sid":"PN10000000000000000000000000000001",` +
		`"price":null,"price_unit":"USD","queue_time":"1000",` +
		`"sid":"CA10000000000000000000000000000001","start_time":null,"status":"queued",` +
		`"subresource_uris":{` +
		`"events":"/2010-04-01/Accounts/` + testAccountSID + `/Calls/CA1000.json/Events.json",` +
		`"notifications":"/2010-04-01/Accounts/` + testAccountSID + `/Calls/CA1000.json/Notifications.json",` +
		`"payments":"/2010-04-01/Accounts/` + testAccountSID + `/Calls/CA1000.json/Payments.json",` +
		`"recordings":"/2010-04-01/Accounts/` + testAccountSID + `/Calls/CA1000.json/Recordings.json",` +
		`"siprec":"/2010-04-01/Accounts/` + testAccountSID + `/Calls/CA1000.json/Siprec.json",` +
		`"streams":"/2010-04-01/Accounts/` + testAccountSID + `/Calls/CA1000.json/Streams.json",` +
		`"transcriptions":"/2010-04-01/Accounts/` + testAccountSID + `/Calls/CA1000.json/Transcriptions.json",` +
		`"user_defined_message_subscriptions":"/2010-04-01/Accounts/` + testAccountSID + `/Calls/CA1000.json/UserDefinedMessageSubscriptions.json",` +
		`"user_defined_messages":"/2010-04-01/Accounts/` + testAccountSID + `/Calls/CA1000.json/UserDefinedMessages.json"},` +
		`"to":"` + to + `","to_formatted":"(865) 555-0111","trunk_sid":null,` +
		`"uri":"/2010-04-01/Accounts/` + testAccountSID + `/Calls/CA1000.json"}`
}

// A CALL THAT WAS ACCEPTED MUST BE REPORTED AS ACCEPTED.
//
// The success body was read through the cap meant for quoting ERROR bodies, so
// a real call resource arrived truncated, failed to parse, and every placed
// call was reported as "the response was not a call resource". Every phone
// rang, every call was billed, and the incident recorded that nothing was
// accepted -- so the ladder re-dialled, for ever. The test suite could not see
// it because the fake 201 was a 230-byte stub.
func TestARealSizedCallResourceIsAccepted(t *testing.T) {
	body := realCreatedCall(testTo)
	if len(body) <= maxErrorBody {
		t.Fatalf("this fixture is %d bytes, which no longer exercises the bug", len(body))
	}
	if strings.Index(body, `"sid"`) <= maxErrorBody {
		t.Fatalf(`"sid" at byte %d is inside the cap; the fixture no longer reproduces`,
			strings.Index(body, `"sid"`))
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := newChannel(t, srv, Config{})
	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("a real Twilio call resource was reported as a failure: %v", err)
	}
}

// TWILIO QUOTES THE NUMBER BACK, AND THAT STRING GETS PUBLISHED.
//
// A delivery error is stored on the incident as LastDeliveryError and served
// from /api/incidents, which does not require signing in so that a wall
// display works. Twilio's own error text names the offending number -- for an
// invalid number, an unverified trial number, and a geo-permission refusal --
// so pasting its message in verbatim published the operator's personal mobile
// to every device on the network, three lines after the code had carefully
// masked it.
func TestTwilioErrorTextDoesNotRepublishTheNumber(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    int
		message string
	}{
		{"invalid number", 21211, `The 'To' number ` + testTo + ` is not a valid phone number.`},
		{"unverified trial", 21219, `The 'To' number ` + testTo + ` is not verified. Trial accounts cannot call unverified numbers.`},
		{"geo permission", 21215, `Account not authorized to call ` + testTo + `. Enable permissions in the console.`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(twilioError(400, tc.code, tc.message)))
			}))
			defer srv.Close()

			c := newChannel(t, srv, Config{})
			err := c.Send(context.Background(), sampleAlert())
			if err == nil {
				t.Fatal("a refused call reported success")
			}
			if strings.Contains(err.Error(), testTo) {
				t.Errorf("the recipient's number is in an error that gets published:\n%v", err)
			}
			if strings.Contains(err.Error(), testFrom) {
				t.Errorf("the caller ID number is in an error that gets published:\n%v", err)
			}
			// The advice still has to survive, or the masking has cost the
			// operator the one thing that tells them how to fix it.
			if !strings.Contains(err.Error(), "+...5310") {
				t.Errorf("the masked number was lost entirely:\n%v", err)
			}
		})
	}
}

// A body far larger than the error cap must not be pasted whole into the
// incident record just because success bodies are now read in full.
func TestAnOversizedErrorBodyIsTruncatedBeforeItIsQuoted(t *testing.T) {
	huge := `<html><body>` + strings.Repeat("proxy error page. ", 2000) + `</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(huge))
	}))
	defer srv.Close()

	c := newChannel(t, srv, Config{})
	err := c.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("a 502 reported success")
	}
	if len(err.Error()) > 4*maxErrorBody {
		t.Errorf("a %d-byte proxy page produced a %d-byte error bound for the incident record",
			len(huge), len(err.Error()))
	}
}
