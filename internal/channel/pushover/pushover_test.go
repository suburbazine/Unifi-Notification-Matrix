package pushover

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// The credentials used throughout. Distinctive strings so that a leak into a
// URL, an error or a log line is unambiguous when a test finds one.
const (
	testToken = "tk-APPLICATIONTOKEN-leakme"
	testUser  = "uk-USERKEY-leakme"
)

// capture records what the server actually received. Every bug this file
// guards against is a bug in what goes on the wire, so that is what is
// asserted on -- including rawURL and rawBody, because "this must never
// appear" is only provable against the unparsed bytes.
type capture struct {
	method  string
	rawURL  string
	query   url.Values
	header  http.Header
	rawBody []byte
	form    url.Values
}

func newServer(t *testing.T, status int, respBody string, headers map[string]string) (*httptest.Server, *[]capture) {
	t.Helper()
	var got []capture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		got = append(got, capture{
			method:  r.Method,
			rawURL:  r.URL.String(),
			query:   r.URL.Query(),
			header:  r.Header.Clone(),
			rawBody: body,
			form:    form,
		})
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func okServer(t *testing.T) (*httptest.Server, *[]capture) {
	t.Helper()
	return newServer(t, http.StatusOK, `{"status":1,"request":"647d2300-702c"}`, nil)
}

func newChannel(t *testing.T, srv *httptest.Server, cfg Config) *Channel {
	t.Helper()
	if cfg.Token.IsZero() {
		cfg.Token = secret.Secret(testToken)
	}
	if cfg.User.IsZero() {
		cfg.User = secret.Secret(testUser)
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

func TestSendPostsFormEncodedBody(t *testing.T) {
	// Pushover accepts only x-www-form-urlencoded on this endpoint; a JSON
	// body is answered with a 4xx that reads like a credential problem.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(*got) != 1 {
		t.Fatalf("want 1 request, got %d", len(*got))
	}
	req := (*got)[0]
	if req.method != http.MethodPost {
		t.Errorf("method = %s, want POST", req.method)
	}
	if ct := req.header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", ct)
	}
	if req.form.Get("message") == "" {
		t.Error("message field is empty")
	}
	if req.form.Get("title") != "Door forced open" {
		t.Errorf("title = %q", req.form.Get("title"))
	}
}

func TestCredentialsReachTheFormAndNothingElse(t *testing.T) {
	// The one leak that matters. A token or user key in the query string is
	// copied into every proxy access log on the path, and a leak into the
	// error string lands in the incident record and the UI. Asserted against
	// the raw bytes, because that is the only way to prove absence.
	srv, got := newServer(t, http.StatusOK, `{"status":1,"request":"x"}`, nil)
	c := newChannel(t, srv, Config{})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]

	if req.form.Get("token") != testToken {
		t.Errorf("token did not reach the form: %q", req.form.Get("token"))
	}
	if req.form.Get("user") != testUser {
		t.Errorf("user key did not reach the form: %q", req.form.Get("user"))
	}
	for _, cred := range []string{testToken, testUser} {
		if strings.Contains(req.rawURL, cred) {
			t.Fatalf("credential leaked into the request URL: %q", req.rawURL)
		}
		for k, vs := range req.query {
			for _, v := range vs {
				if strings.Contains(v, cred) {
					t.Fatalf("credential leaked into query parameter %q", k)
				}
			}
		}
		for k, vs := range req.header {
			for _, v := range vs {
				if strings.Contains(v, cred) {
					t.Fatalf("credential leaked into header %q", k)
				}
			}
		}
	}
}

func TestCredentialsNeverReachAnErrorString(t *testing.T) {
	// This error string is stored on the incident and rendered in the UI, so
	// it is about as observable as a value can get. The response body is
	// hostile on purpose: a server we do not control decides what is in it.
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"4xx echoing the token", http.StatusBadRequest,
			`{"status":0,"errors":["application token ` + testToken + ` is invalid"]}`},
		{"5xx echoing the user key", http.StatusInternalServerError,
			`{"status":0,"errors":["user ` + testUser + ` blew up"]}`},
		{"non-JSON body echoing both", http.StatusBadGateway,
			"<html>" + testToken + " " + testUser + "</html>"},
		{"2xx refusal echoing the token", http.StatusOK,
			`{"status":0,"errors":["token ` + testToken + `"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newServer(t, tc.status, tc.body, nil)
			c := newChannel(t, srv, Config{})

			err := c.Send(context.Background(), sampleAlert())
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), testToken) {
				t.Errorf("error leaked the application token: %v", err)
			}
			if strings.Contains(err.Error(), testUser) {
				t.Errorf("error leaked the user key: %v", err)
			}
		})
	}
}

func TestSecretDoesNotRenderThroughFormatting(t *testing.T) {
	// The reason Config holds secret.Secret rather than string: a Config
	// reaching a log line or an error through %v must not carry the
	// credentials with it.
	cfg := Config{Token: secret.Secret(testToken), User: secret.Secret(testUser)}
	// %v on the struct: the exact accident secret.Secret exists to stop.
	rendered := fmt.Sprintf("%v", cfg)
	if strings.Contains(rendered, testToken) || strings.Contains(rendered, testUser) {
		t.Fatalf("formatting a Config leaked a credential: %s", rendered)
	}
	if !strings.Contains(rendered, "<redacted>") {
		t.Errorf("expected the redaction marker, got %s", rendered)
	}
}

func TestChannelDoesNotRenderCredentialsThroughFormatting(t *testing.T) {
	// THE BUG THIS PINS. secret.Secret's redaction does not survive being
	// reached through Channel's unexported cfg field: fmt calls String() only
	// on a value it may hand to an interface, and a value read out of an
	// unexported field is not one, so before Channel had its own String()
	// method, fmt.Sprintf("%v", channel) printed the application token and the
	// user key in the clear -- while the same Config printed <redacted>.
	//
	// The test above passes either way, because Config's fields are exported
	// and it is formatted directly. This one is the case that was unguarded,
	// and it is the realistic one: what gets logged is the channel, not the
	// config.
	c, err := New(Config{
		Token: secret.Secret(testToken),
		User:  secret.Secret(testUser),
		// Non-secret fields must still be legible, or the next person deletes
		// this method to get their diagnostic back.
		Device: "night-phone",
		Sound:  "siren",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The shape of the line that would have done the damage: a diagnostic
	// reporting a failure and interpolating the channel rather than Name().
	boom := errors.New("delivery failed")

	for _, rendered := range []string{
		fmt.Sprintf("%v", c),  // the pointer everything actually holds
		fmt.Sprintf("%v", *c), // a stray copy
		fmt.Sprintf("channel %v failed: %v", c, boom),
	} {
		if strings.Contains(rendered, testToken) {
			t.Errorf("formatting the channel leaked the application token: %s", rendered)
		}
		if strings.Contains(rendered, testUser) {
			t.Errorf("formatting the channel leaked the user key: %s", rendered)
		}
		if !strings.Contains(rendered, "<redacted>") {
			t.Errorf("expected the redaction marker, got %s", rendered)
		}
		if !strings.Contains(rendered, "night-phone") {
			t.Errorf("the rendering dropped the non-secret detail that makes it useful: %s", rendered)
		}
	}
}

func TestSeverityToPriority(t *testing.T) {
	tests := []struct {
		sev  incident.Severity
		want int
	}{
		{incident.SeverityCritical, 1},
		{incident.SeverityHigh, 1},
		{incident.SeverityMedium, 0},
		{incident.SeverityLow, -1},
		{incident.SeverityInfo, -1},
		// An unrecognised severity must still be delivered audibly-ish: normal
		// priority, not silence.
		{incident.Severity("nonsense"), 0},
		{incident.Severity(""), 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			if got := priorityFor(tt.sev); got != tt.want {
				t.Errorf("priorityFor(%q) = %d, want %d", tt.sev, got, tt.want)
			}
		})
	}
}

func TestPriorityTwoIsUnreachable(t *testing.T) {
	// THE RULE THIS PACKAGE EXISTS TO KEEP. Priority 2 is Pushover's emergency
	// mode: Pushover re-alerts on its own timer until somebody acknowledges IN
	// PUSHOVER. That is a second escalation ladder with a second
	// acknowledgement this product cannot see -- acknowledging there silences
	// the phone while the incident keeps escalating everywhere else, and
	// acknowledging here does not stop the phone. Asserted on the wire for
	// every severity, valid or not, because a mapping table is exactly the
	// kind of thing a well-meaning edit widens.
	severities := []incident.Severity{
		incident.SeverityCritical, incident.SeverityHigh, incident.SeverityMedium,
		incident.SeverityLow, incident.SeverityInfo,
		incident.Severity(""), incident.Severity("emergency"), incident.Severity("2"),
		incident.Severity("CRITICAL"), incident.Severity("critical!!!"),
	}
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	for _, sev := range severities {
		a := sampleAlert()
		a.Severity = sev
		if err := c.Send(context.Background(), a); err != nil {
			t.Fatalf("Send(%q): %v", sev, err)
		}
	}
	if err := c.Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}

	if len(*got) != len(severities)+1 {
		t.Fatalf("want %d requests, got %d", len(severities)+1, len(*got))
	}
	for i, req := range *got {
		p := req.form.Get("priority")
		if p == "2" {
			t.Fatalf("request %d emitted priority=2", i)
		}
		if p != "1" && p != "0" && p != "-1" {
			t.Errorf("request %d priority = %q, outside the permitted set", i, p)
		}
		// Raw-bytes check too: a stray "priority=2" reaching the wire through
		// any path at all, including a duplicated field, must fail this.
		if strings.Contains(string(req.rawBody), "priority=2") {
			t.Fatalf("request %d body carries priority=2: %s", i, req.rawBody)
		}
	}
}

func TestPriorityClampRefusesTwo(t *testing.T) {
	// The second lock. priorityFor cannot return 2 today; form() clamps anyway
	// so that a future edit to the mapping cannot quietly put emergency mode
	// on the wire.
	c := &Channel{cfg: Config{Token: secret.Secret(testToken), User: secret.Secret(testUser)}}
	for _, p := range []int{2, 3, 99} {
		if got := c.form(message{priority: p}).Get("priority"); got != "1" {
			t.Errorf("priority %d encoded as %q, want clamped to 1", p, got)
		}
	}
	// And the floor: -2 is "no notification at all", which a channel that was
	// configured to alert must never produce.
	if got := c.form(message{priority: -2}).Get("priority"); got != "-1" {
		t.Errorf("priority -2 encoded as %q, want clamped to -1", got)
	}
}

func TestAckURLSurvivesIntact(t *testing.T) {
	// The whole point of the channel: somebody taps this at 3am and the
	// escalation stops. A mangled or truncated link means an incident that
	// nags until somebody opens a laptop.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.AckURL = "https://alerts.example.net/ack/inc-1/9f3a?sig=abc%2Fdef&t=1789"

	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	if got := req.form.Get("url"); got != a.AckURL {
		t.Errorf("url = %q\nwant     %q", got, a.AckURL)
	}
	if got := req.form.Get("url_title"); got != "Acknowledge" {
		t.Errorf("url_title = %q, want Acknowledge", got)
	}
}

func TestLongBodyIsTruncatedButTheAckURLIsNot(t *testing.T) {
	// Pushover rejects the WHOLE message when a field is over its limit, so an
	// untruncated body is not a long alert -- it is no alert. The ack link
	// never pays for that: a cut-off URL is a link that fails on the tap,
	// which is worse than a cut-off sentence.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.Body = strings.Repeat("Motion detected in the loading bay. ", 200) // ~7200 chars
	a.Title = strings.Repeat("Very long title ", 40)                     // ~640 chars

	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]

	msg := req.form.Get("message")
	if n := utf8.RuneCountInString(msg); n > maxMessage {
		t.Errorf("message is %d runes, over Pushover's limit of %d", n, maxMessage)
	}
	if n := utf8.RuneCountInString(msg); n < maxMessage-len(truncationMarker)-40 {
		t.Errorf("message is only %d runes; truncation threw away usable space", n)
	}
	if !strings.HasSuffix(msg, truncationMarker) {
		t.Errorf("truncation was not marked; message ends %q", tail(msg, 40))
	}
	if title := req.form.Get("title"); utf8.RuneCountInString(title) > maxTitle {
		t.Errorf("title is %d runes, over the limit of %d", utf8.RuneCountInString(title), maxTitle)
	}
	if got := req.form.Get("url"); got != a.AckURL {
		t.Errorf("ack url = %q, want it untouched by truncation", got)
	}
}

func TestNonASCIIBodyFillsTheFieldItIsGiven(t *testing.T) {
	// THE BUG THIS PINS, and it was a hole in this test rather than in the
	// code: as originally written this test asserted only that the truncated
	// message was valid UTF-8, under the limit, and free of U+FFFD. Replacing
	// truncateRunes with a byte-slicing version satisfied all three for this
	// fixture -- the byte cut happens to land on a rune boundary -- so nothing
	// in the package failed if the truncation stopped counting characters.
	//
	// What byte slicing cannot fake is the FILL. Pushover counts characters,
	// so 1024 bytes of German prose is 975 characters: 49 characters of the
	// alert thrown away silently, every time, on any alert whose text is not
	// pure ASCII. A camera named "Café" is a normal case, not an exotic one.
	//
	// The other half of the original comment, that a byte cut can leave half a
	// rune behind, is pinned in TestTruncateRunesCountsRunesNotBytes, where
	// the offset can be chosen to land mid-rune instead of being left to the
	// luck of a particular sentence.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.Body = strings.Repeat("Bewegung erkannt am Türsensor im Café. ", 100)

	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msg := (*got)[0].form.Get("message")
	if !utf8.ValidString(msg) {
		t.Fatalf("truncation produced invalid UTF-8: %q", tail(msg, 40))
	}
	if strings.Contains(msg, "�") {
		t.Errorf("truncation split a rune: %q", tail(msg, 40))
	}
	n := utf8.RuneCountInString(msg)
	if n > maxMessage {
		t.Errorf("message is %d runes, over the limit of %d", n, maxMessage)
	}
	// The margin is for the trailing whitespace truncateRunes trims off the
	// cut, not for a byte-wise cut: that one lands at 975 and fails here.
	if n < maxMessage-16 {
		t.Errorf("message is %d runes of the %d Pushover allows; truncation counted bytes, not characters", n, maxMessage)
	}
}

func TestTruncateRunesCountsRunesNotBytes(t *testing.T) {
	// The boundary half of the same bug, asserted where the cut offset can be
	// chosen rather than inherited from whatever prose a test happens to use.
	// A byte cut of "a" + "é"*n lands between the two bytes of an é and puts a
	// lone 0xC3 on the wire; Pushover then either shows mojibake or refuses
	// the message, and by the package doc a refused message is a silent alert.
	tests := []struct {
		name   string
		in     string
		limit  int
		marker string
		want   string
	}{
		{
			name:   "under the limit is untouched",
			in:     "Café",
			limit:  10,
			marker: truncationMarker,
			want:   "Café",
		},
		{
			name:   "cut lands mid-rune for a byte slicer",
			in:     "a" + strings.Repeat("é", 200),
			limit:  20,
			marker: "",
			want:   "a" + strings.Repeat("é", 19),
		},
		{
			name:   "every kept character counts as one",
			in:     strings.Repeat("é", 200),
			limit:  8,
			marker: "",
			want:   strings.Repeat("é", 8),
		},
		{
			name:   "the marker is paid for in characters too",
			in:     strings.Repeat("ü", 200),
			limit:  20,
			marker: truncationMarker,
			want:   strings.Repeat("ü", 20-len([]rune(truncationMarker))) + truncationMarker,
		},
		{
			name:   "no room for the marker still cuts cleanly",
			in:     strings.Repeat("ü", 200),
			limit:  4,
			marker: truncationMarker,
			want:   strings.Repeat("ü", 4),
		},
		{
			name:   "nothing fits",
			in:     "Café",
			limit:  0,
			marker: truncationMarker,
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateRunes(tt.in, tt.limit, tt.marker)
			if got != tt.want {
				t.Errorf("truncateRunes(...) = %q\nwant                 %q", got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("result is not valid UTF-8: %q", got)
			}
			if n := utf8.RuneCountInString(got); n > tt.limit {
				t.Errorf("result is %d runes, over the limit of %d", n, tt.limit)
			}
		})
	}
}

func TestOverlongAckURLGoesInTheBodyRatherThanBeingCut(t *testing.T) {
	// A URL past Pushover's 512-character url field cannot go there, and
	// cutting it to fit would produce a dead link. Falling back to the message
	// costs a tap; a broken link costs the acknowledgement entirely.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.AckURL = "https://alerts.example.net/ack/inc-1/" + strings.Repeat("a", 520)
	a.Body = strings.Repeat("Loading bay motion. ", 300)

	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	if req.form.Get("url") != "" {
		t.Errorf("url field carried an over-long link: %q", req.form.Get("url"))
	}
	msg := req.form.Get("message")
	if !strings.Contains(msg, a.AckURL) {
		t.Fatalf("the ack URL did not survive into the body; message tail = %q", tail(msg, 80))
	}
	if n := utf8.RuneCountInString(msg); n > maxMessage {
		t.Errorf("message is %d runes, over the limit of %d", n, maxMessage)
	}
}

func TestNoAckURLSendsNoURLFields(t *testing.T) {
	// Pushover rejects url_title without url, so an incident with no ack route
	// must not emit a dangling label.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.AckURL = ""
	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	if _, ok := req.form["url"]; ok {
		t.Error("url field present with no ack URL")
	}
	if _, ok := req.form["url_title"]; ok {
		t.Error("url_title present with no url")
	}
}

func TestArrivalTimeIsWordedReceivedAndNotSentAsTimestamp(t *testing.T) {
	// Presenting an arrival time as an observation time sends somebody
	// scrubbing footage to a moment that means nothing, and they distrust the
	// product rather than the timestamp. Pushover's own timestamp field is
	// left off too, so the notification shows when it actually arrived.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.AtIsArrivalTime = true
	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	msg := req.form.Get("message")
	if !strings.Contains(msg, "received 03:14:07") {
		t.Errorf("message = %q, want \"received HH:MM:SS\"", msg)
	}
	if strings.Contains(msg, "at 03:14:07") {
		t.Errorf("message = %q, an arrival time must not be presented as an observation time", msg)
	}
	if ts := req.form.Get("timestamp"); ts != "" {
		t.Errorf("timestamp = %q; an arrival time must not be stamped as the event time", ts)
	}
}

func TestObservationTimeIsWordedAtAndIsSentAsTimestamp(t *testing.T) {
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	msg := req.form.Get("message")
	if !strings.Contains(msg, "at 03:14:07") {
		t.Errorf("message = %q, want \"at HH:MM:SS\"", msg)
	}
	if strings.Contains(msg, "received") {
		t.Errorf("message = %q, a real observation time must not say \"received\"", msg)
	}
	if ts := req.form.Get("timestamp"); ts != "1789442047" {
		t.Errorf("timestamp = %q, want the observation time in Unix seconds", ts)
	}
	// The body has to say what happened and to what, not just when.
	if !strings.Contains(msg, "Front Door") {
		t.Errorf("message = %q, missing the entity", msg)
	}
	if !strings.Contains(msg, "Door position reports open.") {
		t.Errorf("message = %q, lost a line of the detail", msg)
	}
	if !strings.Contains(msg, "Open for 12m") {
		t.Errorf("message = %q, missing how long the condition has been true", msg)
	}
}

func TestRepeatSaysWhichReminderItIs(t *testing.T) {
	// A re-alert that looks identical to the one already swiped away gets
	// swiped away too. The marker goes in the title because that is what a
	// locked screen shows, and it survives title truncation because the count
	// is the part that carries the information.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.Repeat = 3
	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if title := (*got)[0].form.Get("title"); title != "Door forced open (reminder 3)" {
		t.Errorf("title = %q", title)
	}

	long := sampleAlert()
	long.Repeat = 7
	long.Title = strings.Repeat("x", 400)
	if err := c.Send(context.Background(), long); err != nil {
		t.Fatalf("Send: %v", err)
	}
	title := (*got)[1].form.Get("title")
	if utf8.RuneCountInString(title) > maxTitle {
		t.Errorf("title is %d runes, over the limit of %d", utf8.RuneCountInString(title), maxTitle)
	}
	if !strings.HasSuffix(title, "(reminder 7)") {
		t.Errorf("truncation ate the reminder count: %q", tail(title, 40))
	}
}

func TestDeviceAndSoundAreSentOnlyWhenSet(t *testing.T) {
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{Device: "night-phone", Sound: "siren"})
	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if d := (*got)[0].form.Get("device"); d != "night-phone" {
		t.Errorf("device = %q", d)
	}
	if s := (*got)[0].form.Get("sound"); s != "siren" {
		t.Errorf("sound = %q", s)
	}

	srv2, got2 := okServer(t)
	c2 := newChannel(t, srv2, Config{})
	if err := c2.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Pushover treats an empty device as a filter matching nothing on some
	// client versions, so the field must be absent rather than blank.
	if _, ok := (*got2)[0].form["device"]; ok {
		t.Error("device sent as an empty field")
	}
	if _, ok := (*got2)[0].form["sound"]; ok {
		t.Error("sound sent as an empty field")
	}
}

func TestHTMLIsNeverEnabled(t *testing.T) {
	// Entity names come from whatever the operator typed into the UniFi
	// console. With html=1 a camera called "Gate <rear> & side" renders as
	// broken markup or silently loses the angle-bracketed part.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.Entity = "Gate <rear> & side"
	a.Title = "Tamper <alarm>"
	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	if _, ok := req.form["html"]; ok {
		t.Errorf("html = %q; alert text is not markup", req.form.Get("html"))
	}
	if !strings.Contains(req.form.Get("message"), "Gate <rear> & side") {
		t.Errorf("message = %q, the entity name was mangled", req.form.Get("message"))
	}
}

func TestSnapshotIsDroppedAndNeverInlinedIntoTheForm(t *testing.T) {
	// Alert.Snapshot is deliberately not sent -- fact 4 in the package doc
	// says so and says what it costs. This test pins the DELIBERATE part, so
	// that the obvious well-meaning fix cannot land silently: base64ing a
	// UniFi frame into a form field turns a 1 KB post into a 300 KB one and
	// Pushover refuses the whole message, which by fact 3 is a silent alert --
	// the picture bought at the price of the alarm.
	//
	// An alert that carries a snapshot must still deliver, text intact. If
	// this channel ever does attach the image it goes as multipart/form-data
	// with a size check and a text-only fallback, and this test is the one
	// that has to be rewritten to say so.
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.Snapshot = bytes.Repeat([]byte{0xFF, 0xD8, 0xFF, 0xE0}, 64*1024) // 256 KB, an ordinary frame

	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	if n := len(req.rawBody); n > 4096 {
		t.Errorf("request body is %d bytes; the snapshot was inlined into it", n)
	}
	for _, field := range []string{"attachment", "attachment_base64", "attachment_type"} {
		if _, ok := req.form[field]; ok {
			t.Errorf("form carries %q; attaching is a deliberate change, not an accident", field)
		}
	}
	if !strings.Contains(req.form.Get("message"), "Front Door") {
		t.Errorf("message = %q; the text alert must survive an alert that carries a frame", req.form.Get("message"))
	}
	if req.form.Get("url") != a.AckURL {
		t.Errorf("ack url = %q, want it intact", req.form.Get("url"))
	}
}

func TestRateLimitIsRetriedAndBounded(t *testing.T) {
	// 429 is worth a short retry; it must still stop. The escalation ladder
	// above this channel is what provides persistence, so a channel that
	// retries for minutes is duplicating that job without any of the incident
	// state that makes it safe.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"status":0,"errors":["message limit reached"]}`)
	}))
	defer srv.Close()

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
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Errorf("attempts = %d, want 4 (one plus three backoffs)", got)
	}
	if len(waits) != len(retryBackoff) {
		t.Fatalf("waits = %v, want the full ladder %v", waits, retryBackoff)
	}
	for i := range retryBackoff {
		if waits[i] != retryBackoff[i] {
			t.Errorf("wait %d = %v, want %v", i, waits[i], retryBackoff[i])
		}
	}
	if !strings.Contains(err.Error(), "message limit reached") {
		t.Errorf("error should still quote what the server said: %v", err)
	}
}

func TestRateLimitAndServerErrorReadDifferently(t *testing.T) {
	// THE BUG THIS PINS. Both statuses shared one sentence, "could not accept
	// the message right now". That is true of a 5xx blip and misleading about
	// a 429: Pushover returns 429 when the application's monthly message
	// allowance is spent, "right now" is then the rest of the month, and the
	// fifteen-second ladder cannot clear it. This error string is what the
	// incident record and the UI show, so it is the only account of the
	// failure most operators read -- and it has to point at the real remedy
	// (more messages, or this stage delivered elsewhere) rather than at
	// waiting.
	t.Run("429 names the allowance", func(t *testing.T) {
		srv, _ := newServer(t, http.StatusTooManyRequests,
			`{"status":0,"errors":["message limit reached"]}`, nil)
		c := newChannel(t, srv, Config{})

		err := c.Send(context.Background(), sampleAlert())
		if err == nil {
			t.Fatal("want an error")
		}
		if !strings.Contains(err.Error(), "monthly message allowance") {
			t.Errorf("error = %v\nwant it to name the monthly allowance", err)
		}
		if !strings.Contains(err.Error(), "message limit reached") {
			t.Errorf("error = %v\nwant it to keep quoting what the server said", err)
		}
		if strings.Contains(err.Error(), "right now") {
			t.Errorf("error = %v\na spent monthly quota must not read as a momentary blip", err)
		}
	})

	t.Run("5xx is not mislabelled as a quota", func(t *testing.T) {
		// The other direction matters just as much: a server blip reported as
		// an exhausted allowance sends the operator to buy messages they
		// already have.
		srv, _ := newServer(t, http.StatusBadGateway, "", nil)
		c := newChannel(t, srv, Config{})

		err := c.Send(context.Background(), sampleAlert())
		if err == nil {
			t.Fatal("want an error")
		}
		if strings.Contains(err.Error(), "allowance") {
			t.Errorf("error = %v\na 502 is not a quota problem", err)
		}
	})
}

func TestServerErrorsAreRetried(t *testing.T) {
	// Pushover runs behind a single API host: a 5xx is nearly always a blip,
	// and losing an alert to a blip is the failure that matters.
	for _, status := range []int{
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.WriteHeader(status)
		}))
		c := newChannel(t, srv, Config{})
		slept := 0
		c.sleep = func(context.Context, time.Duration) error { slept++; return nil }

		if err := c.Send(context.Background(), sampleAlert()); err == nil {
			t.Errorf("status %d: want an error", status)
		}
		if got := atomic.LoadInt32(&calls); got != 4 {
			t.Errorf("status %d: attempts = %d, want 4", status, got)
		}
		if slept != len(retryBackoff) {
			t.Errorf("status %d: slept %d times, want %d", status, slept, len(retryBackoff))
		}
		srv.Close()
	}
}

func TestRetrySucceedsOnASecondAttempt(t *testing.T) {
	// The form has to be rebuilt or re-readable per attempt: a reader reused
	// across a retry posts an empty body the second time, which Pushover
	// answers with a 4xx that looks like a credential problem.
	var calls int32
	var second url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		second, _ = url.ParseQuery(string(body))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":1,"request":"x"}`)
	}))
	defer srv.Close()

	c := newChannel(t, srv, Config{})
	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
	if second.Get("token") != testToken || second.Get("message") == "" {
		t.Errorf("the retried request lost its body: %v", second)
	}
}

func TestClientErrorsAreNotRetried(t *testing.T) {
	// A bad application token will still be bad in eight seconds. Retrying a
	// 4xx only delays the error message that would have told the operator to
	// go and fix their config.
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusRequestEntityTooLarge,
		http.StatusUnprocessableEntity,
	} {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"status":0,"errors":["nope"]}`)
		}))
		c := newChannel(t, srv, Config{})
		slept := 0
		c.sleep = func(context.Context, time.Duration) error { slept++; return nil }

		if err := c.Send(context.Background(), sampleAlert()); err == nil {
			t.Errorf("status %d: want an error", status)
		}
		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Errorf("status %d: attempts = %d, want 1", status, got)
		}
		if slept != 0 {
			t.Errorf("status %d: slept %d times on a permanent failure", status, slept)
		}
		srv.Close()
	}
}

func TestRetryAfterIsHonouredWhenSane(t *testing.T) {
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
			headers := map[string]string{}
			if tt.header != "" {
				headers["Retry-After"] = tt.header
			}
			srv, _ := newServer(t, http.StatusTooManyRequests, `{"status":0,"errors":["slow down"]}`, headers)
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

func TestRetryDoesNotOutlastTheDeliveryBudget(t *testing.T) {
	// The caller is channel.Queue: one worker per channel, each Send bounded
	// by channel.DefaultSendTimeout. A sleep that cannot finish inside the
	// deadline changes nothing except when the failure is reported, while
	// holding the single worker and delaying every alert queued behind it.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

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
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
}

func TestContextCancellationStopsTheRetryLoop(t *testing.T) {
	srv, _ := newServer(t, http.StatusTooManyRequests, `{"status":0,"errors":["slow down"]}`, nil)
	c := newChannel(t, srv, Config{})

	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(ctx context.Context, d time.Duration) error {
		cancel()
		return ctx.Err()
	}
	err := c.Send(ctx, sampleAlert())
	if err == nil {
		t.Fatal("want an error")
	}
	// The underlying failure is what the incident record has to say; the
	// cancellation is a detail of how we stopped waiting for it.
	if !strings.Contains(err.Error(), "slow down") {
		t.Errorf("error lost the underlying failure: %v", err)
	}
}

func TestPushoverErrorsAreQuotedBack(t *testing.T) {
	// {"status":0,"errors":[...]} says exactly what is wrong, and that is the
	// sentence the operator needs. An error that says only "400 Bad Request"
	// sends them reading API docs instead of fixing their token.
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{
			name:   "bad application token",
			status: http.StatusBadRequest,
			body:   `{"token":"invalid","errors":["application token is invalid"],"status":0,"request":"5"}`,
			want:   "application token is invalid",
		},
		{
			name:   "bad user key",
			status: http.StatusBadRequest,
			body:   `{"user":"invalid","errors":["user identifier is not a valid user, group, or subscribed user key"],"status":0}`,
			want:   "user identifier is not a valid user, group, or subscribed user key",
		},
		{
			name:   "several errors at once",
			status: http.StatusBadRequest,
			body:   `{"status":0,"errors":["message cannot be blank","title is too long"]}`,
			want:   "message cannot be blank; title is too long",
		},
		{
			name:   "a 200 that is actually a refusal",
			status: http.StatusOK,
			body:   `{"status":0,"errors":["device name is not valid for this user"]}`,
			want:   "device name is not valid for this user",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := newServer(t, tt.status, tt.body, nil)
			c := newChannel(t, srv, Config{})

			err := c.Send(context.Background(), sampleAlert())
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v\nwant it to quote %q", err, tt.want)
			}
		})
	}
}

func TestQuotedErrorBodyIsCapped(t *testing.T) {
	// A proxy's HTML error page is not going into an incident record whole.
	srv, _ := newServer(t, http.StatusBadGateway, "<html>"+strings.Repeat("padding ", 5000)+"</html>", nil)
	c := newChannel(t, srv, Config{})

	err := c.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("want an error")
	}
	// maxErrorBody of quoted text plus a short prefix; generous headroom so
	// this asserts the cap exists rather than pinning its exact arithmetic.
	if len(err.Error()) > maxErrorBody+400 {
		t.Errorf("error is %d bytes; the response body was not capped", len(err.Error()))
	}
}

func TestUnparseableSuccessBodyIsReportedAsFailure(t *testing.T) {
	// A 2xx whose body is not Pushover's JSON means something in front of the
	// API answered. Calling that a success is a guess, and this product's bias
	// is to err toward a duplicate alert rather than toward silence: a failure
	// here leaves the incident due, so somebody gets told twice instead of not
	// at all.
	srv, _ := newServer(t, http.StatusOK, "<html>hello from the captive portal</html>", nil)
	c := newChannel(t, srv, Config{})

	if err := c.Send(context.Background(), sampleAlert()); err == nil {
		t.Fatal("want an error when a 2xx body is not the expected JSON")
	}
}

func TestSuccessNeedsStatusOne(t *testing.T) {
	srv, _ := newServer(t, http.StatusOK, `{"status":1,"request":"647d2300-702c-4b38-8b2f-d56326ae460b"}`, nil)
	c := newChannel(t, srv, Config{})
	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Errorf("Send: %v", err)
	}
}

func TestTestSendsAHarmlessQuietMessage(t *testing.T) {
	srv, got := okServer(t)
	c := newChannel(t, srv, Config{})

	if err := c.Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}
	req := (*got)[0]
	if req.form.Get("message") == "" || req.form.Get("title") == "" {
		t.Errorf("test message is empty: %v", req.form)
	}
	if p := req.form.Get("priority"); p != "-1" {
		t.Errorf("priority = %q; the self-test must be quiet so nobody switches it off", p)
	}
	if req.form.Get("token") != testToken || req.form.Get("user") != testUser {
		t.Error("the self-test must exercise the real credentials or it proves nothing")
	}
	// A self-test is not an incident, so there is nothing to acknowledge.
	if _, ok := req.form["url"]; ok {
		t.Error("the self-test carried an ack link")
	}
}

func TestTestReportsABadCredential(t *testing.T) {
	// The whole reason Test exists: catching a wrong token at configuration
	// time rather than at 3am on a live incident.
	srv, _ := newServer(t, http.StatusBadRequest,
		`{"status":0,"errors":["application token is invalid"]}`, nil)
	c := newChannel(t, srv, Config{})

	err := c.Test(context.Background())
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "application token is invalid") {
		t.Errorf("error = %v, want it to say what is wrong", err)
	}
}

func TestNewRequiresBothCredentials(t *testing.T) {
	// Refusing at construction rather than at first send: the alternative is
	// discovering the misconfiguration from a failed delivery on a live
	// incident.
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "neither", cfg: Config{}},
		{name: "no user key", cfg: Config{Token: secret.Secret("t")}},
		{name: "no application token", cfg: Config{User: secret.Secret("u")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg, nil); err == nil {
				t.Error("New returned nil error, want a refusal")
			}
		})
	}
	c, err := New(Config{Token: secret.Secret("t"), User: secret.Secret("u")}, nil)
	if err != nil {
		t.Fatalf("New with both credentials: %v", err)
	}
	if c.endpoint != DefaultEndpoint {
		t.Errorf("endpoint = %q, want %q", c.endpoint, DefaultEndpoint)
	}
}

func TestNewRefusalDoesNotLeakTheOtherCredential(t *testing.T) {
	_, err := New(Config{Token: secret.Secret(testToken)}, nil)
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("the refusal leaked the token it did have: %v", err)
	}
}

func TestName(t *testing.T) {
	c, err := New(Config{Token: secret.Secret("t"), User: secret.Secret("u")}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Name() != "pushover" {
		t.Errorf("Name = %q", c.Name())
	}
}

func tail(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

// Compile-time proof that this satisfies the interface the scheduler uses.
var _ channel.Channel = (*Channel)(nil)
