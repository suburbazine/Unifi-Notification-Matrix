package ntfy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// capture records what the server actually received, which is the only thing
// worth asserting on: every bug this file guards against is a bug in what goes
// on the wire.
type capture struct {
	method string
	path   string
	query  url.Values
	header http.Header
	body   []byte
}

func newServer(t *testing.T, status int, headers map[string]string) (*httptest.Server, *[]capture) {
	t.Helper()
	var got []capture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, capture{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.Query(),
			header: r.Header.Clone(),
			body:   body,
		})
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"id":"x"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func newChannel(t *testing.T, srv *httptest.Server, cfg Config) *Channel {
	t.Helper()
	if cfg.ServerURL == "" {
		cfg.ServerURL = srv.URL
	}
	if cfg.Topic == "" {
		cfg.Topic = "unifi-alerts"
	}
	c, err := New(cfg, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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

func TestSendPutsTextInQueryParamsNotHeaders(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(*got) != 1 {
		t.Fatalf("want 1 request, got %d", len(*got))
	}
	req := (*got)[0]

	if req.method != http.MethodPut {
		t.Errorf("method = %s, want PUT", req.method)
	}
	if req.path != "/unifi-alerts" {
		t.Errorf("path = %q, want /unifi-alerts", req.path)
	}
	// The whole point: headers cannot carry a newline, so the body must not be
	// travelling in one.
	for _, h := range []string{"Title", "Message", "X-Title", "X-Message", "Tags", "X-Tags", "Priority"} {
		if v := req.header.Get(h); v != "" {
			t.Errorf("text field arrived as header %s = %q; it must be a query parameter", h, v)
		}
	}
	if q := req.query.Get("title"); q != "Door forced open" {
		t.Errorf("title = %q", q)
	}
	msg := req.query.Get("message")
	if !strings.Contains(msg, "\n") {
		t.Errorf("message lost its newlines: %q", msg)
	}
	if !strings.Contains(msg, "Door position reports open.") {
		t.Errorf("message = %q, missing the second line", msg)
	}
}

func TestSendCarriesNonASCIIAndNewlinesIntact(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.Entity = "Café Türsensor"
	a.Title = "Tür gewaltsam geöffnet"
	a.Body = "Zeile eins\nZeile zwei"

	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	if q := req.query.Get("title"); q != "Tür gewaltsam geöffnet" {
		t.Errorf("non-ASCII title mangled: %q", q)
	}
	if q := req.query.Get("message"); !strings.Contains(q, "Zeile eins\nZeile zwei") {
		t.Errorf("message = %q", q)
	}
	if q := req.query.Get("tags"); !strings.Contains(q, "Café Türsensor") {
		t.Errorf("tags = %q, non-ASCII entity mangled", q)
	}
}

func TestSeverityToPriority(t *testing.T) {
	tests := []struct {
		sev  incident.Severity
		want string
	}{
		{incident.SeverityInfo, "low"},
		{incident.SeverityLow, "default"},
		{incident.SeverityMedium, "high"},
		{incident.SeverityHigh, "high"},
		{incident.SeverityCritical, "urgent"},
		{incident.Severity("nonsense"), "default"},
	}
	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			if got := priorityFor(tt.sev); got != tt.want {
				t.Errorf("priorityFor(%q) = %q, want %q", tt.sev, got, tt.want)
			}
		})
	}
}

func TestTagsCarryOneEmojiAndReadableText(t *testing.T) {
	tests := []struct {
		name      string
		sev       incident.Severity
		wantFirst string
		wantNone  bool
	}{
		{name: "critical gets the siren", sev: incident.SeverityCritical, wantFirst: "rotating_light"},
		{name: "high gets the siren", sev: incident.SeverityHigh, wantFirst: "rotating_light"},
		{name: "medium gets the warning", sev: incident.SeverityMedium, wantFirst: "warning"},
		{name: "low gets no emoji", sev: incident.SeverityLow, wantNone: true},
		{name: "info gets no emoji", sev: incident.SeverityInfo, wantNone: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := sampleAlert()
			a.Severity = tt.sev
			tags := tagsFor(a)
			if tt.wantNone {
				if got := emojiTag(tt.sev); got != "" {
					t.Fatalf("emojiTag = %q, want none", got)
				}
				if tags[0] != string(tt.sev) {
					t.Fatalf("tags = %v, want severity first when no emoji", tags)
				}
				return
			}
			if tags[0] != tt.wantFirst {
				t.Fatalf("tags = %v, want %q first", tags, tt.wantFirst)
			}
			// Exactly one emoji-mappable tag: ntfy eats every one of them into
			// the title prefix, so a second would push the title off screen
			// and leave no visible tags.
			for _, tag := range tags[1:] {
				if tag == "rotating_light" || tag == "warning" {
					t.Errorf("tags = %v, more than one emoji tag", tags)
				}
			}
		})
	}
}

func TestEntityCommasAreStrippedFromTags(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	// A comma here would split into a bogus extra tag on the wire.
	a.Entity = "Front Door, West Wing"

	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	tags := strings.Split((*got)[0].query.Get("tags"), ",")
	for _, tag := range tags {
		if strings.TrimSpace(tag) == "West Wing" {
			t.Fatalf("entity comma produced a stray tag: %v", tags)
		}
	}
	found := false
	for _, tag := range tags {
		if tag == "Front Door West Wing" {
			found = true
		}
	}
	if !found {
		t.Errorf("tags = %v, want the entity as a single tag", tags)
	}
}

func TestAckURLBecomesActionButton(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	actions := (*got)[0].query.Get("actions")
	want := `http, Acknowledge, https://alerts.example.net/ack/inc-1/9f3a, method=GET, clear=true`
	if actions != want {
		t.Errorf("actions = %q\nwant        %q", actions, want)
	}
}

func TestAckURLWithSeparatorsIsQuoted(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
		ok   bool
	}{
		{
			name: "plain url needs no quoting",
			url:  "https://h/ack/1/ab",
			want: `http, Acknowledge, https://h/ack/1/ab, method=GET, clear=true`,
			ok:   true,
		},
		{
			name: "comma in url is double quoted",
			url:  "https://h/ack/1,2/ab",
			want: `http, Acknowledge, "https://h/ack/1,2/ab", method=GET, clear=true`,
			ok:   true,
		},
		{
			name: "semicolon in url is double quoted",
			url:  "https://h/ack/1;2/ab",
			want: `http, Acknowledge, "https://h/ack/1;2/ab", method=GET, clear=true`,
			ok:   true,
		},
		{
			name: "double quote in url falls back to single quotes",
			url:  `https://h/ack/1"2/ab`,
			want: `http, Acknowledge, 'https://h/ack/1"2/ab', method=GET, clear=true`,
			ok:   true,
		},
		{
			name: "both quote kinds is unrepresentable",
			url:  `https://h/ack/1"2'3/ab`,
			ok:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ackAction(tt.url)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("action = %q\nwant       %q", got, tt.want)
			}
		})
	}
}

func TestUnrepresentableAckURLStillReachesTheUser(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.AckURL = `https://h/ack/1"2'3/ab`

	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	if req.query.Get("actions") != "" {
		t.Error("emitted an action ntfy cannot parse correctly")
	}
	if !strings.Contains(req.query.Get("message"), a.AckURL) {
		t.Errorf("ack URL vanished entirely; message = %q", req.query.Get("message"))
	}
}

func TestSnapshotRidesAsBodyWithFilenameParam(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.Snapshot = []byte{0xFF, 0xD8, 0xFF, 0xE0, 'j', 'p', 'g'}

	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	if string(req.body) != string(a.Snapshot) {
		t.Errorf("body = %v, want the JPEG bytes", req.body)
	}
	if fn := req.query.Get("filename"); fn != "front-door.jpg" {
		t.Errorf("filename = %q", fn)
	}
	if ct := req.header.Get("Content-Type"); ct != "image/jpeg" {
		t.Errorf("content-type = %q", ct)
	}
	// The message must still be a query parameter: with the body taken by the
	// attachment there is nowhere else for it to go.
	if req.query.Get("message") == "" {
		t.Error("message parameter empty when a snapshot is attached")
	}
}

func TestNoSnapshotSendsEmptyBody(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len((*got)[0].body) != 0 {
		t.Errorf("body = %q, want empty", (*got)[0].body)
	}
	if ct := (*got)[0].header.Get("Content-Type"); ct != "" {
		t.Errorf("content-type = %q on a bodyless publish", ct)
	}
}

func TestArrivalTimeIsWordedReceived(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.AtIsArrivalTime = true
	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msg := (*got)[0].query.Get("message")
	if !strings.Contains(msg, "received 03:14:07") {
		t.Errorf("message = %q, want \"received HH:MM:SS\"", msg)
	}
	if strings.Contains(msg, "at 03:14:07") {
		t.Errorf("message = %q, an arrival time must not be presented as an observation time", msg)
	}
}

func TestObservationTimeIsWordedAt(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msg := (*got)[0].query.Get("message")
	if !strings.Contains(msg, "at 03:14:07") {
		t.Errorf("message = %q, want \"at HH:MM:SS\"", msg)
	}
	if strings.Contains(msg, "received") {
		t.Errorf("message = %q, a real observation time must not say \"received\"", msg)
	}
}

func TestRepeatIsMarkedInTitle(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.Repeat = 3
	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if title := (*got)[0].query.Get("title"); title != "Door forced open (reminder 3)" {
		t.Errorf("title = %q", title)
	}
	if tags := (*got)[0].query.Get("tags"); !strings.Contains(tags, "reminder 3") {
		t.Errorf("tags = %q, want a reminder tag", tags)
	}
}

func TestTokenTravelsInHeaderNeverInURL(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{Token: secret.Secret("tk_supersecret")})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	if h := req.header.Get("Authorization"); h != "Bearer tk_supersecret" {
		t.Errorf("Authorization = %q", h)
	}
	for k, v := range req.query {
		for _, s := range v {
			if strings.Contains(s, "tk_supersecret") {
				t.Fatalf("token leaked into query parameter %q", k)
			}
		}
	}
}

func TestRateLimitIsRetriedAndBounded(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"code":42901,"error":"limit reached"}`)
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
		t.Fatal("want an error after the retry budget is spent")
	}
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Errorf("attempts = %d, want 4 (one plus three backoffs)", got)
	}
	want := []time.Duration{2 * time.Second, 8 * time.Second, 20 * time.Second}
	if len(waits) != len(want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("wait %d = %v, want %v", i, waits[i], want[i])
		}
	}
}

func TestRateLimitSucceedsOnRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		// The snapshot must survive the retry. A reader reused across attempts
		// would arrive empty here.
		if len(body) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newChannel(t, srv, Config{})
	c.sleep = func(context.Context, time.Duration) error { return nil }

	a := sampleAlert()
	a.Snapshot = []byte{0xFF, 0xD8, 0x01, 0x02}
	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
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
		{name: "absurd value falls back to the ladder", header: "900", want: 2 * time.Second},
		{name: "http-date form is ignored", header: "Wed, 21 Oct 2026 07:28:00 GMT", want: 2 * time.Second},
		{name: "garbage is ignored", header: "soon", want: 2 * time.Second},
		{name: "absent is ignored", header: "", want: 2 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string]string{}
			if tt.header != "" {
				headers["Retry-After"] = tt.header
			}
			srv, _ := newServer(t, http.StatusTooManyRequests, headers)
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

func TestNon429IsNotRetried(t *testing.T) {
	// The escalation ladder above this channel provides persistence. A channel
	// that retries a 500 is duplicating that job with none of the state that
	// makes it safe.
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusForbidden, http.StatusNotFound, http.StatusBadRequest} {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.WriteHeader(status)
		}))
		c := newChannel(t, srv, Config{})
		if err := c.Send(context.Background(), sampleAlert()); err == nil {
			t.Errorf("status %d: want an error", status)
		}
		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Errorf("status %d: attempts = %d, want 1", status, got)
		}
		srv.Close()
	}
}

func TestErrorsDoNotLeakTopicOrToken(t *testing.T) {
	// The topic is a bearer credential in all but name, and this error string
	// is stored on the incident and shown in the UI.
	srv, _ := newServer(t, http.StatusForbidden, nil)
	c := newChannel(t, srv, Config{Topic: "very-secret-topic", Token: secret.Secret("tk_leakme")})

	err := c.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "very-secret-topic") {
		t.Errorf("error leaked the topic: %v", err)
	}
	if strings.Contains(err.Error(), "tk_leakme") {
		t.Errorf("error leaked the token: %v", err)
	}
	if strings.Contains(err.Error(), "Door forced open") {
		t.Errorf("error leaked the alert text: %v", err)
	}
}

func TestContextCancellationStopsTheRetryLoop(t *testing.T) {
	srv, _ := newServer(t, http.StatusTooManyRequests, nil)
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
	if !strings.Contains(err.Error(), "rate-limited") {
		t.Errorf("error should still name the underlying failure: %v", err)
	}
}

func TestRetryDoesNotOutlastTheDeliveryBudget(t *testing.T) {
	// The caller is channel.Queue: one worker per channel, each Send bounded
	// by channel.DefaultSendTimeout. The backoff ladder sums to exactly that
	// budget, so the last rung can only ever expire in it. Sleeping it out
	// anyway does not change the outcome -- it just holds the single worker,
	// and every alert queued behind this one waits for a delay that was
	// already known to be pointless.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newChannel(t, srv, Config{})
	slept := 0
	c.sleep = func(context.Context, time.Duration) error {
		slept++
		return nil
	}

	// Far less budget than even the first rung of the ladder needs.
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
	// The rate limit is still what the incident record has to say.
	if !strings.Contains(err.Error(), "rate-limited") {
		t.Errorf("error should still name the underlying failure: %v", err)
	}
}

func TestRetryStillUsesTheFullLadderWhenThereIsBudget(t *testing.T) {
	srv, _ := newServer(t, http.StatusTooManyRequests, nil)
	c := newChannel(t, srv, Config{})
	var waits []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	// A generous deadline must not shorten the ladder.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	_ = c.Send(ctx, sampleAlert())
	if len(waits) != len(retryBackoff) {
		t.Errorf("waits = %v, want the full ladder %v", waits, retryBackoff)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "no topic", cfg: Config{ServerURL: "https://ntfy.sh"}},
		{name: "bad scheme", cfg: Config{ServerURL: "ftp://ntfy.sh", Topic: "t"}},
		{name: "no host", cfg: Config{ServerURL: "https://", Topic: "t"}},
		{name: "topic with a path separator", cfg: Config{ServerURL: "https://ntfy.sh", Topic: "a/b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg, nil); err == nil {
				t.Errorf("New(%+v) = nil error, want a refusal", tt.cfg)
			}
		})
	}
	if _, err := New(Config{Topic: "alerts"}, nil); err != nil {
		t.Errorf("empty server URL should default to %s: %v", DefaultServer, err)
	}
}

func TestSelfHostedPathPrefixIsPreserved(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{ServerURL: srv.URL + "/ntfy/", Topic: "alerts"})

	if err := c.Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}
	if p := (*got)[0].path; p != "/ntfy/alerts" {
		t.Errorf("path = %q, want /ntfy/alerts", p)
	}
}

func TestTestSendsAProvableMessage(t *testing.T) {
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	if err := c.Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}
	req := (*got)[0]
	if req.query.Get("title") == "" || req.query.Get("message") == "" {
		t.Errorf("test message is empty: %v", req.query)
	}
	if p := req.query.Get("priority"); p != "default" {
		t.Errorf("priority = %q; a silent self-test proves half of nothing", p)
	}
}

func TestName(t *testing.T) {
	c, err := New(Config{Topic: "t"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Name() != "ntfy" {
		t.Errorf("Name = %q", c.Name())
	}
}

// Compile-time proof that this satisfies the interface the scheduler uses.
var _ channel.Channel = (*Channel)(nil)

// A 401 from ntfy is the one status where the useful response is the opposite
// of the obvious one: ntfy validates whatever credential it was given BEFORE
// it considers whether the topic needed one, so a stale or mistyped token is
// refused even on a topic open to anybody. The instinct is to go and find a
// better token; the fix is usually to remove it.
func TestAnUnauthorisedPublishSaysWhichWayToGo(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization") != ""
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":40101,"error":"unauthorized"}`))
	}))
	defer srv.Close()

	// With a token: say that removing it may be the answer.
	withToken, err := New(Config{ServerURL: srv.URL, Topic: "t", Token: "wrong"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = withToken.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("a 401 was reported as a successful publish")
	}
	if !sawAuth {
		t.Error("no Authorization header was sent even though a token was configured")
	}
	if !strings.Contains(err.Error(), "clearing the token") {
		t.Errorf("the error does not offer the counter-intuitive fix:\n%v", err)
	}

	// Without one: say that the topic wants a token.
	noToken, err := New(Config{ServerURL: srv.URL, Topic: "t"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = noToken.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("a 401 was reported as a successful publish")
	}
	if !strings.Contains(err.Error(), "requires a token") {
		t.Errorf("the error does not say a token is needed:\n%v", err)
	}
	// And it must not tell somebody with no token to clear the one they do
	// not have.
	if strings.Contains(err.Error(), "clearing the token") {
		t.Errorf("advised clearing a token that was never set:\n%v", err)
	}
}
