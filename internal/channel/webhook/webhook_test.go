package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// capture records what the server actually received. Every bug this file guards
// against is a bug in what goes on the wire, so the wire is what gets asserted
// on -- and the body is kept as raw bytes because several of these properties
// are "this string must never appear anywhere in the request".
type capture struct {
	method string
	path   string
	rawURL string
	host   string // r.Host, which net/http never puts in r.Header
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
			rawURL: r.URL.String(),
			host:   r.Host,
			header: r.Header.Clone(),
			body:   body,
		})
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

// fixedNow pins the signing clock. Chosen rather than derived: any constant does,
// so long as the tests can reproduce it exactly.
var fixedNow = time.Date(2026, 9, 15, 3, 14, 7, 0, time.UTC)

func newChannel(t *testing.T, srv *httptest.Server, cfg Config) *Channel {
	t.Helper()
	if cfg.URL == "" {
		cfg.URL = srv.URL + "/hook"
	}
	c, err := New(cfg, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No real sleeping in tests; the retry ladder is still exercised in full.
	c.sleep = func(context.Context, time.Duration) error { return nil }
	c.now = func() time.Time { return fixedNow }
	return c
}

func sampleAlert() channel.Alert {
	at := time.Date(2026, 9, 15, 3, 14, 7, 0, time.UTC)
	return channel.Alert{
		IncidentID:      "inc-42",
		Severity:        incident.SeverityCritical,
		Title:           "Door forced open",
		Body:            "Front entrance was forced.\nDoor position reports open.",
		Entity:          "Front Door",
		AckURL:          "https://alerts.example.net/ack/inc-42/9f3a",
		OpenedAt:        at.Add(-12 * time.Minute),
		At:              at,
		AtIsArrivalTime: false,
		Stage:           1,
		Repeat:          2,
	}
}

// goldenEnvelope is the version 1 contract, byte for byte.
//
// THIS TEST FAILING IS A DECISION, NOT A CHORE. The payload is published: Home
// Assistant automations, Node-RED flows and hand-rolled scripts are written
// against these exact key names, this exact nesting, and these exact types. A
// renamed or dropped field does not break those receivers loudly -- their flow
// keeps running and quietly stops doing anything, which is the worst failure a
// product whose job is waking people up can have.
//
// So if this test fails, do not update the string to match the code. Either put
// the code back, or bump PayloadVersion, keep version 1 emitting what it always
// emitted, and tell operators in the release notes.
const goldenEnvelope = `{"version":1,"test":false,"incident_id":"inc-42","severity":"critical","title":"Door forced open","body":"Front entrance was forced.\nDoor position reports open.","entity":"Front Door","ack_url":"https://alerts.example.net/ack/inc-42/9f3a","opened_at":"2026-09-15T03:02:07Z","at":"2026-09-15T03:14:07Z","at_is_arrival_time":false,"stage":1,"repeat":2}`

func TestGoldenEnvelopeIsFrozen(t *testing.T) {
	b, err := json.Marshal(build(sampleAlert(), false))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != goldenEnvelope {
		t.Errorf("the published payload changed.\n got: %s\nwant: %s\n\n"+
			"Read the comment on goldenEnvelope before touching this string.", b, goldenEnvelope)
	}
}

func TestTheGoldenEnvelopeIsWhatActuallyGoesOnTheWire(t *testing.T) {
	// The golden test above pins the encoder. This one proves the bytes the
	// encoder produced are the bytes the receiver gets -- no re-encoding, no
	// wrapper object added on the way out.
	srv, got := newServer(t, http.StatusOK, nil)
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
	if req.path != "/hook" {
		t.Errorf("path = %q, want /hook", req.path)
	}
	if ct := req.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if string(req.body) != goldenEnvelope {
		t.Errorf("body = %s\nwant   %s", req.body, goldenEnvelope)
	}
}

func TestMissingTimestampsAreEmptyStringsNotYearOne(t *testing.T) {
	// Network's Alarm Manager webhook carries no controller timestamp, so a zero
	// time is a normal case. encoding/json would render it as
	// "0001-01-01T00:00:00Z", and a receiver that formats that into a
	// notification tells somebody an event happened two thousand years ago.
	a := sampleAlert()
	a.At = time.Time{}
	a.OpenedAt = time.Time{}

	b, err := json.Marshal(build(a, false))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"at", "opened_at"} {
		v, ok := out[k]
		if !ok {
			t.Fatalf("key %q vanished; every key is always present in this contract", k)
		}
		if v != "" {
			t.Errorf("%s = %v, want an empty string", k, v)
		}
	}
	if strings.Contains(string(b), "0001-01-01") {
		t.Errorf("a zero time reached the wire: %s", b)
	}
}

func TestSnapshotNeverReachesTheWire(t *testing.T) {
	// Base64 of a JPEG in every request, on every escalation repeat, for a field
	// Home Assistant and Node-RED both ignore. Asserted on raw bytes because the
	// property is "these bytes must never appear", in any encoding we might
	// accidentally acquire.
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	a := sampleAlert()
	a.Snapshot = []byte("JPEGJPEGJPEGJPEG")

	if err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	body := (*got)[0].body
	if strings.Contains(string(body), "JPEG") {
		t.Errorf("snapshot bytes reached the payload: %s", body)
	}
	// Base64 of the same bytes, in case somebody adds an encoder later.
	if strings.Contains(string(body), "SlBFR0pQRUdKUEVHSlBFRw") {
		t.Errorf("snapshot reached the payload base64-encoded: %s", body)
	}
	if strings.Contains(string(body), "snapshot") {
		t.Errorf("payload grew a snapshot key: %s", body)
	}
}

func TestSignatureMatchesAnIndependentHMAC(t *testing.T) {
	// Computed here from scratch, NOT by calling sign(): a test that calls the
	// implementation proves only that the implementation is consistent with
	// itself, and would pass just as happily if the signing material were wrong.
	// A receiver author reading the docs will write exactly this code.
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{Secret: secret.Secret("hunter2-shared-secret")})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]

	ts := req.header.Get(HeaderTimestamp)
	if ts != strconv.FormatInt(fixedNow.Unix(), 10) {
		t.Fatalf("timestamp header = %q, want unix seconds %d", ts, fixedNow.Unix())
	}

	mac := hmac.New(sha256.New, []byte("hunter2-shared-secret"))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(req.body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if sig := req.header.Get(HeaderSignature); sig != want {
		t.Errorf("signature = %q\nwant         %q", sig, want)
	}
	// Lowercase hex, because the documented format says lowercase hex and a
	// receiver comparing strings rather than bytes will reject anything else.
	sig := strings.TrimPrefix(req.header.Get(HeaderSignature), "sha256=")
	if sig != strings.ToLower(sig) {
		t.Errorf("signature is not lowercase hex: %q", sig)
	}
	if len(sig) != sha256.Size*2 {
		t.Errorf("signature is %d hex chars, want %d", len(sig), sha256.Size*2)
	}
}

func TestSignatureIsBoundToTheTimestamp(t *testing.T) {
	// The replay defence in one assertion. If the signature did not cover the
	// timestamp, a captured request could be replayed with a fresh timestamp
	// forever and still verify -- so a signature that survives changing the
	// timestamp is a signature that buys nothing.
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{Secret: secret.Secret("hunter2-shared-secret")})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	ts, err := strconv.ParseInt(req.header.Get(HeaderTimestamp), 10, 64)
	if err != nil {
		t.Fatalf("timestamp header is not unix seconds: %v", err)
	}

	hmacOf := func(ts int64, body []byte) string {
		mac := hmac.New(sha256.New, []byte("hunter2-shared-secret"))
		mac.Write([]byte(strconv.FormatInt(ts, 10)))
		mac.Write([]byte("."))
		mac.Write(body)
		return hex.EncodeToString(mac.Sum(nil))
	}
	sent := strings.TrimPrefix(req.header.Get(HeaderSignature), "sha256=")

	if hmacOf(ts, req.body) != sent {
		t.Fatalf("sanity check failed: the signature does not match its own timestamp")
	}
	if hmacOf(ts+1, req.body) == sent {
		t.Error("the signature survives a changed timestamp; a captured request replays forever")
	}
	// And the body is covered too: a valid signature must not transfer onto a
	// different alert.
	if hmacOf(ts, []byte(`{"version":1,"test":true}`)) == sent {
		t.Error("the signature survives a changed body")
	}
}

func TestUnsignedRequestsCarryNoSignatureHeaders(t *testing.T) {
	// A receiver that verifies only when the headers are present must be able to
	// tell "unsigned" from "signed". An empty or placeholder signature header
	// would be read as a signature and fail verification, which looks like an
	// attack rather than an unconfigured secret.
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := (*got)[0]
	for _, h := range []string{HeaderSignature, HeaderTimestamp} {
		if _, ok := req.header[http.CanonicalHeaderKey(h)]; ok {
			t.Errorf("unsigned request carries %s = %q", h, req.header.Get(h))
		}
	}
}

func TestSecretNeverReachesTheWireOrAnError(t *testing.T) {
	// The shared secret authenticates us to the receiver. It goes into the HMAC
	// and nowhere else -- not a header, not the body, and not an error string
	// that gets stored on the incident and shown in the UI.
	srv, got := newServer(t, http.StatusForbidden, nil)
	c := newChannel(t, srv, Config{Secret: secret.Secret("tk_leakme")})

	err := c.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "tk_leakme") {
		t.Errorf("error leaked the secret: %v", err)
	}
	req := (*got)[0]
	if strings.Contains(string(req.body), "tk_leakme") {
		t.Errorf("secret reached the body: %s", req.body)
	}
	for k, vs := range req.header {
		for _, v := range vs {
			if strings.Contains(v, "tk_leakme") {
				t.Errorf("secret reached header %s: %q", k, v)
			}
		}
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	// A redirect would resend the signed body, with its still-valid signature and
	// its live ack URL, to a host the operator never configured. The attacker
	// does not even need our secret: the request they receive is already signed.
	var elsewhereHits int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&elsewhereHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	for _, status := range []int{http.StatusFound, http.StatusMovedPermanently,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+"/stolen", status)
		}))

		c := newChannel(t, redirector, Config{
			URL:    redirector.URL + "/hook",
			Secret: secret.Secret("hunter2-shared-secret"),
		})
		err := c.Send(context.Background(), sampleAlert())
		if err == nil {
			t.Errorf("status %d: the redirect was followed", status)
		}
		if err != nil && !strings.Contains(err.Error(), "redirect") {
			t.Errorf("status %d: error should say a redirect was refused: %v", status, err)
		}
		redirector.Close()
	}
	if n := atomic.LoadInt32(&elsewhereHits); n != 0 {
		t.Fatalf("the signed alert was delivered to the redirect target %d times", n)
	}
}

func TestNewRefusesHeadersThatWouldOverrideSigning(t *testing.T) {
	// An operator who pins X-NotifyMatrix-Signature by hand produces requests
	// that verify against a constant, which is worse than unsigned: the receiver
	// believes it checked something. Refused at New, case-insensitively, because
	// HTTP header names are case-insensitive and "x-notifymatrix-signature" is
	// exactly what somebody copying from a YAML example will type.
	for _, name := range []string{
		"X-NotifyMatrix-Signature",
		"x-notifymatrix-signature",
		"X-NOTIFYMATRIX-SIGNATURE",
		"X-NotifyMatrix-Timestamp",
		"x-notifymatrix-timestamp",
		"Content-Type",
		"content-type",
		"CONTENT-TYPE",
		"  Content-Type  ",
		// net/http frames the request from the body and ignores these two
		// entirely, so accepting them meant accepting something that was then
		// silently dropped -- the quiet degradation the rest of this file exists
		// to prevent.
		"Content-Length",
		"content-length",
		"Transfer-Encoding",
	} {
		_, err := New(Config{URL: "https://h/hook", Headers: map[string]string{name: "x"}}, nil)
		if err == nil {
			t.Errorf("header %q was accepted; it must be refused", name)
			continue
		}
		if !strings.Contains(err.Error(), "cannot be overridden") {
			t.Errorf("header %q: error should say why: %v", name, err)
		}
	}

	// An ordinary header is still allowed, and still arrives.
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{Headers: map[string]string{"X-Api-Key": "abc123"}})
	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if v := (*got)[0].header.Get("X-Api-Key"); v != "abc123" {
		t.Errorf("X-Api-Key = %q, want abc123", v)
	}
	if ct := (*got)[0].header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
}

func TestStaticHeaderMapIsCopiedNotAliased(t *testing.T) {
	// A config reload that reuses the caller's map must not silently re-header a
	// channel that is already running.
	srv, got := newServer(t, http.StatusOK, nil)
	h := map[string]string{"X-Api-Key": "abc123"}
	c := newChannel(t, srv, Config{Headers: h})
	h["X-Api-Key"] = "changed"
	h["X-Injected"] = "nope"

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if v := (*got)[0].header.Get("X-Api-Key"); v != "abc123" {
		t.Errorf("X-Api-Key = %q, want the value captured at New", v)
	}
	if v := (*got)[0].header.Get("X-Injected"); v != "" {
		t.Errorf("a header added after New reached the wire: %q", v)
	}
}

func TestQueryStringTokenNeverReachesAnError(t *testing.T) {
	// Home Assistant, Slack and n8n all authenticate a webhook with an
	// unguessable string in the URL. Anyone holding it can inject fake alarms, so
	// it is a credential -- and channel errors are stored on the incident and
	// rendered in the UI, which is the last place it should surface.
	const token = "tkn_supersecret_do_not_log"

	t.Run("4xx rejection", func(t *testing.T) {
		srv, _ := newServer(t, http.StatusForbidden, nil)
		c := newChannel(t, srv, Config{URL: srv.URL + "/hook?token=" + token})
		assertNoToken(t, c.Send(context.Background(), sampleAlert()), token)
	})

	t.Run("retryable failure after the ladder is spent", func(t *testing.T) {
		srv, _ := newServer(t, http.StatusBadGateway, nil)
		c := newChannel(t, srv, Config{URL: srv.URL + "/hook?token=" + token})
		assertNoToken(t, c.Send(context.Background(), sampleAlert()), token)
	})

	t.Run("transport failure", func(t *testing.T) {
		// net/http wraps every transport failure in *url.Error, which prints the
		// full request URL. That wrapper is the leak this guards against.
		srv, _ := newServer(t, http.StatusOK, nil)
		c := newChannel(t, srv, Config{URL: srv.URL + "/hook?token=" + token})
		srv.Close()
		assertNoToken(t, c.Send(context.Background(), sampleAlert()), token)
	})

	t.Run("refused redirect", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://attacker.example/stolen", http.StatusFound)
		}))
		defer srv.Close()
		c := newChannel(t, srv, Config{URL: srv.URL + "/hook?token=" + token})
		assertNoToken(t, c.Send(context.Background(), sampleAlert()), token)
	})

	t.Run("New refuses an unparseable url without quoting it", func(t *testing.T) {
		_, err := New(Config{URL: "http://[::1/hook?token=" + token}, nil)
		if err == nil {
			t.Fatal("want a refusal")
		}
		assertNoToken(t, err, token)
	})
}

func assertNoToken(t *testing.T, err error, token string) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error leaked the URL token: %v", err)
	}
}

func TestRetryableStatusesAreRetriedAndBounded(t *testing.T) {
	// 429 and 5xx mean "try again"; the ladder is bounded because the escalation
	// ladder above this channel is what provides persistence, and a channel that
	// retries for minutes holds its queue's single worker and delays every other
	// alert behind it.
	for _, status := range []int{
		http.StatusTooManyRequests,
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

		c := newChannel(t, srv, Config{URL: srv.URL + "/hook"})
		var waits []time.Duration
		c.sleep = func(_ context.Context, d time.Duration) error {
			waits = append(waits, d)
			return nil
		}

		if err := c.Send(context.Background(), sampleAlert()); err == nil {
			t.Errorf("status %d: want an error once the retry budget is spent", status)
		}
		if got := atomic.LoadInt32(&calls); got != 4 {
			t.Errorf("status %d: attempts = %d, want 4 (one plus three backoffs)", status, got)
		}
		want := []time.Duration{1 * time.Second, 4 * time.Second, 10 * time.Second}
		if len(waits) != len(want) {
			t.Errorf("status %d: waits = %v, want %v", status, waits, want)
		} else {
			for i := range want {
				if waits[i] != want[i] {
					t.Errorf("status %d: wait %d = %v, want %v", status, i, waits[i], want[i])
				}
			}
		}
		srv.Close()
	}
}

func TestRetrySucceedsAndResendsTheWholeBody(t *testing.T) {
	// A body reader reused across attempts arrives EMPTY the second time, and a
	// receiver happily accepts an empty POST as a valid-looking nothing. That is
	// a silent non-delivery, which is the failure this product exists to avoid.
	var calls int32
	var second []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		second = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newChannel(t, srv, Config{URL: srv.URL + "/hook"})
	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
	if string(second) != goldenEnvelope {
		t.Errorf("retry body = %q, want the full envelope again", second)
	}
}

func TestClientErrorsAreNotRetried(t *testing.T) {
	// A 4xx is the receiver saying the request itself is wrong: a revoked token,
	// a path that no longer exists, a body it will not parse. Retrying gets the
	// same answer four times over and delays the honest failure report that the
	// escalation ladder needs in order to try the next channel.
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusGone,
		http.StatusUnsupportedMediaType,
	} {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.WriteHeader(status)
		}))

		c := newChannel(t, srv, Config{URL: srv.URL + "/hook"})
		slept := 0
		c.sleep = func(context.Context, time.Duration) error { slept++; return nil }

		if err := c.Send(context.Background(), sampleAlert()); err == nil {
			t.Errorf("status %d: want an error", status)
		}
		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Errorf("status %d: attempts = %d, want 1", status, got)
		}
		if slept != 0 {
			t.Errorf("status %d: slept %d times on a 4xx", status, slept)
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
		{name: "sane delta seconds wins over the ladder", header: "3", want: 3 * time.Second},
		{name: "at the bound it is still honoured", header: "15", want: 15 * time.Second},
		{name: "absurd value falls back to the ladder", header: "600", want: 1 * time.Second},
		{name: "http-date form is ignored", header: "Wed, 21 Oct 2026 07:28:00 GMT", want: 1 * time.Second},
		{name: "garbage is ignored", header: "soon", want: 1 * time.Second},
		{name: "negative is ignored", header: "-5", want: 1 * time.Second},
		{name: "absent is ignored", header: "", want: 1 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string]string{}
			if tt.header != "" {
				headers["Retry-After"] = tt.header
			}
			srv, _ := newServer(t, http.StatusServiceUnavailable, headers)
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
				t.Fatal("never slept; the retryable status was not retried")
			}
			if first != tt.want {
				t.Errorf("first wait = %v, want %v", first, tt.want)
			}
		})
	}
}

func TestRetryDoesNotOutlastTheDeliveryBudget(t *testing.T) {
	// The caller is channel.Queue: one worker per channel, each Send bounded by
	// channel.DefaultSendTimeout. Sleeping out a rung that cannot finish inside
	// the remaining budget changes nothing except when the failure is reported,
	// while holding the worker and delaying every alert queued behind this one.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newChannel(t, srv, Config{URL: srv.URL + "/hook"})
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
	// The underlying failure is still what the incident record has to say.
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should still name the underlying failure: %v", err)
	}
}

func TestContextCancellationStopsTheRetryLoop(t *testing.T) {
	srv, _ := newServer(t, http.StatusServiceUnavailable, nil)
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
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should still name the underlying failure: %v", err)
	}
}

func TestTestSendsTheSameEnvelopeWithTheTestFlag(t *testing.T) {
	// Without the flag, a receiver can only recognise a self-test by
	// string-matching the title -- and an automation that unlocks a door on a
	// critical alert would run during the scheduled self-test.
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	if err := c.Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal((*got)[0].body, &p); err != nil {
		t.Fatalf("test payload is not JSON: %v", err)
	}
	if p["test"] != true {
		t.Errorf("test = %v, want true", p["test"])
	}
	if p["version"] != float64(PayloadVersion) {
		t.Errorf("version = %v, want %d", p["version"], PayloadVersion)
	}
	if p["title"] == "" {
		t.Error("test payload has no title")
	}
	if p["at"] == "" {
		t.Error("test payload has no timestamp")
	}
	// Same shape as a real alert: every contract key present, so a receiver
	// written against Send does not crash on Test.
	for _, k := range []string{"incident_id", "severity", "body", "entity",
		"ack_url", "opened_at", "at_is_arrival_time", "stage", "repeat"} {
		if _, ok := p[k]; !ok {
			t.Errorf("test payload is missing contract key %q", k)
		}
	}

	// And a real alert must say so.
	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var real map[string]any
	if err := json.Unmarshal((*got)[1].body, &real); err != nil {
		t.Fatalf("alert payload is not JSON: %v", err)
	}
	if real["test"] != false {
		t.Errorf("a real alert reported test = %v", real["test"])
	}
}

func TestNewValidatesConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "empty url", cfg: Config{}},
		{name: "whitespace url", cfg: Config{URL: "   "}},
		{name: "bad scheme", cfg: Config{URL: "ftp://h/hook"}},
		{name: "no host", cfg: Config{URL: "https:///hook"}},
		{name: "not a url", cfg: Config{URL: "http://[::1/hook"}},
		{name: "empty header name", cfg: Config{URL: "https://h/hook", Headers: map[string]string{" ": "v"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg, nil); err == nil {
				t.Errorf("New(%+v) = nil error, want a refusal", tt.cfg)
			}
		})
	}
	if _, err := New(Config{URL: "https://ha.lan:8123/api/webhook/abc?t=1"}, nil); err != nil {
		t.Errorf("a perfectly ordinary webhook URL was refused: %v", err)
	}
}

func TestInsecureSkipVerifyDoesNotMutateTheCallersClient(t *testing.T) {
	// The caller's client is shared with the UniFi console clients. Turning off
	// certificate verification for one LAN webhook must not turn it off for the
	// controller session too.
	shared := &http.Client{}
	if _, err := New(Config{URL: "https://h/hook", InsecureSkipVerify: true}, shared); err != nil {
		t.Fatalf("New: %v", err)
	}
	if shared.Transport != nil {
		t.Error("New replaced the transport on the caller's client")
	}
	if shared.CheckRedirect != nil {
		t.Error("New changed redirect handling on the caller's client")
	}
}

func TestSigningHeaderNamesAreTheNamesThatActuallyGoOnTheWire(t *testing.T) {
	// THE BUG THIS PREVENTS: the exported constants spelled the headers
	// "X-NotifyMatrix-*", but net/http canonicalises what it writes, so the wire
	// carried "X-Notifymatrix-*" -- lowercase m. The operator documentation is
	// generated from these constants, so an integrator doing a CASE-SENSITIVE
	// lookup (a jq handler, an n8n $request.headers expression, a raw dict index)
	// looked for a name that was never sent, and then either treated every signed
	// alert as unsigned or rejected all of them. From here that is an ordinary
	// 4xx with nothing pointing at the spelling.
	//
	// Indexed directly into the header map rather than through Header.Get, which
	// canonicalises the lookup key and would hide exactly this.
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{Secret: secret.Secret("hunter2-shared-secret")})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for _, name := range []string{HeaderSignature, HeaderTimestamp} {
		if canonical := http.CanonicalHeaderKey(name); name != canonical {
			t.Errorf("exported constant %q is not what net/http sends (%q); "+
				"a receiver told to look for the constant will not find it", name, canonical)
		}
		if _, ok := (*got)[0].header[name]; !ok {
			t.Errorf("no header keyed exactly %q arrived; keys were %v", name, keysOf((*got)[0].header))
		}
	}
}

func keysOf(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	return out
}

func TestArrivalTimeIsCarriedInBothStates(t *testing.T) {
	// THE BUG THIS PREVENTS: at_is_arrival_time was pinned only at its default,
	// so replacing the field with a constant false left the suite green. A
	// Network Alarm Manager event carries no controller timestamp -- "at" is
	// merely when WE received it -- and a receiver whose template then renders
	// "at 03:14" sends the operator to scrub footage at 03:14, where they find
	// nothing and distrust the product rather than the timestamp.
	//
	// Asserted in BOTH states, through the wire, so a constant of either value
	// fails.
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{})

	arrival := sampleAlert()
	arrival.AtIsArrivalTime = true
	if err := c.Send(context.Background(), arrival); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(*got) != 2 {
		t.Fatalf("want 2 requests, got %d", len(*got))
	}
	if !strings.Contains(string((*got)[0].body), `"at_is_arrival_time":true`) {
		t.Errorf("an arrival-time alert went out as anything but true: %s", (*got)[0].body)
	}
	for i, want := range []bool{true, false} {
		var p map[string]any
		if err := json.Unmarshal((*got)[i].body, &p); err != nil {
			t.Fatalf("payload %d is not JSON: %v", i, err)
		}
		if p["at_is_arrival_time"] != want {
			t.Errorf("request %d: at_is_arrival_time = %v, want %v", i, p["at_is_arrival_time"], want)
		}
	}
}

func TestEveryRetryAttemptIsSignedAfresh(t *testing.T) {
	// THE BUG THIS PREVENTS: hoisting the sign block out of attempt() into post()
	// -- an obvious-looking refactor, since the body is identical every time --
	// makes a retry carry the FIRST attempt's timestamp. By the last rung that is
	// fifteen seconds stale, which any receiver enforcing a freshness window
	// rejects, and rejects AS A REPLAY: a silent non-delivery of an alarm whose
	// first attempt had already failed.
	//
	// The clock is unpinned here (newChannel pins it to a constant) precisely so
	// that a cached timestamp shows up as a repeated value.
	const shared = "hunter2-shared-secret"
	var calls int32
	var seen []capture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, capture{header: r.Header.Clone(), body: body})
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newChannel(t, srv, Config{URL: srv.URL + "/hook", Secret: secret.Secret(shared)})
	var tick int64
	c.now = func() time.Time {
		tick++
		return fixedNow.Add(time.Duration(tick) * time.Second)
	}

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("attempts = %d, want 3", len(seen))
	}

	stamps := map[string]bool{}
	for i, req := range seen {
		ts := req.header.Get(HeaderTimestamp)
		if stamps[ts] {
			t.Fatalf("attempt %d reused timestamp %q; the retry is signed once and replayed", i, ts)
		}
		stamps[ts] = true

		// Each signature must verify against ITS OWN timestamp, computed here
		// from scratch rather than by calling sign().
		mac := hmac.New(sha256.New, []byte(shared))
		mac.Write([]byte(ts))
		mac.Write([]byte("."))
		mac.Write(req.body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if sig := req.header.Get(HeaderSignature); sig != want {
			t.Errorf("attempt %d: signature does not cover its own timestamp\n got %q\nwant %q", i, sig, want)
		}
	}
}

func TestPathTokenNeverReachesAnError(t *testing.T) {
	// THE BUG THIS PREVENTS: the redaction dropped only the query string and kept
	// the path -- and the path is where the credential lives for every receiver
	// this channel names. Home Assistant is /api/webhook/<id>, Slack is
	// /services/T../B../<token>, n8n is /webhook/<uuid>. These error strings are
	// stored on the incident record and rendered in the web UI, so anyone who
	// could read an incident held a bearer credential that injects fake alarms
	// into the operator's automation.
	const token = "XQ9sEcReT"
	hook := "/services/T01/B02/" + token

	t.Run("4xx rejection", func(t *testing.T) {
		srv, _ := newServer(t, http.StatusForbidden, nil)
		c := newChannel(t, srv, Config{URL: srv.URL + hook})
		assertNoToken(t, c.Send(context.Background(), sampleAlert()), token)
	})

	t.Run("retryable failure after the ladder is spent", func(t *testing.T) {
		srv, _ := newServer(t, http.StatusInternalServerError, nil)
		c := newChannel(t, srv, Config{URL: srv.URL + hook})
		assertNoToken(t, c.Send(context.Background(), sampleAlert()), token)
	})

	t.Run("transport failure", func(t *testing.T) {
		srv, _ := newServer(t, http.StatusOK, nil)
		c := newChannel(t, srv, Config{URL: srv.URL + hook})
		srv.Close()
		assertNoToken(t, c.Send(context.Background(), sampleAlert()), token)
	})

	t.Run("refused redirect names neither path", func(t *testing.T) {
		// The Location target carries a token of its own, and refuseRedirect
		// prints that URL.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://attacker.example/webhook/"+token, http.StatusFound)
		}))
		defer srv.Close()
		c := newChannel(t, srv, Config{URL: srv.URL + hook})
		assertNoToken(t, c.Send(context.Background(), sampleAlert()), token)
	})
}

func TestHostHeaderRoutesInsteadOfBeingSilentlyDropped(t *testing.T) {
	// THE BUG THIS PREVENTS: a static Host header was accepted by New and then
	// discarded, because net/http writes the Host from req.Host and never from
	// the header map. Behind a LAN reverse proxy doing vhost routing -- exactly
	// the "routing hint" Config.Headers documents -- every alert then landed on
	// the proxy's default vhost: a 404, correctly not retried, with an error that
	// said nothing about the header that caused it.
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{Headers: map[string]string{"Host": "ha.internal"}})

	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if h := (*got)[0].host; h != "ha.internal" {
		t.Errorf("Host = %q, want ha.internal; the operator's routing hint was dropped", h)
	}
}

func TestInvalidStaticHeadersAreRefusedAtConfigTimeNotAtThreeAM(t *testing.T) {
	// THE BUG THIS PREVENTS: an API key pasted with a trailing newline was stored
	// happily by New and then rejected by net/http INSIDE the transport on every
	// single delivery. Nothing leaks -- Go omits the value from that error -- but
	// the channel is permanently dead, the failure is not retryable, and the
	// message names net/http rather than the config field the operator typed.
	srv, got := newServer(t, http.StatusOK, nil)
	c := newChannel(t, srv, Config{Headers: map[string]string{"X-Api-Key": "abc123\n"}})
	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("a pasted trailing newline killed the channel: %v", err)
	}
	if v := (*got)[0].header.Get("X-Api-Key"); v != "abc123" {
		t.Errorf("X-Api-Key = %q, want the trimmed value", v)
	}

	// Anything still illegal after the trim is a config error, refused where the
	// operator can read it rather than inside every request.
	for _, h := range []map[string]string{
		{"X-Api Key": "v"},
		{"X-Api-Key:": "v"},
		{"X-Api\nKey": "v"},
		{"X-Api-Key": "abc\ndef"},
		{"X-Api-Key": "abc\rdef"},
	} {
		_, err := New(Config{URL: "https://h/hook", Headers: h}, nil)
		if err == nil {
			t.Errorf("header %v was accepted; every delivery would fail in the transport", h)
			continue
		}
		// And the refusal must not quote the value back: it is usually a key.
		for _, v := range h {
			if strings.Contains(err.Error(), v) && v != "v" {
				t.Errorf("the refusal quoted the header value: %v", err)
			}
		}
	}
}

func TestInsecureSkipVerifyIsActuallyApplied(t *testing.T) {
	// THE BUG THIS PREVENTS: the only test naming this setting asserted the
	// negative -- that the caller's client was left alone -- so deleting the
	// whole InsecureSkipVerify branch left the suite green. This is the setting
	// the realistic deployment needs (a Home Assistant box on the LAN with a
	// self-signed certificate); if it silently stops taking effect, the operator
	// sees the box ticked and the 3am alert dies on "x509: certificate signed by
	// unknown authority".
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// A plain client, NOT srv.Client(): the httptest client already trusts the
	// test certificate, which would make this pass with or without the setting.
	c, err := New(Config{URL: srv.URL + "/hook", InsecureSkipVerify: true}, &http.Client{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("insecure_skip_verify did not take effect: %v", err)
	}

	// The control: without it the same endpoint must still be refused, or the
	// assertion above proves nothing about verification at all.
	strict, err := New(Config{URL: srv.URL + "/hook"}, &http.Client{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := strict.Send(context.Background(), sampleAlert()); err == nil {
		t.Error("a self-signed certificate was accepted without insecure_skip_verify")
	}
}

// roundTripperFunc is a custom RoundTripper: something whose TLS settings this
// package cannot reach into.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInsecureSkipVerifyIsRefusedWhenItCannotBeHonoured(t *testing.T) {
	// THE BUG THIS PREVENTS: a client carrying a RoundTripper that is not an
	// *http.Transport used to be returned unchanged, so the operator's explicit
	// request was dropped without a word. Silently ignoring it produces the same
	// 3am certificate failure as losing the setting altogether -- so it is
	// refused at New, where somebody can read it.
	custom := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unused")
	})}
	_, err := New(Config{URL: "https://h/hook", InsecureSkipVerify: true}, custom)
	if err == nil {
		t.Fatal("insecure_skip_verify was accepted against a transport that cannot honour it")
	}
	if !strings.Contains(err.Error(), "insecure_skip_verify") {
		t.Errorf("the refusal should name the setting: %v", err)
	}

	// Without the setting the same client is perfectly fine.
	if _, err := New(Config{URL: "https://h/hook"}, custom); err != nil {
		t.Errorf("a custom transport was refused for no reason: %v", err)
	}
}

func TestName(t *testing.T) {
	c, err := New(Config{URL: "https://h/hook"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Name() != "webhook" {
		t.Errorf("Name = %q", c.Name())
	}
}

// Compile-time proof that this satisfies the interface the scheduler uses.
var _ channel.Channel = (*Channel)(nil)
